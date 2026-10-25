import "./preload.mjs";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { chromium } from "playwright";

process.env.BRIDGE_TOKEN ||= randomBytes(32).toString("hex");

const here = path.dirname(fileURLToPath(import.meta.url));
export const verifyRoot = path.resolve(here, "..");
export const repoRoot = path.resolve(verifyRoot, "..");
export const extensionDir = path.join(repoRoot, "extension");
export const backgroundPath = path.join(extensionDir, "background.js");
export const serverDir = path.join(repoRoot, "server");
export const fixtureHtmlPath = path.join(verifyRoot, "fixture", "index.html");

// Playwright's own --disable-features is overwritten by a later switch, so this
// list keeps the interception-related disables and re-enables --load-extension
// on branded Chrome (the switch is gated by DisableLoadExtensionCommandLineSwitch).
const DISABLED_FEATURES = [
  "DisableLoadExtensionCommandLineSwitch",
  "AvoidUnnecessaryBeforeUnloadCheckSync",
  "DestroyProfileOnBrowserClose",
  "HttpsUpgrades",
  "Translate",
  "PaintHolding",
  "ThirdPartyStoragePartitioning",
  "BlockOriginHeaderModificationOnRedirect",
  "AvoidCorsURLLoaderRestartOnRedirect",
].join(",");

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function resolveBun() {
  if (process.env.BUN) return process.env.BUN;
  const found = spawnSync("which", ["bun"], { encoding: "utf8" });
  if (found.status === 0 && found.stdout.trim()) return found.stdout.trim();
  const fallback = path.join(os.homedir(), ".bun", "bin", "bun");
  return fallback;
}

export async function waitUntilBackgroundParses() {
  const start = Date.now();
  let last = "";
  while (Date.now() - start < 20_000) {
    const check = spawnSync(process.execPath, ["--check", backgroundPath], { encoding: "utf8" });
    if (check.status === 0) return;
    last = `${check.stderr || ""}${check.stdout || ""}`.trim();
    await sleep(400);
  }
  throw new Error(`extension/background.js failed node --check (the file may be mid-edit):\n${last}`);
}

// Handler methods are the `async name(` entries inside `const handlers`.
export async function readHandlers() {
  const src = await fs.readFile(backgroundPath, "utf8");
  const start = src.indexOf("const handlers = {");
  const end = src.indexOf("async function connectToPort", start === -1 ? 0 : start);
  const body = start >= 0 && end > start ? src.slice(start, end) : src;
  const names = new Set();
  for (const match of body.matchAll(/^\s{2}async\s+([A-Za-z0-9_]+)\s*\(/gm)) {
    names.add(match[1]);
  }
  return names;
}

export async function startFixture() {
  const html = await fs.readFile(fixtureHtmlPath);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (url.pathname === "/echo") {
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (key.startsWith("x-")) headers[key] = value;
      }
      const body = JSON.stringify({ marker: "echo-original", headers });
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(body);
      return;
    }
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(html);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    url: `${origin}/`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export async function startMcp() {
  const bun = resolveBun();
  try {
    await fs.access(bun);
  } catch {
    throw new Error(`bun was not found at ${bun}. Install bun or set BUN to the binary path.`);
  }
  let stderr = "";
  const transport = new StdioClientTransport({
    command: bun,
    args: ["run", "src/index.ts"],
    cwd: serverDir,
    stderr: "pipe",
    env: { ...process.env },
  });
  const client = new Client({ name: "bridge-verify", version: "1.0.0" });
  transport.stderr?.on("data", (chunk) => {
    const text = chunk.toString();
    stderr = (stderr + text).slice(-80_000);
    process.stderr.write(text);
  });
  await client.connect(transport);
  const readyAt = Date.now();
  while (Date.now() - readyAt < 20_000) {
    if (stderr.includes("MCP server started") && stderr.includes("Server listening")) break;
    await sleep(100);
  }
  if (!stderr.includes("Server listening")) {
    throw new Error(`MCP server did not listen. stderr:\n${stderr}`);
  }
  const tools = new Set();
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined, { timeout: 20_000 });
    for (const tool of page.tools || []) tools.add(tool.name);
    cursor = page.nextCursor;
  } while (cursor);

  async function call(name, args = {}, timeout = 90_000) {
    const result = await client.callTool({ name, arguments: args }, undefined, { timeout });
    const text = (result.content || [])
      .filter((part) => part.type === "text")
      .map((part) => part.text)
      .join("\n");
    if (result.isError) {
      const error = new Error(text || `${name} failed`);
      error.tool = name;
      throw error;
    }
    let json = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = { raw: text };
      }
    }
    return { text, json, result };
  }

  return {
    client,
    transport,
    tools,
    call,
    stderr: () => stderr,
    close: () => transport.close(),
  };
}

function rememberExtensionWorker(session, worker) {
  worker.on("console", (msg) => console.error(`[ext-sw] ${msg.type()} ${msg.text()}`));
  try {
    const id = new URL(worker.url()).host;
    if (id) session.extensionIds.add(id);
  } catch {
    // Not an extension worker URL.
  }
}

// MV3 stops the background worker once the startup script goes idle, which
// closes its WebSocket. An open runtime port plus the popup's retry message
// keeps the worker up and rescans ports 17890–17909.
async function installKeepalive(page) {
  await page.evaluate(() => {
    const port = chrome.runtime.connect({ name: "verify-keepalive" });
    globalThis.__verifyPort = port;
    const poke = () => {
      chrome.runtime.sendMessage({ type: "retry" }, () => void chrome.runtime.lastError);
      try {
        port.postMessage({ type: "verify-keepalive" });
      } catch {
        // The port drops if the worker restarts; the next retry wakes it.
      }
    };
    poke();
    setInterval(poke, 2000);
  });
}

export async function holdBridge(session) {
  const checked = new Set();
  const start = Date.now();
  while (Date.now() - start < 25_000) {
    for (const id of session.extensionIds) {
      if (checked.has(id)) continue;
      checked.add(id);
      const page = await session.context.newPage();
      try {
        await page.goto(`chrome-extension://${id}/manifest.json`, {
          waitUntil: "domcontentloaded",
          timeout: 8_000,
        });
        const text = await page.locator("body").innerText({ timeout: 3_000 });
        if (!text.includes("Claude Code Browser Bridge")) {
          await page.close().catch(() => {});
          continue;
        }
        await page.goto(`chrome-extension://${id}/popup.html`, {
          waitUntil: "domcontentloaded",
          timeout: 8_000,
        });
        await page.locator("#bridgeToken").fill(process.env.BRIDGE_TOKEN);
        await page.locator("#pairForm button[type=submit]").click();
        await installKeepalive(page);
        session.popup = page;
        session.extensionId = id;
        console.error(`[verify] keeping extension ${id} alive via popup`);
        return id;
      } catch (err) {
        const missing = /ERR_FILE_NOT_FOUND|ERR_BLOCKED_BY_CLIENT/.test(err.message);
        if (!missing) {
          console.error(`[verify] extension candidate ${id} failed: ${err.message.split("\n")[0]}`);
          checked.delete(id);
        }
        await page.close().catch(() => {});
      }
    }
    await sleep(300);
  }
  throw new Error(
    `did not find the bridge extension among ${JSON.stringify([...session.extensionIds])}`
  );
}

async function launchOnce(extensionPath, headed) {
  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), "ccb-verify-profile-"));
  const args = [
    `--disable-extensions-except=${extensionPath}`,
    `--load-extension=${extensionPath}`,
    `--disable-features=${DISABLED_FEATURES}`,
  ];
  if (!headed) args.push("--headless=new");
  // Google Chrome 155 ignores --load-extension ("not allowed in Google Chrome").
  // Playwright's Chromium build still honors it. VERIFY_CHANNEL=chrome opts back
  // into the installed Chrome for builds that still accept the switch.
  const context = await chromium.launchPersistentContext(userDataDir, {
    ...(process.env.VERIFY_CHANNEL ? { channel: process.env.VERIFY_CHANNEL } : {}),
    headless: false,
    viewport: { width: 1280, height: 800 },
    ignoreDefaultArgs: [
      "--disable-extensions",
      "--disable-component-extensions-with-background-pages",
    ],
    args,
  });
  const session = {
    context,
    page: null,
    userDataDir,
    headed,
    extensionIds: new Set(),
  };
  const logWorker = (worker) => rememberExtensionWorker(session, worker);
  context.serviceWorkers().forEach(logWorker);
  context.on("serviceworker", logWorker);
  const page = context.pages()[0] || (await context.newPage());
  page.setDefaultTimeout(20_000);
  session.page = page;
  return {
    ...session,
    async close() {
      await context.close().catch(() => {});
      await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    },
  };
}

export async function launchChrome(extensionPath, fixtureUrl) {
  const headedOnly = process.env.VERIFY_HEADED === "1";
  const modes = headedOnly ? [true] : [false, true];
  let lastError;
  for (const headed of modes) {
    let session;
    try {
      session = await launchOnce(extensionPath, headed);
      await session.page.goto(fixtureUrl, { waitUntil: "domcontentloaded", timeout: 30_000 });
      await session.page.waitForFunction(
        () => document.querySelector("#shadow-host")?.shadowRoot?.querySelector("button"),
        null,
        { timeout: 15_000 }
      );
      await holdBridge(session);
      console.error(
        `[verify] Chrome ready (${headed ? "headed" : "headless=new"}), extension ${session.extensionId}`
      );
      return session;
    } catch (err) {
      lastError = err;
      console.error(
        `[verify] Chrome launch (${headed ? "headed" : "headless=new"}) did not load the extension: ${err.message}`
      );
      if (session) await session.close();
    }
  }
  throw lastError;
}

export function livePage(session, origin) {
  const pages = session.context.pages().filter((page) => !page.isClosed());
  return pages.find((page) => page.url().startsWith(origin)) || pages[0] || session.page;
}
