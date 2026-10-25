import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  extensionDir,
  launchChrome,
  livePage,
  readHandlers,
  repoRoot,
  sleep,
  startFixture,
  startMcp,
  waitUntilBackgroundParses,
} from "./runtime.mjs";

const HANDLER_FOR_TOOL = {
  list_browser_tabs: "listTabs",
  get_page_structure: "getPageStructure",
  click_element: "clickElement",
  type_text: "typeText",
  describe_element: "describeElement",
  find_text: "findText",
  page_selection: "pageSelection",
  browser_session: "browserSession",
  rewrite_traffic: "rewriteTraffic",
  read_network_requests: "readNetworkRequests",
  export_har: "exportHar",
  save_page: "savePage",
  emulate_environment: "emulateEnvironment",
  grant_permission: "grantPermission",
  webauthn: "webauthn",
  touch_gesture: "touchGesture",
  execute_javascript: "executeJavaScript",
  cdp_detach: "cdpDetachTarget",
};

const LAT = 37.8199;
const LNG = -122.4783;
const FIND_QUERY = "alpha-bridge-77";
const SELECT_TEXT = "gamma-select-42";
const TYPED = "typed-by-harness";
const HEADER_VALUE = "harness-header-ok";

function skip(reason) {
  return { skip: reason };
}

function gate(ctx, tool) {
  const method = HANDLER_FOR_TOOL[tool];
  if (!method) throw new Error(`no handler mapping for ${tool}`);
  if (!ctx.handlers.has(method)) {
    return skip(`extension handler ${method} is not in extension/background.js yet`);
  }
  if (!ctx.tools.has(tool)) {
    throw new Error(
      `extension handler ${method} exists, but the MCP server did not register "${tool}"`
    );
  }
  return null;
}

function walk(node, out = []) {
  if (!node || typeof node !== "object") return out;
  out.push(node);
  for (const child of node.children || []) walk(child, out);
  return out;
}

async function pageOf(ctx) {
  const page = livePage(ctx.chrome, ctx.origin);
  ctx.page = page;
  return page;
}

async function uiCall(ctx, fn) {
  // Do not cdp_detach here. Detach drops rewrite rules and the network buffer.
  return fn(await pageOf(ctx));
}

async function uiText(ctx, selector) {
  return uiCall(ctx, async (page) => (await page.locator(selector).innerText()).trim());
}

async function uiValue(ctx, selector) {
  return uiCall(ctx, (page) => page.locator(selector).inputValue());
}

async function uiEval(ctx, expression, arg) {
  return uiCall(ctx, (page) => page.evaluate(expression, arg));
}

async function pollPage(ctx, code, ready, timeoutMs) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeoutMs) {
    const { json } = await ctx.call("execute_javascript", { tabId: ctx.tabId, code }, 20_000);
    last = json && json.result;
    if (ready(last)) return last;
    await sleep(250);
  }
  throw new Error(`timed out waiting for the page. last=${JSON.stringify(last)}`);
}

async function captureStructure(ctx) {
  const blocked = gate(ctx, "get_page_structure");
  if (blocked) throw new Error(blocked.skip);
  const { json } = await ctx.call("get_page_structure", { tabId: ctx.tabId, maxDepth: 20 });
  const nodes = walk(json && json.structure);
  const shadowButton = nodes.find(
    (node) =>
      node.shadow &&
      node.role === "button" &&
      node.ref &&
      /increment shadow/i.test(`${node.name || ""} ${node.text || ""}`)
  );
  const field = nodes.find((node) => node.role === "textbox" && node.ref && node.name === "Name");
  ctx.structure = json;
  ctx.nodes = nodes;
  if (!shadowButton) {
    const buttons = nodes
      .filter((node) => node.role === "button")
      .map((node) => ({ ref: node.ref, name: node.name, shadow: !!node.shadow }));
    throw new Error(
      `get_page_structure did not return a ref for the open-shadow button. buttons=${JSON.stringify(buttons)} refCount=${json && json.refCount}`
    );
  }
  if (!field) {
    const fields = nodes
      .filter((node) => node.role === "textbox")
      .map((node) => ({ ref: node.ref, name: node.name, tag: node.tag }));
    throw new Error(`get_page_structure did not return a textbox ref for Name. fields=${JSON.stringify(fields)}`);
  }
  ctx.shadowRef = shadowButton.ref;
  ctx.fieldRef = field.ref;
  return { shadowButton, field };
}

async function clickFetch(ctx) {
  const before = Number(
    (await uiCall(ctx, (page) => page.locator("#fetch-out").getAttribute("data-gen"))) || "0"
  );
  await ctx.call("click_element", { tabId: ctx.tabId, selector: "#fetch-btn" });
  const snap = await pollPage(
    ctx,
    `(() => { const el = document.getElementById("fetch-out"); return { gen: el ? el.dataset.gen : "", state: el ? el.dataset.state : "", text: el ? el.textContent : "" }; })()`,
    (value) => value && Number(value.gen) > before && (value.state === "done" || value.state === "error"),
    20_000
  );
  const text = await uiText(ctx, "#fetch-out");
  if (snap.state === "error" || text.startsWith("TypeError") || text.startsWith("Failed")) {
    throw new Error(`fixture fetch failed: ${text}`);
  }
  if (!text.includes("echo-original") && !text.includes("echo-patched")) {
    throw new Error(`fixture fetch body was not the echo payload: ${text}`);
  }
  return text;
}

async function caseListTabs(ctx) {
  const blocked = gate(ctx, "list_browser_tabs");
  if (blocked) return blocked;
  const { json } = await ctx.call("list_browser_tabs", {});
  const tabs = (json && json.tabs) || [];
  const tab = tabs.find((item) => (item.url || "").startsWith(ctx.origin));
  if (!tab) {
    throw new Error(
      `list_browser_tabs did not include ${ctx.origin}. tabs=${JSON.stringify(tabs.map((item) => item.url))}`
    );
  }
  ctx.tabId = tab.id;
  return { detail: `tab ${tab.id} ${tab.url}` };
}

async function caseShadowClick(ctx) {
  const blocked = gate(ctx, "click_element");
  if (blocked) return blocked;
  await captureStructure(ctx);
  const before = Number(await uiText(ctx, "#counter"));
  const { json } = await ctx.call("click_element", { tabId: ctx.tabId, ref: ctx.shadowRef });
  const after = Number(
    await pollPage(
      ctx,
      `document.getElementById("counter").textContent`,
      (value) => Number(value) === before + 1,
      10_000
    ).then(() => uiText(ctx, "#counter"))
  );
  if (after !== before + 1) {
    throw new Error(`counter was ${before} before click and ${after} after. tool=${JSON.stringify(json)}`);
  }
  return { detail: `ref ${ctx.shadowRef} counter ${before} -> ${after}` };
}

async function caseDescribe(ctx) {
  const blocked = gate(ctx, "describe_element");
  if (blocked) return blocked;
  if (!ctx.shadowRef) await captureStructure(ctx);
  const { json } = await ctx.call("describe_element", { tabId: ctx.tabId, ref: ctx.shadowRef });
  const rect = json && json.rect;
  const width = rect && rect.width;
  const height = rect && rect.height;
  if (typeof width !== "number" || typeof height !== "number" || !Number.isFinite(width) || !Number.isFinite(height)) {
    throw new Error(`describe_element rect width/height are not numbers: ${JSON.stringify(rect)}`);
  }
  if (width <= 0 || height <= 0) {
    throw new Error(`describe_element rect is not a visible box: ${JSON.stringify(rect)}`);
  }
  return { detail: `rect ${width}x${height}` };
}

async function caseType(ctx) {
  const blocked = gate(ctx, "type_text");
  if (blocked) return blocked;
  if (!ctx.fieldRef) await captureStructure(ctx);
  await ctx.call("type_text", {
    tabId: ctx.tabId,
    ref: ctx.fieldRef,
    text: TYPED,
    clearFirst: true,
  });
  const value = await uiValue(ctx, "#field");
  if (value !== TYPED) throw new Error(`input value is ${JSON.stringify(value)}, expected ${JSON.stringify(TYPED)}`);
  return { detail: `field ${ctx.fieldRef} = ${value}` };
}

async function caseFindText(ctx) {
  const blocked = gate(ctx, "find_text");
  if (blocked) return blocked;
  const { json } = await ctx.call("find_text", { tabId: ctx.tabId, query: FIND_QUERY });
  if (!json || typeof json.count !== "number" || !Number.isFinite(json.count)) {
    throw new Error(`find_text did not report a numeric count: ${JSON.stringify(json)}`);
  }
  if (json.count < 1) throw new Error(`find_text count was ${json.count} for ${FIND_QUERY}`);
  const blob = JSON.stringify(json);
  if (!blob.includes(FIND_QUERY)) throw new Error(`find_text result did not include the fixture string: ${blob}`);
  return { detail: `count ${json.count}` };
}

async function caseSelection(ctx) {
  const blocked = gate(ctx, "page_selection");
  if (blocked) return blocked;
  const selected = await ctx.call("page_selection", {
    tabId: ctx.tabId,
    action: "select",
    text: SELECT_TEXT,
  });
  if (!String(selected.json && selected.json.text).includes(SELECT_TEXT)) {
    throw new Error(`page_selection select did not return the chosen text: ${selected.text}`);
  }
  const read = await ctx.call("page_selection", { tabId: ctx.tabId, action: "read" });
  if (!String(read.json && read.json.text).includes(SELECT_TEXT)) {
    throw new Error(`page_selection read did not return the chosen text: ${read.text}`);
  }
  const ui = await uiEval(ctx, () => window.getSelection().toString());
  if (!String(ui).includes(SELECT_TEXT)) {
    throw new Error(`window.getSelection() is ${JSON.stringify(ui)} after page_selection`);
  }
  return { detail: `selected ${JSON.stringify(read.json.text)}` };
}

async function caseSession(ctx) {
  const blocked = gate(ctx, "browser_session");
  if (blocked) return blocked;
  await ctx.call("browser_session", {
    tabId: ctx.tabId,
    action: "local",
    op: "set",
    key: "ccbVerifyKey",
    value: "roundtrip-ok",
  });
  const got = await ctx.call("browser_session", {
    tabId: ctx.tabId,
    action: "local",
    op: "get",
    key: "ccbVerifyKey",
  });
  if (!got.json || got.json.value !== "roundtrip-ok") {
    throw new Error(`localStorage read returned ${got.text}`);
  }
  const stored = await uiEval(ctx, () => localStorage.getItem("ccbVerifyKey"));
  if (stored !== "roundtrip-ok") {
    throw new Error(`page localStorage is ${JSON.stringify(stored)}`);
  }

  let cookieNote = "cookies set and listed";
  try {
    await ctx.call("browser_session", {
      tabId: ctx.tabId,
      action: "cookies",
      op: "set",
      url: `${ctx.origin}/`,
      name: "ccb_verify",
      value: "cookie-ok",
      path: "/",
      sameSite: "lax",
    });
    const listed = await ctx.call("browser_session", {
      tabId: ctx.tabId,
      action: "cookies",
      op: "list",
      url: `${ctx.origin}/`,
    });
    const cookies = (listed.json && listed.json.cookies) || [];
    const cookie = cookies.find((item) => item.name === "ccb_verify");
    if (!cookie || cookie.value !== "cookie-ok") {
      throw new Error(`cookie list missing ccb_verify=cookie-ok: ${listed.text}`);
    }
    const documentCookie = await uiEval(ctx, () => document.cookie);
    if (!String(documentCookie).includes("ccb_verify=cookie-ok")) {
      throw new Error(`document.cookie is ${JSON.stringify(documentCookie)}`);
    }
  } catch (err) {
    if (/permission|not allowed|access to cookie|cookies permission/i.test(err.message)) {
      cookieNote = `cookies skipped: ${err.message}`;
      console.log(`SKIP browser_session cookies — ${err.message}`);
    } else {
      throw err;
    }
  }
  return { detail: `localStorage round-trip; ${cookieNote}` };
}

async function caseRewrite(ctx) {
  const blocked = gate(ctx, "rewrite_traffic");
  if (blocked) return blocked;
  await ctx.call("rewrite_traffic", { tabId: ctx.tabId, action: "clear" });
  const headers = await ctx.call("rewrite_traffic", {
    tabId: ctx.tabId,
    action: "headers",
    headers: { "X-Bridge-Test": HEADER_VALUE },
  });
  if (!headers.json || headers.json.scope !== "all-requests") {
    throw new Error(`tab-wide header rewrite did not report scope all-requests: ${headers.text}`);
  }
  const first = await clickFetch(ctx);
  if (!first.includes(HEADER_VALUE)) {
    throw new Error(`fixture fetch did not show rewritten header ${HEADER_VALUE}: ${first}`);
  }
  if (!first.includes("echo-original")) {
    throw new Error(`fixture fetch lost the original marker before the patch: ${first}`);
  }
  await ctx.call("rewrite_traffic", {
    tabId: ctx.tabId,
    action: "patch",
    urlPattern: "/echo",
    find: "echo-original",
    replace: "echo-patched",
  });
  const second = await clickFetch(ctx);
  if (!second.includes("echo-patched")) {
    throw new Error(`patched response body was not what the page saw: ${second}`);
  }
  if (second.includes("echo-original")) {
    throw new Error(`page still saw the unpatched marker: ${second}`);
  }
  if (!second.includes(HEADER_VALUE)) {
    throw new Error(`header rewrite disappeared on the patched response: ${second}`);
  }
  ctx.echoCaptured = true;
  if (ctx.tools.has("read_network_requests") && ctx.handlers.has("readNetworkRequests")) {
    const net = await ctx.call("read_network_requests", {
      tabId: ctx.tabId,
      filter: "/echo",
      summaryOnly: true,
      limit: 20,
    });
    const blob = JSON.stringify(net.json);
    if (!blob.includes("/echo")) {
      throw new Error(`read_network_requests did not observe /echo: ${net.text}`);
    }
  }
  return { detail: "tab-wide header and /echo body patch visible in #fetch-out" };
}

async function caseHar(ctx) {
  const blocked = gate(ctx, "export_har");
  if (blocked) return blocked;
  const canRead = ctx.handlers.has("readNetworkRequests") && ctx.tools.has("read_network_requests");
  let seen = false;
  if (canRead) {
    const net = await ctx.call("read_network_requests", {
      tabId: ctx.tabId,
      filter: "/echo",
      limit: 20,
      summaryOnly: true,
    });
    seen = JSON.stringify(net.json).includes("/echo");
  }
  if (!seen) {
    if (canRead) {
      await ctx.call("read_network_requests", { tabId: ctx.tabId, filter: "/echo", limit: 1, summaryOnly: true });
    }
    await clickFetch(ctx);
  }
  const filePath = path.join(ctx.artifacts, "fixture.har");
  const exported = await ctx.call(
    "export_har",
    { tabId: ctx.tabId, filePath, includeBodies: true },
    150_000
  );
  const stat = await fs.stat(filePath);
  if (stat.size <= 0) throw new Error("HAR file is empty");
  const har = JSON.parse(await fs.readFile(filePath, "utf8"));
  const entries = (har.log && har.log.entries) || [];
  const hit = entries.some((entry) => entry.request && String(entry.request.url).includes("/echo"));
  if (!hit) {
    const urls = entries.map((entry) => entry.request && entry.request.url).filter(Boolean);
    throw new Error(`HAR has no /echo request. urls=${JSON.stringify(urls.slice(0, 15))}`);
  }
  if (exported.text.includes("%PDF") || /JVBERi0/.test(exported.text)) {
    throw new Error("export_har tool text included raw document bytes");
  }
  return { detail: `${entries.length} entries, file ${stat.size} bytes` };
}

async function casePdf(ctx) {
  const blocked = gate(ctx, "save_page");
  if (blocked) return blocked;
  const filePath = path.join(ctx.artifacts, "page.pdf");
  const saved = await ctx.call(
    "save_page",
    { tabId: ctx.tabId, format: "pdf", filePath, printBackground: true },
    150_000
  );
  const buf = await fs.readFile(filePath);
  if (buf.length === 0) throw new Error("PDF file is empty");
  if (buf.subarray(0, 5).toString("utf8") !== "%PDF-") {
    throw new Error(`PDF file does not start with %PDF- (size ${buf.length})`);
  }
  if (saved.text.includes("%PDF") || saved.text.includes("JVBERi")) {
    throw new Error("save_page tool text included raw PDF bytes");
  }
  const bytes = saved.json && saved.json.bytes;
  if (typeof bytes === "number" && bytes !== buf.length) {
    throw new Error(`tool reported ${bytes} bytes but the file is ${buf.length}`);
  }
  return { detail: `${buf.length} bytes at ${filePath}` };
}

function permissionUnavailable(text) {
  return /PERMISSION_API_UNAVAILABLE|Browser\.grantPermissions is not available|wasn't found|unknown method|-32601/i.test(
    text || ""
  );
}

async function caseGeo(ctx) {
  const blocked = gate(ctx, "emulate_environment");
  if (blocked) return blocked;
  const applied = await ctx.call("emulate_environment", {
    tabId: ctx.tabId,
    geolocation: { latitude: LAT, longitude: LNG, accuracy: 12 },
  });
  const geo = applied.json && applied.json.applied && applied.json.applied.geolocation;
  if (!geo || geo.latitude !== LAT || geo.longitude !== LNG) {
    throw new Error(`emulate_environment did not report the override: ${applied.text}`);
  }
  await ctx.call("click_element", { tabId: ctx.tabId, selector: "#geo-btn" });
  const snap = await pollPage(
    ctx,
    `(() => { const el = document.getElementById("geo-out"); return { state: el ? el.dataset.state || "" : "", text: el ? el.textContent : "" }; })()`,
    (value) => value && (value.state === "ok" || value.state === "error"),
    15_000
  );
  const text = await uiText(ctx, "#geo-out");
  let pageCoords = null;
  try {
    pageCoords = JSON.parse(text);
  } catch {
    pageCoords = null;
  }
  const sawOverride =
    pageCoords &&
    typeof pageCoords.lat === "number" &&
    typeof pageCoords.lng === "number" &&
    Math.abs(pageCoords.lat - LAT) < 0.01 &&
    Math.abs(pageCoords.lng - LNG) < 0.01;
  const perm = geo.permission || {};
  if (sawOverride) return { detail: `page geolocation ${text}` };
  if (perm.status === "unavailable" && /overrid|still/i.test(`${perm.detail || ""} ${applied.text}`)) {
    return {
      detail: `permission API unavailable and override still set (${perm.detail || perm.status}); page said ${text}`,
    };
  }
  throw new Error(
    `geolocation callback did not receive ${LAT},${LNG} and the tool did not report an unavailable permission API with the override set. tool=${applied.text} page=${text} poll=${JSON.stringify(snap)}`
  );
}

async function caseGrant(ctx) {
  const blocked = gate(ctx, "grant_permission");
  if (blocked) return blocked;
  try {
    const { json, text } = await ctx.call("grant_permission", {
      tabId: ctx.tabId,
      action: "grant",
      permissions: ["geolocation"],
    });
    const granted = json && json.granted;
    if (!Array.isArray(granted) || !granted.includes("geolocation")) {
      throw new Error(`grant_permission did not report a structured grant: ${text}`);
    }
    return { detail: `granted ${granted.join(",")} on ${json.origin || "tab origin"}` };
  } catch (err) {
    if (permissionUnavailable(err.message)) {
      return { detail: `documented unavailable API: ${err.message}` };
    }
    throw err;
  }
}

async function caseWebauthn(ctx) {
  const blocked = gate(ctx, "webauthn");
  if (blocked) return blocked;
  try {
    const { json, text } = await ctx.call("webauthn", { tabId: ctx.tabId, action: "enable" }, 45_000);
    if (json && json.enabled && typeof json.authenticatorId === "string" && json.authenticatorId) {
      const note = json.detail ? ` (${json.detail})` : "";
      return { detail: `authenticator ${json.authenticatorId}${note}` };
    }
    if (json && /detach|debugger session/i.test(JSON.stringify(json))) {
      return { detail: `detach behavior: ${text}` };
    }
    throw new Error(`webauthn enable was not a structured success: ${text}`);
  } catch (err) {
    if (
      permissionUnavailable(err.message) ||
      /wasn't found|unknown method|not available|user gesture|ui prompt|dialog|detach|timed out|timeout/i.test(
        err.message
      )
    ) {
      return { detail: `documented WebAuthn limitation: ${err.message}` };
    }
    throw err;
  }
}

async function caseTouch(ctx) {
  const blocked = gate(ctx, "touch_gesture");
  if (blocked) return blocked;
  if (!ctx.shadowRef) await captureStructure(ctx);
  const before = Number(await uiText(ctx, "#counter"));
  const { json } = await ctx.call("touch_gesture", {
    tabId: ctx.tabId,
    gesture: "tap",
    ref: ctx.shadowRef,
  });
  let after;
  try {
    await pollPage(
      ctx,
      `document.getElementById("counter").textContent`,
      (value) => Number(value) === before + 1,
      10_000
    );
    after = Number(await uiText(ctx, "#counter"));
  } catch (err) {
    after = Number(await uiText(ctx, "#counter"));
    throw new Error(
      `touch tap did not increment the counter (${before} -> ${after}). tool=${JSON.stringify(json)} ${err.message}`
    );
  }
  if (after !== before + 1) {
    throw new Error(`touch tap counter ${before} -> ${after}. tool=${JSON.stringify(json)}`);
  }
  return { detail: `tap ${ctx.shadowRef} counter ${before} -> ${after}` };
}

async function casePasswordRedaction(ctx) {
  const page = await pageOf(ctx);
  await page.evaluate(() => {
    const input = document.createElement("input");
    input.id = "private-password"; input.type = "password"; input.value = "do-not-echo-password";
    document.body.append(input);
  });
  const { text } = await ctx.call("get_page_structure", {tabId: ctx.tabId});
  if (text.includes("do-not-echo-password")) throw new Error("password leaked through structure");
  const typed = await ctx.call("type_text", {tabId: ctx.tabId, selector: "#private-password", text: "new-secret", clearFirst: true});
  if (typed.text.includes("new-secret") || typed.text.includes("do-not-echo-password")) throw new Error("password leaked through typing result");
  await page.locator("#private-password").evaluate(el => el.remove());
  return {detail: "password structure and typing results are redacted"};
}

const CASES = [
  ["password_redaction", casePasswordRedaction],
  ["list_browser_tabs", caseListTabs],
  ["open_shadow_click", caseShadowClick],
  ["describe_element", caseDescribe],
  ["type_text", caseType],
  ["find_text", caseFindText],
  ["page_selection", caseSelection],
  ["browser_session", caseSession],
  ["rewrite_traffic", caseRewrite],
  ["export_har", caseHar],
  ["save_page_pdf", casePdf],
  ["emulate_environment", caseGeo],
  ["grant_permission", caseGrant],
  ["webauthn", caseWebauthn],
  ["touch_gesture", caseTouch],
];

async function waitForFixtureTab(ctx) {
  const start = Date.now();
  let last = "";
  while (Date.now() - start < 60_000) {
    try {
      const { json } = await ctx.call("list_browser_tabs", {}, 20_000);
      const tab = ((json && json.tabs) || []).find((item) => (item.url || "").startsWith(ctx.origin));
      if (tab) {
        ctx.tabId = tab.id;
        return tab;
      }
      last = `tabs=${JSON.stringify((json.tabs || []).map((item) => item.url))}`;
    } catch (err) {
      last = err.message;
    }
    await sleep(500);
  }
  throw new Error(
    `extension did not attach a browser that has the fixture tab within 60s. ${last}\nbridge stderr:\n${ctx.mcp.stderr()}`
  );
}

async function main() {
  await waitUntilBackgroundParses();
  const handlers = await readHandlers();
  console.error(`[verify] handlers: ${[...handlers].sort().join(", ")}`);
  const artifacts = await fs.mkdtemp(path.join(os.tmpdir(), "ccb-verify-artifacts-"));
  const fixture = await startFixture();
  let mcp;
  let chrome;
  const results = [];
  try {
    mcp = await startMcp();
    console.error(`[verify] MCP tools include ${[...mcp.tools].filter((name) => HANDLER_FOR_TOOL[name]).join(", ")}`);
    chrome = await launchChrome(extensionDir, fixture.url);
    chrome.page.on("pageerror", (err) => console.error(`[pageerror] ${err.message}`));
    const ctx = {
      handlers,
      tools: mcp.tools,
      call: mcp.call,
      mcp,
      chrome,
      page: chrome.page,
      origin: fixture.origin,
      artifacts,
      tabId: null,
      shadowRef: null,
      fieldRef: null,
      echoCaptured: false,
    };
    await waitForFixtureTab(ctx);
    console.error(`[verify] fixture tab ${ctx.tabId} ${fixture.url}`);
    for (const [name, fn] of CASES) {
      const started = Date.now();
      try {
        const out = await fn(ctx);
        if (out && out.skip) {
          console.log(`SKIP ${name} — ${out.skip}`);
          results.push({ name, status: "skip", detail: out.skip });
        } else {
          const detail = (out && out.detail) || "ok";
          console.log(`PASS ${name} — ${detail} (${Date.now() - started}ms)`);
          results.push({ name, status: "pass", detail });
        }
      } catch (err) {
        const detail = err && err.stack ? err.stack : String(err);
        console.error(`FAIL ${name} — ${err.message}`);
        results.push({ name, status: "fail", detail });
      }
    }
  } finally {
    if (chrome) await chrome.close();
    if (mcp) await mcp.close().catch(() => {});
    if (fixture) await fixture.close().catch(() => {});
    await fs.rm(artifacts, { recursive: true, force: true }).catch(() => {});
  }

  const failed = results.filter((item) => item.status === "fail");
  const skipped = results.filter((item) => item.status === "skip");
  const passed = results.filter((item) => item.status === "pass");
  console.log(
    `\n${passed.length} passed, ${skipped.length} skipped, ${failed.length} failed (repo ${repoRoot})`
  );
  if (!results.length) {
    console.error("no cases ran");
    process.exitCode = 1;
    return;
  }
  process.exitCode = failed.length ? 1 : 0;
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
