import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { WebSocketServer, WebSocket } from "ws";
import { z } from "zod";

const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN;
if (!BRIDGE_TOKEN || !/^[a-f0-9]{64}$/.test(BRIDGE_TOKEN)) {
  throw new Error("BRIDGE_TOKEN must be a private 64-character hex token. See README pairing setup.");
}
const PORT_START = 17890;
const PORT_END = 17909;
const REQUEST_TIMEOUT = 30000;
// Assigned when the extension connects; sendToExtension() talks to it.
let extensionSocket: WebSocket | null = null;
const secureSend = new WeakMap<WebSocket, (message: unknown) => void>();
let requestId = 0;
const pendingRequests = new Map<
  number,
  { resolve: (value: any) => void; reject: (reason: any) => void }
>();

// --- WebSocket + HTTP Server (for Chrome Extension) ---

// 扩展侧错误转发兼容层：handler 可能抛裸字符串或结构化 {code, message}
// 对象。MCP 工具错误通道最终只把 message 文本交给 agent，因此把 code 拼进
// 消息前缀，保证 agent 能看到 code + message 两者。
function toBridgeError(err: unknown): Error {
  if (typeof err === "string") return new Error(err);
  if (err && typeof err === "object") {
    const e = err as { code?: unknown; message?: unknown };
    const message =
      typeof e.message === "string" && e.message.length > 0
        ? e.message
        : JSON.stringify(err);
    if (typeof e.code === "string" && e.code.length > 0) {
      return new Error(`[${e.code}] ${message}`);
    }
    return new Error(message);
  }
  return new Error(String(err));
}

async function startServer(): Promise<WebSocketServer> {
  for (let port = PORT_START; port <= PORT_END; port++) {
    try {
      const httpServer = createServer((req, res) => {
        res.writeHead(200, {
          "Content-Type": "text/plain",
        });
        res.end("claude-chrome-bridge");
      });

      // Listen FIRST, only attach WebSocket after port is confirmed available
      await new Promise<void>((resolve, reject) => {
        httpServer.on("error", reject);
        httpServer.listen(port, "127.0.0.1", () => resolve());
      });

      const wss = new WebSocketServer({
        server: httpServer,
        maxPayload: 32 * 1024 * 1024,
        perMessageDeflate: false,
        verifyClient: ({ req }: { req: IncomingMessage }) => req.headers.host === `127.0.0.1:${port}` &&
          typeof req.headers.origin === "string" && /^chrome-extension:\/\/[a-p]{32}$/.test(req.headers.origin),
      });

      console.error(`[bridge] Server listening on port ${port}`);
      return wss;
    } catch {
      continue;
    }
  }
  throw new Error(`No available port in range ${PORT_START}-${PORT_END}`);
}

const wss = await startServer();

wss.on("connection", (socket) => {
  let authenticated = false;
  let clientNonce = "";
  let sendSeq = 0;
  let recvSeq = 0;
  const serverNonce = randomBytes(32).toString("hex");
  const authTimer = setTimeout(() => socket.close(1008, "Authentication timeout"), 5000);
  socket.send(JSON.stringify({ method: "authChallenge", nonce: serverNonce }));
  const frameMac = (role: string, seq: number, payload: string) => createHmac("sha256", BRIDGE_TOKEN!).update(`ccb-v1:message:${role}:${serverNonce}:${clientNonce}:${seq}:${payload}`).digest();
  socket.on("message", (data) => {
    let msg: any;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (!msg || typeof msg !== "object") return socket.close(1008, "Invalid message");
    if (!authenticated) {
      if (msg.method !== "authResponse" || typeof msg.nonce !== "string" || !/^[a-f0-9]{64}$/.test(msg.nonce) ||
          typeof msg.proof !== "string" || !/^[a-f0-9]{64}$/.test(msg.proof)) return socket.close(1008, "Authentication required");
      const mac = (role: string) => createHmac("sha256", BRIDGE_TOKEN!).update(`ccb-v1:${role}:${serverNonce}:${msg.nonce}`).digest();
      if (!timingSafeEqual(Buffer.from(msg.proof, "hex"), mac("client"))) return socket.close(1008, "Authentication failed");
      if (extensionSocket && extensionSocket.readyState === WebSocket.OPEN) return socket.close(1008, "Extension already connected");
      clientNonce = msg.nonce;
      authenticated = true;
      secureSend.set(socket, (message: unknown) => {
        const payload = JSON.stringify(message);
        const seq = ++sendSeq;
        socket.send(JSON.stringify({seq, payload, proof: frameMac("server", seq, payload).toString("hex")}));
      });
      clearTimeout(authTimer);
      extensionSocket = socket;
      socket.send(JSON.stringify({ method: "authOk", proof: mac("server").toString("hex") }));
      console.error("[bridge] Paired extension connected");
      return;
    }
    if (!Number.isSafeInteger(msg.seq) || msg.seq !== recvSeq + 1 || typeof msg.payload !== "string" ||
        typeof msg.proof !== "string" || !/^[a-f0-9]{64}$/.test(msg.proof) ||
        !timingSafeEqual(Buffer.from(msg.proof, "hex"), frameMac("client", msg.seq, msg.payload))) return socket.close(1008, "Invalid signed frame");
    recvSeq = msg.seq;
    try { msg = JSON.parse(msg.payload); } catch { return socket.close(1008, "Invalid payload"); }
    if (!msg || typeof msg !== "object") return socket.close(1008, "Invalid payload");
    if (msg.method === "extensionInfo") {
      console.error(`[bridge] Extension version: ${msg.params?.version}`);
      return;
    }

    if (msg.method === "pong") return;

    if (msg.id !== undefined && pendingRequests.has(msg.id)) {
      const pending = pendingRequests.get(msg.id)!;
      pendingRequests.delete(msg.id);
      if (msg.error) {
        pending.reject(toBridgeError(msg.error));
      } else {
        pending.resolve(msg.result);
      }
    }
  });

  socket.on("close", () => {
    console.error("[bridge] Chrome extension disconnected");
    clearTimeout(authTimer);
    if (extensionSocket !== socket) return;
    extensionSocket = null;
    for (const [id, pending] of pendingRequests) {
      pending.reject(new Error("Extension disconnected"));
      pendingRequests.delete(id);
    }
  });

  socket.on("error", (err) => {
    console.error("[bridge] WebSocket error:", err.message);
  });
});

function sendToExtension(method: string, params?: any, timeoutMs = REQUEST_TIMEOUT): Promise<any> {
  return new Promise((resolve, reject) => {
    if (!extensionSocket || extensionSocket.readyState !== WebSocket.OPEN) {
      reject(
        new Error(
          "Chrome extension is not connected. Make sure the extension is installed and the browser is open."
        )
      );
      return;
    }

    const id = ++requestId;
    const timeout = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error("Request timed out"));
    }, timeoutMs);

    pendingRequests.set(id, {
      resolve: (v) => {
        clearTimeout(timeout);
        resolve(v);
      },
      reject: (r) => {
        clearTimeout(timeout);
        reject(r);
      },
    });

    secureSend.get(extensionSocket)!({ id, method, params });
  });
}

// --- Keepalive ---

setInterval(() => {
  if (extensionSocket && extensionSocket.readyState === WebSocket.OPEN) {
    secureSend.get(extensionSocket)!({ method: "ping" });
  }
}, 30000);

// --- MCP Tool helper ---

// PDF / MHTML / HAR (and a session export that asked for filePath) come back
// from the extension as an artifact payload. The bytes stay out of the
// conversation: write filePath, or a temp file when the caller omitted it,
// and return only the path and size.
function writeArtifact(art: {
  encoding?: string;
  data: string;
  filePath?: string;
  filename?: string;
}, requestedPath?: string): { path: string; bytes: number } {
  const body =
    art.encoding === "base64"
      ? Buffer.from(art.data, "base64")
      : Buffer.from(art.data, "utf8");
  // Destination authority belongs to the MCP caller, never the extension reply.
  let outPath = requestedPath || "";
  if (!outPath) {
    const dir = mkdtempSync(join(tmpdir(), "ccb-artifact-"));
    const safeName =
      basename(String(art.filename || "artifact.bin")).replace(/[^\w.\-]/g, "_") ||
      "artifact.bin";
    outPath = join(dir, safeName);
  } else {
    mkdirSync(dirname(outPath), { recursive: true });
  }
  writeFileSync(outPath, body, { flag: "wx", mode: 0o600 });
  return { path: outPath, bytes: body.length };
}

function toolHandler(method: string) {
  return async (params: any) => {
    try {
      let forwarded = params;
      // Session import from disk: the extension cannot read an arbitrary
      // local path, so the server loads the JSON and forwards the object.
      if (
        method === "browserSession" &&
        params &&
        params.action === "import" &&
        typeof params.filePath === "string" &&
        params.filePath &&
        params.data == null
      ) {
        const raw = readFileSync(params.filePath, "utf8");
        let data: unknown;
        try {
          data = JSON.parse(raw);
        } catch (e: any) {
          throw new Error(
            `session import file is not valid JSON (${params.filePath}): ${e.message}`
          );
        }
        forwarded = { ...params, data };
        delete forwarded.filePath;
      }
      const longRunning = method === "savePage" || method === "exportHar";
      const waitTimeout =
        method === "waitFor"
          ? Math.max(
              REQUEST_TIMEOUT,
              Number(params?.timeout) || 0,
              Number(params?.downloadTimeout) || 0,
              Number(params?.time) || 0
            ) + 1000
          : longRunning
            ? 120000
            : REQUEST_TIMEOUT;
      const result = await sendToExtension(method, forwarded, waitTimeout);
      if (result.image) {
        const mimeType = `image/${result.format || "png"}`;
        return {
          content: [
            {
              type: "image" as const,
              data: result.image,
              mimeType,
            },
          ],
        };
      }
      if (result && result.artifact && typeof result.artifact.data === "string") {
        const written = writeArtifact(result.artifact, params?.filePath);
        const summary =
          result.summary && typeof result.summary === "object" ? result.summary : {};
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ ...summary, ...written }, null, 2),
            },
          ],
        };
      }
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(result, null, 2) },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  };
}

// --- MCP Server ---

const server = new McpServer({
  name: "chrome-browser-bridge",
  version: "3.4.0",
});

// ============================================================
// Tab management
// ============================================================

server.tool(
  "list_browser_tabs",
  "List all open browser tabs across every Chrome window. Returns tab ID, URL, title, active state, window ID, and index, plus multi-window context: windowType ('normal'/'popup'/...) and windowFocused for the tab's window, and openerTabId when Chrome exposes the tab's lineage — tabs opened from another tab via window.open or target=_blank carry the spawning tab's id natively (tabs without exposed lineage, e.g. manual new tabs, omit the field). Popup-tracking workflow: list before a click, click, list again — the new row plus its openerTabId tells you what opened and from where, no event listeners involved. Filters out chrome://, chrome-extension://, about:, and devtools:// pages.",
  {},
  toolHandler("listTabs")
);

server.tool(
  "open_browser_tab",
  "Open a new tab in the user's Chrome with a given URL. Opens in the same browser profile. Prefixes https:// if no protocol specified. Without windowId the tab opens in Chrome's 'current' window (the one holding OS focus). Side effect: active:true makes the new tab the selected tab of its window — replacing what the user was looking at there — but does NOT raise the window to the OS foreground; use focus_window for that.",
  {
    url: z
      .string()
      .optional()
      .default("about:blank")
      .describe(
        "URL to open. Prefixed with https:// if no protocol. Defaults to about:blank."
      ),
    active: z
      .boolean()
      .optional()
      .default(true)
      .describe("Bring the tab to foreground. Default true."),
    windowId: z
      .number()
      .optional()
      .describe(
        "Window to open the tab in (from list_windows or create_window). Omit for the currently focused window."
      ),
  },
  toolHandler("createTab")
);

server.tool(
  "navigate_tab",
  "Navigate a browser tab: go to a URL, go back/forward in history, or reload the page.",
  {
    tabId: z
      .number()
      .describe("The tab ID to navigate (from list_browser_tabs)."),
    action: z
      .enum(["url", "back", "forward", "reload"])
      .optional()
      .default("url")
      .describe(
        "Navigation action: 'url' (default), 'back', 'forward', or 'reload'."
      ),
    url: z
      .string()
      .optional()
      .describe(
        "URL to navigate to. Required when action is 'url'. Prefixed with https:// if no protocol."
      ),
  },
  toolHandler("navigateTab")
);

server.tool(
  "close_browser_tab",
  "Close a browser tab by its ID.",
  {
    tabId: z
      .number()
      .describe("The tab ID to close (from list_browser_tabs)."),
  },
  toolHandler("closeTab")
);

server.tool(
  "group_tabs",
  "Add tabs to a tab group, creating the group if needed. Can also ungroup tabs or update group properties (title, color, collapsed state).",
  {
    tabIds: z
      .array(z.number())
      .describe("Array of tab IDs to group or ungroup."),
    action: z
      .enum(["group", "ungroup"])
      .optional()
      .default("group")
      .describe(
        "'group' (default) or 'ungroup'. When 'ungroup', removes tabs from their current group."
      ),
    groupId: z
      .number()
      .optional()
      .describe(
        "Existing group ID to add tabs to. If omitted with action='group', a new group is created."
      ),
    title: z
      .string()
      .optional()
      .describe(
        "Title for the tab group. Only used when creating or updating a group."
      ),
    color: z
      .enum([
        "grey",
        "blue",
        "red",
        "yellow",
        "green",
        "pink",
        "purple",
        "cyan",
        "orange",
      ])
      .optional()
      .describe(
        "Group color: grey, blue, red, yellow, green, pink, purple, cyan, orange."
      ),
    collapsed: z
      .boolean()
      .optional()
      .describe("Whether the group is collapsed."),
  },
  toolHandler("groupTabs")
);

// ============================================================
// Window management
// ============================================================

server.tool(
  "list_windows",
  "List all open browser windows. Returns windowId, type ('normal', 'popup', ...), focused (holds OS focus), state ('normal', 'minimized', 'maximized', 'fullscreen'), and tabCount per window. Pair with list_browser_tabs, whose rows carry each tab's windowType/windowFocused and openerTabId lineage.",
  {},
  toolHandler("listWindows")
);

server.tool(
  "create_window",
  "Create a new browser window, optionally with a starting URL. type 'popup' creates a chromeless popup window (the classic window.open look); 'normal' a regular window. Side effect: unless focused:false is passed, the new window draws OS focus immediately — the user sees it take over the screen. Returns windowId plus the initial tab (id/url/title) so follow-up tools can target it, and tabCount.",
  {
    url: z
      .string()
      .optional()
      .describe(
        "URL for the window's initial tab. Prefixed with https:// if no protocol. Omit for the default new-tab page."
      ),
    type: z
      .enum(["normal", "popup"])
      .optional()
      .describe("Window type. 'popup' = chromeless popup window. Default 'normal'."),
    focused: z
      .boolean()
      .optional()
      .describe(
        "Whether the new window draws OS focus immediately. Default is Chrome's behavior (focused); pass false to create it in the background."
      ),
    left: z.number().optional().describe("Window left position in pixels."),
    top: z.number().optional().describe("Window top position in pixels."),
    width: z.number().optional().describe("Window width in pixels."),
    height: z.number().optional().describe("Window height in pixels."),
  },
  toolHandler("createWindow")
);

server.tool(
  "focus_window",
  "Bring a browser window to the OS foreground (chrome.windows.update focused:true). Side effect: takes focus from whatever the user is currently doing. Useful e.g. when clipboard_read failed with CLIPBOARD_FOCUS_FAILED on a tab living in a background window.",
  {
    windowId: z.number().describe("Window to focus (from list_windows)."),
  },
  toolHandler("focusWindow")
);

server.tool(
  "close_window",
  "Close a browser window and ALL of its tabs. Reads the window before closing and reports the damage: tabCount plus closedTabIds, so the agent knows exactly what this cut. Per-tab debugger state is cleaned up automatically. If the window cannot be read (bad windowId), the call fails honestly and closes nothing — never a surprise mass-close.",
  {
    windowId: z.number().describe("Window to close (from list_windows)."),
  },
  toolHandler("closeWindow")
);

// ============================================================
// Page content
// ============================================================

server.tool(
  "get_page_content",
  "Extract visible text content from a browser tab with content-priority extraction. Prefers article/main content over navigation, footers, and ads. Returns clean readable text.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    fullPage: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "If true, returns all body text without content-priority filtering. Default false."
      ),
  },
  toolHandler("getPageContent")
);

server.tool(
  "get_page_structure",
  "Get an accessibility-tree-style snapshot of the page. Each interactive or landmark element gets a stable ref ID (like ref_1, ref_2) that can be used with click_element, type_text, and other interaction tools instead of fragile CSS selectors. Returns element roles, names, states, and hierarchy. The snapshot spans ALL frames: every iframe generates its own subtree, and when the frame can be matched to its <iframe> node the subtree is grafted onto that node (which then carries frameId and url); unmatched frames are listed in a top-level `frames` array with their own structure. Every frame also appears in `frames` as a summary row ({frameId, parentFrameId, url}) — pass that frameId to interaction tools to target selector-based lookups inside a frame. Refs from all frames share one flat namespace, rebuilt on every snapshot — a ref that no longer resolves returns REF_NOT_FOUND, meaning the snapshot is stale: re-run this tool.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    maxDepth: z
      .number()
      .optional()
      .default(15)
      .describe("Maximum depth of tree traversal. Default 15."),
    root: z
      .string()
      .optional()
      .describe(
        "CSS selector for subtree root. If omitted, starts from document.body."
      ),
  },
  toolHandler("getPageStructure")
);

server.tool(
  "find_elements",
  "Search for elements on a web page by text content, ARIA attributes, or CSS selector — across ALL frames (top frame first, then subframes in frameId order). Returns matching elements with their ref IDs (interned into the same flat namespace as get_page_structure) and generated CSS selectors, each annotated with the frameId it lives in (0 = top frame; selectors are frame-local — pass that frameId to interaction tools when using the selector). Element positions are sampled after their rectangles stabilize; `rect` coordinates are converted to TOP-LEVEL viewport space (usable directly with coordinate clicks), except when the frame-offset measurement fails — then rect stays frame-local and the element carries rectFrameLocal:true.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    query: z
      .string()
      .optional()
      .describe(
        "Text to search for in element content, aria-labels, placeholders, and titles. Case-insensitive."
      ),
    selector: z
      .string()
      .optional()
      .describe("CSS selector to match elements."),
    role: z
      .string()
      .optional()
      .describe(
        "ARIA role to filter by (e.g., 'button', 'link', 'textbox')."
      ),
    maxResults: z
      .number()
      .optional()
      .default(20)
      .describe("Maximum number of results to return. Default 20."),
  },
  toolHandler("findElements")
);

// ============================================================
// Page interaction
// ============================================================

server.tool(
  "click_element",
  "Click an element on a web page. Supports left/right/middle click, double/triple click, and coordinate-based clicking. Target by ref ID (from get_page_structure) or CSS selector. Dispatches TRUSTED mouse events via the Chrome DevTools Protocol (isTrusted=true): CSS :active/:hover states work and strict event handlers fire. First use attaches the debugger, showing Chrome's 'started debugging this browser' infobar on the tab. Results report inputMode:'cdp'; if that field is absent, the debugger was unavailable (e.g. DevTools open on the tab) and it fell back to synthetic DOM events. Works inside iframes: refs route to their frame automatically; pass frameId with a selector to target a frame; coordinates are always top-level viewport space (find_elements rects are converted for you).",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID from get_page_structure (e.g., 'ref_12'). Preferred over selector. Refs inside iframes route to their frame automatically."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of the element to click. Used if ref is not provided. Selectors are frame-local — combine with frameId for iframe content."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve the selector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
    coordinates: z
      .object({
        x: z.number().describe("Viewport X coordinate."),
        y: z.number().describe("Viewport Y coordinate."),
      })
      .optional()
      .describe(
        "Click at specific viewport coordinates {x, y} instead of targeting an element. If provided, ref and selector are ignored."
      ),
    button: z
      .enum(["left", "right", "middle"])
      .optional()
      .default("left")
      .describe("Mouse button: 'left', 'right', or 'middle'. Default 'left'."),
    clickCount: z
      .number()
      .optional()
      .default(1)
      .describe(
        "Number of clicks: 1 (single), 2 (double), or 3 (triple). Default 1."
      ),
  },
  toolHandler("clickElement")
);

server.tool(
  "type_text",
  "Type text into an input, textarea, or contentEditable element. Dispatches TRUSTED keystrokes via the Chrome DevTools Protocol (real keyDown/keyUp per character, Input.insertText for non-ASCII), so keydown-based validation, autocomplete, and keyboard shortcuts on the page all fire. Focuses the field with a real mouse click first (DOM focus for checkboxes/radios to avoid toggling them). Native <select> elements are handled via DOM option selection. Falls back to a synthetic native-setter path when the debugger is unavailable. Works inside iframes: refs route to their frame automatically; pass frameId together with a selector.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID from get_page_structure (e.g., 'ref_5'). Preferred over selector. Refs inside iframes route to their frame automatically."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of the input element. If both ref and selector omitted, types into the currently focused element. Selectors are frame-local — combine with frameId for iframe content."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve the selector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
    text: z.string().describe("The text to type."),
    clearFirst: z
      .boolean()
      .optional()
      .default(false)
      .describe("Clear the field before typing. Default false."),
    submit: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Press Enter after typing (dispatches keydown/keyup for Enter key). Default false."
      ),
  },
  toolHandler("typeText")
);

server.tool(
  "hover_element",
  "Hover over an element on a web page. Dispatches a TRUSTED mouse-moved event via the Chrome DevTools Protocol, so CSS :hover activates — dropdown menus, tooltips, and hover-revealed controls behave as with a real mouse. Target by ref ID or CSS selector. Falls back to synthetic pointer events (no CSS :hover) when the debugger is unavailable. Works inside iframes: refs route to their frame automatically; pass frameId together with a selector.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID from get_page_structure. Preferred over selector. Refs inside iframes route to their frame automatically."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of the element to hover over. Used if ref not provided. Selectors are frame-local — combine with frameId for iframe content."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve the selector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
  },
  toolHandler("hoverElement")
);

server.tool(
  "drag_element",
  "Drag an element and drop it onto another element or at specific coordinates. Uses CDP drag interception (Input.setInterceptDrags + dispatchDragEvent) so native HTML5 drag-and-drop works end to end; if the source does not start a native drag, performs a trusted mouse press/move/release drag (sliders, canvases, mouse-event-based DnD libraries). Result reports nativeDrag:true/false. Falls back to a synthetic DragEvent sequence when the debugger is unavailable. Refs inside iframes route automatically; frameId applies to selectors. Coordinates are top-level viewport space. Synthetic-fallback drags cannot cross frame boundaries (CROSS_FRAME_DRAG error) — trusted CDP drags can.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    fromRef: z
      .string()
      .optional()
      .describe("Ref ID of the element to drag."),
    fromSelector: z
      .string()
      .optional()
      .describe(
        "CSS selector of the element to drag. Used if fromRef not provided. Resolved in frameId."
      ),
    toRef: z
      .string()
      .optional()
      .describe("Ref ID of the drop target."),
    toSelector: z
      .string()
      .optional()
      .describe(
        "CSS selector of the drop target. Used if toRef not provided. Resolved in frameId."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve fromSelector/toSelector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
    toCoordinates: z
      .object({
        x: z.number().describe("Viewport X coordinate."),
        y: z.number().describe("Viewport Y coordinate."),
      })
      .optional()
      .describe(
        "Drop at specific top-level viewport coordinates {x, y} instead of a target element."
      ),
  },
  toolHandler("dragElement")
);

server.tool(
  "scroll_page",
  "Scroll a web page in a direction, by a pixel amount, to a specific element, or to the top/bottom of the page. Direction/amount scrolling dispatches a TRUSTED wheel event via CDP (fires wheel listeners, e.g. infinite-scroll triggers); element and top/bottom modes use DOM scrolling. Element scrolling waits for the target rectangle to settle and reports its final viewport rect and visibility. Pass frameId to scroll inside an iframe instead of the top page (the wheel lands at that frame's center; refs route automatically).",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    direction: z
      .enum(["up", "down", "left", "right"])
      .optional()
      .default("down")
      .describe("Scroll direction. Default 'down'."),
    amount: z
      .number()
      .optional()
      .default(500)
      .describe("Pixels to scroll. Default 500."),
    position: z
      .enum(["top", "bottom"])
      .optional()
      .describe(
        "Scroll to absolute position: 'top' or 'bottom'. If provided, direction and amount are ignored."
      ),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID of element to scroll into view. If provided, direction/amount/position are ignored."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of element to scroll into view. If provided, direction/amount/position are ignored. Resolved in frameId."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to scroll inside, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top page). Not needed for refs."
      ),
  },
  toolHandler("scrollPage")
);

server.tool(
  "press_key",
  "Press a key or key combination on the keyboard. Supports special keys (Enter, Escape, Tab, Backspace, Delete, ArrowUp, etc.) and modifier combinations (Control+a, Shift+Enter, Alt+Tab, Meta+c). Dispatches TRUSTED key events via the Chrome DevTools Protocol (real keyDown/keyUp with modifier state), so browser-level shortcuts and strict key handlers respond. Targets the focused element, or focuses a ref/selector first. CDP key events reach whatever frame holds focus — to focus an element inside an iframe, pass its ref (routes automatically) or selector + frameId. Falls back to synthetic KeyboardEvents when the debugger is unavailable.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    key: z
      .string()
      .describe(
        "Key name or combination. Examples: 'Enter', 'Escape', 'Tab', 'Backspace', 'Delete', 'ArrowDown', 'a', 'Control+a', 'Control+Shift+k', 'Meta+c'. Modifier names: Control, Shift, Alt, Meta."
      ),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID of target element. If omitted, dispatches to document.activeElement. Refs inside iframes route to their frame automatically."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of target element. Used if ref not provided. Resolved in frameId."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve the selector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
  },
  toolHandler("pressKey")
);

server.tool(
  "wait_for",
  "Wait for a condition on the page: an element to appear, text to appear or disappear, a page navigation, network idle, a browser download to complete, or a fixed timeout. Returns when the condition is met or times out. navigation/networkIdle are CDP-backed (the debugger attaches automatically; a clear error is returned if it cannot) and can be combined — networkIdle then only starts counting after the navigation settles. download is event-driven via chrome.downloads (no debugger needed) and stands alone: pair it with a click on a download link, then list_downloads to get the file's local path.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector to wait for. Resolves when an element matching this selector exists in DOM and is visible. Resolved in frameId (top frame by default)."
      ),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID to wait for. Resolves when the referenced element is visible. Refs inside iframes route to their frame automatically."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to poll selector/text/textGone in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). navigation/networkIdle always watch the tab's main frame. Frames destroyed mid-wait do not fail the poll."
      ),
    text: z
      .string()
      .optional()
      .describe(
        "Text to wait for on the page. Case-sensitive substring match on document.body.innerText (of frameId when given)."
      ),
    textGone: z
      .string()
      .optional()
      .describe("Text to wait to disappear from the page."),
    navigation: z
      .boolean()
      .optional()
      .describe(
        "Wait for a page navigation or load to finish (main-frame Page.frameNavigated or Page.loadEventFired). Includes a 3-second lookback so a navigation that completed just before this call still matches — agent-turn latency between a click and its wait_for is seconds-scale, and fast navigations finish inside that gap. Trade-off: a navigation from an earlier action within the last 3s can match immediately. If the tab was already loading when called, finishing the load counts too."
      ),
    networkIdle: z
      .boolean()
      .optional()
      .describe(
        "Wait until the network stays idle — no Network.requestWillBeSent/responseReceived/loadingFinished/loadingFailed activity — for idleTime ms. WebSocket frame traffic does NOT count as activity (heartbeats on a long-lived socket would prevent idling); socket open/close events do count."
      ),
    networkIdleIgnorePatterns: z
      .array(z.string())
      .optional()
      .describe(
        "URL patterns whose activity should not reset networkIdle. Plain strings are substring matches; strings wrapped in /.../ are regular expressions. URL-less activity is never ignored."
      ),
    download: z
      .boolean()
      .optional()
      .describe(
        "Wait for a browser download to complete: matches any download whose state transitions to 'complete' while waiting (event-driven via chrome.downloads.onChanged, browser-wide, no debugger needed), and a one-shot 3-second lookback also catches instant downloads (small local files) that finished in the gap between the triggering click and this call — such a hit is flagged viaLookback:true. Downloads that completed more than 3s before the call never match; one already in flight when the call starts does. The result's download field carries id/filename/localPath/url/totalBytes. Use downloadTimeout (or timeout) to bound the wait; typical flow: click a download link, then wait_for {download: true}."
      ),
    downloadTimeout: z
      .number()
      .optional()
      .describe(
        "Maximum time in milliseconds to wait for the download condition (defaults to timeout). Downloads can be large — give this more headroom than a DOM wait."
      ),
    idleTime: z
      .number()
      .optional()
      .default(500)
      .describe(
        "Quiet period in milliseconds for networkIdle. Default 500, minimum 50."
      ),
    time: z
      .number()
      .optional()
      .describe(
        "Fixed wait time in milliseconds. If provided alone, simply waits this duration."
      ),
    timeout: z
      .number()
      .optional()
      .default(10000)
      .describe(
        "Maximum time to wait in milliseconds before giving up. Default 10000."
      ),
  },
  toolHandler("waitFor")
);

// ============================================================
// Visual feedback
// ============================================================

server.tool(
  "take_screenshot",
  "Take a screenshot of a browser tab via CDP Page.captureScreenshot. Works on BACKGROUND tabs without activating them. Supports full-page capture (captureBeyondViewport), element-level clipping by ref or selector, and PNG/JPEG formats. Element clips work inside iframes: refs route to their frame automatically and the clip is converted to top-page coordinates; pass frameId with a selector for frame content. Falls back to captureVisibleTab (active tab, viewport only) when the debugger is unavailable.",
  {
    tabId: z
      .number()
      .optional()
      .describe(
        "Tab ID to screenshot. If omitted, screenshots the active tab. Does not need to be the visible tab."
      ),
    format: z
      .enum(["png", "jpeg"])
      .optional()
      .default("png")
      .describe("Image format: 'png' or 'jpeg'. Default 'png'."),
    quality: z
      .number()
      .optional()
      .default(80)
      .describe(
        "JPEG quality (1-100). Only used when format is 'jpeg'. Default 80."
      ),
    fullPage: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Capture the entire scrollable page, not just the viewport. Ignored when ref/selector is given. Default false."
      ),
    ref: z
      .string()
      .optional()
      .describe(
        "Ref ID of element to screenshot. Captures just this element's bounding box, even if it extends beyond the viewport. Refs inside iframes route to their frame automatically and the clip is converted to top-page coordinates."
      ),
    selector: z
      .string()
      .optional()
      .describe(
        "CSS selector of element to screenshot. Used if ref not provided. Selectors are frame-local — combine with frameId for iframe content."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame to resolve the selector in, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Not needed for refs."
      ),
  },
  toolHandler("takeScreenshot")
);

// ============================================================
// File & Window
// ============================================================

server.tool(
  "upload_file",
  "Upload a file to a file input element on a web page. Preferred: pass filePath (absolute local path) — the file is set via CDP DOM.setFileInputFiles, which works even on hidden inputs and fires trusted input/change events. Alternative: base64Data — the server writes it to a temp file and uses the same CDP path, falling back to synthetic DataTransfer injection only when the debugger is unavailable.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    selector: z
      .string()
      .describe(
        "CSS selector of the file input element. Resolved in frameId (top frame by default); the CDP path locates the frame's document via the frame chain."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Frame containing the file input, from get_page_structure's frames summary or find_elements' frameId (0/omitted = top frame). Same-process and cross-origin (OOPIF) frames are both supported on the CDP filePath route — OOPIFs resolve through their child debugger session automatically."
      ),
    filePath: z
      .string()
      .optional()
      .describe(
        "Absolute path to a local file to upload. Preferred over base64Data."
      ),
    fileName: z
      .string()
      .optional()
      .describe(
        "Display name of the file (used with base64Data; derived from filePath otherwise)."
      ),
    mimeType: z
      .string()
      .optional()
      .default("application/octet-stream")
      .describe(
        "MIME type of the file (base64Data path only). Default 'application/octet-stream'."
      ),
    base64Data: z
      .string()
      .optional()
      .describe(
        "Base64-encoded file content. Used when filePath is not provided."
      ),
  },
  async (args: any) => {
    const params: any = { ...args };
    // Materialize base64 payloads as temp files so the CDP path can be used.
    if (!params.filePath && params.base64Data) {
      try {
        const dir = mkdtempSync(join(tmpdir(), "ccb-upload-"));
        const safeName =
          basename(String(params.fileName || "upload.bin")).replace(
            /[^\w.\-]/g,
            "_"
          ) || "upload.bin";
        const fp = join(dir, safeName);
        writeFileSync(fp, Buffer.from(params.base64Data, "base64"));
        params.filePath = fp;
      } catch {
        // Keep the base64-only synthetic path.
      }
    }
    return toolHandler("uploadFile")(params);
  }
);

server.tool(
  "list_downloads",
  "Browser downloads: list recent entries, or resolve one entry for reading. Triggering a download needs no tool — click the link/button (click_element), then wait_for {download: true} blocks until it completes, then this tool finds the entry; call again with downloadId to get the final localPath plus an exists check, and read the file with local tools directly. Without downloadId: returns recent entries newest-first with id/filename/url/state/totalBytes/exists/startTime/error, narrowed by limit (default 20, max 200) and urlFilter (substring match on url/finalUrl). Optional downloadPath: when the tab's debugger is already attached, CDP Browser.setDownloadBehavior redirects FUTURE downloads to that directory (it must already exist) and turns on Browser.downloadWillBegin/downloadProgress events (raw-readable via read_cdp_events with filter 'Browser.download'); entries correlated by URL then carry the CDP guid. If the debugger is detached or the command is unsupported, this degrades silently — the result's downloadPath.applied tells you which, and plain chrome.downloads listing works regardless.",
  {
    tabId: z
      .number()
      .optional()
      .describe(
        "Tab used for CDP correlation and downloadPath. If omitted, uses the active tab. The download history itself is browser-wide."
      ),
    downloadId: z
      .number()
      .optional()
      .describe(
        "Read mode: resolve this download id (from wait_for's result or a listing) to its final localPath with an exists check. Other list params are ignored."
      ),
    limit: z
      .number()
      .optional()
      .describe("Maximum entries to return, newest first. Default 20, max 200."),
    urlFilter: z
      .string()
      .optional()
      .describe(
        "Only return entries whose url or finalUrl contains this substring. Applied before limit."
      ),
    downloadPath: z
      .string()
      .optional()
      .describe(
        "Absolute directory for FUTURE downloads via CDP Browser.setDownloadBehavior (requires the debugger already attached to the tab; the directory must exist — Chrome does not create it). Note: chrome.debugger generally does NOT expose Browser.setDownloadBehavior (-32601) — in this runtime expect downloadPath.applied:false with an honest reason; the plain listing works regardless. Failure degrades silently to Chrome's default download directory; check downloadPath.applied in the result."
      ),
  },
  toolHandler("listDownloads")
);

server.tool(
  "resize_window",
  "Resize the browser window containing a tab.",
  {
    tabId: z
      .number()
      .optional()
      .describe(
        "Tab ID whose window to resize. If omitted, uses the active tab's window."
      ),
    width: z.number().describe("New window width in pixels."),
    height: z.number().describe("New window height in pixels."),
  },
  toolHandler("resizeWindow")
);

// ============================================================
// Clipboard
// ============================================================

server.tool(
  "clipboard_write",
  "Write text to the OS clipboard, mediated by a page tab. The clipboard is a single global OS resource: this OVERWRITES whatever the user had copied. Primary path needs no debugger (injected textarea + execCommand('copy')); if the page blocks it, falls back to CDP navigator.clipboard.writeText with the clipboard-sanitizer-write permission granted to the page origin — the result's method field says which path ran. Both paths failing yields one CLIPBOARD_WRITE_FAILED error naming both failures. Text only: clipboard images are not supported.",
  {
    tabId: z
      .number()
      .optional()
      .describe(
        "Tab used as the clipboard intermediary. If omitted, uses the active tab. The clipboard itself is browser- and OS-global, not per-tab."
      ),
    text: z
      .string()
      .describe(
        "Text to place on the clipboard. Pass an empty string to clear it."
      ),
  },
  toolHandler("clipboardWrite")
);

server.tool(
  "clipboard_read",
  "Read text from the OS clipboard, mediated by a page tab — CDP-only (grants clipboard-read to the page origin, then navigator.clipboard.readText), so the debugger attaches automatically. Where the runtime does not expose Browser.setPermission (chrome.debugger typically doesn't — -32601), the grant is skipped and readText is attempted directly: an origin that already holds clipboard-read succeeds anyway. readText requires a focused document: the first attempt never steals focus; only a focus-class failure brings the tab to front (Page.bringToFront) and retries once, and the result then carries broughtToFront:true so you know the user's foreground tab changed. Failure modes are distinct: CLIPBOARD_PERMISSION_DENIED = the browser refused the permission override, or no grant path exists and readText itself was refused with NotAllowedError (give up); CLIPBOARD_FOCUS_FAILED = the user is in another window and even the front-retry failed (retry later); CLIPBOARD_EMPTY (empty:true, not an error) = no text on the clipboard. Text longer than 200KB is truncated (truncated:true, same cap as network bodies). Text only: clipboard images are not supported — use take_screenshot for visuals.",
  {
    tabId: z
      .number()
      .optional()
      .describe(
        "Tab used as the clipboard intermediary. If omitted, uses the active tab. The clipboard itself is browser- and OS-global, not per-tab."
      ),
  },
  toolHandler("clipboardRead")
);

// ============================================================
// Debugging
// ============================================================

server.tool(
  "execute_javascript",
  "Execute JavaScript code in a browser tab's page context. Supports async/await. Returns the result or error with full stack trace.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    code: z
      .string()
      .describe(
        "JavaScript code to execute. Can use async/await. The return value of the last expression is returned."
      ),
    allFrames: z
      .boolean()
      .optional()
      .describe(
        "If true, execute in all frames (including iframes). Returns per-frame results with frameId. Default false (top frame only)."
      ),
  },
  toolHandler("executeJavaScript")
);

server.tool(
  "read_console_messages",
  "Read console messages from a browser tab via CDP (Runtime.consoleAPICalled, Runtime.exceptionThrown, Log.entryAdded). Capture starts when the debugger attaches on first call and covers all frames — no page-world hook needed. Entries include level, message, source location, and timestamp. Falls back to a lazily-installed page hook when the debugger is unavailable.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    level: z
      .enum(["debug", "info", "log", "warn", "error"])
      .optional()
      .default("debug")
      .describe(
        "Filter by minimum severity level: 'debug' (all), 'info', 'log', 'warn', or 'error'. Returns messages at this level and above. Default 'debug'."
      ),
    clear: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Clear the message buffer after reading. Default false."
      ),
  },
  toolHandler("readConsoleMessages")
);

server.tool(
  "read_network_requests",
  "Read network requests from a browser tab via the CDP Network domain. Captures every request the tab makes (all types, all frames) with method, URL, status, response headers, postData, resource type, timing, and size — from the moment the debugger attaches on first call. List mode returns newest first, defaults to 50 entries, supports offset pagination, substring or regular-expression URL filtering, and an optional compact summary. WebSocket connections appear in the same listing as entries with kind:\"websocket\" carrying url, state (connecting/open/closed/error), handshake summary, and frame counters (framesSent/framesReceived/bytesSent/bytesReceived); pass includeWsFrames:true to also get the frame ring (most recent 20 frames per socket, text payloads truncated at 2KB, binary frames recorded as {binary:true,length} (true decoded byte count) without payload data — to inspect actual binary content, hook the socket in-page via execute_javascript or capture externally). Pass requestId to fetch one entry: an HTTP request returns its full entry plus RESPONSE BODY (Network.getResponseBody, text truncated at 200KB); a WebSocket requestId returns its handshake + full frame ring instead of a body. Note for waitFor/networkIdle users: WS frame traffic does NOT count as network activity (heartbeats would keep the network from ever idling), though socket create/close do. Falls back to page-world fetch/XHR interception (metadata only, no WS entries) when the debugger is unavailable.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    filter: z
      .string()
      .optional()
      .describe(
        "URL substring to filter requests (applies to HTTP and WebSocket entries alike). Only returns entries whose URL contains this string."
      ),
    urlRegex: z
      .string()
      .optional()
      .describe(
        "JavaScript regular-expression source used to filter request URLs. Combined with filter using AND when both are provided."
      ),
    limit: z
      .number()
      .int()
      .min(1)
      .max(200)
      .optional()
      .default(50)
      .describe("Maximum list entries to return. Default 50, maximum 200."),
    offset: z
      .number()
      .int()
      .min(0)
      .optional()
      .default(0)
      .describe("Zero-based list offset after filtering and newest-first sorting. Default 0."),
    summaryOnly: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Return compact request metadata without headers, postData, handshakes, or WebSocket frames. Default false."
      ),
    requestId: z
      .string()
      .optional()
      .describe(
        "CDP request ID (from a previous listing) to fetch a single entry: HTTP → entry + response body; WebSocket → handshake + frame ring."
      ),
    includeBody: z
      .boolean()
      .optional()
      .default(true)
      .describe(
        "With requestId on an HTTP request: include the response body. Default true. Text bodies over 200KB are truncated; binary bodies come back base64-encoded. Ignored for WebSocket entries."
      ),
    includeWsFrames: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "List mode only: include each WebSocket entry's frame ring (last 20 frames, text payloads capped at 2KB, binary frames as {binary:true,length}). Default false — counters and state ship regardless."
      ),
    clear: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Clear the captured requests buffer (HTTP and WebSocket entries) after reading. Default false."
      ),
  },
  toolHandler("readNetworkRequests")
);

// ============================================================
// Chrome DevTools Protocol (CDP)
// ============================================================

server.tool(
  "cdp_send",
  "Send an arbitrary Chrome DevTools Protocol command to a tab — full access to every CDP domain: Network (cookies, cache, throttling), Fetch (request interception/mocking), Emulation (geolocation, timezone, CPU/network throttling), Page, DOM, CSS, Runtime, Input, Performance, HeapProfiler, and more. The tab is attached via chrome.debugger on first use (protocol 1.3), showing Chrome's debugging infobar. Example: method='Network.getCookies', params={urls:['https://example.com']}. For event-driven domains (e.g. Fetch.enable → Fetch.requestPaused), drain events with read_cdp_events and respond with further cdp_send calls — or use mock_request for rule-based request mocking/fulfill/block without the manual event loop. Consult chromedevtools.github.io/devtools-protocol for method names and params. Cross-origin (OOPIF) frames run in their own process with a dedicated child session: pass frameId (or an explicit sessionId) to address commands there — Input coordinates on a child session are in that frame's own viewport space, and DOM/Runtime/Page methods see only that frame's document.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    method: z
      .string()
      .describe("CDP method name, e.g. 'Network.getCookies', 'Fetch.enable', 'Emulation.setGeolocationOverride'."),
    params: z
      .record(z.string(), z.any())
      .optional()
      .describe("Parameters object for the CDP method. Omit for parameterless commands."),
    sessionId: z
      .string()
      .optional()
      .describe(
        "Target CDP session (flatten-mode child session id, e.g. from Target.attachedToTarget or an OOPIF-annotated read_cdp_events entry). Omit for the tab's root session."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Agent-friendly alias for sessionId: numeric frame id (get_page_structure frames summary / find_elements frameId). Resolved to the frame's OOPIF child session; same-process frames share the root session and error — omit both params for those."
      ),
  },
  toolHandler("cdpSendCommand")
);

server.tool(
  "read_cdp_events",
  "Read buffered CDP events from a tab (ring buffer, up to 1000 events, newest last). Every event from an attached tab is captured: Network.*, Fetch.requestPaused, Page.*, Runtime.*, DOM.*, etc. Filter by method name or domain prefix ('Network' matches all Network.* events). Events from cross-origin (OOPIF) frame child sessions are merged into the same buffer, annotated with sessionId (and frameId where known); filter by sessionId/frameId to isolate one frame's events, or sessionId='root' for the tab's own. Use for event-driven CDP flows: e.g. after Fetch.enable via cdp_send, poll this for Fetch.requestPaused events, then continue/fulfill each via cdp_send.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    methodFilter: z
      .union([z.string(), z.array(z.string())])
      .optional()
      .describe(
        "Exact method name ('Fetch.requestPaused') or domain prefix ('Network', 'Page.frame'). Array = match any."
      ),
    sessionId: z
      .string()
      .optional()
      .describe(
        "Only events from this CDP child session; the literal string 'root' selects events from the tab's root session (no OOPIF annotation)."
      ),
    frameId: z
      .number()
      .optional()
      .describe(
        "Agent-friendly alias for sessionId: numeric frame id, resolved to that OOPIF frame's child session. Same-process frames have no dedicated session — read them without this filter."
      ),
    limit: z
      .number()
      .optional()
      .default(100)
      .describe("Maximum number of (most recent) events to return. Default 100."),
    clear: z
      .boolean()
      .optional()
      .default(false)
      .describe("Clear the event buffer after reading. Default false."),
  },
  toolHandler("readCdpEvents")
);

server.tool(
  "cdp_detach",
  "Detach the debugger from a tab: removes Chrome's debugging infobar and clears that tab's CDP buffers (console/network/events/dialogs). The next CDP-based call re-attaches automatically.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, detaches the active tab."),
  },
  toolHandler("cdpDetachTarget")
);

server.tool(
  "mock_request",
  "Intercept and mock network requests on a tab via the CDP Fetch domain — one tool for the whole lifecycle, sharing that pipeline with rewrite_traffic. Adding a rule (action 'fulfill', 'block', or 'continue') automatically attaches the debugger and enables interception; every paused request is matched against the tab's rules in insertion order (first match wins) and answered in-extension — unmatched requests pass through untouched. Patterns: plain string = substring match on the request URL; /regex/ = regular expression. 'fulfill' returns a canned response (status/headers/body, default 200 + content-type: application/json), 'block' fails the request with net::ERR_BLOCKED_BY_CLIENT, 'continue' explicitly passes it through (useful ahead of a broader regex rule, or to count hits). Mock fulfill/block wins over rewrite_traffic header rewrites and response patches. Rules survive service-worker restarts (chrome.storage.session) but are dropped when the debugger detaches (cdp_detach, tab close, or dismissing Chrome's debugging infobar). action 'list' returns rules with hit counts; 'clear' removes all mock rules for the tab and disables Fetch only when no rewrite_traffic rules still need it. The same rules apply to cross-origin (OOPIF) child sessions. Paused-request events also land in the raw buffer (read_cdp_events, filter 'Fetch').",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["fulfill", "block", "continue", "list", "clear"])
      .describe(
        "'fulfill' / 'block' / 'continue' add a rule for urlPattern; 'list' returns the tab's rules with hit counts; 'clear' removes all rules and disables interception."
      ),
    urlPattern: z
      .string()
      .optional()
      .describe(
        "URL pattern for fulfill/block/continue: plain string = substring match on the request URL; /regex/ = regular expression. Not needed for list/clear."
      ),
    status: z
      .number()
      .optional()
      .describe("HTTP status code for fulfill. Default 200."),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe(
        "Response headers for fulfill as {name: value}. Default {'content-type': 'application/json'}."
      ),
    body: z
      .string()
      .optional()
      .describe(
        "Response body for fulfill, sent as-is (UTF-8 safe). Default empty string."
      ),
  },
  toolHandler("mockRequest")
);

server.tool(
  "handle_dialog",
  "Inspect and handle JavaScript dialogs (alert / confirm / prompt / beforeunload) on a tab. While a dialog is open, the page's JS is blocked and other tools on that tab will hang — call this first. With no action, returns the list of pending dialogs. With action='accept' or 'dismiss', handles the frontmost dialog (pass promptText for prompt inputs).",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["accept", "dismiss"])
      .optional()
      .describe("Accept (OK/yes) or dismiss (Cancel/no). Omit to only list pending dialogs."),
    promptText: z
      .string()
      .optional()
      .describe("Text to enter into a prompt dialog before accepting."),
  },
  toolHandler("handleDialog")
);

server.tool(
  "emulate_device",
  "Emulate a mobile device on a tab via CDP: viewport metrics, device scale factor, touch events, and user-agent override. Presets: 'iphone' (390x844@3x), 'ipad' (820x1180@2x), 'pixel' (412x915@2.625x), or 'reset' to restore normal rendering. Individual fields (width, height, deviceScaleFactor, userAgent, mobile, touch) override the preset.",
  {
    tabId: z
      .number()
      .optional()
      .describe("Tab ID. If omitted, uses the active tab."),
    preset: z
      .enum(["iphone", "ipad", "pixel", "reset"])
      .optional()
      .default("iphone")
      .describe("Device preset. 'reset' clears all emulation. Default 'iphone'."),
    width: z.number().optional().describe("Viewport width in CSS pixels (overrides preset)."),
    height: z.number().optional().describe("Viewport height in CSS pixels (overrides preset)."),
    deviceScaleFactor: z.number().optional().describe("Device scale factor / DPR (overrides preset)."),
    userAgent: z.string().optional().describe("Custom user-agent string (overrides preset)."),
    mobile: z.boolean().optional().describe("Emulate mobile (overlay scrollbars, viewport meta, etc.). Overrides preset."),
    touch: z.boolean().optional().describe("Enable touch event emulation. Overrides preset."),
  },
  toolHandler("emulateDevice")
);

// ============================================================
// Session, page, network rewrite, environment
// ============================================================

server.tool(
  "browser_session",
  "Read and write the signed-in session for the current tab's origin. Cookies go through chrome.cookies (httpOnly included) and do not attach the debugger. localStorage and sessionStorage run in the page's main world. action 'cookies' with op 'list' (default) lists cookies for url, or for domain, or for the tab URL when both are omitted; op 'set' writes one cookie (name required; url defaults to the tab; domain, path, secure, httpOnly, sameSite, expirationDate, and partitionKey are passed through when provided); op 'remove' deletes one cookie by name plus url or domain. action 'local' or 'session' reads the whole store, or one key; op 'set' writes key+value or an entries object; op 'remove' deletes one key. action 'export' returns cookies plus both storages for this origin. includeIndexedDB best-effort exports structured-cloneable databases (Blob and File values are skipped per record; the whole payload is capped around 2MB and flagged truncated). Pass filePath and the server writes that JSON to disk — the tool result is then only the path and byte size. action 'import' writes cookies and both storages from inline data, or from filePath (the server reads the file first). Expired cookies are skipped and counted; storage is written into the tab's origin even if data.origin differs (the result says so). action 'clear' calls chrome.browsingData.remove for this origin's cookies, localStorage, indexedDB, and cache. sessionStorage is not part of browsingData and is left intact. Exported httpOnly cookies stay on the local MCP client, the same trust boundary as execute_javascript and cdp_send.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["cookies", "local", "session", "export", "import", "clear"])
      .describe("Which part of the session to touch."),
    op: z
      .enum(["list", "get", "set", "remove"])
      .optional()
      .describe(
        "cookies: list (default), set, or remove. local/session: get (default; list is an alias), set, or remove."
      ),
    url: z.string().optional().describe("Cookie URL. List defaults to the tab URL. Set/remove build a URL from domain when this is omitted."),
    domain: z.string().optional().describe("Cookie domain filter (list) or domain attribute (set/remove)."),
    name: z.string().optional().describe("Cookie name, or storage key."),
    value: z.string().optional().describe("Cookie value or storage value for op set."),
    path: z.string().optional().describe("Cookie path. Default '/' when a URL is built from domain."),
    secure: z.boolean().optional().describe("Cookie secure flag."),
    httpOnly: z.boolean().optional().describe("Cookie httpOnly flag. chrome.cookies can set this; document.cookie cannot."),
    sameSite: z
      .enum(["no_restriction", "lax", "strict", "unspecified"])
      .optional()
      .describe("Cookie SameSite. Chrome's cookie API names, not the CDP spellings."),
    expirationDate: z
      .number()
      .optional()
      .describe("Cookie expiration as seconds since the Unix epoch. Omit for a session cookie."),
    partitionKey: z
      .object({
        topLevelSite: z.string().optional(),
        hasCrossSiteAncestor: z.boolean().optional(),
      })
      .optional()
      .describe("Chrome cookie partitionKey, passed through when present."),
    storeId: z.string().optional().describe("Cookie store id, when the browser has more than one."),
    key: z.string().optional().describe("localStorage or sessionStorage key."),
    entries: z
      .record(z.string(), z.any())
      .optional()
      .describe("Storage entries to write for op set. Values are stringified."),
    includeIndexedDB: z
      .boolean()
      .optional()
      .describe("export only: also dump IndexedDB. Blob/File values are skipped. Default false."),
    filePath: z
      .string()
      .optional()
      .describe(
        "export: write the JSON here (absolute path recommended) and return only path and bytes. import: read this JSON file on the server and write it into the tab. Omit on export to return the object inline."
      ),
    data: z
      .object({
        origin: z.string().optional(),
        cookies: z.array(z.record(z.string(), z.any())).optional(),
        localStorage: z.record(z.string(), z.any()).optional(),
        sessionStorage: z.record(z.string(), z.any()).optional(),
      })
      .optional()
      .describe("import: inline session object. Ignored when filePath is set and data is omitted — the server reads the file."),
  },
  toolHandler("browserSession")
);

server.tool(
  "grant_permission",
  "Grant or reset site permissions for a tab through CDP Browser.grantPermissions / Browser.resetPermissions. Permission names are the CDP PermissionType enum (geolocation, notifications, clipboardReadWrite, midi, sensors, and the rest of that list) — not Chrome extension permission names. action 'grant' (default) requires permissions and applies them to the tab's origin, or to origin when you pass one. action 'reset' calls Browser.resetPermissions with no origin; it clears permission overrides for the debugger's browser context, which is broader than one site. This does not set geolocation coordinates — use emulate_environment for latitude and longitude. Attaches the debugger. If this Chrome debugger runtime does not expose the Browser domain (JSON-RPC -32601 or 'wasn't found'), the tool fails with PERMISSION_API_UNAVAILABLE and does not pretend the grant was applied.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["grant", "reset"])
      .optional()
      .describe("grant (default) or reset. reset ignores permissions and origin."),
    permissions: z
      .array(z.string())
      .optional()
      .describe("CDP PermissionType names. Required for grant. Example: ['geolocation', 'notifications']."),
    origin: z
      .string()
      .optional()
      .describe("Origin to grant, such as https://example.com. Defaults to the tab's origin."),
  },
  toolHandler("grantPermission")
);

server.tool(
  "describe_element",
  "Describe one element by ref (from get_page_structure or find_elements, including open-shadow nodes) or by CSS selector. Returns the viewport rect in top-level CSS pixels, a small computed-style set (display, position, visibility, opacity, overflow, z-index, color, background-color, font, pointer-events), and DOM.getBoxModel when the debugger can attach. The box model is shifted into the same top-level viewport space as the rect; if the frame offset cannot be measured both stay frame-local and are flagged. Selector lookup also searches open shadow roots, but a selector still cannot pierce a shadow boundary from the outside in one compound selector — it is re-run inside each open root. Does not return the full CSS cascade. Closed shadow roots are not visible. A missing debugger omits the box model and reports boxModelError instead of failing the rect and style.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    ref: z.string().optional().describe("Element ref, e.g. ref_12. Takes precedence over selector."),
    selector: z.string().optional().describe("CSS selector. Searched in the top frame unless frameId is set, and inside open shadow roots."),
    frameId: z
      .number()
      .optional()
      .describe("Frame to search when using selector. Refs already route to their own frame. 0 or omitted = top frame."),
  },
  toolHandler("describeElement")
);

server.tool(
  "find_text",
  "Find visible text on the page, like Ctrl+F, across every frame and open shadow root. Returns the match count, a snippet, a rect in top-level viewport pixels, and a ref for the containing element when the accessibility tree can assign one. Hidden script/style text is skipped. index (0-based) scrolls that match into view, selects it, and highlights it with a yellow ::highlight. limit caps how many matches are returned (default 30, max 100); count is the total found, up to 1000, after which truncated is set. This is not find_elements: it matches raw text, not role or accessible name.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    query: z.string().describe("Text to find. Matched as a literal substring."),
    caseSensitive: z.boolean().optional().describe("Case-sensitive match. Default false."),
    index: z
      .number()
      .int()
      .min(0)
      .optional()
      .describe("0-based match to scroll into view and highlight. Omit to only list."),
    limit: z
      .number()
      .int()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum matches to return inline. Default 30. The focused match is included even past this cap."),
  },
  toolHandler("findText")
);

server.tool(
  "page_selection",
  "Read or change the page's text selection. action 'read' (default) returns the current selection text, its rect, and a ref for the anchor element when one can be assigned. action 'select' builds a Range from ref (the element's contents) or from the first visible occurrence of text, then scrolls it into view. action 'clear' removes the selection in every frame and drops the find_text highlight. Searches open shadow roots. Closed shadow is out of scope.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["read", "select", "clear"])
      .optional()
      .describe("read (default), select, or clear."),
    ref: z.string().optional().describe("select: element whose contents become the selection."),
    text: z.string().optional().describe("select: first visible literal occurrence to select, when ref is omitted."),
    frameId: z.number().optional().describe("Frame for a selector-less ref that is not in the ref registry. Usually omit."),
  },
  toolHandler("pageSelection")
);

server.tool(
  "save_page",
  "Save the page to disk. format 'pdf' uses Page.printToPDF (optional printBackground, paperWidth and paperHeight in inches, landscape). format 'mhtml' uses Page.captureSnapshot. The extension returns the bytes to the server; the server writes filePath, or a temp file when filePath is omitted, and the tool result contains only the path and byte size — the PDF or MHTML is not inlined into the conversation. Attaches the debugger. Very large files still cross the local bridge once as base64 (pdf) or text (mhtml) before being written. Timeout is 120s.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    format: z.enum(["pdf", "mhtml"]).optional().describe("pdf (default) or mhtml."),
    filePath: z
      .string()
      .optional()
      .describe("Absolute path to write. Parent directories are created. Omit to write a temp file and return its path."),
    printBackground: z.boolean().optional().describe("pdf: print background graphics. Omit to leave Chrome's default."),
    paperWidth: z.number().optional().describe("pdf: paper width in inches."),
    paperHeight: z.number().optional().describe("pdf: paper height in inches."),
    landscape: z.boolean().optional().describe("pdf: landscape orientation."),
  },
  toolHandler("savePage")
);

server.tool(
  "rewrite_traffic",
  "Rewrite real network traffic on a tab. Shares one Fetch.enable pipeline with mock_request: mock fulfill/block wins, and a request is header-rewritten only when it is continued. action 'headers' without urlPattern calls Network.setExtraHTTPHeaders so every request on the tab (including OOPIF child sessions) carries those headers — the path for injecting Authorization. With urlPattern, only matching requests are rewritten, at request stage, via Fetch.continueRequest. action 'patch' pauses the matching response, reads Fetch.getResponseBody, and returns it with Fetch.fulfillRequest. You can set status, response headers, and either replace the body outright or apply a literal find/replace. body wins when both body and find are set. Text bodies over 200KB are not rewritten; the rule's truncated count increments and the real response continues. Binary bodies are not find/replaced. action 'list' returns the rules and hit counts. action 'clear' drops rewrite rules and clears extra headers, but leaves mock_request rules in place. Rules persist in chrome.storage.session and are dropped when the debugger detaches, same as mock rules. Patterns: substring, or /regex/.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["headers", "patch", "list", "clear"])
      .describe("headers, patch, list, or clear."),
    urlPattern: z
      .string()
      .optional()
      .describe(
        "Substring match, or /regex/. Omit on headers to apply Network.setExtraHTTPHeaders to every request. Required for patch."
      ),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe("headers action: request headers to set. patch action: response headers to set."),
    status: z.number().optional().describe("patch: HTTP status to return. Default is the real status."),
    body: z.string().optional().describe("patch: replace the response body with this text. Wins over find/replace."),
    find: z.string().optional().describe("patch: literal substring to replace in a text body. Not a regex."),
    replace: z.string().optional().describe("patch: replacement for find. Default empty string."),
  },
  toolHandler("rewriteTraffic")
);

server.tool(
  "export_har",
  "Write the tab's captured HTTP traffic as HAR 1.2. Uses the same network buffer as read_network_requests (requests since the debugger attached — this call attaches if needed). Request headers from Network.requestWillBeSent are included. WebSocket entries are not written. includeBodies pulls response bodies with Network.getResponseBody under about a 2MB total budget; entries past the budget omit the body and are counted in bodiesOmitted. The HAR is written to filePath, or to a temp file when filePath is omitted. The tool result is the path, byte size, and counts — not the HAR document. Timeout is 120s.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    filePath: z
      .string()
      .optional()
      .describe("Absolute path for the .har file. Omit to write a temp file."),
    includeBodies: z
      .boolean()
      .optional()
      .describe("Fetch response bodies into HAR content.text until the ~2MB budget is spent. Default false."),
  },
  toolHandler("exportHar")
);

server.tool(
  "emulate_environment",
  "Override the tab's environment without touching emulate_device (that tool stays viewport, DPR, user agent, and the mobile/touch switch). Each field is independent: only fields you pass are changed. geolocation is {latitude, longitude, accuracy?} or null to clear the override. Setting coordinates also tries Browser.grantPermissions for geolocation on the tab origin; if that API is missing (-32601), the coordinates are still applied and the result says the grant was unavailable. timezone is an IANA name, or null to clear. locale is a locale string such as en-US, or null to clear. colorScheme is dark, light, or no-preference (null clears emulated media features — this replaces the whole emulated feature list). network is online, offline, slow3g, or fast3g via Network.emulateNetworkConditions (Chromium DevTools throughput presets). Overrides are applied on the tab's root debugger session and on OOPIF child sessions that are already attached. Attaches the debugger.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    geolocation: z
      .object({
        latitude: z.number(),
        longitude: z.number(),
        accuracy: z.number().optional(),
      })
      .nullable()
      .optional()
      .describe("Coordinates to override, or null to clear. accuracy defaults to 1."),
    timezone: z
      .string()
      .nullable()
      .optional()
      .describe("IANA time zone, e.g. America/New_York. null clears the override."),
    locale: z.string().nullable().optional().describe("Locale, e.g. en-US. null clears the override."),
    colorScheme: z
      .enum(["dark", "light", "no-preference"])
      .nullable()
      .optional()
      .describe("prefers-color-scheme. null clears emulated media features."),
    network: z
      .enum(["online", "offline", "slow3g", "fast3g"])
      .optional()
      .describe("Network.emulateNetworkConditions preset."),
  },
  toolHandler("emulateEnvironment")
);

server.tool(
  "touch_gesture",
  "Dispatch a touch gesture: tap, longPress, swipe, or pinch. The target is a ref, a selector, or coordinates (x/y or coordinates), in top-level viewport CSS pixels — the same space as click_element. Calling this enables touch emulation on the session that receives the gesture (Emulation.setTouchEmulationEnabled, maxTouchPoints 5). tap and longPress use Input.dispatchTouchEvent (longPress holds for duration ms, default 700). swipe interpolates touch moves from the start point to toX/toY (top-level pixels) or by dx/dy; duration defaults to 300ms over 8 steps. pinch uses Input.synthesizePinchGesture with scaleFactor (>1 spreads, <1 pinches) and gestureSourceType touch. Cross-origin frames receive the gesture on their child session in frame-local coordinates. Attaches the debugger.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    gesture: z.enum(["tap", "longPress", "swipe", "pinch"]).describe("Gesture to perform."),
    ref: z.string().optional().describe("Element ref. The gesture starts at its center."),
    selector: z.string().optional().describe("CSS selector. The gesture starts at the element's center."),
    frameId: z.number().optional().describe("Frame for selector or coordinates routing. Refs route themselves."),
    x: z.number().optional().describe("Start X in top-level viewport CSS pixels."),
    y: z.number().optional().describe("Start Y in top-level viewport CSS pixels."),
    coordinates: z
      .object({ x: z.number(), y: z.number() })
      .optional()
      .describe("Start point, alternative to x and y."),
    toX: z.number().optional().describe("swipe: end X in top-level viewport pixels."),
    toY: z.number().optional().describe("swipe: end Y in top-level viewport pixels."),
    dx: z.number().optional().describe("swipe: horizontal delta from the start, pixels."),
    dy: z.number().optional().describe("swipe: vertical delta from the start, pixels."),
    duration: z
      .number()
      .optional()
      .describe("Milliseconds. longPress default 700, swipe default 300, tap default 40."),
    steps: z.number().int().min(1).optional().describe("swipe: number of move events. Default 8."),
    scaleFactor: z
      .number()
      .optional()
      .describe("pinch: scale factor. >1 zooms in, <1 zooms out. Required for pinch."),
    relativeSpeed: z
      .number()
      .optional()
      .describe("pinch: pointer speed in pixels per second. Omit for the browser default."),
    scrollIntoView: z
      .boolean()
      .optional()
      .describe("Scroll the ref or selector into view before the gesture. Default true."),
  },
  toolHandler("touchGesture")
);

server.tool(
  "webauthn",
  "Virtual WebAuthn authenticator for a tab, so passkey prompts do not wait on a person. action 'enable' turns on the CDP WebAuthn domain and adds one authenticator: ctap2, internal transport, resident keys, user verification, isUserVerified, and automaticPresenceSimulation. A later enable returns that authenticator unless forceNew is set. action 'addCredential' installs a credential on the tracked authenticator (credentialId, privateKey as base64 PKCS#8, rpId, userHandle as base64; isResidentCredential defaults true). action 'list' returns tracked authenticators and their credentials. action 'remove' deletes credentialId, or the authenticator when credentialId is omitted. action 'clear' removes every tracked authenticator and its credentials. Authenticator ids are stored on this tab's debugger session and are invalid after cdp_detach, tab close, dismissing the debugging infobar, or a service-worker restart. The result says so. Attaches the debugger.",
  {
    tabId: z.number().optional().describe("Tab ID. If omitted, uses the active tab."),
    action: z
      .enum(["enable", "addCredential", "list", "remove", "clear"])
      .describe("enable, addCredential, list, remove, or clear."),
    forceNew: z
      .boolean()
      .optional()
      .describe("enable: add another authenticator even if one is already tracked."),
    authenticatorId: z
      .string()
      .optional()
      .describe("Authenticator to use. Defaults to the first one this session created."),
    credentialId: z.string().optional().describe("addCredential or remove: base64 credential id."),
    privateKey: z.string().optional().describe("addCredential: base64 PKCS#8 private key."),
    rpId: z.string().optional().describe("addCredential: relying party id."),
    userHandle: z.string().optional().describe("addCredential: base64 user handle."),
    signCount: z.number().optional().describe("addCredential: signature counter. Default 0."),
    isResidentCredential: z.boolean().optional().describe("addCredential: resident credential. Default true."),
    userName: z.string().optional().describe("addCredential: optional user name."),
    displayName: z.string().optional().describe("addCredential: optional display name."),
    credential: z
      .record(z.string(), z.any())
      .optional()
      .describe("addCredential: credential fields as one object instead of top-level parameters."),
  },
  toolHandler("webauthn")
);

// --- Start ---

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[bridge] MCP server started on stdio");
}

main().catch((err) => {
  console.error("[bridge] Fatal error:", err);
  process.exit(1);
});
