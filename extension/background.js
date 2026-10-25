import { nonce, validNonce, proof, equalProof, frameProof } from "./auth.js";
const PORT_START = 17890;
const PORT_END = 17909;

// port -> { ws: WebSocket, authed: boolean }
// Only mutually authenticated peers may issue commands.
const connections = new Map();

// --- Helpers ---


async function getActiveTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) throw new Error("No active tab found");
  return tab.id;
}

function sendTo(ws, data) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const conn = [...connections.values()].find(c => c.ws === ws);
  if (!conn?.authed) { ws.send(JSON.stringify(data)); return; }
  conn.outgoing = conn.outgoing.then(async () => {
    const payload = JSON.stringify(data);
    const seq = ++conn.sendSeq;
    const mac = await frameProof(conn.token, "client", conn.serverNonce, conn.clientNonce, seq, payload);
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({seq, payload, proof: mac}));
  }).catch(() => ws.close());
}

function getConnectedCount() {
  let count = 0;
  for (const conn of connections.values()) {
    if (conn.authed && conn.ws.readyState === WebSocket.OPEN) count++;
  }
  return count;
}

// --- CDP (chrome.debugger) infrastructure ---
//
// Per-tab CDP sessions, created on demand when a tool needs the Chrome
// DevTools Protocol. Attaching shows Chrome's "started debugging this
// browser" infobar — the accepted cost for trusted input, dialog control,
// full-page/background screenshots and network/console capture.
//
// Buffers live in service-worker memory and are lost if the worker is
// recycled; the debugger attachment itself survives, and ensureCdp()
// recovers it transparently.

const CDP_PROTOCOL_VERSION = "1.3";
const EVENT_BUFFER_MAX = 1000;
const CONSOLE_BUFFER_MAX = 500;
const NETWORK_BUFFER_MAX = 300;
// Same cap read_network_requests uses when returning a response body.
const TEXT_BODY_MAX = 200000;
// export_har includeBodies and browser_session export share this budget.
const EXPORT_BYTE_BUDGET = 2 * 1024 * 1024;
// WebSocket observation bounds: a ring of the most recent frames per socket,
// with each text payload capped. Binary frames never store payload data.
const WS_FRAME_BUFFER_MAX = 20;
const WS_FRAME_PAYLOAD_MAX = 2048;
// wait_for lookback: agent-turn latency between a click and the follow-up
// wait_for call is seconds-scale, so events that fired in that gap (a fast
// navigation, an instantly-completing local download) must still match.
const WAIT_LOOKBACK_MS = 3000;

// Events that count as "network activity" for wait_for networkIdle. Kept as a
// module-level set so the event router can maintain session.lastNetworkActivityTs
// incrementally instead of rescanning the ring buffer on every poll.
// WebSocket semantics: the one-shot lifecycle events (created/closed) count as
// network activity, but frame traffic deliberately does NOT — heartbeats on a
// long-lived socket would keep networkIdle from ever settling.
const NETWORK_ACTIVITY_EVENTS = new Set([
  "Network.requestWillBeSent",
  "Network.responseReceived",
  "Network.loadingFinished",
  "Network.loadingFailed",
  "Network.webSocketCreated",
  "Network.webSocketClosed",
]);

// tabId -> session
const cdpSessions = new Map();
// tabId -> in-flight attach promise (dedupes concurrent ensureCdp calls)
const cdpAttachInFlight = new Map();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newCdpSession() {
  return {
    attached: true,
    events: [], // ring buffer of raw CDP events {method, params, ts}
    console: [], // normalized console/log/exception entries
    dialogs: [], // pending JS dialogs (alert/confirm/prompt/beforeunload)
    network: new Map(), // requestId -> entry
    networkOrder: [], // requestIds in arrival order (for eviction)
    webSockets: new Map(), // requestId -> WS entry (url/state/handshake/frame ring)
    webSocketOrder: [], // WS keys in arrival order (for eviction, whole entries go)
    lastDragIntercepted: null,
    lastNetworkActivityTs: 0, // updated by the event router; O(1) networkIdle checks
    networkActivity: [], // recent activity with URL for wait_for exclusion rules
    domEnabled: false, // DOM.enable sent lazily (frame offset measurement)
    // Virtual WebAuthn authenticators added on this debugger session.
    // Detach destroys them in Chrome; the ids here die with the session.
    webauthn: { enabled: false, authenticators: [] },
  };
}

// True when the debugger could not be attached at all (DevTools open on the
// tab, chrome:// page, policy, ...). Callers fall back to synthetic DOM
// events in that case. CDP *command* failures are real errors and propagate.
function isCdpUnavailable(err) {
  return String((err && err.message) || err).includes("CDP_ATTACH_FAILED");
}

// chrome.debugger surfaces a missing CDP method as "wasn't found" and, on
// some builds, the JSON-RPC code -32601. Callers that must not pretend
// success (grant_permission) turn that into a structured {code, message}.
function isCdpMethodMissing(err) {
  const msg = String((err && err.message) || err);
  return /wasn't found|unknown method|method not found|\b-32601\b/i.test(msg);
}

function codedError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

async function ensureCdp(tabId) {
  const existing = cdpSessions.get(tabId);
  if (existing && existing.attached) return existing;
  if (cdpAttachInFlight.has(tabId)) return cdpAttachInFlight.get(tabId);

  const p = (async () => {
    try {
      await chrome.debugger.attach({ tabId }, CDP_PROTOCOL_VERSION);
    } catch (e) {
      const msg = (e && e.message) || String(e);
      if (!/Another debugger/i.test(msg)) {
        throw new Error(`CDP_ATTACH_FAILED: ${msg}`);
      }
      // Likely our own attachment from a previous service-worker lifetime.
      // Probe it; if commands flow, adopt the session.
      try {
        await chrome.debugger.sendCommand({ tabId }, "Runtime.evaluate", {
          expression: "1",
          returnByValue: true,
        });
      } catch (e2) {
        throw new Error(`CDP_ATTACH_FAILED: ${(e2 && e2.message) || e2}`);
      }
    }

    const session = newCdpSession();
    cdpSessions.set(tabId, session);

    // Enable the domains our event collectors need. Individual failures are
    // non-fatal (some may already be enabled).
    for (const method of ["Page.enable", "Runtime.enable", "Log.enable", "Network.enable"]) {
      try {
        await chrome.debugger.sendCommand({ tabId }, method);
      } catch {}
    }

    // Auto-attach OOPIF child sessions (flatten mode). Events announce them
    // via Target.attachedToTarget; the router queues the numeric-frameId bind.
    // Not recursive — child sessions get their own setAutoAttach when bound.
    try {
      await chrome.debugger.sendCommand({ tabId }, "Target.setAutoAttach", {
        ...AUTO_ATTACH_PARAMS,
        filter: [{ type: "iframe", exclude: false }],
      });
    } catch {
      try {
        await chrome.debugger.sendCommand({ tabId }, "Target.setAutoAttach", AUTO_ATTACH_PARAMS);
      } catch {}
    }

    // Restore Fetch interception if this tab still has mock or rewrite rules,
    // and re-apply global extra headers. Rules live in storage.session, so
    // this covers service-worker restarts and re-attachments.
    try {
      await mockRulesReady;
      await rewriteRulesReady;
      const patterns = fetchPatternsFor(tabId);
      if (patterns.length) {
        await chrome.debugger.sendCommand({ tabId }, "Fetch.enable", {
          patterns,
          handleAuthRequests: false,
        });
      }
      const extra = mergedExtraHeaders(tabId);
      if (extra) {
        await chrome.debugger.sendCommand({ tabId }, "Network.setExtraHTTPHeaders", {
          headers: extra,
        });
      }
    } catch {}

    return session;
  })();

  cdpAttachInFlight.set(tabId, p);
  try {
    return await p;
  } finally {
    cdpAttachInFlight.delete(tabId);
  }
}

async function cdpSend(tabId, method, params) {
  await ensureCdp(tabId);
  try {
    return await chrome.debugger.sendCommand({ tabId }, method, params || {});
  } catch (e) {
    const msg = (e && e.message) || String(e);
    throw new Error(`CDP ${method} failed: ${msg}`);
  }
}

async function cdpDetachTab(tabId) {
  try {
    await chrome.debugger.detach({ tabId });
  } catch {}
  cdpSessions.delete(tabId);
  clearTabBindings(tabId);
  // Interception is off once the debugger is gone; drop the rules so
  // mock_request list reflects reality.
  clearMockRulesForTab(tabId);
  clearRewriteRulesForTab(tabId);
}

chrome.debugger.onDetach.addListener((source) => {
  if (source.tabId !== undefined) {
    cdpSessions.delete(source.tabId);
    clearMockRulesForTab(source.tabId);
    clearRewriteRulesForTab(source.tabId);
    clearTabBindings(source.tabId); // child sessions die with the root attach
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  cdpSessions.delete(tabId);
  clearMockRulesForTab(tabId);
  clearRewriteRulesForTab(tabId);
  refRegistries.delete(tabId);
  clearTabBindings(tabId);
  for (const key of cdpFrameIds.keys()) {
    if (key.startsWith(`${tabId}:`)) cdpFrameIds.delete(key);
  }
});

// --- Mock request rules (CDP Fetch interception) ---
//
// Per-tab rule lists, matched in insertion order against Fetch.requestPaused.
// The in-memory Map is the runtime source of truth (the event router needs it
// without awaiting storage on every request); chrome.storage.session is the
// persistence copy that survives service-worker restarts. Rules are preloaded
// before Fetch.enable is issued, and ensureCdp() re-enables interception after
// a restart/re-attach. Detach (cdp_detach, infobar "Cancel", tab close) drops
// the rules, since interception cannot survive it.

const mockRules = new Map(); // tabId -> rule[]
let mockRuleSeq = 1;

// Loaded-rules barrier: every mutation path awaits this before touching
// mockRules, so early events (tab closed right after SW start) cannot
// overwrite stored rules with an empty snapshot.
const mockRulesReady = (async () => {
  let data;
  try {
    data = await chrome.storage.session.get("mockRules");
  } catch {
    return;
  }
  const saved = (data && data.mockRules) || {};
  for (const [tabId, rules] of Object.entries(saved)) {
    if (Array.isArray(rules) && rules.length) {
      mockRules.set(Number(tabId), rules);
      for (const r of rules) {
        const n = parseInt(String(r.id).replace(/\D/g, ""), 10);
        if (n) mockRuleSeq = Math.max(mockRuleSeq, n + 1);
      }
    }
  }
})();

function persistMockRules() {
  mockRulesReady.then(() => {
    const obj = {};
    for (const [tabId, rules] of mockRules) obj[String(tabId)] = rules;
    chrome.storage.session.set({ mockRules: obj }).catch(() => {});
  });
}

function clearMockRulesForTab(tabId) {
  mockRulesReady.then(() => {
    if (mockRules.delete(tabId)) persistMockRules();
  });
}

// --- Response/request rewrite rules (same Fetch pipeline as mock rules) ---
//
// kind "headers" without a urlPattern is NOT a Fetch pattern: it is applied
// with Network.setExtraHTTPHeaders to every request on the tab (and on each
// bound child session). kind "headers" with a pattern rewrites only matching
// requests, and only when the request is continued (mock fulfill/block wins).
// kind "patch" pauses at the response stage and rewrites status, response
// headers, and/or the body. Persistence and detach lifetime match mock rules.

const rewriteRules = new Map(); // tabId -> rule[]
let rewriteRuleSeq = 1;

const rewriteRulesReady = (async () => {
  let data;
  try {
    data = await chrome.storage.session.get("rewriteRules");
  } catch {
    return;
  }
  const saved = (data && data.rewriteRules) || {};
  for (const [tabId, rules] of Object.entries(saved)) {
    if (Array.isArray(rules) && rules.length) {
      rewriteRules.set(Number(tabId), rules);
      for (const r of rules) {
        const n = parseInt(String(r.id).replace(/\D/g, ""), 10);
        if (n) rewriteRuleSeq = Math.max(rewriteRuleSeq, n + 1);
      }
    }
  }
})();

function persistRewriteRules() {
  rewriteRulesReady.then(() => {
    const obj = {};
    for (const [tabId, rules] of rewriteRules) obj[String(tabId)] = rules;
    chrome.storage.session.set({ rewriteRules: obj }).catch(() => {});
  });
}

function clearRewriteRulesForTab(tabId) {
  rewriteRulesReady.then(() => {
    if (rewriteRules.delete(tabId)) persistRewriteRules();
  });
}

// Global (no-pattern) header rules, later rules overriding earlier ones.
// Null when the tab has none — callers then leave extra headers alone,
// except rewrite clear which passes {} explicitly.
function mergedExtraHeaders(tabId) {
  const headers = {};
  let any = false;
  for (const r of rewriteRules.get(tabId) || []) {
    if (r.kind !== "headers" || r.urlPattern || r.regex) continue;
    if (r.headers && typeof r.headers === "object") {
      Object.assign(headers, r.headers);
      any = true;
    }
  }
  return any ? headers : null;
}

// CDP Fetch.enable patterns covering mock rules and patterned rewrite rules.
// Substring rules become *wildcard* patterns; regex rules intercept everything.
// Patterns may over-match — handleFetchPaused still decides per rule.
// An empty list means "do not intercept" (Fetch.enable with no patterns
// would pause every request).
function fetchPatternsFor(tabId) {
  const patterns = [];
  const seen = new Set();
  const add = (urlPattern, requestStage) => {
    const key = `${requestStage}\0${urlPattern}`;
    if (seen.has(key)) return;
    seen.add(key);
    patterns.push({ urlPattern, requestStage });
  };
  for (const r of mockRules.get(tabId) || []) {
    add(r.regex ? "*" : `*${r.urlPattern}*`, "Request");
  }
  for (const r of rewriteRules.get(tabId) || []) {
    if (r.kind === "headers") {
      if (!r.urlPattern && !r.regex) continue;
      add(r.regex ? "*" : `*${r.urlPattern}*`, "Request");
    } else if (r.kind === "patch" && (r.urlPattern || r.regex)) {
      add(r.regex ? "*" : `*${r.urlPattern}*`, "Response");
    }
  }
  return patterns;
}

function ruleMatchesUrl(rule, url) {
  if (rule.regex) {
    try {
      return new RegExp(rule.regex).test(url);
    } catch {
      return false;
    }
  }
  if (!rule.urlPattern) return false;
  return url.includes(rule.urlPattern);
}

function toBase64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// Header lists for Fetch.continueRequest / fulfillRequest. Pseudo-headers
// (:method, :path, ...) are rejected if echoed back, so they are dropped.
// `base` is either a CDP header object or a Fetch HeaderEntry array.
function overlayHeaders(base, overrides) {
  const map = new Map();
  const put = (name, value) => {
    if (!name || String(name).startsWith(":")) return;
    map.set(String(name).toLowerCase(), { name: String(name), value: String(value ?? "") });
  };
  if (Array.isArray(base)) {
    for (const h of base) if (h && h.name) put(h.name, h.value);
  } else if (base && typeof base === "object") {
    for (const [name, value] of Object.entries(base)) put(name, value);
  }
  if (overrides && typeof overrides === "object") {
    for (const [name, value] of Object.entries(overrides)) put(name, value);
  }
  return [...map.values()];
}

function decodeFetchBody(body, base64Encoded) {
  const raw = body || "";
  if (!base64Encoded) return { text: raw, binary: false, bytes: raw.length };
  let bin;
  try {
    bin = atob(raw);
  } catch {
    return { text: null, binary: true, bytes: 0 };
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { text, binary: false, bytes: bytes.length };
  } catch {
    return { text: null, binary: true, bytes: bytes.length };
  }
}

function assignUrlPattern(rule, pattern) {
  rule.urlPattern = pattern;
  if (pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/")) {
    rule.regex = pattern.slice(1, -1);
    try {
      new RegExp(rule.regex);
    } catch (e) {
      throw new Error(`Invalid regex in urlPattern: ${e.message}`);
    }
  }
}

// Re-apply Fetch.enable/disable on the root session and every child session
// we have seen. Empty patterns disable interception (mock clear must not
// leave rewrite patches off, and the reverse).
async function applyFetchPatterns(tabId) {
  if (!cdpSessions.has(tabId)) return;
  const patterns = fetchPatternsFor(tabId);
  const targets = [null, ...listChildSessions(tabId)];
  for (const sid of targets) {
    try {
      if (patterns.length) {
        await cdpSendTo(tabId, sid, "Fetch.enable", {
          patterns,
          handleAuthRequests: false,
        });
      } else {
        await cdpSendTo(tabId, sid, "Fetch.disable");
      }
    } catch {}
  }
}

async function applyExtraHeaders(tabId, headers) {
  if (!cdpSessions.has(tabId)) return;
  const targets = [null, ...listChildSessions(tabId)];
  for (const sid of targets) {
    try {
      await cdpSendTo(tabId, sid, "Network.setExtraHTTPHeaders", { headers: headers || {} });
    } catch {}
  }
}

function noteHit(rule) {
  rule.hits = (rule.hits || 0) + 1;
  rule.lastHitTs = Date.now();
}

async function fulfillMock(send, params, rule) {
  noteHit(rule);
  const headers =
    rule.headers && Object.keys(rule.headers).length
      ? rule.headers
      : { "content-type": "application/json" };
  await send("Fetch.fulfillRequest", {
    requestId: params.requestId,
    responseCode: rule.status || 200,
    responseHeaders: overlayHeaders(null, headers),
    body: toBase64Utf8(rule.body || ""),
  });
}

// Answer one Fetch.requestPaused on the session that paused it (root or
// OOPIF child). Mock fulfill/block wins. Pattern header rewrites are applied
// only when the request is continued. Response-stage patches run only when
// no mock consumes the URL. Errors fall back to continue so a bad rule
// cannot leave the request paused forever.
async function handleFetchPaused(tabId, params, sessionId) {
  const send = (method, p) =>
    chrome.debugger.sendCommand(sessionId ? { tabId, sessionId } : { tabId }, method, p);
  const requestId = params.requestId;
  try {
    await mockRulesReady;
    await rewriteRulesReady;
    const url = (params.request && params.request.url) || "";
    const mocks = mockRules.get(tabId) || [];
    const rewrites = rewriteRules.get(tabId) || [];
    const mock = mocks.find((r) => ruleMatchesUrl(r, url));
    const responseStage =
      params.responseStatusCode !== undefined || params.responseErrorReason !== undefined;
    const consumed = mock && (mock.action === "fulfill" || mock.action === "block");

    if (responseStage) {
      if (consumed && mock.action === "fulfill") {
        await fulfillMock(send, params, mock);
        return;
      }
      if (consumed && mock.action === "block") {
        noteHit(mock);
        try {
          await send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
        } catch {
          await send("Fetch.continueResponse", { requestId });
        }
        return;
      }
      const patch = rewrites.find((r) => r.kind === "patch" && ruleMatchesUrl(r, url));
      if (!patch) {
        await send("Fetch.continueResponse", { requestId });
        return;
      }
      if (params.responseErrorReason) {
        patch.skipped = (patch.skipped || 0) + 1;
        patch.lastSkip = "response-error";
        await send("Fetch.continueResponse", { requestId });
        return;
      }
      let fetched;
      try {
        fetched = await send("Fetch.getResponseBody", { requestId });
      } catch {
        patch.skipped = (patch.skipped || 0) + 1;
        patch.lastSkip = "no-body";
        await send("Fetch.continueResponse", { requestId });
        return;
      }
      const decoded = decodeFetchBody(fetched && fetched.body, fetched && fetched.base64Encoded);
      const tooBig = decoded.binary
        ? decoded.bytes > TEXT_BODY_MAX
        : (decoded.text || "").length > TEXT_BODY_MAX;
      if (tooBig) {
        patch.truncated = (patch.truncated || 0) + 1;
        patch.lastHitTs = Date.now();
        await send("Fetch.continueResponse", { requestId });
        return;
      }
      if (decoded.binary && patch.body === undefined) {
        patch.skipped = (patch.skipped || 0) + 1;
        patch.lastSkip = "binary";
        await send("Fetch.continueResponse", { requestId });
        return;
      }
      let newBody = decoded.text || "";
      if (patch.body !== undefined) {
        newBody = String(patch.body);
      } else if (patch.find != null) {
        newBody = newBody.split(String(patch.find)).join(patch.replace != null ? String(patch.replace) : "");
      }
      noteHit(patch);
      await send("Fetch.fulfillRequest", {
        requestId,
        responseCode: patch.status || params.responseStatusCode || 200,
        responseHeaders: overlayHeaders(params.responseHeaders, patch.responseHeaders),
        body: toBase64Utf8(newBody),
      });
      return;
    }

    // Request stage.
    if (mock && mock.action === "block") {
      noteHit(mock);
      await send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      return;
    }
    if (mock && mock.action === "fulfill") {
      await fulfillMock(send, params, mock);
      return;
    }
    if (mock && mock.action === "continue") noteHit(mock);

    const headerRules = rewrites.filter(
      (r) => r.kind === "headers" && (r.urlPattern || r.regex) && ruleMatchesUrl(r, url)
    );
    if (headerRules.length) {
      const overrides = {};
      for (const hr of headerRules) {
        noteHit(hr);
        if (hr.headers) Object.assign(overrides, hr.headers);
      }
      const headers = overlayHeaders(params.request && params.request.headers, overrides);
      try {
        await send("Fetch.continueRequest", { requestId, headers });
      } catch {
        await send("Fetch.continueRequest", { requestId });
      }
      return;
    }
    await send("Fetch.continueRequest", { requestId });
  } catch {
    try {
      await send("Fetch.continueRequest", { requestId });
    } catch {
      try {
        await send("Fetch.continueResponse", { requestId });
      } catch {
        // Debugger detached mid-flight or request already handled.
      }
    }
  }
}

function formatRemoteObject(o) {
  if (!o) return "";
  if (o.value !== undefined) {
    if (typeof o.value === "string") return o.value;
    try {
      return JSON.stringify(o.value);
    } catch {
      return String(o.value);
    }
  }
  if (o.unserializableValue) return o.unserializableValue;
  if (o.description) return o.description;
  if (o.preview) {
    const props = (o.preview.properties || [])
      .map((p) => `${p.name}: ${p.value}`)
      .join(", ");
    return `${o.preview.description || o.type}{${props}}`;
  }
  return o.type || "";
}

function pushRing(arr, item, max) {
  arr.push(item);
  if (arr.length > max) arr.splice(0, arr.length - max);
}

// --- WebSocket frame/entry shaping (P3 observation) ---
//
// Frames are stored in a bounded ring per socket. Opcode 2 (binary) frames
// never keep payload data — base64 would blow up both the in-memory buffer
// and the agent's context, so only {binary:true, length} is recorded. An
// agent that needs actual binary bytes should hook the socket inside the
// page (Runtime.evaluate wrapping the WebSocket object) or capture the
// traffic externally.
//
// CDP ships binary-frame payloadData as a base64 STRING, so the honest byte
// length is the decoded length, not the string length ("AQIDBAU=" is 5 bytes,
// not 8 chars). atob first; arithmetic fallback for payloads atob rejects.
function wsBinaryByteLength(b64) {
  try {
    return atob(b64).length;
  } catch {
    let pad = 0;
    if (b64.endsWith("=")) pad = b64.endsWith("==") ? 2 : 1;
    return Math.max(0, Math.floor((b64.length * 3) / 4) - pad);
  }
}

function wsFrameEntry(dir, resp, payload, byteLen) {
  const opcode = resp.opcode;
  if (opcode === 2) {
    return { dir, opcode, ts: Date.now(), binary: true, length: byteLen };
  }
  if (payload.length > WS_FRAME_PAYLOAD_MAX) {
    return {
      dir, opcode, ts: Date.now(),
      payloadData: payload.slice(0, WS_FRAME_PAYLOAD_MAX),
      truncated: true,
      length: payload.length,
    };
  }
  return { dir, opcode, ts: Date.now(), payloadData: payload };
}

function summarizeWsEntry(w, withFrames) {
  return {
    kind: "websocket",
    requestId: w.requestId,
    ...(w.sessionId ? { sessionId: w.sessionId } : {}),
    url: w.url,
    state: w.state,
    createdTs: w.createdTs,
    ...(w.closedTs !== undefined ? { closedTs: w.closedTs } : {}),
    ...(w.initiator ? { initiator: w.initiator } : {}),
    ...(w.handshake ? { handshake: w.handshake } : {}),
    ...(w.error !== undefined ? { error: w.error } : {}),
    framesSent: w.framesSent,
    framesReceived: w.framesReceived,
    bytesSent: w.bytesSent,
    bytesReceived: w.bytesReceived,
    ...(withFrames ? { frames: (w.frames || []).slice() } : {}),
  };
}

function compileUrlPatterns(patterns, name) {
  return (patterns || []).map((value) => {
    const pattern = String(value);
    if (pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/")) {
      try {
        return { regex: new RegExp(pattern.slice(1, -1)) };
      } catch (e) {
        throw new Error(`Invalid regex in ${name}: ${e.message}`);
      }
    }
    return { substring: pattern };
  });
}

function matchesUrlPatterns(patterns, url) {
  return patterns.some((pattern) =>
    pattern.regex ? pattern.regex.test(url) : url.includes(pattern.substring)
  );
}

function networkActivityUrl(session, method, params, netKey) {
  if (method === "Network.requestWillBeSent") return params.request && params.request.url;
  if (method === "Network.responseReceived") return params.response && params.response.url;
  if (method === "Network.webSocketCreated") return params.url;
  if (method === "Network.loadingFinished" || method === "Network.loadingFailed") {
    return session.network.get(netKey)?.url;
  }
  if (method === "Network.webSocketClosed") {
    return session.webSockets.get(netKey)?.url;
  }
  return null;
}

function summarizeNetworkEntry(entry) {
  if (entry.kind === "websocket") {
    return {
      kind: "websocket",
      requestId: entry.requestId,
      ...(entry.sessionId ? { sessionId: entry.sessionId } : {}),
      url: entry.url,
      state: entry.state,
      createdTs: entry.createdTs,
      ...(entry.closedTs !== undefined ? { closedTs: entry.closedTs } : {}),
      ...(entry.error !== undefined ? { error: entry.error } : {}),
      framesSent: entry.framesSent,
      framesReceived: entry.framesReceived,
      bytesSent: entry.bytesSent,
      bytesReceived: entry.bytesReceived,
    };
  }
  return {
    kind: "http",
    ...(entry.requestId !== undefined ? { requestId: entry.requestId } : {}),
    ...(entry.sessionId ? { sessionId: entry.sessionId } : {}),
    url: entry.url,
    ...(entry.method ? { method: entry.method } : {}),
    ...(entry.resourceType || entry.type ? { type: entry.resourceType || entry.type } : {}),
    ...(entry.status !== undefined ? { status: entry.status } : {}),
    ...(entry.startTime !== undefined ? { startTime: entry.startTime } : {}),
    ...(entry.duration !== undefined ? { duration: entry.duration } : {}),
    ...(entry.size !== undefined ? { size: entry.size } : {}),
    ...(entry.done !== undefined ? { done: entry.done } : {}),
    ...(entry.fromCache !== undefined ? { fromCache: entry.fromCache } : {}),
    ...(entry.canceled !== undefined ? { canceled: entry.canceled } : {}),
    ...(entry.error !== undefined ? { error: entry.error } : {}),
  };
}

function paginateNetworkEntries(entries, params) {
  const rawLimit = Number(params.limit ?? 50);
  const rawOffset = Number(params.offset ?? 0);
  const limit = Number.isFinite(rawLimit) ? Math.min(200, Math.max(1, Math.trunc(rawLimit))) : 50;
  const offset = Number.isFinite(rawOffset) ? Math.max(0, Math.trunc(rawOffset)) : 0;
  let urlRegex = null;
  if (params.urlRegex) {
    try {
      urlRegex = new RegExp(String(params.urlRegex));
    } catch (e) {
      throw new Error(`Invalid urlRegex: ${e.message}`);
    }
  }

  const rows = entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => {
      const url = entry.url || "";
      return (!params.filter || url.includes(params.filter)) && (!urlRegex || urlRegex.test(url));
    })
    .sort((a, b) => {
      const aTime = a.entry.startTime ?? a.entry.createdTs ?? 0;
      const bTime = b.entry.startTime ?? b.entry.createdTs ?? 0;
      return bTime - aTime || a.index - b.index;
    })
    .map(({ entry }) => entry);
  const total = rows.length;
  const page = rows.slice(offset, offset + limit);
  const requests = params.summaryOnly ? page.map(summarizeNetworkEntry) : page;
  return {
    count: requests.length,
    total,
    offset,
    limit,
    hasMore: offset + requests.length < total,
    requests,
  };
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId;
  if (tabId === undefined) return;
  const session = cdpSessions.get(tabId);
  if (!session) return;
  // Flatten-mode child sessions (OOPIFs) share this listener; source.sessionId
  // tells which one spoke. Root-session events have no sessionId.
  const sid = source.sessionId || null;

  if (method === "Target.attachedToTarget") {
    const ti = params && params.targetInfo;
    if (ti && ti.type === "iframe" && params.sessionId) {
      queueChildSessionBind(tabId, params.sessionId, ti);
    }
  } else if (method === "Target.detachedFromTarget") {
    if (params && params.sessionId) unbindChildSession(tabId, params.sessionId);
  }

  const eventTs = Date.now();
  pushRing(session.events, { method, params: params || null, ts: eventTs, ...(sid ? { sessionId: sid } : {}) }, EVENT_BUFFER_MAX);

  // Network buffers are keyed per originating session: requestIds are only
  // unique within one renderer process, so an OOPIF's ids could collide with
  // the root's. Entries keep their original requestId plus a sessionId tag.
  const netKey = params && params.requestId !== undefined ? (sid ? `${sid}:${params.requestId}` : params.requestId) : null;

  if (NETWORK_ACTIVITY_EVENTS.has(method)) {
    session.lastNetworkActivityTs = eventTs;
    pushRing(
      session.networkActivity,
      { ts: eventTs, url: networkActivityUrl(session, method, params || {}, netKey) || null },
      EVENT_BUFFER_MAX
    );
  }

  switch (method) {
    case "Page.javascriptDialogOpening":
      session.dialogs.push({
        type: params.type,
        message: params.message,
        defaultPrompt: params.defaultPrompt || null,
        hasBrowserHandler: !!params.hasBrowserHandler,
        // Dialogs must be answered on the session that raised them.
        sessionId: sid,
        frameId: sid ? (sessionFrames.has(`${tabId}:${sid}`) ? sessionFrames.get(`${tabId}:${sid}`) : undefined) : undefined,
        ts: Date.now(),
      });
      break;

    case "Page.javascriptDialogClosed": {
      // The event carries no dialog identity — match on the session that
      // raised it so interleaved OOPIF/root dialogs never pop each other's
      // entry. An entry already removed by handleDialog simply finds no
      // match here (no unconditional shift: that would drop a different
      // session's pending dialog).
      const idx = session.dialogs.findIndex((d) => (d.sessionId || null) === sid);
      if (idx >= 0) session.dialogs.splice(idx, 1);
      break;
    }

    case "Runtime.consoleAPICalled": {
      const level = params.type === "warning" ? "warn" : params.type;
      const frame = params.stackTrace && params.stackTrace.callFrames && params.stackTrace.callFrames[0];
      pushRing(
        session.console,
        {
          level,
          message: (params.args || []).map(formatRemoteObject).join(" "),
          location: frame ? `${frame.url}:${frame.lineNumber + 1}:${frame.columnNumber + 1}` : undefined,
          timestamp: Date.now(),
          ...(sid
            ? {
                sessionId: sid,
                frameId: sessionFrames.has(`${tabId}:${sid}`) ? sessionFrames.get(`${tabId}:${sid}`) : undefined,
              }
            : {}),
        },
        CONSOLE_BUFFER_MAX
      );
      break;
    }

    case "Runtime.exceptionThrown": {
      const d = params.exceptionDetails;
      pushRing(
        session.console,
        {
          level: "error",
          message: (d && d.exception && d.exception.description) || (d && d.text) || "Unhandled exception",
          location: d ? `${d.url}:${(d.lineNumber || 0) + 1}:${(d.columnNumber || 0) + 1}` : undefined,
          timestamp: Date.now(),
          ...(sid
            ? {
                sessionId: sid,
                frameId: sessionFrames.has(`${tabId}:${sid}`) ? sessionFrames.get(`${tabId}:${sid}`) : undefined,
              }
            : {}),
        },
        CONSOLE_BUFFER_MAX
      );
      break;
    }

    case "Log.entryAdded": {
      const en = params.entry;
      const lvl = en.level === "verbose" ? "debug" : en.level;
      pushRing(
        session.console,
        {
          level: lvl,
          message: `[${en.source}] ${en.text}`,
          location: en.url ? `${en.url}:${en.lineNumber || 0}` : undefined,
          timestamp: Date.now(),
          ...(sid
            ? {
                sessionId: sid,
                frameId: sessionFrames.has(`${tabId}:${sid}`) ? sessionFrames.get(`${tabId}:${sid}`) : undefined,
              }
            : {}),
        },
        CONSOLE_BUFFER_MAX
      );
      break;
    }

    case "Network.requestWillBeSent": {
      const r = params.request;
      const prev = session.network.get(netKey);
      if (prev && params.redirectResponse) {
        prev.status = params.redirectResponse.status;
        prev.redirectUrl = r.url;
      }
      if (!session.network.has(netKey)) {
        session.networkOrder.push(netKey);
        while (session.networkOrder.length > NETWORK_BUFFER_MAX) {
          const old = session.networkOrder.shift();
          session.network.delete(old);
        }
      }
      session.network.set(netKey, {
        requestId: params.requestId,
        url: r.url,
        method: r.method,
        resourceType: params.type,
        // Kept for export_har (HAR 1.2 request.headers). postData stays capped;
        // headers are stored whole because HAR has no equivalent truncation.
        requestHeaders: r.headers || undefined,
        postData: r.postData ? r.postData.slice(0, 8192) : undefined,
        startTime: Date.now(),
        documentUrl: params.documentURL,
        ...(sid ? { sessionId: sid } : {}),
      });
      break;
    }

    case "Network.responseReceived": {
      const e = session.network.get(netKey);
      if (e) {
        e.status = params.response.status;
        e.statusText = params.response.statusText;
        e.mimeType = params.response.mimeType;
        e.protocol = params.response.protocol;
        e.responseHeaders = params.response.headers;
        e.fromCache = !!(params.response.fromDiskCache || params.response.fromMemoryCache);
        if (params.type) e.resourceType = params.type;
      }
      break;
    }

    case "Network.loadingFinished": {
      const e = session.network.get(netKey);
      if (e) {
        e.duration = Date.now() - e.startTime;
        e.size = params.encodedDataLength;
        e.done = true;
      }
      break;
    }

    case "Network.loadingFailed": {
      const e = session.network.get(netKey);
      if (e) {
        e.error = params.errorText;
        e.canceled = !!params.canceled;
        e.done = true;
        e.duration = Date.now() - e.startTime;
      }
      break;
    }

    // --- WebSocket observation ---
    // Keyed by the same composite netKey as the HTTP table (requestIds are
    // only unique within one renderer session). Raw events also stay in
    // session.events. Frame events deliberately do NOT touch
    // lastNetworkActivityTs — see NETWORK_ACTIVITY_EVENTS.

    case "Network.webSocketCreated": {
      if (!session.webSockets || netKey === null) break;
      if (!session.webSockets.has(netKey)) {
        session.webSocketOrder.push(netKey);
        while (session.webSocketOrder.length > NETWORK_BUFFER_MAX) {
          const old = session.webSocketOrder.shift();
          session.webSockets.delete(old);
        }
      }
      session.webSockets.set(netKey, {
        requestId: params.requestId,
        url: params.url,
        state: "connecting",
        createdTs: Date.now(),
        ...(params.initiator ? { initiator: params.initiator } : {}),
        frames: [],
        framesSent: 0,
        framesReceived: 0,
        bytesSent: 0,
        bytesReceived: 0,
        ...(sid ? { sessionId: sid } : {}),
      });
      break;
    }

    case "Network.webSocketHandshakeResponseReceived": {
      const w = session.webSockets && session.webSockets.get(netKey);
      if (w && params.response) {
        w.state = "open";
        w.handshake = {
          status: params.response.status,
          statusText: params.response.statusText,
          headers: params.response.headers,
        };
      }
      break;
    }

    case "Network.webSocketFrameSent":
    case "Network.webSocketFrameReceived": {
      const w = session.webSockets && session.webSockets.get(netKey);
      if (!w) break;
      const resp = params.response || {};
      const sent = method === "Network.webSocketFrameSent";
      const payload = typeof resp.payloadData === "string" ? resp.payloadData : "";
      const byteLen = resp.opcode === 2 ? wsBinaryByteLength(payload) : payload.length;
      if (sent) {
        w.framesSent += 1;
        w.bytesSent += byteLen;
        pushRing(w.frames, wsFrameEntry("sent", resp, payload, byteLen), WS_FRAME_BUFFER_MAX);
      } else {
        w.framesReceived += 1;
        w.bytesReceived += byteLen;
        pushRing(w.frames, wsFrameEntry("received", resp, payload, byteLen), WS_FRAME_BUFFER_MAX);
      }
      break;
    }

    case "Network.webSocketFrameError": {
      const w = session.webSockets && session.webSockets.get(netKey);
      if (w) {
        w.state = "error";
        w.error = params.errorMessage;
        pushRing(w.frames, { dir: "error", errorMessage: params.errorMessage, ts: Date.now() }, WS_FRAME_BUFFER_MAX);
      }
      break;
    }

    case "Network.webSocketClosed": {
      const w = session.webSockets && session.webSockets.get(netKey);
      if (w) {
        w.state = "closed";
        w.closedTs = Date.now();
      }
      break;
    }

    case "Input.dragIntercepted":
      session.lastDragIntercepted = params;
      break;

    case "Fetch.requestPaused":
      // Async and self-catching. source.sessionId is required for OOPIF
      // child sessions — answering on the root session leaves the request
      // paused. The raw event stays in the ring buffer for inspection.
      handleFetchPaused(tabId, params, sid);
      break;
  }
});

// --- Cross-frame ref registry ---
//
// Agent-visible refs stay flat and opaque (ref_12). Each frame's content
// script numbers its own refs locally per snapshot (ref_1..), so the
// background interns a per-tab registry: globalRef -> {frameId, localRef}.
// Rebuilt on every get_page_structure snapshot (top frame first, so its refs
// keep the familiar ref_1..N numbering); find_elements interns into the same
// registry. Navigation and tab close invalidate entries. Unknown refs fall
// through to top-frame resolution — that covers service-worker restarts,
// where the page-side registry survived but ours did not.

const refRegistries = new Map(); // tabId -> {seq, byGlobal: Map, byLocal: Map}

function refRegistry(tabId, { reset = false } = {}) {
  if (reset || !refRegistries.has(tabId)) {
    refRegistries.set(tabId, { seq: 0, byGlobal: new Map(), byLocal: new Map() });
  }
  return refRegistries.get(tabId);
}

function internRef(tabId, frameId, localRef) {
  const reg = refRegistry(tabId);
  const key = `${frameId}:${localRef}`;
  let globalRef = reg.byLocal.get(key);
  if (!globalRef) {
    globalRef = `ref_${++reg.seq}`;
    reg.byLocal.set(key, globalRef);
    reg.byGlobal.set(globalRef, { frameId, localRef });
  }
  return globalRef;
}

// Translate an agent-visible ref for execution in a page frame. Frame refs
// route to their frame (callers target it via frameIds / offset conversion);
// unknown refs fall through to the top frame so pre-restart refs still work.
function routeRef(tabId, globalRef) {
  if (!globalRef) return null;
  const reg = refRegistries.get(tabId);
  const route = reg && reg.byGlobal.get(globalRef);
  if (!route) return { frameId: 0, localRef: globalRef, untracked: true };
  return route;
}

// Translate a page-local ref coming back from the top frame to its global form.
function unrouteRef(tabId, frameId, localRef) {
  if (!localRef) return localRef;
  return internRef(tabId, frameId, localRef);
}

// Depth-first pre-order matches the content script's ref assignment order.
function rewriteTreeRefs(tabId, frameId, node) {
  if (!node || typeof node !== "object") return;
  if (node.ref) node.ref = internRef(tabId, frameId, node.ref);
  if (Array.isArray(node.children)) {
    for (const c of node.children) rewriteTreeRefs(tabId, frameId, c);
  }
}

// Best-effort match of a child frame to an <iframe> node in the parent's
// tree: exact URL first, about:blank/srcdoc as fallback. First unused slot
// wins (grafted slots are marked with frameId). Never descends into already
// grafted subtrees. Exact owner mapping for navigated cross-origin frames is
// a CDP job (DOM.getFrameOwner), not a URL-matching job.
function findIframeSlot(tree, url) {
  if (!tree) return null;
  let fallback = null;
  const queue = [tree];
  while (queue.length) {
    const n = queue.shift();
    if ((n.tag === "iframe" || n.tag === "frame") && n.frameId === undefined) {
      if (url && n.src === url) return n;
      const blankish = !n.src || n.src === "about:blank";
      if (!fallback && blankish && (!url || url === "about:blank" || url === "about:srcdoc")) {
        fallback = n;
      }
    }
    if (n.frameId !== undefined) continue; // embedded foreign tree — don't cross
    if (Array.isArray(n.children)) queue.push(...n.children);
  }
  return fallback;
}

// Refs die with their document: drop them on commit (whole registry for the
// top frame, per-frame entries for subframes) and on tab close.
chrome.webNavigation.onCommitted.addListener((details) => {
  // A committed navigation mints a new CDP frame id for this frame. A
  // main-frame commit destroys every frame in the tab, so drop them all.
  if (details.frameId === 0) {
    const prefix = `${details.tabId}:`;
    for (const key of [...cdpFrameIds.keys()]) {
      if (key.startsWith(prefix)) cdpFrameIds.delete(key);
    }
    clearTabBindings(details.tabId);
  } else {
    cdpFrameIds.delete(`${details.tabId}:${details.frameId}`);
    // An OOPIF navigation can swap processes/sessions; detachedFromTarget
    // usually follows, but drop the binding now so nothing routes to a dead
    // session in between. Rebind happens on the next attachedToTarget.
    const bound = frameSessions.get(`${details.tabId}:${details.frameId}`);
    if (bound) unbindChildSession(details.tabId, bound.sessionId);
  }
  const reg = refRegistries.get(details.tabId);
  if (!reg) return;
  if (details.frameId === 0) {
    refRegistries.delete(details.tabId);
    return;
  }
  for (const [globalRef, route] of reg.byGlobal) {
    if (route.frameId === details.frameId) {
      reg.byGlobal.delete(globalRef);
      reg.byLocal.delete(`${route.frameId}:${route.localRef}`);
    }
  }
});

// --- Frame offset chain (frame-local viewport -> top-level viewport) ---

// CDP Input coordinates, Page.captureScreenshot clips and captureVisibleTab
// pixels all live in TOP-LEVEL viewport space, but element rects measured
// inside a frame are in that frame's own viewport space. Converting between
// the two means summing the content-box position of each ancestor <iframe>.
//
// Measurement has two paths:
//  - Debugger attached (exact): chrome.webNavigation's numeric frameIds and
//    CDP's string Page.FrameIds are DIFFERENT namespaces with no public
//    mapping, so DOM.getFrameOwner cannot be fed our frameIds. Instead we
//    stamp the chain's documents with a nonce attribute via
//    executeScript(frameIds) and walk owner <iframe> nodes from the top
//    document with DOM.querySelectorAll + describeNode, matching the stamp.
//    DOM.getContentQuads on each owner yields its content-box quad; in
//    non-headless Chrome (our only mode) quads are relative to the OWNER'S
//    frame viewport — exactly the per-layer quantity the accumulation needs.
//    The owner node's CDP frameId string is recorded for stage ③ reuse.
//  - Not attached (or walk failed, e.g. owner inside a shadow root or an
//    OOPIF whose contentDocument the top session can't see): executeScript
//    in the parent frame matching iframe src against the child frame URL
//    (findIframeSlot's heuristic in DOM form; first match wins, so identical
//    -src sibling iframes may pick the wrong one).

function frameTarget(tabId, frameId) {
  return frameId ? { tabId, frameIds: [frameId] } : { tabId };
}

// DOM commands can require the agent enabled; enable lazily and retry once.
// Session-aware: sessionId null = the tab's root session, otherwise a bound
// OOPIF child session (each tracks its own DOM.enable state).
async function cdpDomCommandAt(tabId, sessionId, method, params) {
  const session = cdpSessions.get(tabId);
  const key = `${tabId}:${sessionId || ""}`;
  const enabled = sessionId ? childDomEnabled.has(key) : !!(session && session.domEnabled);
  try {
    return await cdpRawTo(tabId, sessionId, method, params);
  } catch (e) {
    if (!enabled) {
      try {
        await cdpRawTo(tabId, sessionId, "DOM.enable");
        // only a successful enable counts as enabled
        if (sessionId) childDomEnabled.add(key);
        else if (session) session.domEnabled = true;
      } catch {}
      return await cdpRawTo(tabId, sessionId, method, params);
    }
    throw e;
  }
}

async function cdpDomCommand(tabId, method, params) {
  return cdpDomCommandAt(tabId, null, method, params);
}

// Exact offset chain, per hop, session-aware. chain is ordered outermost-
// first. Two precise mechanisms per hop:
//  - same-process frame: stamped-marker owner walk inside the CURRENT
//    session's tree (contentDocument is visible);
//  - OOPIF (bound child session): DOM.getFrameOwner({frameId: cdp string}) —
//    a browser-level lookup that works from the session hosting the owner
//    element — then getContentQuads on the returned backendNodeId.
// getContentQuads in non-headless Chrome (our only mode) yields quads
// relative to the OWNER'S frame viewport: exactly the per-layer quantity.
// Returns {x, y, docNodeId, sessionId} — sessionId is the session owning the
// target frame's document (null = root) and docNodeId that document's node
// id in that session — or null when the precise path can't complete.
async function frameOffsetChainCdp(tabId, chain) {
  const nonce = `cfm${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  try {
    let marks;
    try {
      marks = await chrome.scripting.executeScript({
        target: { tabId, frameIds: chain },
        func: (n) => {
          try {
            document.documentElement.setAttribute("data-claude-frame-mark", n);
            return true;
          } catch {
            return false;
          }
        },
        args: [nonce],
      });
    } catch {
      return null; // stamping itself failed (frames gone); outer finally still unmarks
    }
    const marked = new Set((marks || []).filter((r) => r && r.result).map((r) => r.frameId));
    const boundInChain = chain.filter((fid) => frameSessions.has(`${tabId}:${fid}`));
    // Same-process hops must all be stamped; OOPIF hops use getFrameOwner and
    // tolerate a failed stamp (e.g. exotic origins scripting can't reach).
    const needMarked = chain.filter((fid) => !frameSessions.has(`${tabId}:${fid}`));
    if (!needMarked.every((fid) => marked.has(fid))) return null;
    if (boundInChain.length && boundInChain.some((fid) => !cdpFrameIds.get(`${tabId}:${fid}`))) return null;

    try {
      let curSession = null; // null = the tab's root session
      let docNodeId = null; // document node within curSession, fetched lazily
      let x = 0;
      let y = 0;
      for (const fid of chain) {
        const bound = frameSessions.get(`${tabId}:${fid}`);
        if (bound) {
          // OOPIF hop: the owner <iframe> element lives in the CURRENT
          // session's tree; getFrameOwner is a browser-level frame lookup.
          const cdpFid = bound.cdpFrameId || cdpFrameIds.get(`${tabId}:${fid}`);
          if (!cdpFid) return null;
          const fo = await cdpDomCommandAt(tabId, curSession, "DOM.getFrameOwner", { frameId: cdpFid });
          const bnid = fo && fo.backendNodeId;
          if (bnid === undefined || bnid === null) return null;
          const cq = await cdpDomCommandAt(tabId, curSession, "DOM.getContentQuads", { backendNodeId: bnid });
          const quad = cq && cq.quads && cq.quads[0];
          if (!quad || quad.length < 2) return null;
          x += quad[0];
          y += quad[1];
          curSession = bound.sessionId;
          docNodeId = null; // refetch in the child session if a later hop needs it
          continue;
        }
        // Same-process hop: marker match inside the current session's tree.
        if (docNodeId == null) {
          const doc = await cdpDomCommandAt(tabId, curSession, "DOM.getDocument", { depth: 1 });
          docNodeId = doc.root.nodeId;
        }
        const q = await cdpDomCommandAt(tabId, curSession, "DOM.querySelectorAll", {
          nodeId: docNodeId,
          selector: "iframe, frame",
        });
        let owner = null;
        for (const nid of q.nodeIds || []) {
          const d = await cdpDomCommandAt(tabId, curSession, "DOM.describeNode", { nodeId: nid, depth: 1 });
          const cd = d.node && d.node.contentDocument;
          if (!cd) continue; // OOPIF from this session, or not a frame owner
          const de = (cd.children || [])[0];
          const attrs = (de && de.attributes) || [];
          let stamped = false;
          for (let i = 0; i + 1 < attrs.length; i += 2) {
            if (attrs[i] === "data-claude-frame-mark" && attrs[i + 1] === nonce) stamped = true;
          }
          if (stamped) {
            owner = { nodeId: nid, cdpFrameId: d.node.frameId || null, contentDocNodeId: cd.nodeId };
            break;
          }
        }
        if (!owner) return null;
        if (owner.cdpFrameId) cdpFrameIds.set(`${tabId}:${fid}`, owner.cdpFrameId);
        const cq = await cdpDomCommandAt(tabId, curSession, "DOM.getContentQuads", { nodeId: owner.nodeId });
        const quad = cq && cq.quads && cq.quads[0];
        if (!quad || quad.length < 2) return null;
        x += quad[0];
        y += quad[1];
        docNodeId = owner.contentDocNodeId;
      }
      if (docNodeId == null) {
        // Last hop was an OOPIF: the target document lives in the child session.
        const doc = await cdpDomCommandAt(tabId, curSession, "DOM.getDocument", { depth: 1 });
        docNodeId = doc.root.nodeId;
      }
      return { x, y, docNodeId, sessionId: curSession };
    } catch {
      return null;
    }
  } finally {
    // Every exit after the stamp attempt (early returns included) unmarks.
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: chain },
        func: () => {
          try {
            document.documentElement.removeAttribute("data-claude-frame-mark");
          } catch {}
        },
      });
    } catch {}
  }
}

// numeric webNavigation frameId -> CDP Page.FrameId string, learned by the
// owner walk above. Stage ③ (OOPIF sessionId routing) builds on this.
const cdpFrameIds = new Map(); // `${tabId}:${frameId}` -> cdp frameId string

// --- OOPIF child sessions (Target.setAutoAttach, flatten mode) ---
//
// Cross-origin iframes render in their own process: the tab's root debugger
// session cannot see their DOM (contentDocument is null from the parent) and
// trusted Input for them must be dispatched on THEIR session in FRAME-LOCAL
// viewport coordinates (the child renderer has its own widget). Since
// Chrome 125 chrome.debugger exposes flatten-mode child sessions:
// sendCommand({tabId, sessionId}) targets them and onEvent sources carry
// sessionId. Auto-attach is NOT recursive — every child session gets its own
// Target.setAutoAttach so nested OOPIFs attach transitively.
//
// Binding a child session to a numeric webNavigation frameId is the inverse
// of the marker bridge: scripting.executeScript reaches OOPIFs, so every
// unbound numeric frame gets stamped with a UNIQUE nonce and the mark is read
// back through the child session's Runtime.evaluate — a unique hit locks the
// triple (numeric frameId <-> sessionId <-> CDP frameId string).

const AUTO_ATTACH_PARAMS = { autoAttach: true, waitForDebuggerOnStart: false, flatten: true };
const frameSessions = new Map(); // `${tabId}:${numericFrameId}` -> {sessionId, cdpFrameId}
const sessionFrames = new Map(); // `${tabId}:${sessionId}` -> numeric frameId
const pendingChildSessions = new Map(); // tabId -> [{sessionId, targetInfo}] awaiting bind
const bindLocks = new Map(); // tabId -> tail promise, serializes bind sweeps
const childDomEnabled = new Set(); // `${tabId}:${sessionId}` with DOM.enable confirmed
// Every child session we enabled, including ones whose numeric frameId never
// bound. Fetch/extra-headers must be re-applied to these when rules change.
const tabChildSessions = new Map(); // tabId -> Set<sessionId>

function rememberChildSession(tabId, sessionId) {
  if (!sessionId) return;
  let set = tabChildSessions.get(tabId);
  if (!set) {
    set = new Set();
    tabChildSessions.set(tabId, set);
  }
  set.add(sessionId);
}

function forgetChildSession(tabId, sessionId) {
  const set = tabChildSessions.get(tabId);
  if (set) set.delete(sessionId);
}

function listChildSessions(tabId) {
  return [...(tabChildSessions.get(tabId) || [])];
}

function clearChildSessions(tabId) {
  tabChildSessions.delete(tabId);
}

// Send a CDP command on the root session (sessionId null) or a child session,
// with the same ensureCdp + error wrapping as cdpSend.
async function cdpSendTo(tabId, sessionId, method, params) {
  await ensureCdp(tabId);
  try {
    return await chrome.debugger.sendCommand(sessionId ? { tabId, sessionId } : { tabId }, method, params || {});
  } catch (e) {
    const msg = (e && e.message) || String(e);
    throw new Error(`CDP ${method} failed: ${msg}`);
  }
}

// Raw variant for the bind flow (no ensureCdp recursion, errors surface).
function cdpRawTo(tabId, sessionId, method, params) {
  return chrome.debugger.sendCommand(sessionId ? { tabId, sessionId } : { tabId }, method, params || {});
}

async function enableChildSession(tabId, sessionId) {
  // Nested auto-attach first so OOPIFs inside this one queue up as well.
  try {
    await cdpRawTo(tabId, sessionId, "Target.setAutoAttach", {
      ...AUTO_ATTACH_PARAMS,
      filter: [{ type: "iframe", exclude: false }],
    });
  } catch {
    try {
      await cdpRawTo(tabId, sessionId, "Target.setAutoAttach", AUTO_ATTACH_PARAMS);
    } catch {}
  }
  // Same collectors the root session runs, so console/network/dialog events
  // from this frame feed the tab's buffers (networkIdle must not miss OOPIF
  // requests; dialogs must be answerable on the session that raised them).
  for (const method of ["Runtime.enable", "Network.enable", "Page.enable", "Log.enable"]) {
    try {
      await cdpRawTo(tabId, sessionId, method);
    } catch {}
  }
  rememberChildSession(tabId, sessionId);
  // Rules that already exist must cover this OOPIF too. Await the storage
  // barrier so a child that attaches during startup does not miss rules that
  // are still loading. No patterns → leave Fetch disabled on the child.
  try {
    await mockRulesReady;
    await rewriteRulesReady;
    const patterns = fetchPatternsFor(tabId);
    if (patterns.length) {
      await cdpRawTo(tabId, sessionId, "Fetch.enable", {
        patterns,
        handleAuthRequests: false,
      });
    }
    const extra = mergedExtraHeaders(tabId);
    if (extra) {
      await cdpRawTo(tabId, sessionId, "Network.setExtraHTTPHeaders", { headers: extra });
    }
  } catch {}
}

function queueChildSessionBind(tabId, sessionId, targetInfo) {
  if (sessionFrames.has(`${tabId}:${sessionId}`)) return; // already bound
  let q = pendingChildSessions.get(tabId);
  if (!q) {
    q = [];
    pendingChildSessions.set(tabId, q);
  }
  q.push({ sessionId, targetInfo });
  // Debounce: setAutoAttach emits one event per child in a burst; one sweep
  // binds them all with a single stamping pass. Serialized per tab so two
  // sweeps never race over nonce stamps.
  const prev = bindLocks.get(tabId) || Promise.resolve();
  const next = prev
    .then(() => sleep(120))
    .then(() => bindSweep(tabId))
    .catch(() => {});
  bindLocks.set(tabId, next);
}

async function bindSweep(tabId) {
  const q = pendingChildSessions.get(tabId) || [];
  pendingChildSessions.set(tabId, []);
  const fresh = q.filter((item) => !sessionFrames.has(`${tabId}:${item.sessionId}`));
  if (!fresh.length) return;
  if (!cdpSessions.has(tabId)) return; // detached meanwhile

  // 1) Each child session's own CDP frameId, from its document root.
  const infos = [];
  for (const item of fresh) {
    let cdpFrameId = (item.targetInfo && item.targetInfo.targetId) || null; // usually equal for OOPIFs
    try {
      const doc = await cdpRawTo(tabId, item.sessionId, "DOM.getDocument", { depth: 0 });
      if (doc && doc.root && doc.root.frameId) cdpFrameId = doc.root.frameId;
    } catch {}
    infos.push({ ...item, cdpFrameId });
  }

  // 2) Numeric candidates: every frame of the tab not yet bound.
  let frames = [];
  try {
    frames = (await chrome.webNavigation.getAllFrames({ tabId })) || [];
  } catch {
    return;
  }
  const candidates = frames.filter(
    (f) => f.frameId !== 0 && !frameSessions.has(`${tabId}:${f.frameId}`)
  );

  // 3) Stamp each candidate with a unique nonce (scripting crosses processes).
  const nonces = new Map();
  for (const c of candidates) {
    const n = `cfs${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}f${c.frameId}`;
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [c.frameId] },
        func: (v) => {
          try {
            document.documentElement.setAttribute("data-claude-frame-mark", v);
            return true;
          } catch {
            return false;
          }
        },
        args: [n],
      });
      nonces.set(c.frameId, n);
    } catch {}
  }

  // 4) Read each child session's mark; a unique nonce hit locks the triple.
  for (const info of infos) {
    let numeric = null;
    if (nonces.size) {
      try {
        const r = await cdpRawTo(tabId, info.sessionId, "Runtime.evaluate", {
          expression: "document.documentElement.getAttribute('data-claude-frame-mark')",
          returnByValue: true,
        });
        const v = r && r.result && r.result.value;
        if (v) {
          for (const [fid, n] of nonces) {
            if (n === v) {
              numeric = fid;
              break;
            }
          }
        }
      } catch {}
    }
    if (numeric != null) {
      frameSessions.set(`${tabId}:${numeric}`, { sessionId: info.sessionId, cdpFrameId: info.cdpFrameId });
      sessionFrames.set(`${tabId}:${info.sessionId}`, numeric);
      if (info.cdpFrameId) cdpFrameIds.set(`${tabId}:${numeric}`, info.cdpFrameId);
    }
    // Enable collectors + nested auto-attach even when the numeric bind failed
    // (the session is still usable by sessionId, just not frame-addressable).
    enableChildSession(tabId, info.sessionId).catch(() => {});
  }

  // 5) Best-effort unstamp.
  if (nonces.size) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [...nonces.keys()] },
        func: () => {
          try {
            document.documentElement.removeAttribute("data-claude-frame-mark");
          } catch {}
        },
      });
    } catch {}
  }
}

function unbindChildSession(tabId, sessionId) {
  const key = `${tabId}:${sessionId}`;
  const numeric = sessionFrames.get(key);
  sessionFrames.delete(key);
  childDomEnabled.delete(key);
  forgetChildSession(tabId, sessionId);
  if (numeric != null) {
    frameSessions.delete(`${tabId}:${numeric}`);
    // The CDP frameId learned through this session is stale once it dies.
    cdpFrameIds.delete(`${tabId}:${numeric}`);
  }
}

function clearTabBindings(tabId) {
  const prefix = `${tabId}:`;
  for (const key of [...frameSessions.keys()]) if (key.startsWith(prefix)) frameSessions.delete(key);
  for (const key of [...sessionFrames.keys()]) if (key.startsWith(prefix)) sessionFrames.delete(key);
  for (const key of [...childDomEnabled]) if (key.startsWith(prefix)) childDomEnabled.delete(key);
  pendingChildSessions.delete(tabId);
  bindLocks.delete(tabId);
  clearChildSessions(tabId);
}

// Bound child session for a numeric frameId, or null when the frame is
// same-process (shares the tab's root session) or not (yet) attached as an
// OOPIF. Re-issues auto-attach when unbound so sessions created since the
// last sweep get a chance to bind before we give up.
async function resolveFrameSession(tabId, frameId) {
  if (!frameId) return null;
  const existing = frameSessions.get(`${tabId}:${frameId}`);
  if (existing) return existing;
  if (!cdpSessions.has(tabId)) return null;
  try {
    await cdpRawTo(tabId, null, "Target.setAutoAttach", AUTO_ATTACH_PARAMS);
  } catch {
    return null;
  }
  await sleep(150); // let attachedToTarget events queue up
  try {
    await bindSweep(tabId);
  } catch {}
  return frameSessions.get(`${tabId}:${frameId}`) || null;
}

// Input dispatch point for a geometry result: OOPIF-bound frames take the
// child session with FRAME-LOCAL coordinates; everything else stays on the
// root session with top-viewport coordinates (stage ② contract).
function inputTargetFor(geo) {
  if (geo && geo.frameId && geo.childSessionId && geo.localX != null) {
    return { sessionId: geo.childSessionId, x: geo.localX, y: geo.localY };
  }
  return { sessionId: null, x: geo ? geo.x : 0, y: geo ? geo.y : 0 };
}

async function measureIframeOffsetDom(tabId, childUrl, parentFrameId) {
  const results = await chrome.scripting.executeScript({
    target: frameTarget(tabId, parentFrameId),
    func: (url) => {
      const candidates = Array.from(document.querySelectorAll("iframe, frame"));
      const isBlankish = (u) => !u || u === "about:blank" || u === "about:srcdoc";
      let best = null;
      for (const f of candidates) {
        const src = f.getAttribute("src") || "";
        let resolved = src;
        try { resolved = src ? new URL(src, location.href).href : ""; } catch {}
        if (url && resolved && resolved === url) { best = f; break; }
        if (!best && isBlankish(resolved) && isBlankish(url)) best = f;
      }
      if (!best) return null;
      const r = best.getBoundingClientRect();
      const cs = window.getComputedStyle(best);
      const pl = parseFloat(cs.paddingLeft) || 0;
      const pt = parseFloat(cs.paddingTop) || 0;
      // Border-box rect + border (clientLeft/Top) + padding = content-box
      // origin, where the child frame's viewport begins.
      return { x: r.x + best.clientLeft + pl, y: r.y + best.clientTop + pt };
    },
    args: [childUrl || ""],
  });
  return (results[0] && results[0].result) || null;
}

// Ordered ancestor chain (outermost child-of-top first) for a frame, from
// webNavigation's frame tree. Throws FRAME_NOT_FOUND for stale frameIds.
async function frameChainFor(tabId, frameId) {
  const frames = await chrome.webNavigation.getAllFrames({ tabId });
  if (!frames) throw new Error(`FRAME_OFFSET_FAILED: cannot enumerate frames of tab ${tabId}`);
  const byId = new Map(frames.map((f) => [f.frameId, f]));
  const chain = [];
  let cur = frameId;
  const seen = new Set([0]);
  while (cur && cur !== 0) {
    if (seen.has(cur)) throw new Error(`FRAME_OFFSET_FAILED: frame cycle at frameId ${cur}`);
    seen.add(cur);
    const info = byId.get(cur);
    if (!info) {
      throw new Error(
        `FRAME_NOT_FOUND: frameId ${cur} is gone (the frame navigated away or was removed); re-run get_page_structure`
      );
    }
    chain.unshift(cur);
    cur = info.parentFrameId >= 0 ? info.parentFrameId : 0;
  }
  return { chain, byId };
}

// Offset of frameId's viewport origin in top-level viewport coordinates.
// Call AFTER any scrollIntoView in the target frame — scrolling can move
// ancestor frames and invalidate measurements taken before it.
async function frameOffsetChain(tabId, frameId) {
  if (!frameId) return { x: 0, y: 0 };
  const { chain, byId } = await frameChainFor(tabId, frameId);
  if (!chain.length) return { x: 0, y: 0 };

  if (cdpSessions.has(tabId)) {
    const off = await frameOffsetChainCdp(tabId, chain);
    if (off) return off;
  }

  let x = 0;
  let y = 0;
  for (const fid of chain) {
    const info = byId.get(fid);
    const parent = info.parentFrameId >= 0 ? info.parentFrameId : 0;
    const off = await measureIframeOffsetDom(tabId, info.url, parent);
    if (!off) {
      throw new Error(
        `FRAME_OFFSET_FAILED: could not locate the <iframe> hosting frameId ${fid} inside parent frame ${parent}`
      );
    }
    x += off.x;
    y += off.y;
  }
  return { x, y };
}

// {sessionId, docNodeId} of a frame's root document for DOM.querySelector /
// setFileInputFiles inside it. OOPIFs resolve straight through their bound
// child session; same-process frames through the stamped owner walk (the
// walk is session-aware, so mixed chains work too). Null when the debugger
// is detached or neither path completes.
async function cdpFrameDocTarget(tabId, frameId) {
  if (!frameId || !cdpSessions.has(tabId)) return null;
  const bound = await resolveFrameSession(tabId, frameId);
  if (bound) {
    try {
      const doc = await cdpDomCommandAt(tabId, bound.sessionId, "DOM.getDocument", { depth: 1 });
      return { sessionId: bound.sessionId, docNodeId: doc.root.nodeId };
    } catch {
      return null;
    }
  }
  const { chain } = await frameChainFor(tabId, frameId);
  if (!chain.length) return null;
  const res = await frameOffsetChainCdp(tabId, chain);
  return res ? { sessionId: res.sessionId || null, docNodeId: res.docNodeId } : null;
}

// --- Element geometry for CDP input tools ---

// Resolve ref/selector/coordinates to viewport geometry via the page.
// CDP input tools dispatch at viewport CSS-pixel coordinates.
// Frame-aware: a ref routes to its frame, params.frameId targets a selector
// inside a frame. Returned x/y/rect are in TOP-LEVEL viewport space (frame
// offsets accumulated after the in-frame scrollIntoView), and scroll/
// viewport/dpr describe the top frame, so Input.dispatchMouseEvent and
// screenshot clips can consume them unchanged.
async function getElementGeometry(tabId, params) {
  await ensureContentScripts(tabId);
  const routed = routeRef(tabId, params.ref);
  const frameId = routed ? routed.frameId : params.frameId || 0;
  const results = await chrome.scripting.executeScript({
    target: frameTarget(tabId, frameId),
    func: (refId, sel, coords, wantScroll) => {
      const viewport = { w: window.innerWidth, h: window.innerHeight };
      if (coords) {
        return { fromCoordinates: true, x: coords.x, y: coords.y, viewport };
      }
      let el;
      if (refId) {
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) el = a11y.getElementByRef(refId);
        if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
      } else if (sel) {
        el = document.querySelector(sel);
        if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
      } else {
        el = document.activeElement || document.body;
      }
      if (wantScroll) el.scrollIntoView({ block: "center", inline: "center", behavior: "instant" });
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        return { error: `ELEMENT_NOT_VISIBLE: ${el.tagName.toLowerCase()} has zero size` };
      }
      const out = {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
        rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        tagName: el.tagName.toLowerCase(),
        text: (el.textContent || "").trim().slice(0, 100),
        viewport,
        dpr: window.devicePixelRatio || 1,
        scroll: { x: window.scrollX, y: window.scrollY },
        disabled: !!el.disabled,
        isEditable: !!el.isContentEditable,
        inputType: el.type || null,
      };
      const a11y = globalThis.__claudeA11yTree;
      if (a11y) {
        const r = a11y.getRefForElement(el);
        if (r) out.ref = r;
      }
      return out;
    },
    args: [
      routed ? routed.localRef : null,
      params.selector || null,
      params.coordinates || null,
      params.scrollIntoView !== false,
    ],
  });
  const r = results[0] && results[0].result;
  if (!r) throw new Error("ELEMENT_NOT_FOUND: page did not respond");
  if (r.error) {
    if (r.error.startsWith("REF_NOT_FOUND") && params.ref) {
      throw new Error(
        `REF_NOT_FOUND: ${params.ref} — the element is no longer registered (page changed or the snapshot is stale); re-run get_page_structure`
      );
    }
    throw new Error(r.error);
  }
  if (r.ref) r.ref = unrouteRef(tabId, frameId, r.ref);
  r.frameId = frameId;
  // Coordinates arrive in top-viewport space already; frame-local rects need
  // the offset chain — measured now, after the in-frame scrollIntoView above
  // (which may have scrolled ancestor frames too).
  if (frameId && !r.fromCoordinates) {
    // Frame-local originals: an OOPIF's child session lives in the frame's
    // OWN viewport space, so trusted input for it consumes these directly
    // and needs no offset chain at all.
    r.localX = r.x;
    r.localY = r.y;
    r.localRect = { ...r.rect };
    r.localScroll = { ...r.scroll };
    const child = await resolveFrameSession(tabId, frameId);
    r.childSessionId = child ? child.sessionId : null;
    if (child) {
      // OOPIF: top-space offsets are only wanted by clip consumers
      // (screenshots) — nice to have, not fatal when unresolvable.
      try {
        const off = await frameOffsetChain(tabId, frameId);
        r.frameOffset = off;
        r.x += off.x;
        r.y += off.y;
        r.rect.x += off.x;
        r.rect.y += off.y;
      } catch {
        r.offsetUnresolved = true;
      }
    } else {
      const off = await frameOffsetChain(tabId, frameId);
      r.frameOffset = off;
      r.x += off.x;
      r.y += off.y;
      r.rect.x += off.x;
      r.rect.y += off.y;
    }
    // scroll/viewport/dpr must describe the TOP frame for clip consumers
    // (captureBeyondViewport clips are root-document space = rect + root scroll).
    const top = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({
        scrollX: window.scrollX,
        scrollY: window.scrollY,
        w: window.innerWidth,
        h: window.innerHeight,
        dpr: window.devicePixelRatio || 1,
      }),
    });
    const t = top[0] && top[0].result;
    if (t) {
      r.scroll = { x: t.scrollX, y: t.scrollY };
      r.viewport = { w: t.w, h: t.h };
      r.dpr = t.dpr;
    }
  }
  return r;
}

async function focusElement(tabId, params) {
  await ensureContentScripts(tabId);
  const routed = routeRef(tabId, params.ref);
  const frameId = routed ? routed.frameId : params.frameId || 0;
  const results = await chrome.scripting.executeScript({
    target: frameTarget(tabId, frameId),
    func: (refId, sel) => {
      let el;
      if (refId) {
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) el = a11y.getElementByRef(refId);
      } else if (sel) {
        el = document.querySelector(sel);
      } else {
        el = document.activeElement;
      }
      if (!el) return { error: refId ? `REF_NOT_FOUND: ${refId}` : `ELEMENT_NOT_FOUND: ${sel}` };
      el.focus({ preventScroll: true });
      return { ok: true };
    },
    args: [routed ? routed.localRef : null, params.selector || null],
  });
  const r = results[0] && results[0].result;
  if (r && r.error) {
    if (r.error.startsWith("REF_NOT_FOUND") && params.ref) {
      throw new Error(
        `REF_NOT_FOUND: ${params.ref} — the element is no longer registered (page changed or the snapshot is stale); re-run get_page_structure`
      );
    }
    throw new Error(r.error);
  }
}

async function selectAllInElement(tabId, params) {
  const routed = routeRef(tabId, params.ref);
  const frameId = routed ? routed.frameId : params.frameId || 0;
  await chrome.scripting.executeScript({
    target: frameTarget(tabId, frameId),
    func: (refId, sel) => {
      let el;
      if (refId) {
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) el = a11y.getElementByRef(refId);
      } else if (sel) {
        el = document.querySelector(sel);
      } else {
        el = document.activeElement;
      }
      if (!el) return;
      if (el.setSelectionRange) {
        try {
          el.setSelectionRange(0, (el.value || "").length);
          return;
        } catch {}
      }
      document.execCommand("selectAll", false, null);
    },
    args: [routed ? routed.localRef : null, params.selector || null],
  });
}

// --- CDP keyboard mapping ---

const MOD_BITS = { alt: 1, ctrl: 2, meta: 4, shift: 8 };

const NAMED_KEYS = {
  Enter: { vk: 13, code: "Enter" },
  Escape: { vk: 27, code: "Escape" },
  Tab: { vk: 9, code: "Tab" },
  Backspace: { vk: 8, code: "Backspace" },
  Delete: { vk: 46, code: "Delete" },
  Insert: { vk: 45, code: "Insert" },
  Space: { vk: 32, code: "Space" },
  " ": { vk: 32, code: "Space" },
  ArrowUp: { vk: 38, code: "ArrowUp" },
  ArrowDown: { vk: 40, code: "ArrowDown" },
  ArrowLeft: { vk: 37, code: "ArrowLeft" },
  ArrowRight: { vk: 39, code: "ArrowRight" },
  Home: { vk: 36, code: "Home" },
  End: { vk: 35, code: "End" },
  PageUp: { vk: 33, code: "PageUp" },
  PageDown: { vk: 34, code: "PageDown" },
  CapsLock: { vk: 20, code: "CapsLock" },
};
for (let i = 1; i <= 12; i++) NAMED_KEYS[`F${i}`] = { vk: 111 + i, code: `F${i}` };

const PUNCT_KEYS = {
  ";": { vk: 186, code: "Semicolon" }, ":": { vk: 186, code: "Semicolon" },
  "=": { vk: 187, code: "Equal" }, "+": { vk: 187, code: "Equal" },
  ",": { vk: 188, code: "Comma" }, "<": { vk: 188, code: "Comma" },
  "-": { vk: 189, code: "Minus" }, "_": { vk: 189, code: "Minus" },
  ".": { vk: 190, code: "Period" }, ">": { vk: 190, code: "Period" },
  "/": { vk: 191, code: "Slash" }, "?": { vk: 191, code: "Slash" },
  "`": { vk: 192, code: "Backquote" }, "~": { vk: 192, code: "Backquote" },
  "[": { vk: 219, code: "BracketLeft" }, "{": { vk: 219, code: "BracketLeft" },
  "\\": { vk: 220, code: "Backslash" }, "|": { vk: 220, code: "Backslash" },
  "]": { vk: 221, code: "BracketRight" }, "}": { vk: 221, code: "BracketRight" },
  "'": { vk: 222, code: "Quote" }, '"': { vk: 222, code: "Quote" },
};

function keyDefFor(k) {
  if (NAMED_KEYS[k]) return { ...NAMED_KEYS[k], key: k === " " ? "Space" : k };
  if (k.length === 1) {
    const upper = k.toUpperCase();
    const c = upper.charCodeAt(0);
    if (c >= 65 && c <= 90) return { vk: c, code: `Key${upper}`, key: k };
    if (c >= 48 && c <= 57) return { vk: c, code: `Digit${k}`, key: k };
    if (PUNCT_KEYS[k]) return { ...PUNCT_KEYS[k], key: k };
    // Non-ASCII: rely on the text payload, vk is irrelevant.
    return { vk: 0, code: "", key: k };
  }
  return { vk: 0, code: "", key: k };
}

function parseKeyCombo(keyStr) {
  const parts = String(keyStr).split("+");
  const mods = { ctrl: false, shift: false, alt: false, meta: false };
  let main = "";
  for (const p of parts) {
    const lower = p.toLowerCase();
    if (lower === "control" || lower === "ctrl") mods.ctrl = true;
    else if (lower === "shift") mods.shift = true;
    else if (lower === "alt" || lower === "option") mods.alt = true;
    else if (lower === "meta" || lower === "command" || lower === "cmd") mods.meta = true;
    else main = p;
  }
  if (!main) main = parts.length === 1 ? parts[0] : "+";
  let bits = 0;
  if (mods.alt) bits |= MOD_BITS.alt;
  if (mods.ctrl) bits |= MOD_BITS.ctrl;
  if (mods.meta) bits |= MOD_BITS.meta;
  if (mods.shift) bits |= MOD_BITS.shift;
  return { mods, main, bits };
}

const MOD_KEYS = [
  { name: "ctrl", key: "Control", code: "ControlLeft", vk: 17, bit: MOD_BITS.ctrl },
  { name: "alt", key: "Alt", code: "AltLeft", vk: 18, bit: MOD_BITS.alt },
  { name: "shift", key: "Shift", code: "ShiftLeft", vk: 16, bit: MOD_BITS.shift },
  { name: "meta", key: "Meta", code: "MetaLeft", vk: 91, bit: MOD_BITS.meta },
];

// Dispatch one trusted key or combination, e.g. "a", "Enter", "Control+Shift+k".
async function cdpPressKeyCombo(tabId, keyStr) {
  const { mods, main } = parseKeyCombo(keyStr);
  const pressed = [];
  let activeBits = 0;
  for (const m of MOD_KEYS) {
    if (!mods[m.name]) continue;
    await cdpSend(tabId, "Input.dispatchKeyEvent", {
      type: "rawKeyDown",
      key: m.key,
      code: m.code,
      windowsVirtualKeyCode: m.vk,
      nativeVirtualKeyCode: m.vk,
      modifiers: activeBits,
    });
    activeBits |= m.bit;
    pressed.unshift(m);
  }

  const def = keyDefFor(main);
  const printable = main.length === 1 && !mods.ctrl && !mods.alt && !mods.meta;
  const base = {
    key: def.key || main,
    code: def.code,
    windowsVirtualKeyCode: def.vk,
    nativeVirtualKeyCode: def.vk,
    modifiers: activeBits,
  };
  if (printable) {
    if (main.codePointAt(0) > 126) {
      // Non-ASCII (CJK, emoji, ...): insertText is the reliable route.
      await cdpSend(tabId, "Input.insertText", { text: main });
    } else {
      await cdpSend(tabId, "Input.dispatchKeyEvent", { type: "keyDown", ...base, text: main, unmodifiedText: main });
      await cdpSend(tabId, "Input.dispatchKeyEvent", { type: "keyUp", ...base });
    }
  } else {
    await cdpSend(tabId, "Input.dispatchKeyEvent", { type: "rawKeyDown", ...base });
    await cdpSend(tabId, "Input.dispatchKeyEvent", { type: "keyUp", ...base });
  }

  for (const m of pressed) {
    activeBits &= ~m.bit;
    await cdpSend(tabId, "Input.dispatchKeyEvent", {
      type: "keyUp",
      key: m.key,
      code: m.code,
      windowsVirtualKeyCode: m.vk,
      nativeVirtualKeyCode: m.vk,
      modifiers: activeBits,
    });
  }
}

const MOUSE_BUTTONS = {
  left: { button: "left", buttons: 1 },
  right: { button: "right", buttons: 2 },
  middle: { button: "middle", buttons: 4 },
};

// Ensure content scripts are available in a tab
async function ensureContentScripts(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => !!globalThis.__claudeA11yTree,
    });
    if (results[0]?.result) return; // Already injected (manifest all_frames:true covers subframes)
  } catch {
    // Can't check, try injecting anyway
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["content-scripts/accessibility-tree.js"],
    });
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["content-scripts/visual-indicator.js"],
    });
  } catch {
    // Some pages don't allow script injection (chrome://, etc.)
  }
}

// --- Session / HAR / emulation helpers ---

function publicCookie(c) {
  const out = {
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    sameSite: c.sameSite,
  };
  if (c.expirationDate != null) out.expirationDate = c.expirationDate;
  if (c.hostOnly != null) out.hostOnly = c.hostOnly;
  if (c.session != null) out.session = c.session;
  if (c.storeId) out.storeId = c.storeId;
  if (c.partitionKey) out.partitionKey = c.partitionKey;
  return out;
}

function cookieToUrl(c) {
  if (c && c.url) return String(c.url);
  const host = String((c && c.domain) || "").replace(/^\./, "");
  if (!host) throw new Error("cookie is missing url and domain");
  const proto = c.secure ? "https:" : "http:";
  const path = c.path && String(c.path).startsWith("/") ? c.path : "/";
  return `${proto}//${host}${path}`;
}

async function tabHttpOrigin(tabId) {
  const tab = await chrome.tabs.get(tabId);
  let u;
  try {
    u = new URL(tab.url || "");
  } catch {
    throw new Error(`TAB_URL_INVALID: tab ${tabId} has no usable URL (${tab.url || "empty"})`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`TAB_URL_INVALID: this tool needs an http(s) page, got ${tab.url}`);
  }
  return { url: tab.url, origin: u.origin, title: tab.title || "" };
}

function capSessionExport(payload) {
  const limit = EXPORT_BYTE_BUDGET;
  const size = () => {
    try {
      return JSON.stringify(payload).length;
    } catch {
      return Infinity;
    }
  };
  if (size() <= limit) return payload;
  payload.truncated = true;
  const idb = payload.indexedDB && payload.indexedDB.databases;
  if (idb) {
    while (idb.length && size() > limit) idb.pop();
    payload.indexedDB.truncated = true;
    if (size() > limit) {
      delete payload.indexedDB;
      payload.indexedDBOmitted = true;
    }
  }
  for (const bagName of ["localStorage", "sessionStorage"]) {
    const bag = payload[bagName];
    if (!bag || typeof bag !== "object") continue;
    for (const k of Object.keys(bag)) {
      if (size() <= limit) return payload;
      const v = bag[k];
      if (typeof v === "string" && v.length > 64) bag[k] = v.slice(0, 64);
    }
  }
  for (const bagName of ["sessionStorage", "localStorage"]) {
    const bag = payload[bagName];
    if (!bag) continue;
    const keys = Object.keys(bag);
    while (keys.length && size() > limit) delete bag[keys.pop()];
  }
  if (Array.isArray(payload.cookies)) {
    while (payload.cookies.length && size() > limit) payload.cookies.pop();
  }
  return payload;
}

async function emulateOnSessions(tabId, method, params) {
  const targets = [null, ...listChildSessions(tabId)];
  const errors = [];
  let ok = 0;
  for (const sid of targets) {
    try {
      await cdpSendTo(tabId, sid, method, params || {});
      ok++;
    } catch (e) {
      errors.push((e && e.message) || String(e));
    }
  }
  if (!ok) throw new Error(errors[0] || `${method} failed`);
  return { sessions: ok, ...(errors.length ? { sessionErrors: errors } : {}) };
}

function shiftQuad(quad, dx, dy) {
  if (!Array.isArray(quad)) return quad;
  const out = quad.slice();
  for (let i = 0; i + 1 < out.length; i += 2) {
    out[i] += dx;
    out[i + 1] += dy;
  }
  return out;
}

async function frameRectOffset(tabId, frameId) {
  if (!frameId) return { x: 0, y: 0 };
  try {
    return await frameOffsetChain(tabId, frameId);
  } catch {
    return null;
  }
}

function harHeaders(h) {
  if (!h) return [];
  if (Array.isArray(h)) {
    return h
      .filter((x) => x && x.name)
      .map((x) => ({ name: String(x.name), value: String(x.value ?? "") }));
  }
  return Object.entries(h).map(([name, value]) => ({ name, value: String(value) }));
}

function harQuery(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function harHttpVersion(protocol) {
  if (!protocol) return "HTTP/1.1";
  const p = String(protocol).toLowerCase();
  if (p === "h2") return "HTTP/2";
  if (p === "h3") return "HTTP/3";
  if (p.startsWith("http/")) return String(protocol).toUpperCase();
  return String(protocol);
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return "";
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return String(v);
  }
  return "";
}

const NETWORK_CONDITION_PRESETS = {
  online: { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 },
  offline: { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 },
  // Chromium DevTools presets: throughput is bytes/s.
  slow3g: {
    offline: false,
    latency: 400,
    downloadThroughput: Math.round((500 * 1024) / 8),
    uploadThroughput: Math.round((500 * 1024) / 8),
    connectionType: "cellular3g",
  },
  fast3g: {
    offline: false,
    latency: 150,
    downloadThroughput: Math.round((1.6 * 1024 * 1024) / 8),
    uploadThroughput: Math.round((750 * 1024) / 8),
    connectionType: "cellular3g",
  },
};

const DEFAULT_AUTHENTICATOR = {
  protocol: "ctap2",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};

const WEBAUTHN_DETACH_NOTE =
  "Virtual authenticator ids live on this tab's debugger session. They stop working after cdp_detach, closing the tab, dismissing the debugging infobar, or a service-worker restart (tracked ids are forgotten even if Chrome keeps the attachment).";

function webauthnState(session) {
  if (!session.webauthn) session.webauthn = { enabled: false, authenticators: [] };
  return session.webauthn;
}

// --- Command handlers ---

const handlers = {

  // === Tab management ===

  async listTabs() {
    // Popup lineage tracking: openerTabId is natively carried on
    // chrome.tabs.Tab for tabs opened from another tab (window.open /
    // target=_blank). Combined with each window's type/focus state, an agent
    // can diff two listings around a click to find the new tab AND its
    // source — no event listeners needed. Tabs whose lineage Chrome does not
    // expose (manual new tabs, some session-restore paths) simply omit the
    // field rather than getting a reconstructed guess.
    const [tabs, wins] = await Promise.all([
      chrome.tabs.query({}),
      chrome.windows.getAll({ populate: false }).catch(() => []),
    ]);
    const winById = new Map((wins || []).map((w) => [w.id, w]));
    return {
      tabs: tabs
        .filter((t) => {
          const url = t.url || "";
          return (
            !url.startsWith("chrome://") &&
            !url.startsWith("chrome-extension://") &&
            !url.startsWith("about:") &&
            !url.startsWith("devtools://")
          );
        })
        .map((t) => {
          const w = winById.get(t.windowId);
          return {
            id: t.id,
            url: t.url,
            title: t.title,
            active: t.active,
            windowId: t.windowId,
            index: t.index,
            ...(t.openerTabId != null ? { openerTabId: t.openerTabId } : {}),
            ...(w ? { windowType: w.type, windowFocused: !!w.focused } : {}),
          };
        }),
    };
  },

  async createTab(params) {
    let url = (params && params.url) || "about:blank";
    if (url !== "about:blank" && !/^https?:\/\//i.test(url)) {
      url = `https://${url}`;
    }
    const active = params && params.active !== undefined ? params.active : true;
    const createOpts = { url, active };
    // Explicit window target; omitted = Chrome's "current" window (the one
    // holding OS focus). active:true selects the tab within its window but
    // does NOT raise that window to the OS foreground.
    if (params && params.windowId !== undefined) createOpts.windowId = Number(params.windowId);
    const tab = await chrome.tabs.create(createOpts);
    return {
      id: tab.id,
      url: tab.url || url,
      title: tab.title || "",
      active: tab.active,
      windowId: tab.windowId,
    };
  },

  async navigateTab(params) {
    const { tabId } = params;
    const action = params.action || "url";

    if (action === "back") {
      await chrome.tabs.goBack(tabId);
      await new Promise((r) => setTimeout(r, 100));
      const tab = await chrome.tabs.get(tabId);
      return { id: tab.id, url: tab.url, title: tab.title };
    }

    if (action === "forward") {
      await chrome.tabs.goForward(tabId);
      await new Promise((r) => setTimeout(r, 100));
      const tab = await chrome.tabs.get(tabId);
      return { id: tab.id, url: tab.url, title: tab.title };
    }

    if (action === "reload") {
      await chrome.tabs.reload(tabId);
      await new Promise((r) => setTimeout(r, 100));
      const tab = await chrome.tabs.get(tabId);
      return { id: tab.id, url: tab.url, title: tab.title };
    }

    // action === "url"
    let targetUrl = params.url;
    if (!targetUrl) throw new Error("url is required when action is 'url'");
    if (!/^https?:\/\//i.test(targetUrl) && targetUrl !== "about:blank") {
      targetUrl = `https://${targetUrl}`;
    }
    const tab = await chrome.tabs.update(tabId, { url: targetUrl });
    return { id: tab.id, url: tab.url || targetUrl, title: tab.title || "" };
  },

  async closeTab(params) {
    await chrome.tabs.remove(params.tabId);
    return { success: true };
  },

  // === Window management ===

  // Create a browser window. type "popup" gives the chromeless popup window
  // (classic window.open look); "normal" a regular one. Note the side effect:
  // unless focused:false, the new window draws OS focus immediately.
  async createWindow(params) {
    const opts = {};
    if (params && params.url) {
      let url = String(params.url);
      if (url !== "about:blank" && !/^https?:\/\//i.test(url)) url = `https://${url}`;
      opts.url = url;
    }
    if (params && params.type) opts.type = String(params.type);
    if (params && params.focused !== undefined) opts.focused = !!params.focused;
    if (params) {
      for (const k of ["left", "top", "width", "height"]) {
        if (params[k] !== undefined) opts[k] = Number(params[k]);
      }
    }
    const win = await chrome.windows.create(opts);
    // Report the initial tab so follow-up tools can target it directly.
    let tabs = win && win.tabs;
    if (!tabs) {
      try {
        tabs = await chrome.tabs.query({ windowId: win.id });
      } catch {
        tabs = [];
      }
    }
    tabs = tabs || [];
    const t0 = tabs[0];
    return {
      windowId: win.id,
      type: win.type,
      focused: !!win.focused,
      state: win.state,
      tabCount: tabs.length,
      ...(t0
        ? { tab: { id: t0.id, url: t0.url || opts.url || "", title: t0.title || "", active: !!t0.active } }
        : {}),
    };
  },

  async focusWindow(params) {
    if (!params || params.windowId === undefined) {
      throw new Error("focus_window requires windowId (from list_windows)");
    }
    const windowId = Number(params.windowId);
    const win = await chrome.windows.update(windowId, { focused: true });
    return { windowId: win.id, focused: true, type: win.type, state: win.state };
  },

  async closeWindow(params) {
    if (!params || params.windowId === undefined) {
      throw new Error("close_window requires windowId (from list_windows)");
    }
    const windowId = Number(params.windowId);
    // Inspect BEFORE the drop: the agent needs to know how much content this
    // closes, and a window we cannot read (bad id) must never be blindly
    // removed — fail honestly without touching anything. Per-tab debugger
    // state cleans itself up via the existing tabs.onRemoved listener.
    let win;
    try {
      win = await chrome.windows.get(windowId, { populate: true });
    } catch (e) {
      throw new Error(
        `close_window failed: cannot read window ${windowId} before closing it (bad windowId?): ${e.message}`
      );
    }
    let tabs = win && win.tabs;
    if (!tabs) {
      try {
        tabs = await chrome.tabs.query({ windowId });
      } catch {
        tabs = [];
      }
    }
    tabs = tabs || [];
    await chrome.windows.remove(windowId);
    return {
      windowId,
      closed: true,
      type: win.type,
      tabCount: tabs.length,
      closedTabIds: tabs.map((t) => t.id),
    };
  },

  async listWindows() {
    const [wins, tabs] = await Promise.all([
      chrome.windows.getAll({ populate: false }),
      chrome.tabs.query({}).catch(() => []),
    ]);
    const counts = new Map();
    for (const t of tabs) counts.set(t.windowId, (counts.get(t.windowId) || 0) + 1);
    return {
      windows: (wins || []).map((w) => ({
        windowId: w.id,
        type: w.type,
        focused: !!w.focused,
        state: w.state,
        tabCount: counts.get(w.id) || 0,
      })),
    };
  },

  async groupTabs(params) {
    const { tabIds } = params;
    const action = params.action || "group";

    if (action === "ungroup") {
      await chrome.tabs.ungroup(tabIds);
      return { ungrouped: true, tabIds };
    }

    // Group
    const groupOptions = { tabIds };
    if (params.groupId) groupOptions.groupId = params.groupId;
    const groupId = await chrome.tabs.group(groupOptions);

    const updateProps = {};
    if (params.title !== undefined) updateProps.title = params.title;
    if (params.color !== undefined) updateProps.color = params.color;
    if (params.collapsed !== undefined) updateProps.collapsed = params.collapsed;

    if (Object.keys(updateProps).length > 0) {
      await chrome.tabGroups.update(groupId, updateProps);
    }

    const group = await chrome.tabGroups.get(groupId);
    return {
      groupId: group.id,
      title: group.title,
      color: group.color,
      collapsed: group.collapsed,
      tabIds,
    };
  },

  // === Page content ===

  async getPageContent(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const fullPage = params.fullPage || false;

    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: (full) => {
        if (full) {
          return { content: document.body.innerText, source: "body" };
        }
        // Content-priority extraction
        const selectors = ["article", "main", '[role="main"]', ".content, .post, .entry, #content"];
        for (const sel of selectors) {
          const el = document.querySelector(sel);
          if (el && el.innerText.trim().length > 100) {
            // Clone and remove noise elements
            const clone = el.cloneNode(true);
            const removeSelectors = [
              "script", "style", "nav", "footer", "aside", "header",
              '[role="banner"]', '[role="navigation"]', '[role="contentinfo"]',
              '[aria-hidden="true"]'
            ];
            for (const rs of removeSelectors) {
              clone.querySelectorAll(rs).forEach(n => n.remove());
            }
            return { content: clone.innerText, source: sel };
          }
        }
        return { content: document.body.innerText, source: "body" };
      },
      args: [fullPage],
    });
    return results[0]?.result || { content: "", source: "body" };
  },

  async getPageStructure(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const maxDepth = (params && params.maxDepth) || 15;
    const root = params.root || null;

    await ensureContentScripts(tabId);

    // Every frame generates its own local tree; InjectionResults carry frameId.
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: (depth, rootSel) => {
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) {
          return a11y.generate({ maxDepth: depth, root: rootSel });
        }
        return { structure: null, refCount: 0, error: "Accessibility tree not loaded" };
      },
      args: [maxDepth, root],
    });

    // Frame hierarchy (parentFrameId + current URL) for grafting subtrees.
    let frameInfos = [];
    try {
      frameInfos = (await chrome.webNavigation.getAllFrames({ tabId })) || [];
    } catch {}
    const infoByFrame = new Map(frameInfos.map((f) => [f.frameId, f]));

    // Fresh snapshot: rebuild the global ref registry. Top frame registers
    // first, so its refs keep the familiar ref_1..N numbering.
    refRegistry(tabId, { reset: true });

    const treeByFrame = new Map();
    for (const fr of results || []) {
      if (!fr || fr.result === undefined || fr.result === null) continue;
      treeByFrame.set(fr.frameId, fr.result);
    }

    const topRes = treeByFrame.get(0) || { structure: null, refCount: 0 };
    rewriteTreeRefs(tabId, 0, topRes.structure);

    const childrenOf = new Map();
    for (const f of frameInfos) {
      if (f.frameId === 0) continue;
      if (!childrenOf.has(f.parentFrameId)) childrenOf.set(f.parentFrameId, []);
      childrenOf.get(f.parentFrameId).push(f.frameId);
    }

    const framesOut = [];
    const graft = (parentFrameId, parentTree) => {
      for (const fid of childrenOf.get(parentFrameId) || []) {
        const info = infoByFrame.get(fid) || {};
        const res = treeByFrame.get(fid);
        const childTree = res && res.structure ? res.structure : null;
        rewriteTreeRefs(tabId, fid, childTree);
        const slot = findIframeSlot(parentTree, info.url);
        if (slot && childTree) {
          slot.frameId = fid;
          if (info.url) slot.url = info.url;
          slot.children = [childTree];
          framesOut.push({ frameId: fid, parentFrameId, url: info.url || null, embedded: true });
        } else {
          framesOut.push({
            frameId: fid,
            parentFrameId,
            url: info.url || null,
            embedded: false,
            ...(childTree ? { structure: childTree } : {}),
            ...(res && !res.structure && res.error ? { note: res.error } : {}),
          });
        }
        graft(fid, childTree);
      }
    };
    graft(0, topRes.structure);

    // Frames that answered executeScript but are missing from webNavigation
    // (frame committed/removed mid-call): surface them instead of dropping.
    for (const [fid, res] of treeByFrame) {
      if (fid === 0 || infoByFrame.has(fid)) continue;
      rewriteTreeRefs(tabId, fid, res.structure);
      framesOut.push({
        frameId: fid,
        parentFrameId: null,
        url: null,
        embedded: false,
        ...(res.structure ? { structure: res.structure } : {}),
      });
    }

    return {
      structure: topRes.structure,
      refCount: refRegistry(tabId).byGlobal.size,
      frameCount: treeByFrame.size,
      ...(framesOut.length ? { frames: framesOut } : {}),
    };
  },

  async findElements(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { query, selector, role } = params;
    const maxResults = params.maxResults || 20;

    await ensureContentScripts(tabId);

    // Search every frame; results carry frameId and frame-local refs.
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: async (q, sel, roleFilter, max) => {
        const a11y = globalThis.__claudeA11yTree;
        const found = [];
        const foundElements = [];

        function inOpenShadow(el) {
          const root = el.getRootNode && el.getRootNode();
          return !!(window.ShadowRoot && root instanceof ShadowRoot);
        }

        function queryAllDeep(selector) {
          const out = [];
          const seen = new Set();
          const visit = (root) => {
            const list = root.querySelectorAll(selector);
            list.forEach((el) => {
              if (seen.has(el)) return;
              seen.add(el);
              out.push(el);
            });
            root.querySelectorAll("*").forEach((el) => {
              if (el.shadowRoot) visit(el.shadowRoot);
            });
          };
          visit(document);
          return out;
        }

        function buildSelector(el) {
          // document.querySelector cannot cross an open shadow boundary.
          // Omit the selector and keep the ref.
          if (inOpenShadow(el)) return null;
          if (el.id) return `#${CSS.escape(el.id)}`;
          const testId = el.getAttribute("data-testid");
          if (testId) return `[data-testid="${CSS.escape(testId)}"]`;
          const ariaLabel = el.getAttribute("aria-label");
          if (ariaLabel) {
            const tag = el.tagName.toLowerCase();
            const matches = document.querySelectorAll(`${tag}[aria-label="${CSS.escape(ariaLabel)}"]`);
            if (matches.length === 1) return `${tag}[aria-label="${CSS.escape(ariaLabel)}"]`;
          }
          const tag = el.tagName.toLowerCase();
          if (el.className && typeof el.className === "string") {
            const cls = el.className.trim().split(/\s+/)[0];
            if (cls) {
              const matches = document.querySelectorAll(`${tag}.${CSS.escape(cls)}`);
              if (matches.length === 1) return `${tag}.${CSS.escape(cls)}`;
            }
          }
          const parent = el.parentElement;
          if (!parent) return tag;
          const siblings = Array.from(parent.children).filter((c) => c.tagName === el.tagName);
          if (siblings.length === 1) return `${buildSelector(parent)} > ${tag}`;
          const idx = siblings.indexOf(el) + 1;
          return `${buildSelector(parent)} > ${tag}:nth-of-type(${idx})`;
        }

        function getRole(el) {
          const explicit = el.getAttribute("role");
          if (explicit) return explicit;
          const tag = el.tagName.toLowerCase();
          const roleMap = {
            a: "link", button: "button", input: "textbox", select: "combobox",
            textarea: "textbox", nav: "navigation", main: "main",
            h1: "heading", h2: "heading", h3: "heading", h4: "heading", h5: "heading", h6: "heading",
          };
          return roleMap[tag] || null;
        }

        function isVisibleEl(el) {
          const rect = el.getBoundingClientRect();
          if (rect.width === 0 && rect.height === 0) return false;
          const style = window.getComputedStyle(el);
          return style.display !== "none" && style.visibility !== "hidden";
        }

        const nextFrame = () =>
          new Promise((resolve) => {
            let done = false;
            const finish = () => {
              if (done) return;
              done = true;
              resolve();
            };
            requestAnimationFrame(finish);
            setTimeout(finish, 50);
          });
        const sampleRects = () =>
          foundElements.map((el) => {
            const rect = el.getBoundingClientRect();
            return [rect.x, rect.y, rect.width, rect.height];
          });
        const rectSetsEqual = (a, b) =>
          a &&
          a.length === b.length &&
          a.every((rect, index) =>
            rect.every((value, part) => Math.abs(value - b[index][part]) <= 0.5)
          );
        const waitForStableRects = async () => {
          if (!foundElements.length) return;
          let previous = null;
          let stableFrames = 0;
          const deadline = performance.now() + 1000;
          while (performance.now() < deadline && stableFrames < 2) {
            await nextFrame();
            const current = sampleRects();
            stableFrames = rectSetsEqual(previous, current) ? stableFrames + 1 : 0;
            previous = current;
          }
        };

        if (sel) {
          try {
            const els = queryAllDeep(sel);
            els.forEach((el, i) => {
              if (found.length >= max) return;
              const elRole = getRole(el);
              if (roleFilter && elRole !== roleFilter) return;
              const rect = el.getBoundingClientRect();
              const built = buildSelector(el);
              const item = {
                tagName: el.tagName.toLowerCase(),
                text: el.textContent?.trim().slice(0, 100) || "",
                visible: isVisibleEl(el),
                rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
              };
              if (built) item.selector = built;
              if (el.id) item.id = el.id;
              if (el.className && typeof el.className === "string") item.className = el.className.split(/\s+/).slice(0, 3).join(" ");
              if (elRole) item.role = elRole;
              if (el.getAttribute("aria-label")) item.ariaLabel = el.getAttribute("aria-label");
              if (el.getAttribute("href")) item.href = el.getAttribute("href");
              if (a11y) {
                const ref = a11y.getRefForElement(el);
                if (ref) item.ref = ref;
              }
              found.push(item);
              foundElements.push(el);
            });
          } catch (e) {
            return { error: "SELECTOR_INVALID: " + e.message, elements: [] };
          }
        } else if (q) {
          const lowerQ = q.toLowerCase();
          const stack = [];
          const pushKids = (parent) => {
            const kids = [];
            if (parent && parent.children) {
              for (const c of parent.children) kids.push(c);
            }
            if (parent && parent.shadowRoot) {
              for (const c of parent.shadowRoot.children) kids.push(c);
            }
            for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
          };
          if (document.body) pushKids(document.body);
          while (stack.length && found.length < max) {
            const node = stack.pop();
            pushKids(node);
            const text = node.textContent?.trim() || "";
            const ariaLabel = node.getAttribute("aria-label") || "";
            const placeholder = node.getAttribute("placeholder") || "";
            const title = node.getAttribute("title") || "";

            const matches =
              text.toLowerCase().includes(lowerQ) ||
              ariaLabel.toLowerCase().includes(lowerQ) ||
              placeholder.toLowerCase().includes(lowerQ) ||
              title.toLowerCase().includes(lowerQ);

            if (!matches) continue;

            const elRole = getRole(node);
            if (roleFilter && elRole !== roleFilter) continue;

            const tag = node.tagName.toLowerCase();
            const interactable = ["a", "button", "input", "select", "textarea", "label"];
            if (!interactable.includes(tag) && !node.getAttribute("role") && !roleFilter) continue;

            const rect = node.getBoundingClientRect();
            const built = buildSelector(node);
            const item = {
              tagName: tag,
              text: text.slice(0, 100),
              visible: isVisibleEl(node),
              rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
            };
            if (built) item.selector = built;
            if (node.id) item.id = node.id;
            if (elRole) item.role = elRole;
            if (ariaLabel) item.ariaLabel = ariaLabel;
            if (node.getAttribute("href")) item.href = node.getAttribute("href");
            if (a11y) {
              const ref = a11y.getRefForElement(node);
              if (ref) item.ref = ref;
            }
            found.push(item);
            foundElements.push(node);
          }
        }

        await waitForStableRects();
        found.forEach((item, index) => {
          const el = foundElements[index];
          const rect = el.getBoundingClientRect();
          item.visible = isVisibleEl(el);
          item.rect = { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
        });
        return { elements: found };
      },
      args: [query || null, selector || null, role || null, maxResults],
    });

    // Merge across frames: top frame first, then ascending frameId. Refs are
    // interned into the current global registry so they route like snapshot
    // refs; elements report which frame they live in.
    const perFrame = (results || []).filter((fr) => fr && fr.result);
    perFrame.sort((a, b) => (a.frameId === 0 ? -1 : b.frameId === 0 ? 1 : a.frameId - b.frameId));
    const merged = [];
    let firstError = null;
    for (const fr of perFrame) {
      const r = fr.result;
      if (r.error) {
        if (!firstError) firstError = r.error;
        continue;
      }
      for (const item of r.elements || []) {
        if (merged.length >= maxResults) break;
        item.frameId = fr.frameId;
        if (item.ref) item.ref = internRef(tabId, fr.frameId, item.ref);
        merged.push(item);
      }
      if (merged.length >= maxResults) break;
    }

    // Rects come back frame-local; agents feed them to coordinate clicks and
    // screenshots, which live in top-viewport space. Convert once per frame
    // (no scrollIntoView here, so one measurement per frameId is valid for
    // all its items). On failure keep the local rect and flag it.
    const offsets = new Map();
    for (const item of merged) {
      if (!item.frameId || !item.rect) continue;
      if (!offsets.has(item.frameId)) {
        try {
          offsets.set(item.frameId, await frameOffsetChain(tabId, item.frameId));
        } catch {
          offsets.set(item.frameId, null);
        }
      }
      const off = offsets.get(item.frameId);
      if (off) {
        item.rect.x += off.x;
        item.rect.y += off.y;
      } else {
        item.rectFrameLocal = true; // offset lookup failed — rect is frame-local
      }
    }

    if (!merged.length && firstError) return { error: firstError, elements: [] };
    return { elements: merged };
  },

  // === Page interactions ===

  async clickElement(params) {
    const tabId = params.tabId || (await getActiveTabId());
    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.clickElementSynthetic(params);
      throw e;
    }

    const btn = params.button || "left";
    const count = Math.max(1, params.clickCount || 1);
    const geo = await getElementGeometry(tabId, params);
    const { button, buttons } = MOUSE_BUTTONS[btn] || MOUSE_BUTTONS.left;
    // OOPIF elements: trusted input goes to the frame's OWN session in
    // frame-local coordinates; everything else stays root-session/top-space.
    const tgt = inputTargetFor(geo);

    // Trusted mouse sequence via CDP: move, then press/release per click.
    await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
      type: "mouseMoved", x: tgt.x, y: tgt.y, buttons: 0,
    });
    for (let i = 1; i <= count; i++) {
      await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mousePressed", x: tgt.x, y: tgt.y, button, buttons, clickCount: i,
      });
      await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mouseReleased", x: tgt.x, y: tgt.y, button, buttons: 0, clickCount: i,
      });
      if (i < count) await sleep(40);
    }

    const result = { inputMode: "cdp", button: btn, clickCount: count };
    if (geo.frameId) result.frameId = geo.frameId;
    if (tgt.sessionId) result.inputSession = "oopif-child";
    if (geo.tagName) {
      result.tagName = geo.tagName;
      result.text = geo.text;
    }
    if (geo.ref) result.ref = geo.ref;
    return result;
  },

  // Fallback: synthetic DOM events (debugger unavailable, e.g. DevTools open
  // on the tab). Triggers JS handlers but not CSS :active / trusted-input checks.
  async clickElementSynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { ref, selector, button, clickCount } = params;
    const btn = button || "left";
    const count = clickCount || 1;
    const routed = routeRef(tabId, ref);
    const execFrame = routed ? routed.frameId : params.frameId || 0;

    await ensureContentScripts(tabId);

    // Agent-visible coordinates are top-viewport space; elementFromPoint
    // inside a frame needs frame-local ones.
    let coordinates = params.coordinates || null;
    if (coordinates && execFrame) {
      const off = await frameOffsetChain(tabId, execFrame);
      coordinates = { x: coordinates.x - off.x, y: coordinates.y - off.y };
    }

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: (refId, sel, coords, mouseBtn, clicks) => {
        // Resolve element
        let el;
        if (refId) {
          const a11y = globalThis.__claudeA11yTree;
          if (a11y) el = a11y.getElementByRef(refId);
          if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
        } else if (sel) {
          el = document.querySelector(sel);
          if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        } else if (coords) {
          el = document.elementFromPoint(coords.x, coords.y);
          if (!el) return { error: "ELEMENT_NOT_FOUND: no element at coordinates" };
        } else {
          return { error: "Must provide ref, selector, or coordinates" };
        }

        el.scrollIntoView({ block: "center", behavior: "instant" });
        const rect = el.getBoundingClientRect();
        const cx = coords ? coords.x : rect.left + rect.width / 2;
        const cy = coords ? coords.y : rect.top + rect.height / 2;

        const eventInit = {
          bubbles: true, cancelable: true, composed: true,
          view: window, clientX: cx, clientY: cy,
        };

        if (mouseBtn === "right") {
          el.dispatchEvent(new MouseEvent("mouseover", eventInit));
          el.dispatchEvent(new MouseEvent("mouseenter", { ...eventInit, bubbles: false }));
          el.dispatchEvent(new MouseEvent("mousemove", eventInit));
          el.dispatchEvent(new MouseEvent("mousedown", { ...eventInit, button: 2 }));
          el.dispatchEvent(new MouseEvent("mouseup", { ...eventInit, button: 2 }));
          el.dispatchEvent(new MouseEvent("contextmenu", { ...eventInit, button: 2 }));
        } else if (mouseBtn === "middle") {
          el.dispatchEvent(new MouseEvent("mousedown", { ...eventInit, button: 1 }));
          el.dispatchEvent(new MouseEvent("mouseup", { ...eventInit, button: 1 }));
          el.dispatchEvent(new MouseEvent("auxclick", { ...eventInit, button: 1 }));
        } else {
          // Left click
          el.dispatchEvent(new MouseEvent("mouseover", eventInit));
          el.dispatchEvent(new MouseEvent("mouseenter", { ...eventInit, bubbles: false }));
          el.dispatchEvent(new MouseEvent("mousemove", eventInit));
          el.dispatchEvent(new MouseEvent("mousedown", { ...eventInit, button: 0 }));
          el.dispatchEvent(new MouseEvent("mouseup", { ...eventInit, button: 0 }));
          el.dispatchEvent(new MouseEvent("click", { ...eventInit, button: 0, detail: 1 }));

          if (clicks >= 2) {
            el.dispatchEvent(new MouseEvent("mousedown", { ...eventInit, button: 0 }));
            el.dispatchEvent(new MouseEvent("mouseup", { ...eventInit, button: 0 }));
            el.dispatchEvent(new MouseEvent("click", { ...eventInit, button: 0, detail: 2 }));
            el.dispatchEvent(new MouseEvent("dblclick", { ...eventInit, button: 0 }));
          }
          if (clicks >= 3) {
            el.dispatchEvent(new MouseEvent("mousedown", { ...eventInit, button: 0 }));
            el.dispatchEvent(new MouseEvent("mouseup", { ...eventInit, button: 0 }));
            el.dispatchEvent(new MouseEvent("click", { ...eventInit, button: 0, detail: 3 }));
          }
        }

        const a11y = globalThis.__claudeA11yTree;
        const result = {
          tagName: el.tagName.toLowerCase(),
          text: el.textContent?.slice(0, 100) || "",
        };
        if (a11y) {
          const r = a11y.getRefForElement(el);
          if (r) result.ref = r;
        }
        return result;
      },
      args: [routed ? routed.localRef : null, selector || null, coordinates, btn, count],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    if (r && r.ref) r.ref = unrouteRef(tabId, execFrame, r.ref);
    return r || { success: true };
  },

  async typeText(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { text, clearFirst, submit } = params;
    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.typeTextSynthetic(params);
      throw e;
    }

    const geo = await getElementGeometry(tabId, params);
    if (geo.tagName === "select") {
      // Native <select> popups are OS-level; pick the option via DOM instead.
      return handlers.typeTextSynthetic(params);
    }

    // Focus like a user would: a real click for text-ish fields (places the
    // caret), DOM focus() otherwise so we don't toggle checkboxes/radios.
    const clickToFocus =
      !geo.disabled &&
      (geo.tagName === "textarea" ||
        geo.isEditable ||
        (geo.tagName === "input" &&
          !["checkbox", "radio", "button", "submit", "reset", "file", "range", "color"].includes(
            geo.inputType || "text"
          )));
    if (clickToFocus) {
      // OOPIF fields: the focusing click goes to the frame's own session in
      // frame-local coordinates. Keyboard events that follow are frame-
      // agnostic (the browser routes them to the focused widget).
      const tgt = inputTargetFor(geo);
      await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mousePressed", x: tgt.x, y: tgt.y, button: "left", buttons: 1, clickCount: 1,
      });
      await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mouseReleased", x: tgt.x, y: tgt.y, button: "left", buttons: 0, clickCount: 1,
      });
    } else {
      await focusElement(tabId, params);
    }

    if (clearFirst) {
      await selectAllInElement(tabId, params);
      await cdpPressKeyCombo(tabId, "Backspace");
    }

    for (const ch of String(text)) {
      if (ch === "\n" || ch === "\r") {
        await cdpPressKeyCombo(tabId, "Enter");
        continue;
      }
      if (ch === "\t") {
        await cdpPressKeyCombo(tabId, "Tab");
        continue;
      }
      if (ch.codePointAt(0) > 126) {
        // Non-ASCII (CJK, emoji, ...): insertText is the reliable route.
        await cdpSend(tabId, "Input.insertText", { text: ch });
        continue;
      }
      const def = keyDefFor(ch);
      await cdpSend(tabId, "Input.dispatchKeyEvent", {
        type: "keyDown", text: ch, unmodifiedText: ch, key: ch,
        code: def.code, windowsVirtualKeyCode: def.vk, nativeVirtualKeyCode: def.vk,
      });
      await cdpSend(tabId, "Input.dispatchKeyEvent", {
        type: "keyUp", key: ch, code: def.code,
        windowsVirtualKeyCode: def.vk, nativeVirtualKeyCode: def.vk,
      });
    }

    if (submit) await cdpPressKeyCombo(tabId, "Enter");

    // Read back from the frame that was typed into — activeElement lives there.
    const readBack = await chrome.scripting.executeScript({
      target: frameTarget(tabId, geo.frameId || 0),
      func: () => {
        const el = document.activeElement;
        if (!el) return {};
        return {
          tagName: el.tagName.toLowerCase(),
          value:
            el.value !== undefined && el.value !== null
              ? (el.type === "password" || /password|one-time-code|cc-number|cc-csc/.test(el.autocomplete || "") ? "[redacted]" : el.value)
              : (el.textContent || "").slice(0, 200),
        };
      },
    });
    const rb = (readBack[0] && readBack[0].result) || {};
    return { inputMode: "cdp", ...rb, ...(geo.ref ? { ref: geo.ref } : {}) };
  },

  // Fallback: native property descriptor setter (debugger unavailable).
  async typeTextSynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { ref, selector, text, clearFirst, submit } = params;
    const routed = routeRef(tabId, ref);
    const execFrame = routed ? routed.frameId : params.frameId || 0;

    await ensureContentScripts(tabId);

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: (refId, sel, txt, clear, doSubmit) => {
        let el;
        if (refId) {
          const a11y = globalThis.__claudeA11yTree;
          if (a11y) el = a11y.getElementByRef(refId);
          if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
        } else if (sel) {
          el = document.querySelector(sel);
          if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        } else {
          el = document.activeElement;
          if (!el) return { error: "No active element" };
        }

        el.focus();

        const tag = el.tagName.toLowerCase();

        // Select element
        if (tag === "select") {
          let matched = false;
          for (const opt of el.options) {
            if (opt.value === txt || opt.textContent.trim() === txt) {
              el.value = opt.value;
              matched = true;
              break;
            }
          }
          if (!matched) return { error: "No matching option found for: " + txt };
          el.dispatchEvent(new Event("change", { bubbles: true }));
          return { tagName: tag, value: el.type === "password" || /password|one-time-code|cc-number|cc-csc/.test(el.autocomplete || "") ? "[redacted]" : el.value };
        }

        // ContentEditable
        if (el.isContentEditable) {
          if (clear) {
            el.innerHTML = "";
          }
          document.execCommand("selectAll", false, null);
          if (clear) {
            document.execCommand("delete", false, null);
          }
          document.execCommand("insertText", false, txt);
          if (el.textContent !== (clear ? txt : el.textContent)) {
            el.textContent = clear ? txt : el.textContent + txt;
            el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: txt }));
          }
          return { tagName: tag, value: el.textContent?.slice(0, 200) || "" };
        }

        // Input / Textarea
        const proto = tag === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;

        if (clear && setter) {
          setter.call(el, "");
          el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "deleteContentBackward" }));
        } else if (clear) {
          el.value = "";
          el.dispatchEvent(new Event("input", { bubbles: true }));
        }

        const newValue = clear ? txt : (el.value || "") + txt;
        if (setter) {
          setter.call(el, newValue);
        } else {
          el.value = newValue;
        }
        el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: txt }));
        el.dispatchEvent(new Event("change", { bubbles: true }));

        if (doSubmit) {
          el.dispatchEvent(new KeyboardEvent("keydown", {
            key: "Enter", code: "Enter", keyCode: 13, which: 13,
            bubbles: true, cancelable: true, composed: true,
          }));
          el.dispatchEvent(new KeyboardEvent("keyup", {
            key: "Enter", code: "Enter", keyCode: 13, which: 13,
            bubbles: true, cancelable: true, composed: true,
          }));
          // Also try form submit
          const form = el.closest("form");
          if (form) {
            form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
          }
        }

        return { tagName: tag, value: el.type === "password" || /password|one-time-code|cc-number|cc-csc/.test(el.autocomplete || "") ? "[redacted]" : el.value };
      },
      args: [routed ? routed.localRef : null, selector || null, text, clearFirst || false, submit || false],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    return r || { success: true };
  },

  async hoverElement(params) {
    const tabId = params.tabId || (await getActiveTabId());
    if (!params.ref && !params.selector) {
      throw new Error("Must provide ref or selector");
    }
    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.hoverElementSynthetic(params);
      throw e;
    }

    const geo = await getElementGeometry(tabId, params);
    // A real mouse move: activates CSS :hover and pointer media queries.
    // OOPIF elements take their frame's own session + frame-local point.
    const tgt = inputTargetFor(geo);
    await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchMouseEvent", {
      type: "mouseMoved", x: tgt.x, y: tgt.y, buttons: 0,
    });
    return {
      inputMode: "cdp",
      tagName: geo.tagName,
      text: geo.text,
      ...(geo.frameId ? { frameId: geo.frameId } : {}),
      ...(geo.ref ? { ref: geo.ref } : {}),
    };
  },

  // Fallback: synthetic pointer/mouse enter sequence (no CSS :hover).
  async hoverElementSynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { ref, selector } = params;
    const routed = routeRef(tabId, ref);
    const execFrame = routed ? routed.frameId : params.frameId || 0;

    await ensureContentScripts(tabId);

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: (refId, sel) => {
        let el;
        if (refId) {
          const a11y = globalThis.__claudeA11yTree;
          if (a11y) el = a11y.getElementByRef(refId);
          if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
        } else if (sel) {
          el = document.querySelector(sel);
          if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        } else {
          return { error: "Must provide ref or selector" };
        }

        el.scrollIntoView({ block: "center", behavior: "instant" });
        const rect = el.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;

        const eventInit = { bubbles: true, cancelable: true, composed: true, view: window, clientX: cx, clientY: cy };

        el.dispatchEvent(new PointerEvent("pointerover", { ...eventInit, pointerType: "mouse" }));
        el.dispatchEvent(new PointerEvent("pointerenter", { ...eventInit, pointerType: "mouse", bubbles: false }));
        el.dispatchEvent(new MouseEvent("mouseover", eventInit));
        el.dispatchEvent(new MouseEvent("mouseenter", { ...eventInit, bubbles: false }));
        el.dispatchEvent(new PointerEvent("pointermove", { ...eventInit, pointerType: "mouse" }));
        el.dispatchEvent(new MouseEvent("mousemove", eventInit));

        const result = {
          tagName: el.tagName.toLowerCase(),
          text: el.textContent?.slice(0, 100) || "",
        };
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) {
          const r = a11y.getRefForElement(el);
          if (r) result.ref = r;
        }
        return result;
      },
      args: [routed ? routed.localRef : null, selector || null],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    if (r && r.ref) r.ref = unrouteRef(tabId, execFrame, r.ref);
    return r || { success: true };
  },

  async dragElement(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { fromRef, fromSelector, toRef, toSelector, toCoordinates } = params;
    if (!fromRef && !fromSelector) {
      throw new Error("Must provide fromRef or fromSelector");
    }
    if (!toRef && !toSelector && !toCoordinates) {
      throw new Error("Must provide toRef, toSelector, or toCoordinates");
    }
    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.dragElementSynthetic(params);
      throw e;
    }

    const frameId = params.frameId || 0;
    const from = await getElementGeometry(tabId, { ref: fromRef, selector: fromSelector, frameId });
    const to = toCoordinates
      ? { x: toCoordinates.x, y: toCoordinates.y }
      : await getElementGeometry(tabId, { ref: toRef, selector: toSelector, frameId });

    // Per-endpoint dispatch points: an OOPIF endpoint takes its own child
    // session with frame-local coords; everything else stays root/top-space.
    const fromTgt = inputTargetFor(from);
    let toTgt;
    if (toCoordinates) {
      if (fromTgt.sessionId) {
        // Drop coords are top-space; the source frame's session needs local.
        let off;
        try {
          off = await frameOffsetChain(tabId, from.frameId);
        } catch {
          throw new Error(
            `CROSS_FRAME_DRAG: cannot convert the drop coordinates into OOPIF frameId ${from.frameId}'s own viewport space (frame offset unavailable); drop onto an element ref instead`
          );
        }
        toTgt = { sessionId: fromTgt.sessionId, x: toCoordinates.x - off.x, y: toCoordinates.y - off.y };
      } else {
        toTgt = { sessionId: null, x: toCoordinates.x, y: toCoordinates.y };
      }
    } else {
      toTgt = inputTargetFor(to);
    }
    const crossSession = toTgt.sessionId !== fromTgt.sessionId;

    const session = cdpSessions.get(tabId);
    if (session) session.lastDragIntercepted = null;

    // Intercept native drags on whichever sessions will receive the events.
    await cdpSendTo(tabId, fromTgt.sessionId, "Input.setInterceptDrags", { enabled: true });
    if (crossSession) {
      await cdpSendTo(tabId, toTgt.sessionId, "Input.setInterceptDrags", { enabled: true });
    }
    let nativeDrag = false;
    try {
      await cdpSendTo(tabId, fromTgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mouseMoved", x: fromTgt.x, y: fromTgt.y, buttons: 0,
      });
      await cdpSendTo(tabId, fromTgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mousePressed", x: fromTgt.x, y: fromTgt.y, button: "left", buttons: 1, clickCount: 1,
      });
      // Nudge past the drag threshold so the renderer starts a native drag.
      await cdpSendTo(tabId, fromTgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mouseMoved", x: fromTgt.x + 4, y: fromTgt.y + 4, button: "left", buttons: 1,
      });

      const deadline = Date.now() + 2000;
      while (session && !session.lastDragIntercepted && Date.now() < deadline) {
        await sleep(50);
      }
      const drag = session && session.lastDragIntercepted;

      if (drag) {
        nativeDrag = true;
        await cdpSendTo(tabId, toTgt.sessionId, "Input.dispatchMouseEvent", {
          type: "mouseMoved", x: toTgt.x, y: toTgt.y, button: "left", buttons: 1,
        });
        for (const type of ["dragEnter", "dragOver", "drop"]) {
          await cdpSendTo(tabId, toTgt.sessionId, "Input.dispatchDragEvent", { type, x: toTgt.x, y: toTgt.y, data: drag.data });
        }
      } else if (!crossSession) {
        // No native drag started: plain trusted mouse drag (sliders,
        // canvases, custom DnD libraries that listen to mouse events).
        const steps = 12;
        for (let i = 1; i <= steps; i++) {
          const x = fromTgt.x + ((toTgt.x - fromTgt.x) * i) / steps;
          const y = fromTgt.y + ((toTgt.y - fromTgt.y) * i) / steps;
          await cdpSendTo(tabId, fromTgt.sessionId, "Input.dispatchMouseEvent", {
            type: "mouseMoved", x, y, button: "left", buttons: 1,
          });
          await sleep(15);
        }
      } else {
        // Two widgets with no shared coordinate space to interpolate across:
        // jump straight to the drop point inside the target frame.
        await cdpSendTo(tabId, toTgt.sessionId, "Input.dispatchMouseEvent", {
          type: "mouseMoved", x: toTgt.x, y: toTgt.y, button: "left", buttons: 1,
        });
      }
      await cdpSendTo(tabId, toTgt.sessionId, "Input.dispatchMouseEvent", {
        type: "mouseReleased", x: toTgt.x, y: toTgt.y, button: "left", buttons: 0, clickCount: 1,
      });
    } finally {
      try {
        await cdpSendTo(tabId, fromTgt.sessionId, "Input.setInterceptDrags", { enabled: false });
      } catch {}
      if (crossSession) {
        try {
          await cdpSendTo(tabId, toTgt.sessionId, "Input.setInterceptDrags", { enabled: false });
        } catch {}
      }
    }

    return {
      inputMode: "cdp",
      nativeDrag,
      ...(crossSession ? { crossSession: true } : {}),
      from: { tagName: from.tagName, ...(from.ref ? { ref: from.ref } : {}) },
      to: toCoordinates
        ? { coordinates: toCoordinates }
        : { tagName: to.tagName, ...(to.ref ? { ref: to.ref } : {}) },
    };
  },

  // Fallback: synthetic HTML5 DragEvent sequence (debugger unavailable).
  async dragElementSynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { fromRef, fromSelector, toRef, toSelector, toCoordinates } = params;
    const routedFrom = routeRef(tabId, fromRef);
    const routedTo = routeRef(tabId, toRef);
    // Synthetic drags run in ONE frame's document, so both endpoints must
    // resolve there. Refs route to their own frame; selectors use params.frameId.
    const fromFrame = routedFrom ? routedFrom.frameId : params.frameId || 0;
    const toFrame = routedTo ? routedTo.frameId : toCoordinates ? fromFrame : params.frameId || 0;
    if (toFrame !== fromFrame) {
      throw new Error(
        `CROSS_FRAME_DRAG: drag source (frameId ${fromFrame}) and drop target (frameId ${toFrame}) live in different frames; ` +
          `synthetic drags cannot cross frame boundaries without the Chrome debugger. Close DevTools on this tab to use the trusted CDP drag, or drag within one frame.`
      );
    }
    const execFrame = fromFrame;

    await ensureContentScripts(tabId);

    // toCoordinates are top-viewport space; elementFromPoint in a frame needs frame-local.
    let tCoords = toCoordinates || null;
    if (tCoords && execFrame) {
      const off = await frameOffsetChain(tabId, execFrame);
      tCoords = { x: tCoords.x - off.x, y: tCoords.y - off.y };
    }

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: (fRef, fSel, tRef, tSel, tCoords) => {
        const a11y = globalThis.__claudeA11yTree;

        // Resolve source
        let from;
        if (fRef && a11y) {
          from = a11y.getElementByRef(fRef);
          if (!from) return { error: `REF_NOT_FOUND: ${fRef}` };
        } else if (fSel) {
          from = document.querySelector(fSel);
          if (!from) return { error: `ELEMENT_NOT_FOUND: ${fSel}` };
        } else {
          return { error: "Must provide fromRef or fromSelector" };
        }

        // Resolve target
        let to;
        if (tRef && a11y) {
          to = a11y.getElementByRef(tRef);
          if (!to) return { error: `REF_NOT_FOUND: ${tRef}` };
        } else if (tSel) {
          to = document.querySelector(tSel);
          if (!to) return { error: `ELEMENT_NOT_FOUND: ${tSel}` };
        } else if (tCoords) {
          to = document.elementFromPoint(tCoords.x, tCoords.y);
          if (!to) return { error: "ELEMENT_NOT_FOUND: no element at target coordinates" };
        } else {
          return { error: "Must provide toRef, toSelector, or toCoordinates" };
        }

        const fr = from.getBoundingClientRect();
        const fx = fr.left + fr.width / 2;
        const fy = fr.top + fr.height / 2;

        let tx, ty;
        if (tCoords) {
          tx = tCoords.x;
          ty = tCoords.y;
        } else {
          const tr = to.getBoundingClientRect();
          tx = tr.left + tr.width / 2;
          ty = tr.top + tr.height / 2;
        }

        const dt = new DataTransfer();

        from.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, clientX: fx, clientY: fy }));
        from.dispatchEvent(new DragEvent("dragstart", { bubbles: true, clientX: fx, clientY: fy, dataTransfer: dt }));
        from.dispatchEvent(new DragEvent("drag", { bubbles: true, clientX: fx, clientY: fy, dataTransfer: dt }));
        to.dispatchEvent(new DragEvent("dragenter", { bubbles: true, clientX: tx, clientY: ty, dataTransfer: dt }));
        const overEvent1 = new DragEvent("dragover", { bubbles: true, cancelable: true, clientX: tx, clientY: ty, dataTransfer: dt });
        to.dispatchEvent(overEvent1);
        const overEvent2 = new DragEvent("dragover", { bubbles: true, cancelable: true, clientX: tx, clientY: ty, dataTransfer: dt });
        to.dispatchEvent(overEvent2);
        to.dispatchEvent(new DragEvent("drop", { bubbles: true, clientX: tx, clientY: ty, dataTransfer: dt }));
        from.dispatchEvent(new DragEvent("dragend", { bubbles: true, clientX: tx, clientY: ty, dataTransfer: dt }));

        const result = {
          from: { tagName: from.tagName.toLowerCase() },
          to: tCoords ? { coordinates: tCoords } : { tagName: to.tagName.toLowerCase() },
        };
        if (a11y) {
          const fRefId = a11y.getRefForElement(from);
          if (fRefId) result.from.ref = fRefId;
          if (!tCoords) {
            const tRefId = a11y.getRefForElement(to);
            if (tRefId) result.to.ref = tRefId;
          }
        }
        if (!overEvent1.defaultPrevented && !overEvent2.defaultPrevented) {
          result.warning = "dragover was not cancelled by the page - drop zone may not accept the drop";
        }
        return result;
      },
      args: [
        routedFrom ? routedFrom.localRef : null,
        fromSelector || null,
        routedTo ? routedTo.localRef : null,
        toSelector || null,
        tCoords,
      ],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    if (r && r.from && r.from.ref) r.from.ref = unrouteRef(tabId, execFrame, r.from.ref);
    if (r && r.to && r.to.ref) r.to.ref = unrouteRef(tabId, execFrame, r.to.ref);
    // Report coordinates in the agent-visible top-viewport space.
    if (r && r.to && toCoordinates) r.to.coordinates = toCoordinates;
    return r || { success: true };
  },

  async scrollPage(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { ref, selector, position } = params;
    const frameId = params.frameId || 0;

    // Element / absolute-position scrolling stays DOM territory.
    if (ref || selector || position) return handlers.scrollPageSynthetic(params);

    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.scrollPageSynthetic(params);
      throw e;
    }

    const px = params.amount || 500;
    const map = { up: [0, -px], down: [0, px], left: [-px, 0], right: [px, 0] };
    const [deltaX, deltaY] = map[params.direction || "down"] || [0, px];

    // Trusted wheel event. The renderer routes it to the frame under the
    // point, so scrolling an iframe means dispatching at a point inside it
    // (frame center, in top-viewport space). OOPIF frames are the exception:
    // their child session has its own viewport space, so dispatch the wheel
    // frame-locally there and skip the offset measurement entirely.
    let wheelX;
    let wheelY;
    let wheelSessionId = null;
    if (frameId) {
      const dims = await chrome.scripting.executeScript({
        target: frameTarget(tabId, frameId),
        func: () => ({ w: window.innerWidth, h: window.innerHeight }),
      });
      const d = (dims[0] && dims[0].result) || { w: 0, h: 0 };
      const bound = frameSessions.get(`${tabId}:${frameId}`);
      if (bound) {
        wheelSessionId = bound.sessionId;
        wheelX = d.w / 2;
        wheelY = d.h / 2;
      } else {
        const off = await frameOffsetChain(tabId, frameId);
        wheelX = off.x + d.w / 2;
        wheelY = off.y + d.h / 2;
      }
    } else {
      const geo = await getElementGeometry(tabId, { scrollIntoView: false });
      wheelX = geo.viewport.w / 2;
      wheelY = geo.viewport.h / 2;
    }
    await cdpSendTo(tabId, wheelSessionId, "Input.dispatchMouseEvent", {
      type: "mouseWheel", x: wheelX, y: wheelY, deltaX, deltaY,
    });
    await sleep(200);

    const metrics = await chrome.scripting.executeScript({
      target: frameTarget(tabId, frameId),
      func: () => ({
        scrollX: Math.round(window.scrollX),
        scrollY: Math.round(window.scrollY),
        scrollHeight: document.documentElement.scrollHeight,
        clientHeight: document.documentElement.clientHeight,
        atTop: window.scrollY === 0,
        atBottom:
          window.scrollY + document.documentElement.clientHeight >=
          document.documentElement.scrollHeight - 1,
      }),
    });
    return { inputMode: "cdp", ...(frameId ? { frameId } : {}), ...((metrics[0] && metrics[0].result) || {}) };
  },

  // Fallback: DOM scrollBy/scrollTo/scrollIntoView (debugger unavailable).
  async scrollPageSynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { ref, selector, direction, amount, position } = params;
    const routed = routeRef(tabId, ref);
    const execFrame = routed ? routed.frameId : params.frameId || 0;

    await ensureContentScripts(tabId);

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: async (refId, sel, dir, amt, pos) => {
        const a11y = globalThis.__claudeA11yTree;
        const nextFrame = () =>
          new Promise((resolve) => {
            let done = false;
            const finish = () => {
              if (done) return;
              done = true;
              resolve();
            };
            requestAnimationFrame(finish);
            setTimeout(finish, 50);
          });
        const rectValue = (rect) => ({
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
        });
        const rectsEqual = (a, b) =>
          a &&
          Math.abs(a.x - b.x) <= 0.5 &&
          Math.abs(a.y - b.y) <= 0.5 &&
          Math.abs(a.width - b.width) <= 0.5 &&
          Math.abs(a.height - b.height) <= 0.5;
        const scrollToElement = async (el, target) => {
          el.scrollIntoView({ behavior: "instant", block: "center", inline: "nearest" });
          let previous = null;
          let stableFrames = 0;
          let rect = rectValue(el.getBoundingClientRect());
          const deadline = performance.now() + 1000;
          while (performance.now() < deadline && stableFrames < 2) {
            await nextFrame();
            rect = rectValue(el.getBoundingClientRect());
            stableFrames = rectsEqual(previous, rect) ? stableFrames + 1 : 0;
            previous = rect;
          }
          const visible =
            rect.width > 0 &&
            rect.height > 0 &&
            rect.x < window.innerWidth &&
            rect.y < window.innerHeight &&
            rect.x + rect.width > 0 &&
            rect.y + rect.height > 0;
          return { scrolledTo: target, settled: stableFrames >= 2, visible, rect };
        };

        // Priority: ref/selector > position > direction+amount
        if (refId) {
          let el;
          if (a11y) el = a11y.getElementByRef(refId);
          if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
          return scrollToElement(el, refId);
        }
        if (sel) {
          const el = document.querySelector(sel);
          if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
          return scrollToElement(el, sel);
        }
        if (pos === "top") {
          window.scrollTo({ top: 0, behavior: "instant" });
        } else if (pos === "bottom") {
          window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "instant" });
        } else {
          const px = amt ?? 500;
          const map = { up: [0, -px], down: [0, px], left: [-px, 0], right: [px, 0] };
          const [x, y] = map[dir] || [0, px];
          window.scrollBy({ left: x, top: y, behavior: "instant" });
        }
        await nextFrame();
        return {
          scrollX: Math.round(window.scrollX),
          scrollY: Math.round(window.scrollY),
          scrollHeight: document.documentElement.scrollHeight,
          clientHeight: document.documentElement.clientHeight,
          atTop: window.scrollY === 0,
          atBottom: window.scrollY + document.documentElement.clientHeight >= document.documentElement.scrollHeight - 1,
        };
      },
      args: [routed ? routed.localRef : null, selector || null, direction || "down", amount || 500, position || null],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    if (r && r.scrolledTo && routed && !routed.untracked && r.scrolledTo === routed.localRef) {
      r.scrolledTo = ref; // report the agent-visible global ref
    }
    if (r && r.rect && execFrame) {
      try {
        const offset = await frameOffsetChain(tabId, execFrame);
        r.rect.x += offset.x;
        r.rect.y += offset.y;
      } catch {
        r.rectFrameLocal = true;
      }
    }
    if (r && execFrame) r.frameId = execFrame;
    return r || { success: true };
  },

  async pressKey(params) {
    const tabId = params.tabId || (await getActiveTabId());
    if (!params.key) throw new Error("key is required");
    try {
      await ensureCdp(tabId);
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.pressKeySynthetic(params);
      throw e;
    }

    if (params.ref || params.selector) await focusElement(tabId, params);
    await cdpPressKeyCombo(tabId, params.key);
    return { inputMode: "cdp", key: params.key };
  },

  // Fallback: synthetic KeyboardEvent dispatch (debugger unavailable).
  async pressKeySynthetic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { key, ref, selector } = params;
    const routed = routeRef(tabId, ref);
    const execFrame = routed ? routed.frameId : params.frameId || 0;

    await ensureContentScripts(tabId);

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, execFrame),
      func: (keyStr, refId, sel) => {
        // Parse key combination
        const parts = keyStr.split("+");
        const modifiers = { ctrlKey: false, shiftKey: false, altKey: false, metaKey: false };
        let mainKey = "";
        for (const p of parts) {
          const lower = p.toLowerCase();
          if (lower === "control" || lower === "ctrl") modifiers.ctrlKey = true;
          else if (lower === "shift") modifiers.shiftKey = true;
          else if (lower === "alt") modifiers.altKey = true;
          else if (lower === "meta" || lower === "command" || lower === "cmd") modifiers.metaKey = true;
          else mainKey = p;
        }

        // Key-to-code mapping
        const keyCodeMap = {
          Enter: 13, Escape: 27, Tab: 9, Backspace: 8, Delete: 46,
          ArrowUp: 38, ArrowDown: 40, ArrowLeft: 37, ArrowRight: 39,
          Home: 36, End: 35, PageUp: 33, PageDown: 34, " ": 32, Space: 32,
          F1: 112, F2: 113, F3: 114, F4: 115, F5: 116, F6: 117,
          F7: 118, F8: 119, F9: 120, F10: 121, F11: 122, F12: 123,
        };

        function getCode(k) {
          if (keyCodeMap[k]) return k;
          if (k === " ") return "Space";
          if (k.length === 1) {
            const code = k.charCodeAt(0);
            if (code >= 48 && code <= 57) return `Digit${k}`;
            if (code >= 65 && code <= 90 || code >= 97 && code <= 122) return `Key${k.toUpperCase()}`;
          }
          return k;
        }

        const keyCode = keyCodeMap[mainKey] || (mainKey.length === 1 ? mainKey.toUpperCase().charCodeAt(0) : 0);
        const code = getCode(mainKey);

        // Resolve target
        let target;
        if (refId) {
          const a11y = globalThis.__claudeA11yTree;
          if (a11y) target = a11y.getElementByRef(refId);
          if (!target) return { error: `REF_NOT_FOUND: ${refId}` };
        } else if (sel) {
          target = document.querySelector(sel);
          if (!target) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        } else {
          target = document.activeElement || document.body;
        }

        const eventInit = {
          key: mainKey, code, keyCode, which: keyCode,
          ...modifiers,
          bubbles: true, cancelable: true, composed: true,
        };

        target.dispatchEvent(new KeyboardEvent("keydown", eventInit));

        // For printable characters without modifiers (except shift), also dispatch input
        const hasModifier = modifiers.ctrlKey || modifiers.altKey || modifiers.metaKey;
        if (mainKey.length === 1 && !hasModifier) {
          const inputChar = modifiers.shiftKey ? mainKey.toUpperCase() : mainKey;
          target.dispatchEvent(new InputEvent("beforeinput", {
            bubbles: true, cancelable: true, composed: true,
            inputType: "insertText", data: inputChar,
          }));
          target.dispatchEvent(new InputEvent("input", {
            bubbles: true, composed: true,
            inputType: "insertText", data: inputChar,
          }));
        }

        target.dispatchEvent(new KeyboardEvent("keyup", eventInit));

        // Enter on input inside form
        if (mainKey === "Enter" && !hasModifier) {
          const form = target.closest?.("form");
          if (form && target.tagName === "INPUT") {
            form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
          }
        }

        const result = { key: keyStr, target: { tagName: target.tagName.toLowerCase() } };
        const a11y = globalThis.__claudeA11yTree;
        if (a11y) {
          const r = a11y.getRefForElement(target);
          if (r) result.target.ref = r;
        }
        return result;
      },
      args: [key, routed ? routed.localRef : null, selector || null],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    if (r && r.target && r.target.ref) r.target.ref = unrouteRef(tabId, execFrame, r.target.ref);
    return r || { success: true };
  },

  async waitFor(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { selector, ref, text, textGone, time, navigation, networkIdle, download } = params;
    const timeout = params.timeout || 10000;

    // Fixed wait
    if (time && !selector && !ref && !text && !textGone && !navigation && !networkIdle && !download) {
      await new Promise((r) => setTimeout(r, time));
      return { matched: true, duration: time, detail: `Waited ${time}ms` };
    }

    // Download completion: event-driven via chrome.downloads.onChanged (no
    // search polling), plus a one-shot lookback scan: an instant download
    // (small local file) can finish inside the agent-turn gap between the
    // click that started it and this call, and onChanged never fires for it.
    // Only completions within WAIT_LOOKBACK_MS of the call are accepted —
    // older history cannot produce a false hit, and a download already in
    // flight when the wait starts (the usual click -> wait_for race) still
    // matches via the event path.
    if (download) {
      const dlTimeout = params.downloadTimeout || timeout;
      const startTime = Date.now();
      return await new Promise((resolve) => {
        let settled = false;
        const seen = new Map(); // download id -> last observed state
        const finish = (result) => {
          if (settled) return;
          settled = true;
          chrome.downloads.onChanged.removeListener(onChanged);
          clearTimeout(timer);
          resolve(result);
        };
        const downloadPayload = (item) => ({
          id: item.id,
          filename: item.filename || null,
          localPath: item.filename || null,
          url: item.finalUrl || item.url,
          state: item.state,
          totalBytes: item.totalBytes,
          ...(item.mime ? { mime: item.mime } : {}),
        });
        const onChanged = (delta) => {
          if (!delta || delta.id == null) return;
          const st = delta.state && delta.state.current;
          if (st) seen.set(delta.id, st);
          if (st !== "complete") return;
          // Hydrate the finished item for filename/localPath in the result.
          chrome.downloads
            .search({ id: delta.id })
            .then((items) => {
              const item = items && items[0];
              if (!item) return;
              finish({
                matched: true,
                duration: Date.now() - startTime,
                detail: `download complete: ${item.filename || item.url || "id " + item.id}`,
                download: downloadPayload(item),
              });
            })
            .catch(() => {});
        };
        chrome.downloads.onChanged.addListener(onChanged);
        // Lookback scan (see above). Items without a parseable endTime are
        // skipped; the newest completion inside the window wins.
        // orderBy is load-bearing: chrome.downloads.search WITHOUT it applies
        // no sorter and tie-breaks by id ASCENDING (Chromium download_query.h),
        // so limit:10 would return the TEN OLDEST entries and the just-finished
        // download would never be in the scan window on any machine with >10
        // history items. -startTime puts recent completions first.
        chrome.downloads
          .search({ state: "complete", orderBy: ["-startTime"], limit: 10 })
          .then((items) => {
            const cutoff = Date.now() - WAIT_LOOKBACK_MS;
            let best = null;
            let bestEnd = 0;
            for (const it of items || []) {
              const end = it && it.endTime ? Date.parse(it.endTime) : NaN;
              if (Number.isFinite(end) && end >= cutoff && end > bestEnd) {
                best = it;
                bestEnd = end;
              }
            }
            if (best) {
              finish({
                matched: true,
                duration: Date.now() - startTime,
                detail:
                  `download complete (finished ${Date.now() - bestEnd}ms before the wait): ` +
                  (best.filename || best.url || "id " + best.id),
                download: downloadPayload(best),
                viaLookback: true,
              });
            }
          })
          .catch(() => {});
        const timer = setTimeout(() => {
          const partial = [...seen.entries()]
            .filter(([, s]) => s !== "complete")
            .map(([id, s]) => `id ${id}: ${s}`)
            .join(", ");
          finish({
            matched: false,
            duration: Date.now() - startTime,
            detail:
              `TIMEOUT: no download completed within ${dlTimeout}ms` +
              (partial ? ` (seen during wait but unfinished — ${partial})` : ""),
          });
        }, dlTimeout);
      });
    }

    // CDP-backed conditions: navigation / networkIdle. Both read the tab's
    // event ring buffer, so the debugger must be attached (ensureCdp does
    // that on demand; there is no synthetic fallback for these signals).
    if (navigation || networkIdle) {
      let session;
      try {
        session = await ensureCdp(tabId);
      } catch (e) {
        throw new Error(
          `wait_for navigation/networkIdle requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
        );
      }

      const startTime = Date.now();
      // Lookback: a navigation triggered before this call — the usual
      // click -> wait_for race, where agent-turn latency is seconds-scale —
      // may already be in the buffer. WAIT_LOOKBACK_MS bounds the false-hit
      // window (a navigation from an earlier action could otherwise match).
      const navLookback = startTime - WAIT_LOOKBACK_MS;
      const quietMs = Math.max(50, params.idleTime || 500);
      const ignorePatterns = compileUrlPatterns(
        params.networkIdleIgnorePatterns,
        "networkIdleIgnorePatterns"
      );
      const pollInterval = 100;

      const relevantNetworkActivityTs = () => {
        if (!ignorePatterns.length) return session.lastNetworkActivityTs;
        for (let i = session.networkActivity.length - 1; i >= 0; i--) {
          const activity = session.networkActivity[i];
          if (!activity.url || !matchesUrlPatterns(ignorePatterns, activity.url)) {
            return activity.ts;
          }
        }
        return 0;
      };

      // If the tab is mid-load at call time, "load finished" also counts as
      // the navigation even if frameNavigated fired before we attached.
      let wasLoading = false;
      try {
        wasLoading = (await chrome.tabs.get(tabId)).status === "loading";
      } catch {}

      let navDetail = null;
      let idleDetail = null;

      while (Date.now() - startTime < timeout) {
        // The debugger may detach mid-wait (e.g. the user dismissed Chrome's
        // infobar); the captured session object then stops receiving events
        // and the wait would silently time out. Re-acquire or fail loudly.
        if (cdpSessions.get(tabId) !== session) {
          try {
            session = await ensureCdp(tabId);
          } catch (e) {
            throw new Error(
              `wait_for aborted: the Chrome debugger detached from tab ${tabId} during the wait and could not re-attach: ${e.message}`
            );
          }
        }

        // Scan newest-first; events arrive in ts order so we can stop early.
        if (navigation && !navDetail) {
          for (let i = session.events.length - 1; i >= 0; i--) {
            const e = session.events[i];
            if (e.ts < navLookback) break;
            // Only root-session events count: an OOPIF child session is the
            // root document of its own process (frameNavigated there has no
            // parentId), so child-session events would masquerade as
            // main-frame navigations.
            if (e.method === "Page.loadEventFired" && !e.sessionId) {
              navDetail = "navigation detected (Page.loadEventFired)";
              break;
            }
            if (
              e.method === "Page.frameNavigated" && !e.sessionId &&
              e.params && e.params.frame && !e.params.frame.parentId
            ) {
              navDetail = `navigation detected (Page.frameNavigated -> ${e.params.frame.url || ""})`;
              break;
            }
          }
          if (!navDetail && wasLoading) {
            try {
              if ((await chrome.tabs.get(tabId)).status === "complete") {
                wasLoading = false;
                navDetail = "navigation detected (tab finished loading)";
              }
            } catch {}
          }
        }

        // networkIdle only starts counting once navigation (if requested)
        // has settled, so the load's own requests are not misread as noise.
        if (networkIdle && !idleDetail && (!navigation || navDetail)) {
          const quietSince = Math.max(relevantNetworkActivityTs(), startTime);
          if (Date.now() - quietSince >= quietMs) {
            idleDetail = `network idle for ${Date.now() - quietSince}ms (threshold ${quietMs}ms)`;
          }
        }

        if ((!navigation || navDetail) && (!networkIdle || idleDetail)) {
          return {
            matched: true,
            duration: Date.now() - startTime,
            detail: [navDetail, idleDetail].filter(Boolean).join("; "),
            ...(navigation ? { navigation: true } : {}),
            ...(networkIdle ? { networkIdle: true } : {}),
          };
        }

        await sleep(pollInterval);
      }

      return {
        matched: false,
        duration: Date.now() - startTime,
        detail:
          "TIMEOUT: " +
          [
            navigation && !navDetail ? "no navigation detected" : null,
            networkIdle && !idleDetail ? `network never stayed idle for ${quietMs}ms` : null,
          ]
            .filter(Boolean)
            .join(", ") +
          ` within ${timeout}ms`,
        ...(navigation ? { navigation: !!navDetail } : {}),
        ...(networkIdle ? { networkIdle: !!idleDetail } : {}),
      };
    }

    await ensureContentScripts(tabId);

    const routed = routeRef(tabId, ref);
    // Poll inside the frame the ref/selector lives in (refs route themselves;
    // selectors can be aimed with params.frameId from the frames summary).
    const execFrame = routed ? routed.frameId : params.frameId || 0;
    const startTime = Date.now();
    const pollInterval = 200;
    const maxPolls = Math.ceil(timeout / pollInterval);

    for (let i = 0; i < maxPolls; i++) {
      let results;
      try {
        results = await chrome.scripting.executeScript({
          target: frameTarget(tabId, execFrame),
        func: (sel, refId, txt, txtGone) => {
          if (sel) {
            const el = document.querySelector(sel);
            if (el) {
              const style = window.getComputedStyle(el);
              if (style.display !== "none" && style.visibility !== "hidden") {
                return { found: true, detail: `selector "${sel}" found` };
              }
            }
            return { found: false };
          }
          if (refId) {
            const a11y = globalThis.__claudeA11yTree;
            if (a11y) {
              const el = a11y.getElementByRef(refId);
              if (el) {
                const style = window.getComputedStyle(el);
                if (style.display !== "none" && style.visibility !== "hidden") {
                  return { found: true, detail: `ref "${refId}" found and visible` };
                }
              }
            }
            return { found: false };
          }
          if (txt) {
            if (document.body.innerText.includes(txt)) {
              return { found: true, detail: `text "${txt}" found` };
            }
            return { found: false };
          }
          if (txtGone) {
            if (!document.body.innerText.includes(txtGone)) {
              return { found: true, detail: `text "${txtGone}" is gone` };
            }
            return { found: false };
          }
          return { found: true, detail: "no condition specified" };
        },
        args: [selector || null, routed ? routed.localRef : null, text || null, textGone || null],
        });
      } catch {
        results = null; // frame gone mid-poll (navigating/removed); keep polling
      }

      const r = results[0]?.result;
      if (r && r.found) {
        // detail quotes the frame-local ref; show the agent-visible global one.
        if (ref && routed && !routed.untracked && routed.localRef !== ref && r.detail) {
          r.detail = r.detail.split(routed.localRef).join(ref);
        }
        return { matched: true, duration: Date.now() - startTime, detail: r.detail };
      }

      await new Promise((r) => setTimeout(r, pollInterval));
    }

    return { matched: false, duration: Date.now() - startTime, detail: "TIMEOUT: condition not met within " + timeout + "ms" };
  },

  // === Screenshot ===

  async takeScreenshot(params) {
    const tabId = (params && params.tabId) || (await getActiveTabId());
    const format = (params && params.format) || "png";
    const quality = (params && params.quality) || 80;
    const fullPage = !!(params && params.fullPage);
    const wantsElement = !!(params && (params.ref || params.selector));

    try {
      await ensureCdp(tabId);
      const shot = { format, fromSurface: true };
      if (format === "jpeg") shot.quality = quality;

      let dims = null;
      let shotSessionId = null;
      let oopif = null;
      if (wantsElement) {
        const geo = await getElementGeometry(tabId, params);
        shot.captureBeyondViewport = true;
        if (geo.offsetUnresolved && geo.childSessionId && geo.localRect) {
          // Element inside an OOPIF whose offset into top space could not be
          // measured: capture from the child session instead, where the
          // coordinate space is the frame's own viewport.
          shotSessionId = geo.childSessionId;
          oopif = { oopifCapture: true, ...(geo.frameId ? { frameId: geo.frameId } : {}) };
          const ls = geo.localScroll || { x: 0, y: 0 };
          shot.clip = {
            x: Math.max(0, geo.localRect.x + ls.x),
            y: Math.max(0, geo.localRect.y + ls.y),
            width: Math.max(1, geo.localRect.width),
            height: Math.max(1, geo.localRect.height),
            scale: 1,
          };
          dims = { width: Math.round(geo.localRect.width), height: Math.round(geo.localRect.height) };
        } else {
          shot.clip = {
            x: Math.max(0, geo.rect.x + geo.scroll.x),
            y: Math.max(0, geo.rect.y + geo.scroll.y),
            width: Math.max(1, geo.rect.width),
            height: Math.max(1, geo.rect.height),
            scale: 1,
          };
          dims = { width: Math.round(geo.rect.width), height: Math.round(geo.rect.height) };
        }
      } else if (fullPage) {
        shot.captureBeyondViewport = true;
      } else {
        shot.captureBeyondViewport = false;
      }

      const r = await cdpSendTo(tabId, shotSessionId, "Page.captureScreenshot", shot);
      return { image: r.data, format, source: "cdp", ...(dims || {}), ...(oopif || {}) };
    } catch (e) {
      if (isCdpUnavailable(e)) {
        const legacy = await handlers.takeScreenshotLegacy(params);
        return {
          ...legacy,
          note: "Debugger unavailable; captured the visible viewport via captureVisibleTab (fullPage ignored).",
        };
      }
      throw e;
    }
  },

  // Fallback: captureVisibleTab + OffscreenCanvas crop (requires tab activation).
  async takeScreenshotLegacy(params) {
    let tabId = params && params.tabId;
    let windowId;
    const format = (params && params.format) || "png";
    const quality = (params && params.quality) || 80;

    if (tabId) {
      const tab = await chrome.tabs.get(tabId);
      windowId = tab.windowId;
      if (!tab.active) {
        await chrome.tabs.update(tabId, { active: true });
        await new Promise((r) => setTimeout(r, 300));
      }
    } else {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab) throw new Error("No active tab found");
      tabId = activeTab.id;
      windowId = activeTab.windowId;
    }

    const captureOpts = { format };
    if (format === "jpeg") captureOpts.quality = quality;

    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, captureOpts);
    const base64Prefix = `data:image/${format};base64,`;
    const base64 = dataUrl.startsWith(base64Prefix) ? dataUrl.slice(base64Prefix.length) : dataUrl.replace(/^data:image\/\w+;base64,/, "");

    // If ref or selector provided, crop to element
    if (params.ref || params.selector) {
      await ensureContentScripts(tabId);
      const routed = routeRef(tabId, params.ref);
      const execFrame = routed ? routed.frameId : params.frameId || 0;

      const rectResults = await chrome.scripting.executeScript({
        target: frameTarget(tabId, execFrame),
        func: (refId, sel) => {
          let el;
          if (refId) {
            const a11y = globalThis.__claudeA11yTree;
            if (a11y) el = a11y.getElementByRef(refId);
          } else if (sel) {
            el = document.querySelector(sel);
          }
          if (!el) return null;
          el.scrollIntoView({ block: "center", inline: "center", behavior: "instant" });
          const rect = el.getBoundingClientRect();
          return {
            x: rect.x, y: rect.y, width: rect.width, height: rect.height,
            dpr: window.devicePixelRatio || 1,
          };
        },
        args: [routed ? routed.localRef : null, params.selector || null],
      });

      const rectInfo = rectResults[0]?.result;
      if (rectInfo && execFrame) {
        // captureVisibleTab pixels are top-viewport space: shift the
        // frame-local rect by the accumulated iframe offsets. Measured after
        // the scrollIntoView above, which may have moved ancestor frames.
        const off = await frameOffsetChain(tabId, execFrame);
        rectInfo.x += off.x;
        rectInfo.y += off.y;
      }
      if (rectInfo) {
        // Crop the image using OffscreenCanvas in the page context
        const cropResults = await chrome.scripting.executeScript({
          target: { tabId },
          world: "MAIN",
          func: async (imgBase64, imgFormat, rect) => {
            const img = new Image();
            await new Promise((resolve, reject) => {
              img.onload = resolve;
              img.onerror = reject;
              img.src = `data:image/${imgFormat};base64,${imgBase64}`;
            });

            const dpr = rect.dpr;
            const sx = rect.x * dpr;
            const sy = rect.y * dpr;
            const sw = rect.width * dpr;
            const sh = rect.height * dpr;

            const canvas = new OffscreenCanvas(sw, sh);
            const ctx = canvas.getContext("2d");
            ctx.drawImage(img, sx, sy, sw, sh, 0, 0, sw, sh);

            const mimeType = imgFormat === "jpeg" ? "image/jpeg" : "image/png";
            const blob = await canvas.convertToBlob({ type: mimeType, quality: 0.9 });
            const reader = new FileReader();
            return new Promise((resolve) => {
              reader.onload = () => {
                const result = reader.result;
                const b64 = result.split(",")[1];
                resolve({ image: b64, width: Math.round(rect.width), height: Math.round(rect.height) });
              };
              reader.readAsDataURL(blob);
            });
          },
          args: [base64, format, rectInfo],
        });

        const cropResult = cropResults[0]?.result;
        if (cropResult && cropResult.image) {
          return { image: cropResult.image, format, width: cropResult.width, height: cropResult.height };
        }
      }
    }

    return { image: base64, format };
  },

  // === File upload ===

  async uploadFile(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const { selector, fileName, mimeType, base64Data, filePath } = params;
    const frameId = params.frameId || 0;

    // Preferred path: a real local file via CDP DOM.setFileInputFiles.
    // Works on hidden inputs and fires trusted input/change events.
    if (filePath) {
      try {
        await ensureCdp(tabId);
        // Resolve the frame's document AND the session that owns it: OOPIFs
        // live on their child session, same-process frames on the root one.
        let docSessionId = null;
        let searchDocNodeId;
        if (frameId) {
          const doc = await cdpFrameDocTarget(tabId, frameId);
          if (!doc) {
            throw new Error(
              `FRAME_NOT_ACCESSIBLE: cannot resolve the document of frameId ${frameId} through the debugger ` +
                `(frame walk failed or the OOPIF child session never bound); retry after a get_page_structure pass so the frame is known`
            );
          }
          docSessionId = doc.sessionId;
          searchDocNodeId = doc.docNodeId;
        } else {
          const doc = await cdpDomCommandAt(tabId, null, "DOM.getDocument", { depth: 1 });
          searchDocNodeId = doc.root.nodeId;
        }
        // DOM domain calls go through the lazy-enable wrapper: child sessions
        // only get DOM.enable on first use, same as the root session.
        const q = await cdpDomCommandAt(tabId, docSessionId, "DOM.querySelector", {
          nodeId: searchDocNodeId,
          selector,
        });
        if (!q.nodeId) throw new Error(`ELEMENT_NOT_FOUND: ${selector}`);
        await cdpDomCommandAt(tabId, docSessionId, "DOM.setFileInputFiles", { files: [filePath], nodeId: q.nodeId });
        return {
          inputMode: "cdp",
          filePath,
          fileName: fileName || filePath.split(/[\\/]/).pop(),
          ...(frameId ? { frameId } : {}),
          ...(docSessionId ? { oopif: true } : {}),
        };
      } catch (e) {
        if (!(isCdpUnavailable(e) && base64Data)) throw e;
        // Debugger unavailable but we have base64 data: fall through.
      }
    }

    if (!base64Data) throw new Error("Either filePath or base64Data is required");

    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, frameId),
      world: "MAIN",
      func: (sel, name, mime, data) => {
        const input = document.querySelector(sel);
        if (!input) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        if (input.tagName.toLowerCase() !== "input" || input.type !== "file")
          return { error: "Element is not a file input" };
        try {
          const binary = atob(data);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const file = new File([bytes], name, { type: mime });
          const dt = new DataTransfer();
          dt.items.add(file);
          input.files = dt.files;
          input.dispatchEvent(new Event("change", { bubbles: true }));
          return { fileName: name, size: file.size, type: mime };
        } catch (e) {
          return { error: e.message };
        }
      },
      args: [selector, fileName, mimeType || "application/octet-stream", base64Data],
    });
    const r = results[0]?.result;
    if (r && r.error) throw new Error(r.error);
    return r || { success: true };
  },

  // === Window management ===

  async resizeWindow(params) {
    const { tabId, width, height } = params;
    let windowId;
    if (tabId) {
      const tab = await chrome.tabs.get(tabId);
      windowId = tab.windowId;
    } else {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab) throw new Error("No active tab found");
      windowId = activeTab.windowId;
    }
    const win = await chrome.windows.update(windowId, { width, height });
    return { windowId: win.id, width: win.width, height: win.height };
  },

  // === JavaScript execution ===

  async executeJavaScript(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const code = params.code;
    const allFrames = params.allFrames || false;
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames },
      world: "MAIN",
      func: async (c) => {
        try {
          const result = await (async () => { return eval(c); })();
          if (result === undefined) return { value: "undefined" };
          if (typeof result === "function") return { value: result.toString() };
          return { value: JSON.parse(JSON.stringify(result)) };
        } catch (e) {
          return {
            error: e.message,
            name: e.name,
            stack: e.stack?.split("\n").slice(0, 5).join("\n"),
          };
        }
      },
      args: [code],
    });
    if (allFrames) {
      const frames = results.map((fr) => {
        const r = fr.result;
        return {
          frameId: fr.frameId,
          ...(r && r.error
            ? { error: `${r.name || "Error"}: ${r.error}` }
            : { result: r ? r.value : null }),
        };
      });
      return { frames };
    }
    const r = results[0]?.result;
    if (r && r.error) throw new Error(`${r.name || "Error"}: ${r.error}`);
    return { result: r ? r.value : null };
  },

  // === Console messages ===

  async readConsoleMessages(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const level = params.level || "debug";
    const clear = params.clear || false;

    try {
      const session = await ensureCdp(tabId);
      const severityMap = { debug: 0, info: 1, log: 2, warn: 3, error: 4 };
      const minSeverity = severityMap[level] || 0;
      const messages = session.console.filter(
        (m) => (severityMap[m.level] || 0) >= minSeverity
      );
      if (clear) session.console.length = 0;
      return { source: "cdp", status: "active", messages };
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.readConsoleMessagesLegacy(params);
      throw e;
    }
  },

  // Fallback: page-world console hook (debugger unavailable).
  async readConsoleMessagesLegacy(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const level = params.level || "debug";
    const clear = params.clear || false;

    const results = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: (filterLevel, doClear) => {
        const severityMap = { debug: 0, info: 1, log: 2, warn: 3, error: 4 };
        const minSeverity = severityMap[filterLevel] || 0;

        if (!window.__claudeConsoleCapture) {
          window.__claudeConsoleCapture = [];
          const orig = {};
          ["log", "warn", "error", "info", "debug"].forEach((lvl) => {
            orig[lvl] = console[lvl];
            console[lvl] = function (...args) {
              window.__claudeConsoleCapture.push({
                level: lvl,
                message: args.map((a) => typeof a === "object" ? JSON.stringify(a) : String(a)).join(" "),
                timestamp: Date.now(),
              });
              if (window.__claudeConsoleCapture.length > 500) window.__claudeConsoleCapture.shift();
              return orig[lvl].apply(console, args);
            };
          });
          window.addEventListener("error", (e) => {
            window.__claudeConsoleCapture.push({
              level: "error",
              message: `${e.message} at ${e.filename}:${e.lineno}:${e.colno}`,
              timestamp: Date.now(),
            });
          });
          window.addEventListener("unhandledrejection", (e) => {
            window.__claudeConsoleCapture.push({
              level: "error",
              message: `Unhandled rejection: ${e.reason}`,
              timestamp: Date.now(),
            });
          });
          return { status: "monitoring_started", messages: [] };
        }

        const filtered = window.__claudeConsoleCapture.filter(
          (m) => (severityMap[m.level] || 0) >= minSeverity
        );

        if (doClear) {
          window.__claudeConsoleCapture = [];
        }

        return { status: "active", messages: filtered };
      },
      args: [level, clear],
    });
    return results[0]?.result || { messages: [] };
  },

  // === Network requests ===

  async readNetworkRequests(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const clear = params.clear || false;
    const { requestId, includeBody } = params;

    try {
      const session = await ensureCdp(tabId);

      // Single-request mode: WS entries answer with handshake + frame ring;
      // HTTP entries answer with the full entry + body via Network.getResponseBody.
      if (requestId) {
        const wsMap = session.webSockets;
        if (wsMap) {
          let ws = wsMap.get(requestId) || null;
          if (!ws) {
            // Composite keys (`sessionId:requestId`) mean the raw requestId
            // only hits root-session entries directly — scan for OOPIF ones.
            for (const w of wsMap.values()) {
              if (w.requestId === requestId) { ws = w; break; }
            }
          }
          if (ws) {
            return { source: "cdp", requestId, kind: "websocket", entry: summarizeWsEntry(ws, true) };
          }
        }
        const entry = session.network.get(requestId) || null;
        const out = { source: "cdp", requestId, entry };
        if (includeBody !== false) {
          try {
            const r = await cdpSend(tabId, "Network.getResponseBody", { requestId });
            out.base64Encoded = !!r.base64Encoded;
            out.body =
              !r.base64Encoded && r.body && r.body.length > 200000
                ? r.body.slice(0, 200000) + "\n...[truncated at 200KB]"
                : r.body;
          } catch (e) {
            out.body = null;
            out.bodyError = e.message || String(e);
          }
        }
        return out;
      }

      const entries = [...session.network.values()];
      if (session.webSockets) {
        for (const w of session.webSockets.values()) {
          entries.push(summarizeWsEntry(w, !!params.includeWsFrames && !params.summaryOnly));
        }
      }
      const page = paginateNetworkEntries(entries, params);
      if (clear) {
        session.network.clear();
        session.networkOrder.length = 0;
        if (session.webSockets) {
          session.webSockets.clear();
          session.webSocketOrder.length = 0;
        }
      }
      return { source: "cdp", ...page };
    } catch (e) {
      if (isCdpUnavailable(e)) return handlers.readNetworkRequestsLegacy(params);
      throw e;
    }
  },

  // Fallback: page-world fetch/XHR interception + Performance API
  // (debugger unavailable). Metadata only, no response bodies.
  async readNetworkRequestsLegacy(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const clear = params.clear || false;

    const results = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: (doClear) => {
        // Install interceptors if not already done
        if (!window.__claudeNetworkCapture) {
          window.__claudeNetworkCapture = [];
          window.__claudeNetworkIntercepting = true;

          // Wrap fetch
          const origFetch = window.fetch;
          window.fetch = function (...args) {
            const req = args[0];
            const url = typeof req === "string" ? req : req?.url || "";
            const method = (args[1]?.method || (typeof req !== "string" ? req?.method : null) || "GET").toUpperCase();
            const startTime = Date.now();

            return origFetch.apply(this, args).then(
              (response) => {
                const entry = {
                  url, method, status: response.status, statusText: response.statusText,
                  type: "fetch", duration: Date.now() - startTime, startTime,
                  responseHeaders: {},
                };
                response.headers.forEach((v, k) => { entry.responseHeaders[k] = v; });
                window.__claudeNetworkCapture.push(entry);
                if (window.__claudeNetworkCapture.length > 200) window.__claudeNetworkCapture.shift();
                return response;
              },
              (err) => {
                window.__claudeNetworkCapture.push({
                  url, method, type: "fetch", startTime,
                  duration: Date.now() - startTime, error: err.message,
                });
                throw err;
              }
            );
          };

          // Wrap XMLHttpRequest
          const origOpen = XMLHttpRequest.prototype.open;
          const origSend = XMLHttpRequest.prototype.send;

          XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            this.__claudeReq = { method: method.toUpperCase(), url: String(url) };
            return origOpen.call(this, method, url, ...rest);
          };

          XMLHttpRequest.prototype.send = function (body) {
            if (this.__claudeReq) {
              const info = this.__claudeReq;
              info.startTime = Date.now();

              this.addEventListener("load", () => {
                const entry = {
                  url: info.url, method: info.method,
                  status: this.status, statusText: this.statusText,
                  type: "xhr", duration: Date.now() - info.startTime,
                  startTime: info.startTime,
                  size: parseInt(this.getResponseHeader("content-length")) || 0,
                };
                window.__claudeNetworkCapture.push(entry);
                if (window.__claudeNetworkCapture.length > 200) window.__claudeNetworkCapture.shift();
              });

              this.addEventListener("error", () => {
                window.__claudeNetworkCapture.push({
                  url: info.url, method: info.method, type: "xhr",
                  startTime: info.startTime, duration: Date.now() - info.startTime,
                  error: "Request failed",
                });
              });
            }
            return origSend.call(this, body);
          };
        }

        // Also include performance API entries for pre-existing requests
        let requests = [...window.__claudeNetworkCapture];
        const perfEntries = performance.getEntriesByType("resource").slice(-100);
        for (const e of perfEntries) {
          const startTime = Math.round(performance.timeOrigin + e.startTime);
          // Only add if not already captured by intercept (check URL + timing proximity)
          const alreadyCaptured = requests.some(
            (r) => r.url === e.name && Math.abs(r.startTime - startTime) < 100
          );
          if (!alreadyCaptured) {
            requests.push({
              url: e.name, type: e.initiatorType,
              duration: Math.round(e.duration),
              size: e.transferSize || 0,
              startTime,
              status: e.responseStatus || undefined,
            });
          }
        }

        if (doClear) {
          window.__claudeNetworkCapture = [];
        }

        return { requests, intercepting: !!window.__claudeNetworkIntercepting };
      },
      args: [clear],
    });
    const result = results[0]?.result || { requests: [], intercepting: false };
    return {
      intercepting: !!result.intercepting,
      ...paginateNetworkEntries(result.requests || [], params),
    };
  },

  // === Downloads ===

  // Browser downloads: list recent entries, or resolve one by id for reading.
  // Triggering a download needs no tool of its own — click the link/button,
  // block on wait_for {download:true}, then find the file here. When
  // downloadPath is passed AND the tab's debugger is already attached, future
  // downloads are redirected via CDP Browser.setDownloadBehavior and matching
  // entries carry the CDP guid; any failure there degrades silently to the
  // plain chrome.downloads path (which works debugger-free).
  async listDownloads(params) {
    // read mode: a single download by id -> final local path + exists check.
    if (params.downloadId != null) {
      let items;
      try {
        items = await chrome.downloads.search({ id: Number(params.downloadId) });
      } catch (e) {
        throw new Error(`chrome.downloads.search failed: ${e.message}`);
      }
      const item = items && items[0];
      if (!item) {
        return {
          found: false,
          downloadId: Number(params.downloadId),
          detail: "No download with this id in browser history (it may have been cleared)",
        };
      }
      return {
        found: true,
        download: {
          id: item.id,
          filename: item.filename || null,
          localPath: item.filename || null,
          exists: !!item.exists,
          url: item.finalUrl || item.url,
          state: item.state,
          totalBytes: item.totalBytes,
          bytesReceived: item.bytesReceived,
          startTime: item.startTime,
          ...(item.mime ? { mime: item.mime } : {}),
          ...(item.endTime ? { endTime: item.endTime } : {}),
          ...(item.error ? { error: item.error } : {}),
        },
        ...(item.state === "complete" && item.exists && item.filename
          ? { detail: `File is on disk at ${item.filename} — local tools can read it directly` }
          : {}),
      };
    }

    // list mode: recent entries, newest first.
    const limit = Math.min(Math.max(Number(params.limit) || 20, 1), 200);
    let items;
    try {
      items = await chrome.downloads.search({
        orderBy: ["-startTime"],
        // Overfetch when filtering so `limit` applies after the filter.
        limit: params.urlFilter ? 200 : limit,
      });
    } catch (e) {
      throw new Error(`chrome.downloads.search failed: ${e.message}`);
    }
    items = items || [];
    if (params.urlFilter) {
      const q = String(params.urlFilter);
      items = items.filter(
        (it) => (it.url && it.url.includes(q)) || (it.finalUrl && it.finalUrl.includes(q))
      );
    }
    items = items.slice(0, limit);

    let tabId = params.tabId != null ? params.tabId : null;
    if (tabId == null) {
      try {
        tabId = await getActiveTabId();
      } catch {}
    }
    const session = tabId != null ? cdpSessions.get(tabId) : null;

    // Optional CDP redirect of the browser's download directory. Only when
    // the debugger is already attached — never auto-attach for this, and
    // never surface a failure (version/permission differences degrade to
    // the default directory without breaking the chrome.downloads path).
    let downloadPathStatus = null;
    if (params.downloadPath) {
      if (!session) {
        downloadPathStatus = {
          applied: false,
          reason: "debugger not attached to the tab; downloads keep going to Chrome's default directory",
        };
      } else {
        try {
          await cdpSendTo(tabId, null, "Browser.setDownloadBehavior", {
            behavior: "allow",
            downloadPath: String(params.downloadPath),
            eventsEnabled: true,
          });
          downloadPathStatus = { applied: true, downloadPath: String(params.downloadPath) };
        } catch (e) {
          downloadPathStatus = {
            applied: false,
            reason: `Browser.setDownloadBehavior unavailable (${e.message}); downloads keep going to Chrome's default directory`,
          };
        }
      }
    }

    // CDP correlation: Browser.downloadWillBegin events buffered on the tab's
    // session carry a guid + suggestedFilename; attach them to entries whose
    // URL matches so agents can tie chrome.downloads rows to raw CDP events
    // (read_cdp_events filter 'Browser.download').
    let guidByUrl = null;
    if (session) {
      for (const ev of session.events) {
        if (ev.method === "Browser.downloadWillBegin" && ev.params && ev.params.url) {
          if (!guidByUrl) guidByUrl = new Map();
          guidByUrl.set(ev.params.url, {
            guid: ev.params.guid,
            suggestedFilename: ev.params.suggestedFilename,
          });
        }
      }
    }

    const downloads = items.map((it) => {
      const cdpInfo = guidByUrl ? guidByUrl.get(it.url) || (it.finalUrl ? guidByUrl.get(it.finalUrl) : null) : null;
      return {
        id: it.id,
        filename: it.filename || null,
        url: it.finalUrl || it.url,
        state: it.state,
        totalBytes: it.totalBytes,
        exists: !!it.exists,
        startTime: it.startTime,
        ...(it.error ? { error: it.error } : {}),
        ...(cdpInfo ? { guid: cdpInfo.guid, suggestedFilename: cdpInfo.suggestedFilename, viaCdp: true } : {}),
      };
    });

    return {
      count: downloads.length,
      downloads,
      ...(downloadPathStatus ? { downloadPath: downloadPathStatus } : {}),
    };
  },

  // === Clipboard ===

  // Write text to the OS clipboard, mediated by a page tab. The clipboard is
  // a global OS resource — this overwrites whatever the user had copied.
  // Primary path needs no debugger: an injected temp textarea +
  // document.execCommand("copy") (backed by the clipboardWrite manifest
  // permission). When the page blocks or the API is gone, fall back to CDP:
  // grant clipboard-sanitizer-write to the page origin, then
  // navigator.clipboard.writeText with a synthetic user gesture. Both paths
  // failing produces one honest error naming both failures.
  async clipboardWrite(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const text = String(params.text != null ? params.text : "");

    let primaryError = null;
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: (t) => {
          const ta = document.createElement("textarea");
          ta.value = t;
          ta.setAttribute("readonly", "");
          ta.style.cssText = "position:fixed;top:0;left:0;opacity:0;pointer-events:none";
          document.body.appendChild(ta);
          ta.select();
          ta.setSelectionRange(0, ta.value.length);
          let ok = false;
          try {
            ok = document.execCommand("copy");
          } catch (e) {
            ok = false;
          }
          ta.remove();
          return ok;
        },
        args: [text],
      });
      const r0 = results && results[0];
      if (r0 && r0.result === true) {
        return { ok: true, length: text.length, method: "execCommand", tabId };
      }
      primaryError = (r0 && r0.error && r0.error.message) || "execCommand('copy') returned false (blocked by the page or deprecated)";
    } catch (e) {
      primaryError = e.message;
    }

    // Fallback: CDP writeText. Requires the debugger; grant the write
    // permission first, but a grant failure is not immediately fatal — the
    // origin may already hold the permission via site settings.
    let session;
    try {
      session = await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `CLIPBOARD_WRITE_FAILED: primary execCommand path failed (${primaryError}) and the CDP fallback could not attach the debugger to tab ${tabId}: ${e.message}`
      );
    }
    let permError = null;
    try {
      const tab = await chrome.tabs.get(tabId);
      const origin = new URL(tab.url).origin;
      await cdpSendTo(tabId, null, "Browser.setPermission", {
        origin,
        permission: "clipboard-sanitizer-write",
        value: "granted",
      });
    } catch (e) {
      permError = e.message;
    }
    let writeError = null;
    try {
      const res = await cdpSendTo(tabId, null, "Runtime.evaluate", {
        expression: `navigator.clipboard.writeText(${JSON.stringify(text)})`,
        awaitPromise: true,
        userGesture: true,
      });
      if (res && res.exceptionDetails) {
        const d = res.exceptionDetails;
        writeError = (d.exception && d.exception.description) || d.text || "writeText rejected";
      }
    } catch (e) {
      writeError = e.message;
    }
    if (writeError) {
      throw new Error(
        `CLIPBOARD_WRITE_FAILED: primary execCommand path failed (${primaryError}); CDP fallback writeText also failed (${writeError})` +
          (permError ? `; Browser.setPermission(clipboard-sanitizer-write) had failed too (${permError})` : "")
      );
    }
    return {
      ok: true,
      length: text.length,
      method: "cdp-writeText",
      tabId,
      ...(permError ? { permissionWarning: `writeText succeeded despite the grant failing: ${permError}` } : {}),
    };
  },

  // Read text from the OS clipboard, mediated by a page tab. CDP-only:
  // execCommand("paste") is dead in page context. Grants clipboard-read to
  // the page origin, then navigator.clipboard.readText() with a synthetic
  // user gesture. Some chrome.debugger builds do not expose the Browser
  // domain at all (setPermission answers -32601 "wasn't found") — that is a
  // missing method, NOT a denied permission, so the read proceeds directly:
  // the origin may already hold clipboard-read via site settings, and a
  // NotAllowedError from readText is then classified as the real denial.
  // readText requires a focused document, so: first attempt never steals
  // focus; only a focus-class failure triggers Page.bringToFront + exactly
  // one retry, flagged as broughtToFront:true in the result. Failure classes
  // are kept distinct so the agent knows whether to retry or give up:
  // PERMISSION_DENIED / FOCUS_FAILED / READ_FAILED / EMPTY.
  async clipboardRead(params) {
    const tabId = params.tabId || (await getActiveTabId());
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `CLIPBOARD_READ_FAILED: reading the clipboard needs the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    let origin;
    try {
      const tab = await chrome.tabs.get(tabId);
      origin = new URL(tab.url).origin;
    } catch (e) {
      throw new Error(`CLIPBOARD_READ_FAILED: cannot resolve tab ${tabId}'s origin for the permission grant: ${e.message}`);
    }
    let permMethodMissing = false;
    try {
      await cdpSendTo(tabId, null, "Browser.setPermission", {
        origin,
        permission: "clipboard-read",
        value: "granted",
      });
    } catch (e) {
      if (/wasn't found|unknown method|\b-32601\b/i.test(e.message || "")) {
        // Method does not exist in this runtime — fall through to readText.
        permMethodMissing = true;
      } else {
        throw new Error(
          `CLIPBOARD_PERMISSION_DENIED: Browser.setPermission(clipboard-read) for origin ${origin} failed: ${e.message}. The browser refused the permission override — retrying will not help; give up or ask the user to paste manually.`
        );
      }
    }

    const readOnce = async () => {
      const res = await cdpSendTo(tabId, null, "Runtime.evaluate", {
        expression: "navigator.clipboard.readText()",
        awaitPromise: true,
        userGesture: true,
        returnByValue: true,
      });
      if (res && res.exceptionDetails) {
        const d = res.exceptionDetails;
        const desc = (d.exception && d.exception.description) || d.text || "readText rejected";
        const err = new Error(desc);
        err.notAllowed = /NotAllowedError/.test(desc);
        err.focus = /not focused/i.test(desc);
        throw err;
      }
      return res && res.result ? res.result.value : undefined;
    };

    let text;
    let broughtToFront = false;
    try {
      text = await readOnce();
    } catch (e) {
      if (!(e.notAllowed && e.focus)) {
        if (e.notAllowed && permMethodMissing) {
          // No grant path exists in this runtime and readText was refused —
          // this IS the permission-denied terminal state.
          throw new Error(
            `CLIPBOARD_PERMISSION_DENIED: this Chrome debugging runtime does not expose Browser.setPermission, so the clipboard-read grant could not be attempted, and navigator.clipboard.readText() was rejected with NotAllowedError: ${e.message}. The origin lacks clipboard-read permission — retrying will not help; give up or ask the user to paste manually.`
          );
        }
        throw new Error(
          `CLIPBOARD_READ_FAILED: navigator.clipboard.readText() was rejected: ${e.message}` +
            (e.notAllowed
              ? " (NotAllowedError but not a focus problem — the origin's clipboard-read grant did not take; retrying is unlikely to help)"
              : "")
        );
      }
      // Focus-class failure: the user is in another window/tab. Steal focus
      // once (visible side effect, reported) and retry exactly once.
      try {
        await cdpSendTo(tabId, null, "Page.bringToFront", {});
        broughtToFront = true;
      } catch (e2) {
        throw new Error(
          `CLIPBOARD_FOCUS_FAILED: the document is not focused and Page.bringToFront failed too: ${e2.message}. Retry later when the user is back in this window.`
        );
      }
      try {
        text = await readOnce();
      } catch (e3) {
        throw new Error(
          `CLIPBOARD_FOCUS_FAILED: the document was not focused (user is in another window); brought the tab to front and retried, but the read still failed: ${e3.message}`
        );
      }
    }

    if (typeof text !== "string" || text === "") {
      return {
        text: "",
        empty: true,
        tabId,
        ...(broughtToFront ? { broughtToFront: true } : {}),
        detail:
          "CLIPBOARD_EMPTY: the clipboard holds no text (it may hold an image, or nothing) — not an error, but there is nothing to read",
      };
    }
    // Same cap as network response bodies in read_network_requests (200KB).
    let truncated = false;
    if (text.length > 200000) {
      text = text.slice(0, 200000);
      truncated = true;
    }
    return {
      text,
      length: text.length,
      tabId,
      ...(truncated ? { truncated: true, detail: "text truncated at 200KB (same cap as network bodies)" } : {}),
      ...(broughtToFront ? { broughtToFront: true } : {}),
    };
  },

  // === CDP passthrough & events ===

  // Send an arbitrary Chrome DevTools Protocol command. This is the escape
  // hatch that exposes every CDP domain (Network, Fetch, Emulation, Page,
  // DOM, Runtime, CSS, Performance, ...) on top of the curated tools.
  async cdpSendCommand(params) {
    const tabId = params.tabId || (await getActiveTabId());
    if (!params.method) throw new Error("method is required, e.g. 'Network.getCookies'");
    // Optional routing: sessionId addresses a CDP session directly; frameId
    // is the agent-friendly alias, resolved through the OOPIF binding table.
    let sessionId = params.sessionId || null;
    if (!sessionId && params.frameId) {
      const bound = await resolveFrameSession(tabId, params.frameId);
      if (!bound) {
        throw new Error(
          `FRAME_NOT_ATTACHED: frameId ${params.frameId} has no dedicated debugger session. ` +
            "Same-process frames share the tab's root session — omit frameId/sessionId and use frame-scoped " +
            "method params instead (e.g. DOM.getDocument with a frameId argument)."
        );
      }
      sessionId = bound.sessionId;
    }
    const result = await cdpSendTo(tabId, sessionId, params.method, params.params || {});
    return { tabId, method: params.method, ...(sessionId ? { sessionId } : {}), result: result === undefined ? null : result };
  },

  // Read the raw CDP event buffer for a tab (ring buffer, newest last).
  // Pair with cdpSendCommand for event-driven flows like Fetch interception:
  // enable a domain via cdpSendCommand, drain its events here.
  async readCdpEvents(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const session = await ensureCdp(tabId);
    const filter = params.methodFilter || null;
    const limit = params.limit || 100;

    let events = session.events;
    if (filter) {
      const filters = Array.isArray(filter) ? filter : [filter];
      events = events.filter((e) =>
        filters.some((f) => e.method === f || e.method.startsWith(f.endsWith(".") ? f : f + "."))
      );
    }
    // Session filter: child-session (OOPIF) events carry sessionId; events
    // from the tab's root session do not. "root" selects the latter.
    let wantSession = params.sessionId || null;
    if (!wantSession && params.frameId) {
      const bound = await resolveFrameSession(tabId, params.frameId);
      if (!bound) {
        throw new Error(
          `FRAME_NOT_ATTACHED: frameId ${params.frameId} has no dedicated debugger session — its events ` +
            "(if any) arrive on the tab's root session; read them without frameId."
        );
      }
      wantSession = bound.sessionId;
    }
    if (wantSession) {
      events =
        wantSession === "root"
          ? events.filter((e) => !e.sessionId)
          : events.filter((e) => e.sessionId === wantSession);
    }
    const slice = events.slice(-limit);
    if (params.clear) session.events.length = 0;
    return { tabId, count: slice.length, totalBuffered: session.events.length, events: slice };
  },

  async cdpDetachTarget(params) {
    const tabId = params.tabId || (await getActiveTabId());
    await cdpDetachTab(tabId);
    return { tabId, detached: true };
  },

  // Inspect and handle JavaScript dialogs (alert/confirm/prompt/beforeunload).
  // While a dialog is open the page's JS is blocked; this is the only way out.
  async handleDialog(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const session = await ensureCdp(tabId);
    const pending = session.dialogs.map((d) => ({
      type: d.type,
      message: d.message,
      defaultPrompt: d.defaultPrompt,
      // OOPIF dialogs must be answered on the child session that raised them;
      // surfaced so the agent can see where the dialog lives.
      ...(d.sessionId ? { sessionId: d.sessionId, oopif: true } : {}),
      ...(d.frameId != null ? { frameId: d.frameId } : {}),
    }));

    if (!params.action) return { tabId, pendingDialogs: pending };
    if (pending.length === 0) {
      return { tabId, pendingDialogs: [], handled: false, detail: "No dialog is currently open on this tab" };
    }

    const dialog = session.dialogs[0];
    const cmd = { accept: params.action === "accept" };
    if (params.promptText !== undefined) cmd.promptText = params.promptText;
    await cdpSendTo(tabId, dialog.sessionId || null, "Page.handleJavaScriptDialog", cmd);
    session.dialogs.shift();
    return {
      tabId,
      handled: true,
      action: params.action,
      dialog: {
        type: dialog.type,
        message: dialog.message,
        ...(dialog.sessionId ? { sessionId: dialog.sessionId } : {}),
        ...(dialog.frameId != null ? { frameId: dialog.frameId } : {}),
      },
      remainingDialogs: session.dialogs.length,
    };
  },

  // Device emulation: viewport metrics, touch, and user-agent override.
  async emulateDevice(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const preset = params.preset || "reset";
    await ensureCdp(tabId);

    const PRESETS = {
      iphone: {
        width: 390, height: 844, deviceScaleFactor: 3, mobile: true, touch: true,
        userAgent:
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      },
      ipad: {
        width: 820, height: 1180, deviceScaleFactor: 2, mobile: true, touch: true,
        userAgent:
          "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      },
      pixel: {
        width: 412, height: 915, deviceScaleFactor: 2.625, mobile: true, touch: true,
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
      },
    };

    if (preset === "reset" || preset === "none") {
      await cdpSend(tabId, "Emulation.clearDeviceMetricsOverride");
      await cdpSend(tabId, "Emulation.setTouchEmulationEnabled", { enabled: false });
      try {
        await cdpSend(tabId, "Emulation.setUserAgentOverride", { userAgent: "" });
      } catch {}
      return { tabId, emulating: false };
    }

    const cfg = { ...(PRESETS[preset] || PRESETS.iphone) };
    if (params.width) cfg.width = params.width;
    if (params.height) cfg.height = params.height;
    if (params.deviceScaleFactor) cfg.deviceScaleFactor = params.deviceScaleFactor;
    if (params.userAgent) cfg.userAgent = params.userAgent;
    if (params.mobile !== undefined) cfg.mobile = params.mobile;
    if (params.touch !== undefined) cfg.touch = params.touch;

    await cdpSend(tabId, "Emulation.setDeviceMetricsOverride", {
      width: cfg.width,
      height: cfg.height,
      deviceScaleFactor: cfg.deviceScaleFactor,
      mobile: cfg.mobile,
    });
    await cdpSend(tabId, "Emulation.setTouchEmulationEnabled", {
      enabled: cfg.touch,
      maxTouchPoints: cfg.touch ? 5 : 0,
    });
    if (cfg.userAgent) {
      const uaParams = { userAgent: cfg.userAgent };
      if (cfg.mobile) uaParams.platform = "Linux armv8l";
      await cdpSend(tabId, "Emulation.setUserAgentOverride", uaParams);
    }
    return { tabId, emulating: true, preset, ...cfg };
  },

  // === Request mocking (CDP Fetch interception) ===

  // One tool for the whole mock lifecycle: action fulfill/block/continue adds
  // a rule (and starts interception on first use), 'list' returns rules with
  // hit counts, 'clear' removes all rules for the tab and disables Fetch.
  async mockRequest(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action;
    await mockRulesReady;

    if (action === "list") {
      const rules = mockRules.get(tabId) || [];
      return { tabId, intercepting: rules.length > 0, count: rules.length, rules };
    }

    if (action === "clear") {
      const had = (mockRules.get(tabId) || []).length;
      mockRules.delete(tabId);
      persistMockRules();
      // Re-sync rather than blindly Fetch.disable: rewrite_traffic rules share
      // this pipeline and must keep intercepting. Skip the call entirely when
      // the debugger is detached — re-attaching only to disable would pop the
      // infobar for nothing.
      if (cdpSessions.has(tabId)) await applyFetchPatterns(tabId);
      return { tabId, cleared: had, intercepting: fetchPatternsFor(tabId).length > 0 };
    }

    // Add a rule: action is fulfill | block | continue.
    if (!params.urlPattern) {
      throw new Error("urlPattern is required when adding a mock rule (or use action 'list'/'clear')");
    }
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `mock_request requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }

    const pattern = String(params.urlPattern);
    const rule = {
      id: `mock_${mockRuleSeq++}`,
      action,
      hits: 0,
      createdTs: Date.now(),
    };
    assignUrlPattern(rule, pattern);
    if (action === "fulfill") {
      if (params.status !== undefined) rule.status = params.status;
      if (params.headers) rule.headers = params.headers;
      if (params.body !== undefined) rule.body = params.body;
    }

    const rules = mockRules.get(tabId) || [];
    rules.push(rule);
    mockRules.set(tabId, rules);
    persistMockRules();

    // (Re-)enable Fetch on the root session and any OOPIF child sessions.
    // Fetch.enable replaces the previous pattern list.
    await applyFetchPatterns(tabId);

    return { tabId, added: rule, ruleCount: rules.length, intercepting: true };
  },

  // Cookies via chrome.cookies (httpOnly included, no debugger). Storage via
  // the page main world. IndexedDB export is best-effort and capped.
  async browserSession(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action;
    const info = await tabHttpOrigin(tabId);

    if (action === "cookies") {
      const op = params.op || "list";
      if (op === "list") {
        const query = {};
        if (params.url) query.url = params.url;
        else if (params.domain) query.domain = params.domain;
        else query.url = info.url;
        if (params.partitionKey) query.partitionKey = params.partitionKey;
        const cookies = await chrome.cookies.getAll(query);
        return {
          tabId,
          origin: info.origin,
          count: cookies.length,
          ...(query.url ? { url: query.url } : {}),
          ...(query.domain ? { domain: query.domain } : {}),
          cookies: cookies.map(publicCookie),
        };
      }
      if (op === "remove") {
        if (!params.name) throw new Error("name is required to remove a cookie");
        const url = params.url || (params.domain ? cookieToUrl(params) : info.url);
        const removed = await chrome.cookies.remove({
          url,
          name: params.name,
          ...(params.storeId ? { storeId: params.storeId } : {}),
          ...(params.partitionKey ? { partitionKey: params.partitionKey } : {}),
        });
        return { tabId, removed: removed || null };
      }
      if (op === "set") {
        if (!params.name) throw new Error("name is required to set a cookie");
        const url = params.url || cookieToUrl({ ...params, url: params.url || (params.domain ? undefined : info.url) });
        const details = {
          url,
          name: params.name,
          value: params.value != null ? String(params.value) : "",
        };
        if (params.domain) details.domain = params.domain;
        if (params.path) details.path = params.path;
        if (params.secure != null) details.secure = !!params.secure;
        if (params.httpOnly != null) details.httpOnly = !!params.httpOnly;
        if (params.sameSite) details.sameSite = params.sameSite;
        if (params.expirationDate != null) details.expirationDate = params.expirationDate;
        if (params.storeId) details.storeId = params.storeId;
        if (params.partitionKey) details.partitionKey = params.partitionKey;
        const cookie = await chrome.cookies.set(details);
        if (!cookie) throw new Error("chrome.cookies.set returned null (the browser rejected the cookie)");
        return { tabId, cookie: publicCookie(cookie) };
      }
      throw new Error(`Unknown cookies op '${op}'. Use list, set, or remove.`);
    }

    if (action === "local" || action === "session") {
      const op = params.op === "list" || !params.op ? "get" : params.op;
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        world: "MAIN",
        func: (kind, operation, key, value, entries) => {
          const store = kind === "session" ? window.sessionStorage : window.localStorage;
          if (operation === "remove") {
            if (key == null || key === "") return { error: "key is required to remove a storage entry" };
            store.removeItem(String(key));
            return { removed: String(key) };
          }
          if (operation === "set") {
            const write = {};
            if (entries && typeof entries === "object") {
              for (const [k, v] of Object.entries(entries)) write[k] = v;
            }
            if (key != null && key !== "") write[String(key)] = value;
            if (!Object.keys(write).length) return { error: "set requires key and value, or entries" };
            const keys = [];
            for (const [k, v] of Object.entries(write)) {
              store.setItem(k, v == null ? "" : String(v));
              keys.push(k);
            }
            return { set: keys };
          }
          if (key != null && key !== "") return { key: String(key), value: store.getItem(String(key)) };
          const all = {};
          for (let i = 0; i < store.length; i++) {
            const k = store.key(i);
            all[k] = store.getItem(k);
          }
          return { entries: all, count: store.length };
        },
        args: [action, op, params.key ?? null, params.value ?? null, params.entries || null],
      });
      const r = results[0] && results[0].result;
      if (!r) throw new Error("STORAGE_FAILED: the page did not return storage data");
      if (r.error) throw new Error(r.error);
      return { tabId, origin: info.origin, storage: action, ...r };
    }

    if (action === "export") {
      const cookies = (await chrome.cookies.getAll({ url: info.url })).map(publicCookie);
      const dumped = await chrome.scripting.executeScript({
        target: { tabId },
        world: "MAIN",
        func: async (includeIdb, budget) => {
          const dumpStore = (store) => {
            const all = {};
            for (let i = 0; i < store.length; i++) {
              const k = store.key(i);
              all[k] = store.getItem(k);
            }
            return all;
          };
          const sanitize = (value, depth, seen) => {
            if (value == null || typeof value === "number" || typeof value === "string" || typeof value === "boolean") {
              return value;
            }
            if (typeof value === "bigint") return value.toString();
            if (depth > 30) return { __skipped: "depth" };
            if (typeof File !== "undefined" && value instanceof File) return { __skipped: "File" };
            if (typeof Blob !== "undefined" && value instanceof Blob) return { __skipped: "Blob" };
            if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return { __skipped: "binary" };
            if (value instanceof Date) return value.toISOString();
            if (typeof value !== "object") return { __skipped: typeof value };
            if (seen.has(value)) return { __skipped: "cycle" };
            seen.add(value);
            if (Array.isArray(value)) return value.map((v) => sanitize(v, depth + 1, seen));
            const out = {};
            for (const k of Object.keys(value)) out[k] = sanitize(value[k], depth + 1, seen);
            return out;
          };
          const out = {
            localStorage: dumpStore(localStorage),
            sessionStorage: dumpStore(sessionStorage),
          };
          if (!includeIdb) return out;
          const skipped = [];
          const databases = [];
          let truncated = false;
          let used = 0;
          const charge = (obj) => {
            let s;
            try {
              s = JSON.stringify(obj);
            } catch {
              return false;
            }
            if (used + s.length > budget) return false;
            used += s.length;
            return true;
          };
          let infos = [];
          try {
            infos = typeof indexedDB.databases === "function" ? (await indexedDB.databases()) || [] : [];
            if (typeof indexedDB.databases !== "function") {
              return { ...out, indexedDB: { databases, skipped, truncated, error: "indexedDB.databases() is not available" } };
            }
          } catch (e) {
            return { ...out, indexedDB: { databases, skipped, truncated, error: e.message || String(e) } };
          }
          for (const info of infos) {
            if (truncated || !info || !info.name) continue;
            let db;
            try {
              db = await new Promise((resolve, reject) => {
                const req = indexedDB.open(info.name);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error || new Error("open failed"));
                req.onblocked = () => reject(new Error("blocked"));
              });
            } catch (e) {
              skipped.push({ database: info.name, reason: e.message || String(e) });
              continue;
            }
            const dbOut = { name: info.name, version: db.version, stores: {} };
            try {
              for (const storeName of [...db.objectStoreNames]) {
                if (truncated) break;
                let records = [];
                try {
                  records = await new Promise((resolve, reject) => {
                    const tx = db.transaction(storeName, "readonly");
                    const req = tx.objectStore(storeName).getAll();
                    req.onsuccess = () => resolve(req.result || []);
                    req.onerror = () => reject(req.error || new Error("getAll failed"));
                  });
                } catch (e) {
                  skipped.push({ database: info.name, store: storeName, reason: e.message || String(e) });
                  continue;
                }
                const kept = [];
                for (const rec of records) {
                  const clean = sanitize(rec, 0, new WeakSet());
                  if (clean && clean.__skipped) {
                    skipped.push({ database: info.name, store: storeName, reason: clean.__skipped });
                    continue;
                  }
                  if (!charge(clean)) {
                    truncated = true;
                    break;
                  }
                  kept.push(clean);
                }
                dbOut.stores[storeName] = kept;
              }
            } finally {
              try { db.close(); } catch {}
            }
            databases.push(dbOut);
          }
          out.indexedDB = { databases, skipped, truncated, bytes: used };
          return out;
        },
        args: [!!params.includeIndexedDB, Math.floor(EXPORT_BYTE_BUDGET * 0.75)],
      });
      const page = (dumped[0] && dumped[0].result) || {};
      const payload = capSessionExport({
        origin: info.origin,
        url: info.url,
        exportedAt: new Date().toISOString(),
        cookies,
        localStorage: page.localStorage || {},
        sessionStorage: page.sessionStorage || {},
        ...(page.indexedDB ? { indexedDB: page.indexedDB } : {}),
      });
      const summary = {
        tabId,
        origin: info.origin,
        cookies: (payload.cookies || []).length,
        localStorageKeys: Object.keys(payload.localStorage || {}).length,
        sessionStorageKeys: Object.keys(payload.sessionStorage || {}).length,
        ...(payload.truncated ? { truncated: true } : {}),
        ...(payload.indexedDB
          ? { indexedDBDatabases: (payload.indexedDB.databases || []).length }
          : {}),
        ...(payload.indexedDBOmitted ? { indexedDBOmitted: true } : {}),
      };
      if (params.filePath) {
        return {
          artifact: {
            kind: "session",
            encoding: "utf8",
            data: JSON.stringify(payload),
            filePath: params.filePath,
            filename: "session.json",
          },
          summary,
        };
      }
      return { ...summary, ...payload };
    }

    if (action === "import") {
      const data = params.data;
      if (!data || typeof data !== "object") {
        throw new Error("import requires data (an object) or filePath (read by the server before this call)");
      }
      if (data.cookies != null && !Array.isArray(data.cookies)) {
        throw new Error("import data.cookies must be an array");
      }
      const now = Date.now() / 1000;
      let cookiesSet = 0;
      let skipped = 0;
      const errors = [];
      for (const c of data.cookies || []) {
        if (!c || !c.name) {
          skipped++;
          continue;
        }
        if (c.expirationDate != null && Number(c.expirationDate) < now) {
          skipped++;
          continue;
        }
        try {
          const url = c.url || cookieToUrl(c);
          const details = { url, name: c.name, value: c.value != null ? String(c.value) : "" };
          if (c.domain) details.domain = c.domain;
          if (c.path) details.path = c.path;
          if (c.secure != null) details.secure = !!c.secure;
          if (c.httpOnly != null) details.httpOnly = !!c.httpOnly;
          if (c.sameSite) details.sameSite = c.sameSite;
          if (c.expirationDate != null) details.expirationDate = c.expirationDate;
          if (c.storeId) details.storeId = c.storeId;
          if (c.partitionKey) details.partitionKey = c.partitionKey;
          const set = await chrome.cookies.set(details);
          if (!set) errors.push({ name: c.name, message: "chrome.cookies.set returned null" });
          else cookiesSet++;
        } catch (e) {
          errors.push({ name: c.name, message: e.message || String(e) });
        }
      }
      const stored = await chrome.scripting.executeScript({
        target: { tabId },
        world: "MAIN",
        func: (localBag, sessionBag) => {
          const write = (store, bag) => {
            if (!bag || typeof bag !== "object") return 0;
            let n = 0;
            for (const [k, v] of Object.entries(bag)) {
              store.setItem(k, v == null ? "" : String(v));
              n++;
            }
            return n;
          };
          return {
            localStorage: write(localStorage, localBag),
            sessionStorage: write(sessionStorage, sessionBag),
          };
        },
        args: [data.localStorage || null, data.sessionStorage || null],
      });
      const counts = (stored[0] && stored[0].result) || {};
      return {
        tabId,
        origin: info.origin,
        cookiesSet,
        skipped,
        ...(errors.length ? { errors } : {}),
        localStorage: counts.localStorage || 0,
        sessionStorage: counts.sessionStorage || 0,
        ...(data.origin && data.origin !== info.origin
          ? {
              originMismatch: {
                file: data.origin,
                tab: info.origin,
                detail:
                  "Storage was written into the tab origin. Each cookie was set from its own url or domain.",
              },
            }
          : {}),
      };
    }

    if (action === "clear") {
      await chrome.browsingData.remove(
        { origins: [info.origin] },
        { cookies: true, localStorage: true, indexedDB: true, cache: true }
      );
      return {
        tabId,
        origin: info.origin,
        cleared: ["cookies", "localStorage", "indexedDB", "cache"],
        sessionStorage: "left intact (chrome.browsingData has no sessionStorage type)",
      };
    }

    throw new Error(
      "browser_session action must be cookies, local, session, export, import, or clear"
    );
  },

  async grantPermission(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action || "grant";
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `grant_permission requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    if (action === "reset") {
      try {
        await cdpSend(tabId, "Browser.resetPermissions", {});
      } catch (e) {
        if (isCdpMethodMissing(e)) {
          throw codedError(
            "PERMISSION_API_UNAVAILABLE",
            `Browser.resetPermissions is not available in this Chrome debugger runtime (${e.message}). Permissions were not reset.`
          );
        }
        throw e;
      }
      return {
        tabId,
        reset: true,
        detail:
          "Browser.resetPermissions clears permission overrides for the debugger's browser context. It does not take an origin.",
      };
    }
    const permissions = Array.isArray(params.permissions) ? params.permissions.filter(Boolean) : [];
    if (!permissions.length) throw new Error("grant requires a non-empty permissions array of CDP PermissionType names");
    let origin = params.origin;
    if (!origin) origin = (await tabHttpOrigin(tabId)).origin;
    try {
      await cdpSend(tabId, "Browser.grantPermissions", { origin, permissions });
    } catch (e) {
      if (isCdpMethodMissing(e)) {
        throw codedError(
          "PERMISSION_API_UNAVAILABLE",
          `Browser.grantPermissions is not available in this Chrome debugger runtime (${e.message}). The grant was not applied.`
        );
      }
      throw e;
    }
    return {
      tabId,
      origin,
      granted: permissions,
      detail: "Geolocation coordinates are not set here. Use emulate_environment for latitude and longitude.",
    };
  },

  async describeElement(params) {
    const tabId = params.tabId || (await getActiveTabId());
    if (!params.ref && !params.selector) throw new Error("describe_element requires ref or selector");
    await ensureContentScripts(tabId);
    const routed = routeRef(tabId, params.ref);
    const frameId = routed ? routed.frameId : params.frameId || 0;
    const nonce = `cd${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const results = await chrome.scripting.executeScript({
      target: frameTarget(tabId, frameId),
      func: (refId, sel, stamp) => {
        const PROPS = [
          "display", "position", "visibility", "opacity", "overflow",
          "z-index", "color", "background-color", "font", "pointer-events",
        ];
        const findSel = (selector) => {
          const visit = (root) => {
            const hit = root.querySelector(selector);
            if (hit) return hit;
            for (const el of root.querySelectorAll("*")) {
              if (el.shadowRoot) {
                const inner = visit(el.shadowRoot);
                if (inner) return inner;
              }
            }
            return null;
          };
          return visit(document);
        };
        let el = null;
        if (refId) {
          const a11y = globalThis.__claudeA11yTree;
          if (a11y) el = a11y.getElementByRef(refId);
          if (!el) return { error: `REF_NOT_FOUND: ${refId}` };
        } else {
          try {
            el = findSel(sel);
          } catch (e) {
            return { error: `SELECTOR_INVALID: ${e.message}` };
          }
          if (!el) return { error: `ELEMENT_NOT_FOUND: ${sel}` };
        }
        try { el.setAttribute("data-claude-describe", stamp); } catch {}
        const rect = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        const style = {};
        for (const p of PROPS) style[p] = cs.getPropertyValue(p);
        const a11y = globalThis.__claudeA11yTree;
        const root = el.getRootNode();
        return {
          tagName: el.tagName.toLowerCase(),
          ref: a11y ? a11y.getRefForElement(el) : null,
          shadow: !!(window.ShadowRoot && root instanceof ShadowRoot),
          rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          style,
          stamped: true,
        };
      },
      args: [routed ? routed.localRef : null, params.selector || null, nonce],
    });
    const r = results[0] && results[0].result;
    if (!r) throw new Error("ELEMENT_NOT_FOUND: page did not respond");
    if (r.error) {
      if (String(r.error).startsWith("REF_NOT_FOUND") && params.ref) {
        throw new Error(
          `REF_NOT_FOUND: ${params.ref} — the element is no longer registered (page changed or the snapshot is stale); re-run get_page_structure`
        );
      }
      throw new Error(r.error);
    }
    const out = {
      tabId,
      tagName: r.tagName,
      ...(r.shadow ? { shadow: true } : {}),
      ...(frameId ? { frameId } : {}),
      rect: r.rect,
      style: r.style,
    };
    if (r.ref) out.ref = unrouteRef(tabId, frameId, r.ref);
    const off = await frameRectOffset(tabId, frameId);
    if (frameId) {
      if (off) {
        out.rect = { ...out.rect, x: out.rect.x + off.x, y: out.rect.y + off.y };
      } else {
        out.rectFrameLocal = true;
      }
    }
    let objectId = null;
    let sessionId = null;
    try {
      await ensureCdp(tabId);
      if (frameId) {
        const bound = await resolveFrameSession(tabId, frameId);
        sessionId = bound ? bound.sessionId : null;
      }
      // Same-process iframes share the root debugger session, whose default
      // execution context is the top document. Open a world in the frame that
      // actually holds the stamp so the shadow walk sees that document.
      let contextId = null;
      if (frameId && !sessionId) {
        const docTarget = await cdpFrameDocTarget(tabId, frameId);
        if (!docTarget || docTarget.docNodeId == null) {
          throw new Error("frame document is not available to the debugger");
        }
        sessionId = docTarget.sessionId || null;
        const described = await cdpDomCommandAt(tabId, sessionId, "DOM.describeNode", {
          nodeId: docTarget.docNodeId,
        });
        const cdpFrameId = described && described.node && described.node.frameId;
        if (!cdpFrameId) throw new Error("frame has no CDP frame id");
        const world = await cdpSendTo(tabId, sessionId, "Page.createIsolatedWorld", {
          frameId: cdpFrameId,
          worldName: "claude-describe",
        });
        contextId = world && world.executionContextId;
        if (contextId == null) throw new Error("Page.createIsolatedWorld returned no execution context");
      }
      const expression = `(() => {
        const stamp = ${JSON.stringify(nonce)};
        function walk(root) {
          const hit = root.querySelector('[data-claude-describe="' + stamp + '"]');
          if (hit) return hit;
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) {
              const inner = walk(el.shadowRoot);
              if (inner) return inner;
            }
          }
          return null;
        }
        return walk(document);
      })()`;
      const ev = await cdpSendTo(tabId, sessionId, "Runtime.evaluate", {
        expression,
        ...(contextId != null ? { contextId } : {}),
      });
      objectId = ev && ev.result && ev.result.objectId;
      if (!objectId) {
        out.boxModelError = "element not reachable from the debugger session";
      } else {
        const req = await cdpDomCommandAt(tabId, sessionId, "DOM.requestNode", { objectId });
        const model = await cdpDomCommandAt(tabId, sessionId, "DOM.getBoxModel", { nodeId: req.nodeId });
        const box = model && model.model ? model.model : null;
        if (box && off && frameId) {
          out.boxModel = {
            ...box,
            content: shiftQuad(box.content, off.x, off.y),
            padding: shiftQuad(box.padding, off.x, off.y),
            border: shiftQuad(box.border, off.x, off.y),
            margin: shiftQuad(box.margin, off.x, off.y),
          };
        } else {
          out.boxModel = box;
          if (frameId && !off) out.boxModelFrameLocal = true;
        }
      }
    } catch (e) {
      out.boxModelError = isCdpUnavailable(e)
        ? "debugger unavailable"
        : (e && e.message) || String(e);
    } finally {
      if (objectId) {
        try { await cdpSendTo(tabId, sessionId, "Runtime.releaseObject", { objectId }); } catch {}
      }
      if (r.stamped) {
        try {
          await chrome.scripting.executeScript({
            target: frameTarget(tabId, frameId),
            func: (stamp) => {
              const visit = (root) => {
                const hit = root.querySelector(`[data-claude-describe="${stamp}"]`);
                if (hit) {
                  hit.removeAttribute("data-claude-describe");
                  return;
                }
                for (const el of root.querySelectorAll("*")) {
                  if (el.shadowRoot) visit(el.shadowRoot);
                }
              };
              visit(document);
            },
            args: [nonce],
          });
        } catch {}
      }
    }
    return out;
  },

  async findText(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const query = params.query != null ? String(params.query) : "";
    if (!query) throw new Error("find_text requires a non-empty query");
    const caseSensitive = !!params.caseSensitive;
    const limit = Math.min(100, Math.max(1, Number(params.limit) || 30));
    const cap = 1000;
    await ensureContentScripts(tabId);
    const scan = (q, sensitive, maxMatches, focusLocal) => {
      const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT"]);
      const needle = sensitive ? q : q.toLowerCase();
      const matches = [];
      let truncated = false;
      const consider = (node) => {
        if (matches.length >= maxMatches) {
          truncated = true;
          return;
        }
        const el = node.parentElement;
        if (!el || SKIP.has(el.tagName)) return;
        const style = getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden") return;
        const text = node.textContent || "";
        if (!text) return;
        const hay = sensitive ? text : text.toLowerCase();
        let from = 0;
        while (from <= hay.length && matches.length < maxMatches) {
          const at = hay.indexOf(needle, from);
          if (at < 0) break;
          const range = document.createRange();
          range.setStart(node, at);
          range.setEnd(node, at + q.length);
          const rect = range.getBoundingClientRect();
          const a11y = globalThis.__claudeA11yTree;
          const item = {
            snippet:
              (at > 40 ? "…" : "") +
              text.slice(Math.max(0, at - 40), Math.min(text.length, at + q.length + 40)) +
              (at + q.length + 40 < text.length ? "…" : ""),
            rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          };
          if (a11y) {
            const ref = a11y.getRefForElement(el);
            if (ref) item.ref = ref;
          }
          if (window.ShadowRoot && el.getRootNode() instanceof ShadowRoot) item.shadow = true;
          if (focusLocal === matches.length) {
            const sel = window.getSelection();
            if (sel) {
              sel.removeAllRanges();
              sel.addRange(range);
            }
            try { el.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" }); } catch {}
            try {
              if (!document.getElementById("claude-find-style")) {
                const st = document.createElement("style");
                st.id = "claude-find-style";
                st.textContent = "::highlight(claude-find){background-color:#ffe08a;color:inherit}";
                (document.head || document.documentElement).appendChild(st);
              }
              CSS.highlights.set("claude-find", new Highlight(range));
            } catch {}
            const again = range.getBoundingClientRect();
            item.rect = { x: again.x, y: again.y, width: again.width, height: again.height };
            item.focused = true;
          }
          matches.push(item);
          from = at + Math.max(q.length, 1);
        }
      };
      const walk = (root) => {
        if (truncated) return;
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        let n;
        while ((n = walker.nextNode())) {
          consider(n);
          if (truncated) return;
        }
        const elements = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
        let el;
        while ((el = elements.nextNode())) {
          if (el.shadowRoot) walk(el.shadowRoot);
          if (truncated) return;
        }
      };
      if (document.body) walk(document.body);
      return { matches, truncated };
    };
    const frames = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: scan,
      args: [query, caseSensitive, cap, null],
    });
    const ordered = (frames || []).filter((fr) => fr && fr.result);
    ordered.sort((a, b) => (a.frameId === 0 ? -1 : b.frameId === 0 ? 1 : a.frameId - b.frameId));
    const merged = [];
    let truncated = false;
    for (const fr of ordered) {
      if (fr.result.truncated) truncated = true;
      for (const item of fr.result.matches || []) {
        item.frameId = fr.frameId;
        if (item.ref) item.ref = internRef(tabId, fr.frameId, item.ref);
        item.index = merged.length;
        merged.push(item);
      }
    }
    let focused = null;
    if (params.index != null) {
      const index = Number(params.index);
      if (!Number.isInteger(index) || index < 0 || index >= merged.length) {
        throw new Error(`MATCH_INDEX_OUT_OF_RANGE: index ${params.index} but ${merged.length} match(es) were found`);
      }
      let seen = 0;
      let owner = null;
      let localIndex = 0;
      for (const fr of ordered) {
        const n = (fr.result.matches || []).length;
        if (seen + n > index) {
          owner = fr;
          localIndex = index - seen;
          break;
        }
        seen += n;
      }
      if (owner) {
        const again = await chrome.scripting.executeScript({
          target: frameTarget(tabId, owner.frameId),
          func: scan,
          args: [query, caseSensitive, cap, localIndex],
        });
        const got = again[0] && again[0].result && again[0].result.matches && again[0].result.matches[localIndex];
        if (got) {
          merged[index].rect = got.rect;
          merged[index].focused = true;
          focused = { index, frameId: owner.frameId, scrolled: true };
        }
      }
    }
    const offsets = new Map();
    for (const item of merged) {
      if (!item.frameId || !item.rect) continue;
      if (!offsets.has(item.frameId)) offsets.set(item.frameId, await frameRectOffset(tabId, item.frameId));
      const off = offsets.get(item.frameId);
      if (off) {
        item.rect = { ...item.rect, x: item.rect.x + off.x, y: item.rect.y + off.y };
      } else {
        item.rectFrameLocal = true;
      }
    }
    const shown = merged.slice(0, limit).map((item) => {
      const copy = { ...item };
      if (!copy.frameId) delete copy.frameId;
      return copy;
    });
    if (focused && focused.index >= limit) {
      const extra = { ...merged[focused.index] };
      if (!extra.frameId) delete extra.frameId;
      shown.push(extra);
    }
    return {
      tabId,
      query,
      count: merged.length,
      ...(truncated ? { truncated: true, detail: `stopped after ${cap} matches` } : {}),
      matches: shown,
      ...(focused ? { focused } : {}),
    };
  },

  async pageSelection(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action || "read";
    await ensureContentScripts(tabId);
    if (action === "clear") {
      await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: () => {
          const sel = window.getSelection();
          if (sel) sel.removeAllRanges();
          try { CSS.highlights.delete("claude-find"); } catch {}
          return true;
        },
      });
      return { tabId, cleared: true };
    }
    if (action === "read") {
      const frames = await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: () => {
          const sel = window.getSelection();
          if (!sel || sel.rangeCount === 0 || sel.isCollapsed) {
            return { text: "", collapsed: true };
          }
          const text = sel.toString();
          const node = sel.anchorNode;
          const el = node ? (node.nodeType === 1 ? node : node.parentElement) : null;
          const a11y = globalThis.__claudeA11yTree;
          const range = sel.getRangeAt(0);
          const rect = range.getBoundingClientRect();
          return {
            text,
            collapsed: false,
            ref: el && a11y ? a11y.getRefForElement(el) : null,
            rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          };
        },
      });
      const ordered = (frames || []).filter((fr) => fr && fr.result);
      ordered.sort((a, b) => (a.frameId === 0 ? -1 : b.frameId === 0 ? 1 : a.frameId - b.frameId));
      const hit = ordered.find((fr) => fr.result && fr.result.text) || ordered[0];
      if (!hit || !hit.result) return { tabId, text: "", collapsed: true };
      const r = hit.result;
      if (r.ref) r.ref = unrouteRef(tabId, hit.frameId, r.ref);
      if (hit.frameId && r.rect) {
        const off = await frameRectOffset(tabId, hit.frameId);
        if (off) r.rect = { ...r.rect, x: r.rect.x + off.x, y: r.rect.y + off.y };
        else r.rectFrameLocal = true;
      }
      return {
        tabId,
        text: r.text || "",
        collapsed: !!r.collapsed,
        ...(hit.frameId ? { frameId: hit.frameId } : {}),
        ...(r.ref ? { ref: r.ref } : {}),
        ...(r.rect ? { rect: r.rect } : {}),
        ...(r.rectFrameLocal ? { rectFrameLocal: true } : {}),
      };
    }
    if (action === "select") {
      if (!params.ref && !params.text) throw new Error("select requires ref or text");
      const routed = routeRef(tabId, params.ref);
      const run = async (frameId, refId, text) => {
        const res = await chrome.scripting.executeScript({
          target: frameTarget(tabId, frameId),
          func: (localRef, visibleText) => {
            const sel = window.getSelection();
            if (!sel) return { error: "SELECTION_UNAVAILABLE: window.getSelection() returned null" };
            sel.removeAllRanges();
            if (localRef) {
              const a11y = globalThis.__claudeA11yTree;
              const el = a11y && a11y.getElementByRef(localRef);
              if (!el) return { error: `REF_NOT_FOUND: ${localRef}` };
              const range = document.createRange();
              range.selectNodeContents(el);
              sel.addRange(range);
              try { el.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" }); } catch {}
              const rect = range.getBoundingClientRect();
              return {
                text: sel.toString(),
                ref: a11y.getRefForElement(el),
                rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
              };
            }
            const needle = String(visibleText);
            const lower = needle.toLowerCase();
            const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT"]);
            const visit = (root) => {
              const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
              let n;
              while ((n = walker.nextNode())) {
                const el = n.parentElement;
                if (!el || SKIP.has(el.tagName)) continue;
                const style = getComputedStyle(el);
                if (style.display === "none" || style.visibility === "hidden") continue;
                const text = n.textContent || "";
                const at = text.toLowerCase().indexOf(lower);
                if (at < 0) continue;
                const range = document.createRange();
                range.setStart(n, at);
                range.setEnd(n, at + needle.length);
                sel.addRange(range);
                try { el.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" }); } catch {}
                const rect = range.getBoundingClientRect();
                const a11y = globalThis.__claudeA11yTree;
                return {
                  text: sel.toString(),
                  ref: a11y ? a11y.getRefForElement(el) : null,
                  rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
                };
              }
              const elements = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
              let el;
              while ((el = elements.nextNode())) {
                if (el.shadowRoot) {
                  const hit = visit(el.shadowRoot);
                  if (hit) return hit;
                }
              }
              return null;
            };
            const hit = document.body ? visit(document.body) : null;
            if (!hit) return { error: `TEXT_NOT_FOUND: ${needle}` };
            return hit;
          },
          args: [refId, text],
        });
        return { frameId, result: res[0] && res[0].result };
      };
      let picked = null;
      if (params.ref) {
        picked = await run(routed ? routed.frameId : params.frameId || 0, routed ? routed.localRef : params.ref, null);
      } else {
        const frames = await chrome.webNavigation.getAllFrames({ tabId });
        const ids = (frames || []).map((f) => f.frameId).sort((a, b) => (a === 0 ? -1 : b === 0 ? 1 : a - b));
        for (const fid of ids) {
          const got = await run(fid, null, params.text);
          if (got.result && !got.result.error) {
            picked = got;
            break;
          }
          if (!picked) picked = got;
        }
      }
      const r = picked && picked.result;
      if (!r) throw new Error("SELECTION_FAILED: page did not respond");
      if (r.error) {
        if (String(r.error).startsWith("REF_NOT_FOUND") && params.ref) {
          throw new Error(
            `REF_NOT_FOUND: ${params.ref} — the element is no longer registered; re-run get_page_structure`
          );
        }
        throw new Error(r.error);
      }
      if (r.ref) r.ref = unrouteRef(tabId, picked.frameId, r.ref);
      if (picked.frameId && r.rect) {
        const off = await frameRectOffset(tabId, picked.frameId);
        if (off) r.rect = { ...r.rect, x: r.rect.x + off.x, y: r.rect.y + off.y };
        else r.rectFrameLocal = true;
      }
      return {
        tabId,
        selected: true,
        text: r.text || "",
        ...(picked.frameId ? { frameId: picked.frameId } : {}),
        ...(r.ref ? { ref: r.ref } : {}),
        ...(r.rect ? { rect: r.rect } : {}),
        ...(r.rectFrameLocal ? { rectFrameLocal: true } : {}),
      };
    }
    throw new Error("page_selection action must be read, select, or clear");
  },

  async savePage(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const format = params.format || "pdf";
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `save_page requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    if (format === "mhtml") {
      const snap = await cdpSend(tabId, "Page.captureSnapshot", { format: "mhtml" });
      const data = (snap && snap.data) || "";
      return {
        artifact: {
          kind: "mhtml",
          encoding: "utf8",
          data,
          filePath: params.filePath,
          filename: "page.mhtml",
        },
        summary: { format: "mhtml", tabId },
      };
    }
    if (format !== "pdf") throw new Error(`Unknown save_page format '${format}'. Use pdf or mhtml.`);
    const pdfParams = {};
    if (params.printBackground != null) pdfParams.printBackground = !!params.printBackground;
    if (params.paperWidth != null) pdfParams.paperWidth = params.paperWidth;
    if (params.paperHeight != null) pdfParams.paperHeight = params.paperHeight;
    if (params.landscape != null) pdfParams.landscape = !!params.landscape;
    const pdf = await cdpSend(tabId, "Page.printToPDF", pdfParams);
    const data = (pdf && pdf.data) || "";
    if (!data) throw new Error("Page.printToPDF returned no data");
    return {
      artifact: {
        kind: "pdf",
        encoding: "base64",
        data,
        filePath: params.filePath,
        filename: "page.pdf",
      },
      summary: { format: "pdf", tabId, ...(params.printBackground != null ? { printBackground: !!params.printBackground } : {}) },
    };
  },

  async rewriteTraffic(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action;
    await rewriteRulesReady;

    if (action === "list") {
      const rules = rewriteRules.get(tabId) || [];
      return {
        tabId,
        count: rules.length,
        extraHeaders: mergedExtraHeaders(tabId),
        intercepting: fetchPatternsFor(tabId).length > 0,
        rules,
      };
    }

    if (action === "clear") {
      const had = (rewriteRules.get(tabId) || []).length;
      rewriteRules.delete(tabId);
      persistRewriteRules();
      if (cdpSessions.has(tabId)) {
        await applyFetchPatterns(tabId);
        await applyExtraHeaders(tabId, {});
      }
      return { tabId, cleared: had, intercepting: fetchPatternsFor(tabId).length > 0 };
    }

    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `rewrite_traffic requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }

    if (action === "headers") {
      const headers = params.headers;
      if (!headers || typeof headers !== "object" || !Object.keys(headers).length) {
        throw new Error("headers action requires a headers object of {name: value}");
      }
      const rule = {
        id: `rewrite_${rewriteRuleSeq++}`,
        kind: "headers",
        headers,
        hits: 0,
        createdTs: Date.now(),
      };
      if (params.urlPattern) assignUrlPattern(rule, String(params.urlPattern));
      const rules = rewriteRules.get(tabId) || [];
      rules.push(rule);
      rewriteRules.set(tabId, rules);
      persistRewriteRules();
      if (rule.urlPattern || rule.regex) await applyFetchPatterns(tabId);
      else await applyExtraHeaders(tabId, mergedExtraHeaders(tabId) || {});
      return {
        tabId,
        added: rule,
        ruleCount: rules.length,
        scope: rule.urlPattern || rule.regex ? "matching-requests" : "all-requests",
      };
    }

    if (action === "patch") {
      if (!params.urlPattern) throw new Error("patch requires urlPattern (substring, or /regex/)");
      if (
        params.status == null &&
        !params.headers &&
        params.body === undefined &&
        params.find == null
      ) {
        throw new Error("patch requires at least one of status, headers, body, or find/replace");
      }
      const rule = {
        id: `rewrite_${rewriteRuleSeq++}`,
        kind: "patch",
        hits: 0,
        truncated: 0,
        skipped: 0,
        createdTs: Date.now(),
      };
      assignUrlPattern(rule, String(params.urlPattern));
      if (params.status != null) rule.status = params.status;
      if (params.headers) rule.responseHeaders = params.headers;
      if (params.body !== undefined) rule.body = params.body;
      if (params.find != null) {
        if (String(params.find) === "") throw new Error("find must be a non-empty literal string");
        rule.find = String(params.find);
        rule.replace = params.replace != null ? String(params.replace) : "";
      }
      const rules = rewriteRules.get(tabId) || [];
      rules.push(rule);
      rewriteRules.set(tabId, rules);
      persistRewriteRules();
      await applyFetchPatterns(tabId);
      return {
        tabId,
        added: rule,
        ruleCount: rules.length,
        detail:
          "Text response bodies over 200KB are left unchanged and counted on the rule as truncated. Binary bodies are not find/replaced. A body field replaces the payload entirely (and wins over find/replace). Mock fulfill/block still wins over this patch.",
      };
    }

    throw new Error("rewrite_traffic action must be headers, patch, list, or clear");
  },

  async exportHar(params) {
    const tabId = params.tabId || (await getActiveTabId());
    let session;
    try {
      session = await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `export_har requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    const info = await chrome.tabs.get(tabId).catch(() => null);
    const httpEntries = [];
    for (const key of session.networkOrder || []) {
      const entry = session.network.get(key);
      if (!entry) continue;
      if (entry.resourceType === "WebSocket") continue;
      httpEntries.push(entry);
    }
    let budget = EXPORT_BYTE_BUDGET;
    let bodiesIncluded = 0;
    let bodiesOmitted = 0;
    const harEntries = [];
    for (const entry of httpEntries) {
      let bodyText = null;
      let bodyEncoding = null;
      let bodyComment = null;
      if (params.includeBodies && entry.done && !entry.error) {
        const declared = Number(entry.size);
        if (Number.isFinite(declared) && declared > budget) {
          bodiesOmitted++;
          bodyComment = "body omitted: export budget exceeded";
        } else {
          try {
            const fetched = await cdpSendTo(tabId, entry.sessionId || null, "Network.getResponseBody", {
              requestId: entry.requestId,
            });
            const text = (fetched && fetched.body) || "";
            const bytes = fetched && fetched.base64Encoded ? Math.floor((text.length * 3) / 4) : text.length;
            if (bytes > budget) {
              bodiesOmitted++;
              bodyComment = "body omitted: export budget exceeded";
            } else {
              budget -= bytes;
              bodiesIncluded++;
              bodyText = text;
              if (fetched && fetched.base64Encoded) bodyEncoding = "base64";
            }
          } catch {
            bodiesOmitted++;
            bodyComment = "body omitted: Network.getResponseBody failed";
          }
        }
      }
      const wait = entry.duration != null ? entry.duration : -1;
      const postMime = headerValue(entry.requestHeaders, "content-type");
      harEntries.push({
        ...(info ? { pageref: "page_1" } : {}),
        startedDateTime: new Date(entry.startTime || Date.now()).toISOString(),
        time: wait >= 0 ? wait : 0,
        request: {
          method: entry.method || "GET",
          url: entry.url || "",
          httpVersion: harHttpVersion(entry.protocol),
          cookies: [],
          headers: harHeaders(entry.requestHeaders),
          queryString: harQuery(entry.url || ""),
          headersSize: -1,
          bodySize: entry.postData ? entry.postData.length : -1,
          ...(entry.postData
            ? { postData: { mimeType: postMime, text: entry.postData } }
            : {}),
        },
        response: {
          status: entry.status != null ? entry.status : 0,
          statusText: entry.statusText || "",
          httpVersion: harHttpVersion(entry.protocol),
          cookies: [],
          headers: harHeaders(entry.responseHeaders),
          content: {
            size: entry.size != null ? entry.size : bodyText != null ? bodyText.length : 0,
            mimeType: entry.mimeType || "",
            ...(bodyText != null ? { text: bodyText } : {}),
            ...(bodyEncoding ? { encoding: bodyEncoding } : {}),
            ...(bodyComment ? { comment: bodyComment } : {}),
          },
          redirectURL: entry.redirectUrl || "",
          headersSize: -1,
          bodySize: entry.size != null ? entry.size : -1,
        },
        cache: {},
        timings: { send: -1, wait, receive: -1 },
      });
    }
    const log = {
      version: "1.2",
      creator: { name: "claude-chrome-bridge", version: "3.4.0" },
      pages: info
        ? [
            {
              startedDateTime: new Date().toISOString(),
              id: "page_1",
              title: info.title || "",
              pageTimings: { onContentLoad: -1, onLoad: -1 },
            },
          ]
        : [],
      entries: harEntries,
    };
    return {
      artifact: {
        kind: "har",
        encoding: "utf8",
        data: JSON.stringify({ log }),
        filePath: params.filePath,
        filename: "network.har",
      },
      summary: {
        tabId,
        entries: harEntries.length,
        websocketsExcluded: true,
        ...(params.includeBodies
          ? { bodiesIncluded, bodiesOmitted, bodyBudget: EXPORT_BYTE_BUDGET }
          : {}),
      },
    };
  },

  async emulateEnvironment(params) {
    const tabId = params.tabId || (await getActiveTabId());
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `emulate_environment requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    const applied = {};
    if (params.geolocation !== undefined) {
      if (params.geolocation === null) {
        applied.geolocation = await emulateOnSessions(tabId, "Emulation.clearGeolocationOverride", {});
        applied.geolocation.cleared = true;
      } else {
        const g = params.geolocation || {};
        if (typeof g.latitude !== "number" || typeof g.longitude !== "number") {
          throw new Error("geolocation requires latitude and longitude numbers, or null to clear");
        }
        const accuracy = g.accuracy != null ? g.accuracy : 1;
        let origin = null;
        try {
          origin = (await tabHttpOrigin(tabId)).origin;
        } catch {
          origin = null;
        }
        const permission = { status: "skipped" };
        if (origin) {
          try {
            await cdpSend(tabId, "Browser.grantPermissions", {
              origin,
              permissions: ["geolocation"],
            });
            permission.status = "granted";
            permission.origin = origin;
          } catch (e) {
            if (isCdpMethodMissing(e)) {
              permission.status = "unavailable";
              permission.detail =
                "Browser.grantPermissions is not available in this debugger runtime. Coordinates were still overridden; the page may not see them until geolocation is allowed.";
            } else {
              permission.status = "failed";
              permission.detail = e.message || String(e);
            }
          }
        }
        const set = await emulateOnSessions(tabId, "Emulation.setGeolocationOverride", {
          latitude: g.latitude,
          longitude: g.longitude,
          accuracy,
        });
        applied.geolocation = { latitude: g.latitude, longitude: g.longitude, accuracy, permission, ...set };
      }
    }
    if (params.timezone !== undefined) {
      const timezoneId = params.timezone == null ? "" : String(params.timezone);
      applied.timezone = {
        timezoneId: timezoneId || null,
        ...(await emulateOnSessions(tabId, "Emulation.setTimezoneOverride", { timezoneId })),
      };
    }
    if (params.locale !== undefined) {
      const locale = params.locale == null ? "" : String(params.locale);
      applied.locale = {
        locale: locale || null,
        ...(await emulateOnSessions(tabId, "Emulation.setLocaleOverride", { locale })),
      };
    }
    if (params.colorScheme !== undefined) {
      const value = params.colorScheme;
      if (value != null && !["dark", "light", "no-preference"].includes(value)) {
        throw new Error("colorScheme must be dark, light, no-preference, or null to clear");
      }
      const features = value == null ? [] : [{ name: "prefers-color-scheme", value }];
      applied.colorScheme = {
        value: value == null ? null : value,
        ...(await emulateOnSessions(tabId, "Emulation.setEmulatedMedia", { features })),
        detail: "setEmulatedMedia replaces the emulated media-feature list for this session.",
      };
    }
    if (params.network !== undefined) {
      const preset = NETWORK_CONDITION_PRESETS[params.network];
      if (!preset) {
        throw new Error(`Unknown network '${params.network}'. Use online, offline, slow3g, or fast3g.`);
      }
      const cond = {
        offline: preset.offline,
        latency: preset.latency,
        downloadThroughput: preset.downloadThroughput,
        uploadThroughput: preset.uploadThroughput,
      };
      if (preset.connectionType) cond.connectionType = preset.connectionType;
      try {
        applied.network = { preset: params.network, ...(await emulateOnSessions(tabId, "Network.emulateNetworkConditions", cond)) };
      } catch (e) {
        if (!cond.connectionType) throw e;
        delete cond.connectionType;
        applied.network = {
          preset: params.network,
          connectionTypeOmitted: true,
          ...(await emulateOnSessions(tabId, "Network.emulateNetworkConditions", cond)),
        };
      }
    }
    if (!Object.keys(applied).length) {
      return { tabId, applied, detail: "No environment fields were passed; nothing changed." };
    }
    return { tabId, applied };
  },

  async touchGesture(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const gesture = params.gesture || params.action;
    if (!["tap", "longPress", "swipe", "pinch"].includes(gesture)) {
      throw new Error("touch_gesture requires gesture tap, longPress, swipe, or pinch");
    }
    try {
      await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `touch_gesture requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    const hasPoint = params.x != null && params.y != null;
    if (!params.ref && !params.selector && !params.coordinates && !hasPoint) {
      throw new Error("touch_gesture requires ref, selector, or coordinates (x/y are top-level viewport pixels)");
    }
    const geo = await getElementGeometry(tabId, {
      ref: params.ref,
      selector: params.selector,
      frameId: params.frameId,
      coordinates: params.coordinates || (hasPoint ? { x: params.x, y: params.y } : null),
      scrollIntoView: params.scrollIntoView,
    });
    const tgt = inputTargetFor(geo);
    await cdpSendTo(tabId, tgt.sessionId, "Emulation.setTouchEmulationEnabled", {
      enabled: true,
      maxTouchPoints: 5,
    });
    const touch = async (type, points) => {
      await cdpSendTo(tabId, tgt.sessionId, "Input.dispatchTouchEvent", { type, touchPoints: points });
    };
    if (gesture === "tap" || gesture === "longPress") {
      await touch("touchStart", [{ x: tgt.x, y: tgt.y, id: 1 }]);
      await sleep(gesture === "longPress" ? Number(params.duration) || 700 : Number(params.duration) || 40);
      await touch("touchEnd", []);
    } else if (gesture === "swipe") {
      let endX;
      let endY;
      if (params.toX != null && params.toY != null) {
        if (tgt.sessionId && geo.offsetUnresolved) {
          throw new Error(
            "FRAME_OFFSET_FAILED: cannot convert toX/toY into this cross-origin frame. Pass dx/dy instead."
          );
        }
        if (tgt.sessionId && geo.localX != null) {
          endX = params.toX - (geo.x - geo.localX);
          endY = params.toY - (geo.y - geo.localY);
        } else {
          endX = params.toX;
          endY = params.toY;
        }
      } else if (params.dx != null || params.dy != null) {
        endX = tgt.x + (Number(params.dx) || 0);
        endY = tgt.y + (Number(params.dy) || 0);
      } else {
        throw new Error("swipe requires toX/toY (top-level viewport pixels) or dx/dy");
      }
      const steps = Math.max(1, Number(params.steps) || 8);
      const duration = Math.max(0, Number(params.duration) || 300);
      await touch("touchStart", [{ x: tgt.x, y: tgt.y, id: 1 }]);
      for (let i = 1; i <= steps; i++) {
        if (duration) await sleep(duration / steps);
        const t = i / steps;
        await touch("touchMove", [{
          x: tgt.x + (endX - tgt.x) * t,
          y: tgt.y + (endY - tgt.y) * t,
          id: 1,
        }]);
      }
      await touch("touchEnd", []);
    } else {
      if (params.scaleFactor == null) throw new Error("pinch requires scaleFactor (>1 zoom in, <1 zoom out)");
      await cdpSendTo(tabId, tgt.sessionId, "Input.synthesizePinchGesture", {
        x: tgt.x,
        y: tgt.y,
        scaleFactor: Number(params.scaleFactor),
        ...(params.relativeSpeed != null ? { relativeSpeed: Number(params.relativeSpeed) } : {}),
        gestureSourceType: "touch",
      });
    }
    return {
      tabId,
      gesture,
      touchEmulation: true,
      x: tgt.x,
      y: tgt.y,
      ...(geo.frameId ? { frameId: geo.frameId } : {}),
      ...(tgt.sessionId ? { inputSession: "oopif-child" } : {}),
      ...(geo.ref ? { ref: geo.ref } : {}),
    };
  },

  async webauthn(params) {
    const tabId = params.tabId || (await getActiveTabId());
    const action = params.action || "enable";
    let session;
    try {
      session = await ensureCdp(tabId);
    } catch (e) {
      throw new Error(
        `webauthn requires the Chrome debugger, which could not be attached to tab ${tabId}: ${e.message}`
      );
    }
    const state = webauthnState(session);
    const note = { detail: WEBAUTHN_DETACH_NOTE };

    if (action === "enable") {
      await cdpSend(tabId, "WebAuthn.enable", {});
      state.enabled = true;
      if (state.authenticators.length && !params.forceNew) {
        return {
          tabId,
          enabled: true,
          alreadyEnabled: true,
          authenticatorId: state.authenticators[0].authenticatorId,
          authenticators: state.authenticators.map((a) => ({
            authenticatorId: a.authenticatorId,
            options: a.options,
          })),
          ...note,
        };
      }
      const options = { ...DEFAULT_AUTHENTICATOR };
      const added = await cdpSend(tabId, "WebAuthn.addVirtualAuthenticator", { options });
      const authenticatorId = added && added.authenticatorId;
      if (!authenticatorId) throw new Error("WebAuthn.addVirtualAuthenticator returned no authenticatorId");
      state.authenticators.push({ authenticatorId, options });
      return { tabId, enabled: true, authenticatorId, options, ...note };
    }

    const resolveAuth = () => {
      const id = params.authenticatorId || (state.authenticators[0] && state.authenticators[0].authenticatorId);
      if (!id) {
        throw new Error(
          "No virtual authenticator is tracked on this debugger session. Call action enable first. " +
            WEBAUTHN_DETACH_NOTE
        );
      }
      return id;
    };

    if (action === "addCredential") {
      const src = params.credential && typeof params.credential === "object" ? params.credential : params;
      const credential = {
        credentialId: src.credentialId,
        isResidentCredential: src.isResidentCredential !== false,
        rpId: src.rpId,
        privateKey: src.privateKey,
        userHandle: src.userHandle,
        signCount: src.signCount != null ? src.signCount : 0,
      };
      if (!credential.credentialId || !credential.privateKey || !credential.rpId || !credential.userHandle) {
        throw new Error(
          "addCredential requires credentialId, privateKey (base64 PKCS#8), rpId, and userHandle (base64)"
        );
      }
      if (src.userName) credential.userName = src.userName;
      if (src.displayName) credential.displayName = src.displayName;
      if (src.largeBlob) credential.largeBlob = src.largeBlob;
      const authenticatorId = resolveAuth();
      await cdpSend(tabId, "WebAuthn.addCredential", { authenticatorId, credential });
      return { tabId, authenticatorId, added: { credentialId: credential.credentialId, rpId: credential.rpId }, ...note };
    }

    if (action === "list") {
      const authenticators = [];
      for (const a of state.authenticators) {
        try {
          const creds = await cdpSend(tabId, "WebAuthn.getCredentials", { authenticatorId: a.authenticatorId });
          authenticators.push({
            authenticatorId: a.authenticatorId,
            options: a.options,
            credentials: (creds && creds.credentials) || [],
          });
        } catch (e) {
          authenticators.push({
            authenticatorId: a.authenticatorId,
            options: a.options,
            error: e.message || String(e),
          });
        }
      }
      return { tabId, enabled: !!state.enabled, authenticators, ...note };
    }

    if (action === "remove") {
      const authenticatorId = resolveAuth();
      if (params.credentialId) {
        await cdpSend(tabId, "WebAuthn.removeCredential", {
          authenticatorId,
          credentialId: params.credentialId,
        });
        return { tabId, authenticatorId, removedCredential: params.credentialId, ...note };
      }
      await cdpSend(tabId, "WebAuthn.removeVirtualAuthenticator", { authenticatorId });
      state.authenticators = state.authenticators.filter((a) => a.authenticatorId !== authenticatorId);
      return { tabId, removedAuthenticator: authenticatorId, ...note };
    }

    if (action === "clear") {
      const removed = [];
      for (const a of [...state.authenticators]) {
        try {
          await cdpSend(tabId, "WebAuthn.clearCredentials", { authenticatorId: a.authenticatorId });
        } catch {}
        try {
          await cdpSend(tabId, "WebAuthn.removeVirtualAuthenticator", { authenticatorId: a.authenticatorId });
          removed.push(a.authenticatorId);
        } catch (e) {
          removed.push({ authenticatorId: a.authenticatorId, error: e.message || String(e) });
        }
      }
      state.authenticators = [];
      return { tabId, cleared: removed, ...note };
    }

    throw new Error("webauthn action must be enable, addCredential, list, remove, or clear");
  },
};

// --- Multi-instance WebSocket connections ---


async function connectToPort(port) {
  if (!Number.isInteger(port) || port < PORT_START || port > PORT_END) return;
  const { bridgeToken } = await chrome.storage.local.get("bridgeToken");
  if (!validNonce(bridgeToken)) return;
  const existing = connections.get(port);
  if (
    existing &&
    (existing.ws.readyState === WebSocket.CONNECTING ||
      existing.ws.readyState === WebSocket.OPEN)
  ) {
    return;
  }

  // Probe with HTTP first to avoid noisy WebSocket ERR_CONNECTION_REFUSED errors
  try {
    await fetch(`http://127.0.0.1:${port}`, {
      method: "HEAD",
      signal: AbortSignal.timeout(1000),
    });
  } catch {
    return; // No server on this port
  }

  // Another scan may have connected while the HTTP probe was pending.
  const current = connections.get(port);
  if (current && current.ws.readyState <= WebSocket.OPEN) return;
  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  const conn = { ws, authed: false, outgoing: Promise.resolve(), incoming: Promise.resolve(), sendSeq: 0, recvSeq: 0, token: bridgeToken };
  connections.set(port, conn);

  const clientNonce = nonce();
  let serverNonce = null;
  let phase = "challenge";
  const authTimer = setTimeout(() => ws.close(), 5000);
  ws.onopen = () => {};

  ws.onmessage = (event) => {
    conn.incoming = conn.incoming.then(() => handleMessage(event)).catch(() => ws.close());
    return conn.incoming;
  };
  const handleMessage = async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }

    if (!msg || typeof msg !== "object") return ws.close();
    if (!conn.authed) {
      try {
        if (phase === "challenge" && msg.method === "authChallenge" && validNonce(msg.nonce)) {
          phase = "verifying";
          serverNonce = msg.nonce;
          const mac = await proof(bridgeToken, "client", serverNonce, clientNonce);
          phase = "ack";
          sendTo(ws, { method: "authResponse", nonce: clientNonce, proof: mac });
          return;
        }
        if (phase === "ack" && msg.method === "authOk") {
          phase = "verifying";
          const expected = await proof(bridgeToken, "server", serverNonce, clientNonce);
          if (!equalProof(msg.proof, expected)) return ws.close();
          conn.serverNonce = serverNonce;
          conn.clientNonce = clientNonce;
          conn.authed = true;
          clearTimeout(authTimer);
          broadcastState();
          sendTo(ws, { method: "extensionInfo", params: { version: "3.4.0", port } });
          return;
        }
      } catch {}
      ws.close();
      return;
    }

    // Every application frame is signed, including sequence and session nonces.
    // A relaying local service cannot inject or alter commands after pairing.
    if (!Number.isSafeInteger(msg.seq) || msg.seq !== conn.recvSeq + 1 || typeof msg.payload !== "string") return ws.close();
    const expectedFrame = await frameProof(bridgeToken, "server", serverNonce, clientNonce, msg.seq, msg.payload);
    if (!equalProof(msg.proof, expectedFrame)) return ws.close();
    conn.recvSeq = msg.seq;
    try { msg = JSON.parse(msg.payload); } catch { return ws.close(); }
    if (!msg || typeof msg !== "object") return ws.close();

    if (msg.method === "ping") {
      sendTo(ws, { method: "pong" });
      return;
    }

    if (Object.hasOwn(handlers, msg.method)) {
      try {
        const result = await handlers[msg.method](msg.params || {});
        sendTo(ws, { id: msg.id, result });
      } catch (err) {
        const error =
          err &&
          typeof err === "object" &&
          typeof err.code === "string" &&
          err.code &&
          typeof err.message === "string"
            ? { code: err.code, message: err.message }
            : (err && err.message) || String(err);
        sendTo(ws, { id: msg.id, error });
      }
    }
  };

  ws.onclose = () => {
    clearTimeout(authTimer);
    if (connections.get(port) === conn) connections.delete(port);
    chrome.storage.session.get("activePorts", (data) => {
      const ports = new Set(data.activePorts || []);
      ports.delete(port);
      chrome.storage.session.set({ activePorts: [...ports] });
    });
    broadcastState();
  };

  ws.onerror = () => {
    if (connections.get(port) === conn) connections.delete(port);
  };
}

function scanPorts() {
  // Prioritize known active ports
  chrome.storage.session.get("activePorts", (data) => {
    const activePorts = data.activePorts || [];
    for (const port of activePorts) {
      connectToPort(port);
    }
    // Then scan all ports
    for (let port = PORT_START; port <= PORT_END; port++) {
      connectToPort(port);
    }
  });
}

function getStatePayload() {
  const count = getConnectedCount();
  return {
    connected: count > 0,
    instanceCount: count,
  };
}

function broadcastState() {
  chrome.runtime
    .sendMessage({ type: "stateUpdate", ...getStatePayload() })
    .catch(() => {});
}

// --- Popup communication ---

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("popup.html")) return;
  if (msg.type === "getState") {
    sendResponse(getStatePayload());
    return true;
  }
  if (msg.type === "retry") {
    scanPorts();
    sendResponse({ ok: true });
    return true;
  }
});

chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.bridgeToken) {
    for (const conn of connections.values()) conn.ws.close();
    connections.clear();
    broadcastState();
    scanPorts();
  }
});

// --- Alarms-based port scanning ---

chrome.alarms.create("scanPorts", { periodInMinutes: 0.1 }); // ~6 seconds
chrome.alarms.create("keepalive", { periodInMinutes: 0.4 }); // ~24 seconds

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "scanPorts") {
    scanPorts();
  }
  if (alarm.name === "keepalive") {
    for (const conn of connections.values()) {
      if (conn.authed) sendTo(conn.ws, { method: "ping" });
    }
  }
});

// Initial scan on service worker start
scanPorts();
