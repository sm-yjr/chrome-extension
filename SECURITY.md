# Security and privacy

## Trust boundary

The server binds to `127.0.0.1` only. WebSocket upgrades require the exact loopback Host and a Chrome-extension Origin; ordinary website Origins and missing Origins are rejected. HTTP probes do not enable CORS. Origin checks alone are not authentication: local programs can forge headers.

Both peers must prove possession of a random, shared 256-bit pairing token using HMAC-SHA-256. Fresh 256-bit nonces and distinct client/server proof labels prevent replay and reflection between authentication roles. The raw token is never sent over the WebSocket. Each application frame in both directions also carries a role-separated HMAC over the session nonces, sequence number and exact payload. This prevents a local relay from injecting or modifying messages after authentication; replayed or out-of-order messages are rejected. Authentication times out after five seconds; commands are not dispatched before server verification. One authenticated extension can occupy each server. Unauthenticated connections cannot replace it or cancel its pending requests. Payloads received by the server are bounded at 32 MiB.

The extension scans local ports only after pairing. A fake local service without the token cannot authenticate itself and issue browser commands. Unpairing removes the saved token and closes connections. The token is stored in Chrome local storage restricted to trusted extension contexts, not sync storage. Server configuration uses `BRIDGE_TOKEN` from the environment, and logs do not print it. Use high-entropy generated tokens, not passwords.

This protocol authenticates peers; it does not encrypt loopback traffic. It does not protect against a compromised OS, a local administrator, malware with access to your browser profile/environment, a leaked token, a malicious paired MCP client, or network traffic inspection by privileged local software. Do not port-forward or expose this service through a network proxy. All clients sharing a token belong to the same trust group.

## Browser authority

After pairing, the client has broad automation authority. There is no per-command approval dialog or site allowlist. All-site permissions, debugger, cookies, storage, downloads, clipboard and browsing-data APIs support the advertised tools. The debugger can read and change pages, including authenticated sessions. Browser/agent prompt-injection risks remain: untrusted website text must not authorize actions. Use a separate profile and the MCP client's own action approvals.

The extension's runtime status/retry endpoint accepts messages from its own popup only. No external-message entry point is declared. Content scripts support page structure and activity indicators; pairing secrets are not exposed to content-script storage access.

## Sensitive data

There is no configured external telemetry, analytics or remote logging endpoint. Data is returned to the local MCP client on request, which may then send it elsewhere according to its own settings. Network and console buffers are held in extension worker memory. Traffic rewrite/mock configuration uses session storage and is removed on debugger detach or tab close. HAR, cookies, storage exports, page snapshots, uploads, screenshots and arbitrary script/CDP results may contain credentials or personal data. Pairing is authorization to access this data; it does not anonymize it.

Structured accessibility trees and typing readback redact password fields and fields marked with password, one-time-code, credit-card-number or security-code autocomplete hints. This is a limited accidental-disclosure safeguard, not a general secret detector. Page text, screenshots, CDP, script execution and intentionally requested session tools are outside that safeguard.

Export destinations come from the MCP caller, not paths supplied in extension replies. Files are created exclusively with mode `0600` (subject to OS filesystem semantics), refusing overwrites and final-component symlinks. Parent directories must be trusted; this is not protection from hostile local filesystem manipulation. Session imports and file uploads deliberately read caller-selected paths. Do not grant browser automation to an untrusted client.

## Public source hygiene

The public repository begins with a clean source snapshot, without the original local commit history, workstation remotes, private author metadata, browser profiles or local artifacts. `.gitignore` excludes environment files, common private-key formats, profiles and exports. This is a guardrail, not a substitute for reviewing staged files. Do not commit real tokens or real session fixtures.

## Reporting

For a suspected vulnerability, avoid posting credentials, browsing data or a working exploit containing private data in public issues. Use GitHub private vulnerability reporting when available. Otherwise open a minimal issue requesting a private reporting channel without sensitive details.

## Optional macOS native keyboard backend

`BRIDGE_NATIVE_INPUT=1` opts the local MCP server into a locally compiled helper with Accessibility/event-posting authorization. Only the fixed project helper is spawned; no extension-supplied executable or shell command is executed, and text is sent through stdin rather than process arguments. No new listening endpoint is opened. The helper addresses Google Chrome's process with `CGEventPostToPid`, never the global input tap. It refuses non-HTTP(S) document targets, other foreground applications, non-editable focused elements and browser-chrome controls, and stops if the focused AX element changes during a batch. The extension additionally checks the original tab/window, exact document, target element and an expiring opaque ticket between batches. Tokens and password-manager data are not provided to this helper. Password readback remains redacted.

This backend deliberately requires a foreground browser and carries the normal focus-race limitations of OS input automation. Do not manually operate the target Chrome window during input. Page scripts can react to trusted input, and a trusted paired MCP client remains a powerful actor. Failure after partial input is reported without automatically repeating characters. iCloud Passwords and its in-page list do not need to be disabled or edited. Native input is labeled `native`; it is not presented as CDP or as human physical keystrokes.
