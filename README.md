# Chrome Browser Bridge

A local MCP server and Chrome extension for browser automation. Exposes page structure, clicks and typing, screenshots, tabs and windows, CDP tools, network inspection, session operations, PDF/MHTML/HAR exports, and environment emulation to an MCP client.

**This is a powerful development tool. Use a dedicated browser profile and only connect trusted MCP clients.** Pairing grants the connected client broad browser access, including authenticated websites, cookies, page scripts, downloads and uploads. It does not ask for confirmation before each action. No telemetry or cloud endpoint is configured in this project; your MCP client may send returned data to its own model provider.

Independent community project; not affiliated with or endorsed by Anthropic or Google.

## Requirements

- Bun and Node.js 22 or later, with npm.
- A Chromium browser that supports unpacked Manifest V3 extensions and the debugger API.
- An MCP client that supports stdio servers.

## Install and pair

1. Clone the repository. Run `npm ci --ignore-scripts` in `server/`.
2. Generate a private pairing token locally:

   ```sh
   openssl rand -hex 32
   ```

   Keep the output private. Do not put it in this repository, issue reports, screenshots, shared shell history, or a public MCP configuration. Prefer your MCP client's local secret configuration. If using a file, restrict it to your account.

3. Configure the MCP client with your absolute local paths and the token:

   ```json
   {
     "mcpServers": {
       "chrome-browser-bridge": {
         "command": "/absolute/path/to/bun",
         "args": ["run", "/absolute/path/to/chrome-extension/server/src/index.ts"],
         "env": { "BRIDGE_TOKEN": "REPLACE_WITH_YOUR_PRIVATE_64_HEX_TOKEN" }
       }
     }
   }
   ```

4. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `extension/`.
5. Open the extension popup and paste the same token into **Save pairing token**. It should display **Connected** once the MCP server starts. Multiple MCP instances can share a token; ports 17890–17909 are scanned on loopback only.
6. Use **Unpair and disconnect** to remove the extension's saved key and close its connections. To revoke a leaked token, generate a new token, update every server configuration, restart those servers, and pair again.

The server refuses to start without a valid token. The extension stays disconnected until paired. Existing installations of earlier unauthenticated versions must be reloaded and paired; the protocol is intentionally incompatible.

## Security and privacy

Read [SECURITY.md](SECURITY.md) for the trust boundary, data handling, and limitations. The pairing token is stored in extension-local Chrome storage (not Chrome Sync) and is restricted to trusted extension contexts. It is not an OS keychain secret.

Artifacts are created with private file permissions and refuse existing destination files, including symlinks. Choose a new filename for each export. Do not upload session exports, HAR files, screenshots or recordings without reviewing their contents. Password, payment-card and one-time-code input values are redacted in structured accessibility output and typing results; screenshots, page text, arbitrary JavaScript, CDP and session/network tools can still expose sensitive data.

## Verification

```sh
cd server
npm ci --ignore-scripts
npm run check
npm run test:security
npm audit

cd ../verify
npm ci --ignore-scripts
npx playwright install chromium
npm test
```

Tests create a random token and disposable browser profile. They do not use your daily Chrome profile. See [verify/README.md](verify/README.md). Some CDP capabilities vary across Chromium builds; the tests accept explicit unsupported-API errors for site permission overrides.

### Password-manager extension compatibility

Some Chrome builds block debugger input or screenshots when another extension inserts its own frame (observed with iCloud Passwords). Before any text has been entered, the bridge can fall back to ordinary page DOM input and labels the result `inputMode: synthetic`. It does not access the other extension or change its settings. Sites requiring trusted input events may still reject this fallback. Partially typed input is never automatically replayed. Screenshot fallback captures the visible viewport through Chrome's normal capture API; full-page capture is unavailable in this case.

### Keep iCloud's in-page list and use trusted OS keyboard input (macOS)

Chrome can deny its debugger when a password manager embeds its own extension frame. The optional macOS helper keeps that frame and the password manager enabled while sending operating-system keyboard events directly to Google Chrome's process. Successful input reports `inputMode: native` and `backend: macOS-CGEventPostToPid`; it is separate from CDP input and DOM synthesis.

1. Run `./script/build_and_run.sh --verify` from the repository root. Xcode Command Line Tools are required. The helper is built locally; no prebuilt helper is downloaded.
2. Set `BRIDGE_NATIVE_INPUT` to `1` in the local environment configuration for this MCP server, alongside the existing pairing token. Restart the MCP client and reload the unpacked extension. Do not publish the local configuration or token.
3. macOS must authorize Accessibility/event posting for the process running the helper. The status check reports availability without requesting permission or changing system settings. Missing authorization produces an explicit error; it does not silently use DOM synthesis.

The native path is used only if initial CDP input cannot run. It activates the requested tab/window, focuses the requested editable element, checks the same tab, document and focused element between batches, and checks the foreground application, document URL, editable AX role, page-content ancestry and focused AX element before each key pair. Input is serialized, limited to 4096 UTF-16 units per request, and passed to the fixed helper over stdin in batches of at most 16 characters. It never uses the clipboard, global keyboard posting, or the password manager's contents or settings. A focus change or partial failure stops input without retrying it. Like other foreground automation, it should not be used while you are interacting with that Chrome window. Browser shortcuts and contentEditable/embedded-frame accessibility support can vary across Chrome versions; unsupported focus states fail closed.

For a real acceptance test, inspect the page's `keydown`/`input` event `isTrusted` counters and confirm the password manager's frame remains present. Text appearing in a field alone is insufficient evidence. Screenshots may still use `captureVisibleTab` while the password-manager frame is present.
