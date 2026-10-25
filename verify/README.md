# Bridge acceptance tests

Launches Google Chrome with the unpacked extension, starts the MCP server (`server/src/index.ts` via bun), and drives tools over stdio. Playwright reads the fixture page the tools were supposed to change.

## Run

```bash
cd verify
npm ci --ignore-scripts
npm test
```

Requires `bun` and Playwright's Chromium (`npx playwright install chromium` from this directory). The browser profile is a throwaway directory, not your real Chrome profile.

Google Chrome 155 ignores `--load-extension`, so the default browser is Playwright's Chromium, which still accepts it. The run uses `--headless=new` on that full browser, not the headless shell. If the extension service worker does not start, the suite retries in a visible window. `VERIFY_HEADED=1 npm test` skips the headless attempt. `VERIFY_CHANNEL=chrome npm test` uses the installed Google Chrome instead, for a build that still honors `--load-extension`.

The harness generates a fresh private pairing token and pairs only its disposable extension profile. Existing profiles using a different token cannot take the test connection.

## What it accepts

The bridge acceptance cases: the fixture tab is listed, an open-shadow button ref clicks through to a light-DOM counter, typing sticks, `find_text` reports a count, selection round-trips, local storage round-trips, cookies set and list when `chrome.cookies` allows it, request-header rewrite and response patch show up on a same-origin fetch, HAR contains that request, PDF is a non-empty file and is not inlined in the tool text, geolocation override is visible to the page or honestly reported as permission-API unavailable, and `grant_permission` / `webauthn` / `touch_gesture` / `describe_element` match their documented results.

A wrong counter, a missing ref, or a tool error fails the run. A case is skipped only when its handler method is not in `extension/background.js` yet (re-read on every run). Skips are printed. `grant_permission` and `webauthn` pass on structured success or on `PERMISSION_API_UNAVAILABLE` / detach / missing WebAuthn UI, so a Chrome build without those CDP surfaces does not fail the suite.
