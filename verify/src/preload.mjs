// Cursor's sandbox exports PLAYWRIGHT_BROWSERS_PATH at a temp cache. The suite
// should use the normal Playwright cache so `npx playwright install chromium` sticks.
delete process.env.PLAYWRIGHT_BROWSERS_PATH;
