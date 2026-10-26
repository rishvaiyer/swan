const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");
const base = process.env.WEARABLE_BASE_URL || "http://127.0.0.1:18766";
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  await page.goto(base + "/wearables/", { waitUntil: "networkidle" });
  await page.locator("#case-select").selectOption("pre-permission-buffer");
  await page.locator("#review-button").click();
  await page.locator("#report-content").waitFor({ state: "visible" });
  const out = path.resolve("evidence/visual");
  fs.mkdirSync(out, { recursive: true });
  await page.screenshot({
    path: path.join(out, "swan-wearable-review-1440.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: path.join(out, "swan-wearable-review-390.png"),
    fullPage: true,
  });
  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
