const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const base = process.env.LAB_URL || "http://127.0.0.1:8766/reference";
  const out = path.resolve("evidence/walkthrough");
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(),
  });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
    recordVideo: { dir: out, size: { width: 1440, height: 1000 } },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const pause = (ms) => page.waitForTimeout(ms);
  await page.goto(base, { waitUntil: "networkidle" });
  await page.waitForFunction(
    () => document.querySelector("#scenario").options.length > 1,
  );
  await page.selectOption("#scenario", "qr_injection");
  await pause(5000);
  if (await page.locator("#replay-button").isDisabled())
    throw new Error("No actual saved evidence is available to record.");
  await page.locator("#replay-button").click();
  await page.waitForFunction(() =>
    /replay/i.test(document.querySelector("#run-mode").textContent),
  );
  await pause(6000);
  await page.locator("#sources").scrollIntoViewIfNeeded();
  await pause(6000);
  await page.locator("#comparison").scrollIntoViewIfNeeded();
  await pause(7000);
  await page.locator("#trace-heading").scrollIntoViewIfNeeded();
  await pause(7000);
  await page.locator("#receipt-button").click();
  await pause(5000);
  await page.locator("#receipt-close").click();
  await page.locator("button[data-tab=evidence]").click();
  await pause(7000);
  await page.locator("button[data-tab=defense]").click();
  await pause(7000);
  await page.locator(".defense-question").scrollIntoViewIfNeeded();
  await pause(5000);
  await page.locator("button[data-tab=kit]").click();
  await pause(6000);
  await page.locator("button[data-tab=lab]").click();
  await page.selectOption("#scenario", "legitimate_note");
  if (!(await page.locator("#replay-button").isDisabled())) {
    await page.locator("#replay-button").click();
    await pause(5000);
    await page.locator("#comparison").scrollIntoViewIfNeeded();
    await pause(5000);
  }
  const video = page.video();
  await context.close();
  const file = await video.path();
  const target = path.join(out, "demo-walkthrough.webm");
  fs.renameSync(file, target);
  await browser.close();
  console.log(target);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
