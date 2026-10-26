const { chromium } = require("playwright");
const fs = require("node:fs");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(),
  });
  const context = await browser.newContext({
    viewport: { width: 600, height: 600 },
    recordVideo: { dir: "evidence/video", size: { width: 600, height: 600 } },
  });
  const page = await context.newPage();
  await page.goto(process.env.LAB_URL || "http://127.0.0.1:8766/native/");
  await page.waitForTimeout(7000);
  await page.locator("#stage").click();
  await page.waitForTimeout(8000);
  await page.locator("#mutate").click();
  await page.waitForTimeout(5000);
  await page.locator("#confirm").focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(6000);
  await page.locator("#mutate").click();
  await page.waitForTimeout(7000);
  await page.locator("#apply").focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(10000);
  const video = page.video();
  await context.close();
  const file = await video.path();
  fs.renameSync(file, "evidence/video/swan-local-native-handler.webm");
  await browser.close();
  console.log("evidence/video/swan-local-native-handler.webm");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
