const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");
const base = (process.env.WEARABLE_BASE_URL || "http://127.0.0.1:8766").replace(
  /\/$/,
  "",
);
const checks = [];
const ok = (name, value) => {
  assert.ok(value, name);
  checks.push({ name, passed: true });
};

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(),
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(base + "/wearables/", { waitUntil: "networkidle" });
  ok(
    "wearable review page loads",
    (await page.title()) === "Swan · Wearable trace review",
  );
  ok(
    "scope limitation visible",
    (await page.locator(".scope-note").innerText()).includes(
      "does not control or attest Meta glasses",
    ),
  );
  await page.waitForFunction(() => {
    const select = document.querySelector("#case-select");
    return (
      select && !select.options[0]?.textContent.includes("Loading examples")
    );
  });
  const count = await page.locator("#case-select option").count();
  ok("curated regression corpus is available", count >= 16);
  ok(
    "safe local case is the default",
    (await page.locator("#case-select").inputValue()) === "safe-local",
  );
  if (count && (await page.locator("#case-select").isEnabled())) {
    await page.locator("#review-button").click();
    await page.waitForFunction(
      () => document.querySelector("#report-content")?.hidden === false,
    );
    ok(
      "sample trace reviewed",
      (await page.locator("#report-summary").innerText()).includes("Events"),
    );
    ok(
      "report JSON download enabled",
      await page.locator("#download-json").isEnabled(),
    );
    const jsonDownload = page.waitForEvent("download");
    await page.locator("#download-json").click();
    ok(
      "report JSON downloads",
      (await jsonDownload).suggestedFilename() === "swan-wearable-review.json",
    );
    const sarifDownload = page.waitForEvent("download");
    await page.locator("#download-sarif").click();
    ok(
      "SARIF downloads",
      (await sarifDownload).suggestedFilename() ===
        "swan-wearable-review.sarif.json",
    );
    await page
      .locator("#case-select")
      .selectOption({ index: Math.min(1, count - 1) });
    ok(
      "changing trace clears old report",
      await page.locator("#report-content").isHidden(),
    );
  } else {
    ok(
      "import-only mode available",
      await page.locator("#trace-file").isEnabled(),
    );
  }
  for (const file of fs
    .readdirSync(path.join(__dirname, "../fixtures/wearables"))
    .filter((name) => name.endsWith(".json"))) {
    const fixture = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "../fixtures/wearables", file),
        "utf8",
      ),
    );
    await page.locator("#case-select").selectOption(fixture.id);
    await page.locator("#review-button").click();
    await page.locator("#report-content").waitFor({ state: "visible" });
    const rules = [
      ...new Set(await page.locator("#finding-list code").allTextContents()),
    ].sort();
    assert.deepEqual(rules, fixture.expected_rule_ids, fixture.id);
    ok("curated trace: " + fixture.id, true);
  }
  const goodTrace = fs.readFileSync(
    path.join(__dirname, "../examples/wearable-safe.json"),
  );
  await page
    .locator("#trace-file")
    .setInputFiles({
      name: "example.json",
      mimeType: "application/json",
      buffer: goodTrace,
    });
  await page.locator("#review-button").click();
  await page.locator("#report-content").waitFor({ state: "visible" });
  ok(
    "imported valid trace is reviewed",
    (await page.locator("#report-message").innerText()).includes(
      "Synthetic trace",
    ),
  );
  const verifiedDownload = page.waitForEvent("download");
  await page.locator("#download-json").click();
  const downloadedReport = JSON.parse(
    fs.readFileSync(await (await verifiedDownload).path(), "utf8"),
  );
  ok(
    "downloaded JSON contains actual result",
    downloadedReport.summary.errors === 0 &&
      downloadedReport.summary.events === 6,
  );
  await page.locator("#trace-file").setInputFiles({
    name: "bad.json",
    mimeType: "application/json",
    buffer: Buffer.from(
      '{"schema_version":"0","secret":"PRIVATE_BROWSER_MARKER"}',
    ),
  });
  await page.locator("#review-button").click();
  await page.locator("#error-message:not([hidden])").waitFor();
  const message = await page.locator("#error-message").innerText();
  ok(
    "invalid trace gets generic error",
    message.includes("supported schema") &&
      !message.includes("PRIVATE_BROWSER_MARKER"),
  );
  ok(
    "old report stays cleared",
    await page.locator("#report-content").isHidden(),
  );
  for (const width of [380, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    ok(
      width + "px viewport has no page overflow",
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
  }
  ok("no uncaught browser errors", errors.length === 0);
  console.log(JSON.stringify({ checks, total: checks.length }));
  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
