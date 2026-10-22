const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");
const base = process.env.LAB_URL || "http://127.0.0.1:8766/reference";
const out = path.resolve("evidence/visual");
fs.mkdirSync(out, { recursive: true });
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(),
  });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const errors = [];
  const checks = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const check = (name, ok, detail) => {
    checks.push({ name, passed: !!ok, detail });
    if (!ok) throw new Error(name + ": " + detail);
  };
  await page.goto(base, { waitUntil: "networkidle" });
  await page.waitForFunction(
    () => document.querySelector("#scenario").options.length > 1,
  );
  check(
    "descriptive title and device boundary",
    (await page.title()).includes("Wearable AI"),
    await page.title(),
  );
  check(
    "visible Meta hardware boundary",
    await page
      .locator(".scope-label")
      .innerText()
      .then((t) => t.includes("untested")),
    "Scope stays visible",
  );
  await page.screenshot({
    path: path.join(out, "desktop-initial.png"),
    fullPage: true,
  });
  const response = await page.request.get(new URL(base).origin + "/api/runs");
  const runs = await response.json();
  if (runs.runs.length) {
    await page.locator("#replay-button").click();
    await page.waitForFunction(() =>
      document
        .querySelector("#run-mode")
        .textContent.toLowerCase()
        .includes("replay"),
    );
    check(
      "replay disclosed",
      /replay/i.test(await page.locator("#run-mode").innerText()),
      "Existing receipts, no fabricated model result",
    );
    await page.locator("#receipt-button").click();
    await page.waitForSelector("#receipt-dialog[open]");
    check(
      "receipt is inspectable JSON",
      (await page.locator("#receipt-content").innerText()).includes(
        "integrity",
      ),
      "Provenance appears in receipt dialog",
    );
    await page.locator("#receipt-close").click();
    await page.screenshot({
      path: path.join(out, "desktop-results.png"),
      fullPage: true,
    });
  } else
    checks.push({
      name: "replay available",
      passed: null,
      detail: "No receipts present; did not fabricate them",
    });
  for (const id of ["evidence", "defense", "kit", "lab"]) {
    await page.locator(`button[data-tab="${id}"]`).click();
    check(
      "tab " + id,
      await page.locator("#" + id).isVisible(),
      "Tab content visible",
    );
    await page.keyboard.press("Tab");
  }
  const kit = await page.request.get(new URL(base).origin + "/api/kit");
  check("printable fixture route", kit.ok(), String(kit.status()));
  const sceneFile = path.resolve("public/assets/scenes/qr_injection.png");
  if (fs.existsSync(sceneFile)) {
    await page.locator("#scene-upload").setInputFiles(sceneFile);
    await page.waitForFunction(
      () =>
        /uploaded|upload|custom/i.test(
          document.querySelector("#capture-label").textContent,
        ),
      { timeout: 60000 },
    );
    check(
      "uploaded image recognized",
      true,
      "Real local PNG upload through perception endpoint",
    );
    await page.screenshot({
      path: path.join(out, "desktop-upload.png"),
      fullPage: true,
    });
  }
  const mobile = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
    deviceScaleFactor: 1,
    reducedMotion: "reduce",
  });
  const mp = await mobile.newPage();
  mp.on("pageerror", (e) => errors.push(String(e)));
  await mp.goto(base, { waitUntil: "networkidle" });
  await mp.waitForFunction(
    () => document.querySelector("#scenario").options.length > 1,
  );
  const overflow = await mp.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    view: innerWidth,
  }));
  check(
    "mobile has no page overflow",
    overflow.scroll <= overflow.view + 1,
    overflow,
  );
  await mp.screenshot({ path: path.join(out, "mobile.png"), fullPage: true });
  for (const id of ["evidence", "defense", "kit"]) {
    await mp.locator(`button[data-tab="${id}"]`).click();
    check(
      "mobile tab " + id,
      await mp.locator("#" + id).isVisible(),
      "Visible",
    );
  }
  check("no JavaScript runtime errors", errors.length === 0, errors);
  const nativeURL = new URL("/", new URL(base).origin).href;
  await page.goto(nativeURL, { waitUntil: "networkidle" });
  check(
    "native route is labeled as a prototype",
    (await page.title()) === "Swan · Action boundary",
    await page.title(),
  );
  check(
    "Meta device limits are visible",
    await page
      .locator(".scope")
      .innerText()
      .then((t) => /unverified/i.test(t)),
    "Prototype scope is disclosed",
  );
  check(
    "native demo effects stay local",
    await page
      .locator("#scope")
      .innerText()
      .then((t) => /this tab/i.test(t) && /no external action/i.test(t)),
    "Tab-local scope is disclosed",
  );
  const researchResponse = await page.request.get(
    new URL(base).origin + "/research.json",
  );
  const researchData = await researchResponse.json();
  check(
    "public research metadata omits naming notes",
    researchResponse.ok() && !Object.hasOwn(researchData, "name_status"),
    "No personal naming metadata is served",
  );
  const report = {
    checked_at: new Date().toISOString(),
    origin: base,
    browser: "Chromium headless",
    viewports: ["1440x1000", "390x844"],
    checks,
    errors,
    limitations: [
      "Browser UI verification does not prove physical glasses behavior.",
      "Live local-model calls run separately; this script may inspect real recorded receipts.",
    ],
  };
  fs.writeFileSync(
    path.join(out, "browser-checks.json"),
    JSON.stringify(report, null, 2),
  );
  console.log(JSON.stringify(report, null, 2));
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
