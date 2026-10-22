const { chromium } = require("playwright");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const base = process.env.LAB_URL || "http://127.0.0.1:8766";
const checks = [];
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(),
  });
  const page = await browser.newPage({ viewport: { width: 600, height: 600 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const ok = (name, v) => {
    assert.ok(v, name);
    checks.push({ name, passed: true });
  };
  await page.goto(base);
  ok("Swan native primary", (await page.title()) === "Swan · Action boundary");
  ok(
    "ordinary browser honestly unavailable",
    (await page.locator("#host-status").innerText()) ===
      "Native tools unavailable",
  );
  await page.locator("#stage").click();
  await page.locator("#confirm").evaluate((el) => {
    el.click();
    el.onclick({ isTrusted: true });
  });
  ok(
    "scripted confirmation cannot grant",
    (await page.locator("#result").innerText()).includes(
      "TRUSTED CURRENT PREVIEW REQUIRED",
    ),
  );
  await page.waitForTimeout(350);
  await page.locator("#confirm").click();
  ok(
    "browser trusted activation grants",
    (await page.locator("#result").innerText()).includes("Approved once"),
  );
  await page.locator("#mutate").click();
  ok(
    "changed body denied",
    (await page.locator("#result").innerText()).includes("PREVIEW MISMATCH"),
  );
  await page.locator("#apply").click();
  ok(
    "unchanged approved body applies",
    (await page.locator("#note").innerText()).includes("blue notebook"),
  );
  ok(
    "no horizontal overflow",
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  fs.mkdirSync("evidence/visual", { recursive: true });
  await page.screenshot({
    path: "evidence/visual/swan-native-600.png",
    fullPage: true,
  });
  await page.keyboard.press("ArrowDown");
  ok(
    "directional navigation focuses control",
    await page.evaluate(() => document.activeElement.matches("button,a")),
  );
  await page.setViewportSize({ width: 360, height: 720 });
  await page.screenshot({
    path: "evidence/visual/swan-native-360.png",
    fullPage: true,
  });
  ok(
    "360px no horizontal overflow",
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );

  // Exercise the real renderer while a genuine browser gesture is in flight.
  await page.locator("#stage").click();
  await page.waitForTimeout(350);
  await page.locator("#confirm").hover();
  await page.mouse.down();
  await page.locator("#stage").evaluate((el) => el.click());
  await page.waitForTimeout(350);
  await page.mouse.up();
  ok(
    "rendered replacement during pointer gesture denied",
    (await page.locator("#result").innerText()).includes(
      "TRUSTED CURRENT PREVIEW REQUIRED",
    ),
  );
  await page.locator("#stage").click();
  await page.waitForTimeout(350);
  await page.locator("#confirm").focus();
  await page.keyboard.down("Space");
  await page.locator("#stage").evaluate((el) => el.click());
  await page.waitForTimeout(350);
  await page.keyboard.up("Space");
  ok(
    "rendered replacement during keyboard gesture denied",
    (await page.locator("#result").innerText()).includes(
      "TRUSTED CURRENT PREVIEW REQUIRED",
    ),
  );
  await page.waitForTimeout(350);
  await page.locator("#confirm").click();
  ok(
    "approval expiry countdown visible",
    (await page.locator("#result").innerText()).includes("expires in"),
  );
  await page.waitForTimeout(15300);
  ok(
    "expired approval visibly returns to review",
    !(await page.locator("#confirm").isDisabled()) &&
      (await page.locator("#result").innerText()).includes(
        "expired review again",
      ),
  );
  await page.waitForTimeout(350);
  await page.locator("#confirm").click();
  await page.locator("#apply").click();
  ok(
    "fresh trusted activation after expiry applies",
    (await page.locator("#result").innerText()).includes(
      "applied to tab sandbox",
    ),
  );

  await page.goto(base + "/native/");
  await page.evaluate(async () => {
    const { SwanBoundary, registerNativeTools } =
      await import("/native/boundary.mjs");
    window.testBoundary = new SwanBoundary();
    window.testTools = [];
    window.stubResult = registerNativeTools(
      { modelContext: { registerTool: (t) => window.testTools.push(t) } },
      window.testBoundary,
      { testStub: true },
    );
    const b = document.createElement("button");
    b.id = "test-approve";
    b.textContent = "Isolated browser approval";
    document.body.append(b);
    window.bindTestApproval = () =>
      window.testBoundary.bindApproval(
        b,
        window.testBoundary.snapshot().pending.nonce,
      );
  });
  ok(
    "registration exact official API tool shape",
    await page.evaluate(
      () =>
        window.testTools.length === 3 &&
        window.testTools.every(
          (t) =>
            typeof t.execute === "function" &&
            t.inputSchema.type === "object" &&
            typeof t.name === "string" &&
            typeof t.description === "string",
        ),
    ),
  );
  const stage = async (extras) =>
    page.evaluate((extras) => {
      const a = {
        action: "save_note",
        body: "message-l9wdsf",
        recipient: "sandbox-notebook",
        expectedRevision: window.testBoundary.snapshot().state.revision,
        ...extras,
      };
      return window.testTools[1].execute(a);
    }, extras || {});
  const approval = async () => {
    await page.evaluate(() => window.bindTestApproval());
    await page.waitForTimeout(350);
    await page.locator("#test-approve").click();
  };
  const apply = async (extras) =>
    page.evaluate(
      (extras) =>
        window.testTools[2].execute({
          ...window.testBoundary.snapshot().pending,
          ...extras,
        }),
      extras || {},
    );
  const reason = (r) => JSON.parse(r.content[0].text).reason;
  await stage({ confirmed: true });
  ok(
    "model confirmed true rejected",
    await page.evaluate(() => window.testBoundary.snapshot().pending === null),
  );
  await stage();
  ok(
    "apply without human denied",
    reason(await apply()) === "HUMAN_APPROVAL_REQUIRED",
  );
  await approval();
  for (const [name, extra, expected] of [
    ["FNV collision body", { body: "message-mva67n" }, "PREVIEW_MISMATCH"],
    [
      "recipient",
      { recipient: "external@example.test" },
      "RECIPIENT_NOT_ALLOWED",
    ],
    [
      "action",
      { action: "set_inventory_note", recipient: "sandbox-inventory" },
      "PREVIEW_MISMATCH",
    ],
    [
      "nonce",
      { nonce: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
      "PREVIEW_MISMATCH",
    ],
    ["authority", { authority: "allow" }, "UNKNOWN_OR_MISSING_ARGUMENT"],
  ])
    ok(name + " mutation blocked", reason(await apply(extra)) === expected);
  ok(
    "valid host-shaped invocation applies",
    JSON.parse((await apply()).content[0].text).status ===
      "applied_to_tab_sandbox",
  );
  ok(
    "repeat blocked",
    JSON.parse((await apply()).content[0].text).status === "denied",
  );
  await stage({
    action: "set_inventory_note",
    recipient: "sandbox-inventory",
    body: "Spare sensor in drawer",
  });
  await approval();
  ok(
    "approved inventory note applies",
    JSON.parse((await apply()).content[0].text).status ===
      "applied_to_tab_sandbox",
  );
  ok(
    "inventory state changed at bound revision",
    await page.evaluate(
      () =>
        window.testBoundary.snapshot().state.inventoryNote ===
        "Spare sensor in drawer",
    ),
  );
  await stage();
  await page.evaluate(() => window.bindTestApproval());
  await stage({ body: "Replacement while old preview was focused" });
  await page.waitForTimeout(350);
  await page.locator("#test-approve").click();
  ok(
    "trusted activation of stale preview cannot approve replacement",
    await page.evaluate(
      () => window.testBoundary.snapshot().approval === "not_approved",
    ),
  );
  ok(
    "stub invocations labelled, never Meta proof",
    await page.evaluate(() =>
      window.testBoundary
        .snapshot()
        .events.filter((e) => ["proposed", "sandbox_applied"].includes(e.kind))
        .every((e) => e.origin === "isolated_registration_stub"),
    ),
  );
  ok(
    "receipt hash chain verifies",
    await page.evaluate(() => window.testBoundary.verify()),
  );
  await page.evaluate(async () => {
    const { SwanBoundary } = await import("/native/boundary.mjs");
    window.testBoundary = new SwanBoundary({
      notify: () => {
        throw Error("broken view");
      },
    });
    window.testBoundary.stage({
      action: "save_note",
      body: "Must retain successful result",
      recipient: "sandbox-notebook",
      expectedRevision: 0,
    });
    window.bindTestApproval();
  });
  await page.waitForTimeout(350);
  await page.locator("#test-approve").click();
  ok(
    "notification failure cannot misreport applied state",
    await page.evaluate(
      () =>
        window.testBoundary.apply(window.testBoundary.snapshot().pending)
          .status === "applied_to_tab_sandbox",
    ),
  );
  ok(
    "notification failure preserves applied receipt",
    await page.evaluate(
      () =>
        window.testBoundary.snapshot().events.at(-1).kind ===
          "sandbox_applied" && window.testBoundary.verify(),
    ),
  );
  // Fresh short-lived session with a real browser click; no exported approval seam.
  await page.evaluate(async () => {
    const { SwanBoundary } = await import("/native/boundary.mjs");
    window.testBoundary = new SwanBoundary({ ttlMs: 1 });
    window.testBoundary.stage({
      action: "save_note",
      body: "Expiry check",
      recipient: "sandbox-notebook",
      expectedRevision: 0,
    });
    window.bindTestApproval();
  });
  await page.waitForTimeout(350);
  await page.locator("#test-approve").click();
  ok(
    "expired authority denied",
    reason(
      await page.evaluate(() => ({
        content: [
          {
            text: JSON.stringify(
              window.testBoundary.apply(window.testBoundary.snapshot().pending),
            ),
          },
        ],
      })),
    ) === "CAPABILITY_EXPIRED",
  );
  ok(
    "unavailable host registers nothing",
    await page.evaluate(async () => {
      const { registerNativeTools } = await import("/native/boundary.mjs");
      return registerNativeTools({}, window.testBoundary).available === false;
    }),
  );
  await page.goto(base);
  await page.locator("#stage").evaluate((button) => {
    for (let i = 0; i < 1010; i += 1) button.click();
  });
  ok(
    "session budget visibly stops further changes",
    await page
      .locator("#result")
      .innerText()
      .then((text) => text.includes("Session event limit reached")),
  );
  ok(
    "exhausted session disables action controls without changing state",
    (await page.locator("#stage").isDisabled()) &&
      (await page.locator("#confirm").isDisabled()) &&
      (await page.locator("#apply").isDisabled()) &&
      (await page.locator("#revision").innerText()) === "Revision 0",
  );
  const reference = await page.request.get(base + "/reference");
  ok(
    "OCR/QR reference route retained",
    reference.ok() &&
      (await reference.text()).includes("OCR/QR reference experiment"),
  );
  ok("no page errors", errors.length === 0);
  fs.mkdirSync("research", { recursive: true });
  fs.writeFileSync(
    "research/native-verification.json",
    JSON.stringify(
      {
        scope:
          "Headless Chromium local handler and isolated host-shape checks only. No real Meta AI, glasses, HTTPS, native voice or Neural Band verified.",
        checks,
        errors,
      },
      null,
      2,
    ) + "\n",
  );
  console.log(
    JSON.stringify({ passed: checks.length, failed: 0, checks }, null, 2),
  );
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
