import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_EVENTS,
  SwanBoundary,
  registerNativeTools,
} from "../public/native/boundary.mjs";
const action = {
  action: "save_note",
  body: "A harmless note",
  recipient: "sandbox-notebook",
  expectedRevision: 0,
};
test("proposal is a reviewable plan, never authority", () => {
  const b = new SwanBoundary();
  const r = b.stage(action);
  assert.equal(r.status, "awaiting_human");
  assert.equal(b.snapshot().state.revision, 0);
  assert.equal(b.apply(b.snapshot().pending).reason, "HUMAN_APPROVAL_REQUIRED");
});
test("model cannot self-confirm or add capabilities", () => {
  for (const field of [
    "confirmed",
    "confirmation",
    "authority",
    "capabilityId",
  ]) {
    const b = new SwanBoundary();
    assert.equal(b.stage({ ...action, [field]: true }).status, "denied");
    assert.equal(b.snapshot().pending, null);
  }
});
test("finite action and recipient scope enforced outside annotations", () => {
  const b = new SwanBoundary();
  for (const patch of [
    { action: "send_email" },
    { recipient: "user@example.test" },
    { expectedRevision: -1 },
    { body: "x".repeat(281) },
  ])
    assert.equal(b.stage({ ...action, ...patch }).status, "denied");
});
test("unknown and changed revisions fail closed", () => {
  const b = new SwanBoundary();
  assert.equal(
    b.stage({ ...action, expectedRevision: 1 }).reason,
    "REVISION_CHANGED",
  );
  assert.equal(b.stage(null).status, "denied");
  assert.equal(b.stage([]).status, "denied");
});
test("scripted event lacks DOM authority", () => {
  const b = new SwanBoundary();
  b.stage(action);
  const button = {};
  b.bindApproval(button, b.snapshot().pending.nonce);
  button.onclick({ isTrusted: false });
  button.onclick({ isTrusted: true });
  assert.equal(b.snapshot().approval, "not_approved");
  assert.equal(b.apply(b.snapshot().pending).status, "denied");
});
test("stale displayed nonce cannot authorize replacement proposal", () => {
  const b = new SwanBoundary();
  b.stage(action);
  const first = b.snapshot().pending;
  const button = {};
  b.bindApproval(button, first.nonce);
  b.stage({ ...action, body: "replacement" });
  button.onclick({ isTrusted: false });
  button.onclick({ isTrusted: true });
  assert.equal(b.snapshot().approval, "not_approved");
});
test("native registration uses host API and returns explicit absence", () => {
  const b = new SwanBoundary();
  assert.equal(registerNativeTools({}, b).available, false);
  const tools = [];
  const r = registerNativeTools(
    { modelContext: { registerTool: (t) => tools.push(t) } },
    b,
    { testStub: true },
  );
  assert.equal(r.status, "Isolated registration stub");
  assert.equal(tools.length, 3);
  assert.ok(tools.every((t) => t.execute && t.inputSchema && t.name));
  assert.ok(!tools.some((t) => /^swan_(approve|confirm)/.test(t.name)));
});
test("host-shaped isolated callback returns origin-labelled state and chain", async () => {
  const b = new SwanBoundary();
  const tools = [];
  registerNativeTools(
    { modelContext: { registerTool: (t) => tools.push(t) } },
    b,
    { testStub: true },
  );
  await tools[1].execute(action);
  await tools[0].execute({});
  assert.equal(b.snapshot().events[0].origin, "isolated_registration_stub");
  assert.equal(b.verify(), true);
});

test("notification exceptions preserve successful proposal result and chain", () => {
  const b = new SwanBoundary({
    notify: () => {
      throw Error("renderer failed");
    },
  });
  assert.equal(b.stage(action).status, "awaiting_human");
  assert.equal(b.snapshot().events.at(-1).kind, "proposed");
  assert.equal(b.snapshot().notificationErrors, 1);
  assert.equal(b.verify(), true);
});
test("hidden Unicode format and bidi characters are rejected", () => {
  for (const body of [
    "safe\u202Ehidden",
    "safe\u200Bhidden",
    "safe\u2066hidden",
    "safe\u034fhidden",
  ]) {
    const b = new SwanBoundary();
    assert.equal(b.stage({ ...action, body }).reason, "BODY_INVALID");
  }
});

test("event budget is terminal and prevents unreceipted actions", () => {
  const b = new SwanBoundary();
  for (let i = 0; i < MAX_EVENTS + 20; i++) b.read("event_limit_test");
  const exhausted = b.snapshot();
  assert.equal(exhausted.events.length, MAX_EVENTS);
  assert.equal(exhausted.logLimitReached, true);
  assert.equal(b.verify(), true);
  assert.equal(b.stage(action).reason, "EVENT_LOG_LIMIT_REACHED");
  assert.equal(b.snapshot().pending, null);
  const before = b.snapshot().state;
  assert.equal(b.apply(null).reason, "EVENT_LOG_LIMIT_REACHED");
  assert.deepEqual(b.snapshot().state, before);
  assert.equal(b.snapshot().events.length, MAX_EVENTS);
  assert.equal(b.verify(), true);
});
