import { ReferenceBroker, secureHash } from "./lib/reference-broker.mjs";

export const MAX_EVENTS = 1000;

// The model proposes JSON. Only a trusted DOM activation on a page-owned,
// rendered preview can issue the broker capability. There is no approval tool.
const ACTION_KEYS = ["action", "body", "recipient", "expectedRevision"];
function actionInput(input, withNonce = false) {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype)
    throw Error("INVALID_ACTION");
  const keys = [...ACTION_KEYS, ...(withNonce ? ["nonce"] : [])];
  if (
    Object.keys(input).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(input, k))
  )
    throw Error("UNKNOWN_OR_MISSING_ARGUMENT");
  if (!["save_note", "set_inventory_note"].includes(input.action))
    throw Error("ACTION_NOT_ALLOWED");
  const recipient =
    input.action === "save_note" ? "sandbox-notebook" : "sandbox-inventory";
  if (input.recipient !== recipient) throw Error("RECIPIENT_NOT_ALLOWED");
  if (
    typeof input.body !== "string" ||
    !input.body.trim() ||
    input.body.length > 280 ||
    /\p{Cf}|[\u034f\ufe00-\ufe0f]/u.test(input.body) ||
    /[\u0000-\u0008\u000b-\u001f\u007f]/.test(input.body)
  )
    throw Error("BODY_INVALID");
  if (
    !Number.isSafeInteger(input.expectedRevision) ||
    input.expectedRevision < 0
  )
    throw Error("REVISION_INVALID");
  if (
    withNonce &&
    (typeof input.nonce !== "string" || !/^[a-f0-9-]{36}$/.test(input.nonce))
  )
    throw Error("NONCE_INVALID");
  return structuredClone(input);
}
export class SwanBoundary {
  #bindings = new WeakMap();
  #notificationErrors = 0;
  #broker;
  #pending = null;
  #permit = null;
  #clock;
  #notify;
  #state = {
    revision: 0,
    note: "Nothing saved yet.",
    inventoryNote: "No inventory note.",
  };
  #events = [];
  #logLimitReached = false;
  constructor({
    clock = () => Date.now(),
    notify = () => {},
    ttlMs = 15000,
  } = {}) {
    this.#clock = clock;
    this.#notify = notify;
    this.ttlMs = Math.min(Math.max(ttlMs, 1), 15000);
    this.#broker = new ReferenceBroker({ clock, idPrefix: "SWAN-NATIVE" });
  }
  #limitDenial() {
    const newlyReached = !this.#logLimitReached;
    this.#logLimitReached = true;
    if (this.#permit) this.#broker.revoke(this.#permit.capabilityId);
    this.#permit = null;
    if (newlyReached) {
      try {
        this.#notify(this.snapshot());
      } catch {
        this.#notificationErrors += 1;
      }
    }
    return {
      status: "denied",
      reason: "EVENT_LOG_LIMIT_REACHED",
      next_action:
        "Stop and start a fresh sandbox session; no further actions were applied.",
    };
  }
  #record(kind, origin, data) {
    // Keep one receipt slot while a capability is live. Approval itself must
    // also leave room for the eventual applied-action event.
    if (
      this.#logLimitReached ||
      this.#events.length >= MAX_EVENTS ||
      (this.#permit?.usesRemaining === 1 &&
        kind !== "sandbox_applied" &&
        this.#events.length >= MAX_EVENTS - 1)
    )
      return this.#limitDenial();
    const previousHash = this.#events.at(-1)?.hash ?? "genesis";
    const event = {
      sequence: this.#events.length + 1,
      at: this.#clock(),
      kind,
      origin,
      data: structuredClone(data),
      previousHash,
    };
    this.#events.push({ ...event, hash: secureHash(event) });
    if (this.#events.length >= MAX_EVENTS) this.#logLimitReached = true;
    try {
      this.#notify(this.snapshot());
    } catch {
      this.#notificationErrors += 1;
    }
    return data;
  }
  #deny(reason, origin) {
    return this.#record("denied", origin, {
      status: "denied",
      reason,
      next_action: "Stop and tell the wearer the action was not applied.",
    });
  }
  #preview(action) {
    return {
      proposalId: action.nonce,
      operation: action.action,
      destination: action.recipient,
      payloadHash: secureHash({ schema: "swan-sandbox-action-v1", ...action }),
      disclosedContextRefs: [],
    };
  }
  snapshot() {
    return {
      notificationErrors: this.#notificationErrors,
      logLimitReached: this.#logLimitReached,
      expiresAt: this.#permit?.expiresAt ?? null,
      state: structuredClone(this.#state),
      pending: structuredClone(this.#pending),
      approval: this.#permit
        ? this.#permit.usesRemaining === 0
          ? "consumed"
          : this.#clock() >= this.#permit.expiresAt
            ? "expired"
            : "approved_once"
        : "not_approved",
      events: structuredClone(this.#events),
      scope:
        "Tab-local sandbox only. No email, purchase, physical device or external action.",
    };
  }
  read(origin) {
    return this.#record("read", origin, {
      status: "read",
      state: structuredClone(this.#state),
      pending: structuredClone(this.#pending),
      next_action: "Propose a sandbox change or stop and talk.",
    });
  }
  stage(input, origin = "manual_local_harness") {
    if (this.#logLimitReached || this.#events.length > MAX_EVENTS - 3)
      return this.#limitDenial();
    try {
      const a = actionInput(input);
      if (a.expectedRevision !== this.#state.revision)
        return this.#deny("REVISION_CHANGED", origin);
      if (this.#permit) this.#broker.revoke(this.#permit.capabilityId);
      this.#permit = null;
      this.#pending = { ...a, nonce: crypto.randomUUID() };
      return this.#record("proposed", origin, {
        status: "awaiting_human",
        proposal: structuredClone(this.#pending),
        next_action:
          "Stop and ask the wearer to review and activate Confirm on the page. A tool argument cannot approve.",
      });
    } catch (e) {
      return this.#deny(e.message, origin);
    }
  }
  refresh() {
    if (
      this.#permit &&
      this.#permit.usesRemaining === 1 &&
      this.#clock() >= this.#permit.expiresAt
    ) {
      this.#broker.revoke(this.#permit.capabilityId);
      this.#permit = null;
      // Expiry creates a fresh review identity, never remints the old confirmation.
      this.#pending = { ...this.#pending, nonce: crypto.randomUUID() };
      this.#record("approval_expired", "page_clock", {
        status: "expired_review_again",
        nonce: this.#pending.nonce,
      });
    }
    return this.snapshot();
  }
  bindApproval(button, renderedNonce) {
    let binding = this.#bindings.get(button);
    if (!binding) {
      binding = {
        nonce: renderedNonce,
        startedNonce: null,
        changedAt: this.#clock(),
      };
      this.#bindings.set(button, binding);
      const start = (event) => {
        if (
          event.isTrusted &&
          (event.type === "pointerdown" || ["Enter", " "].includes(event.key))
        )
          binding.startedNonce = binding.nonce;
      };
      button.addEventListener?.("pointerdown", start);
      button.addEventListener?.("keydown", start);
      button.onclick = (event) => {
        const startedNonce = binding.startedNonce;
        binding.startedNonce = null;
        if (
          !(event instanceof Event) ||
          event.isTrusted !== true ||
          event.currentTarget !== button ||
          !button.isConnected ||
          !this.#pending ||
          binding.nonce !== this.#pending.nonce ||
          (startedNonce !== null && startedNonce !== binding.nonce)
        )
          return this.#deny(
            "TRUSTED_CURRENT_PREVIEW_REQUIRED",
            "dom_activation",
          );
        // A short review interval prevents a newly replaced preview inheriting
        // the release of an in-flight gesture. It is not evidence of attention.
        if (this.#clock() - binding.changedAt < 300)
          return this.#deny("PREVIEW_CHANGED_REVIEW_AGAIN", "dom_activation");
        if (this.#pending.expectedRevision !== this.#state.revision)
          return this.#deny("REVISION_CHANGED", "dom_activation");
        if (this.#permit)
          return this.#deny("ALREADY_APPROVED", "dom_activation");
        if (this.#logLimitReached || this.#events.length > MAX_EVENTS - 2)
          return this.#limitDenial();
        const preview = this.#preview(this.#pending);
        this.#permit = this.#broker.issueCapability(
          {
            status: "confirm",
            authority: "one_time_capability",
            proposalId: this.#pending.nonce,
            preview,
          },
          { confirmation: true, ttlMs: this.ttlMs },
        );
        return this.#record("human_approved", "trusted_dom_activation", {
          status: "approved_once",
          nonce: this.#pending.nonce,
          previewHash: secureHash(preview),
          expiresAt: this.#permit.expiresAt,
        });
      };
    } else if (binding.nonce !== renderedNonce) {
      binding.nonce = renderedNonce;
      binding.changedAt = this.#clock();
      // Preserve startedNonce: an in-flight old gesture must be rejected.
    }
  }
  apply(input, origin = "manual_local_harness") {
    if (this.#logLimitReached || this.#events.length >= MAX_EVENTS)
      return this.#limitDenial();
    try {
      const action = actionInput(input, true);
      if (!this.#pending || !this.#permit)
        return this.#deny("HUMAN_APPROVAL_REQUIRED", origin);
      if (action.expectedRevision !== this.#state.revision)
        return this.#deny("REVISION_CHANGED", origin);
      const gate = this.#broker.execute(
        this.#permit.capabilityId,
        this.#preview(action),
      );
      if (gate.status !== "executed_local_simulation")
        return this.#deny(gate.reason, origin);
      this.#permit.usesRemaining = 0;
      const before = structuredClone(this.#state);
      if (action.action === "save_note") this.#state.note = action.body;
      else this.#state.inventoryNote = action.body;
      this.#state.revision += 1;
      return this.#record("sandbox_applied", origin, {
        status: "applied_to_tab_sandbox",
        action,
        before,
        after: structuredClone(this.#state),
        next_action: "Stop and tell the wearer the sandbox change is saved.",
      });
    } catch (e) {
      return this.#deny(e.message, origin);
    }
  }
  verify() {
    let previousHash = "genesis";
    for (const entry of this.#events) {
      const { hash, ...event } = entry;
      if (event.previousHash !== previousHash || secureHash(event) !== hash)
        return false;
      previousHash = hash;
    }
    return true;
  }
}
const output = (value) => ({
  content: [{ type: "text", text: JSON.stringify(value) }],
  isError: value.status === "denied",
});
export function registerNativeTools(doc, boundary, { testStub = false } = {}) {
  const host = doc?.modelContext;
  if (typeof host?.registerTool !== "function")
    return { available: false, status: "Native tools unavailable", tools: [] };
  // API presence identifies a host callback, not authenticated Meta identity.
  // Explicit test stubs are labelled separately in every request receipt.
  const origin = testStub
    ? "isolated_registration_stub"
    : "native_webmcp_callback_unattested";
  const properties = {
    action: { type: "string", enum: ["save_note", "set_inventory_note"] },
    body: { type: "string", maxLength: 280 },
    recipient: {
      type: "string",
      enum: ["sandbox-notebook", "sandbox-inventory"],
    },
    expectedRevision: { type: "integer", minimum: 0 },
  };
  const tools = [
    {
      name: "swan_read_sandbox",
      description:
        "Read the Swan sandbox and pending proposal. No external or physical device effects.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
      execute: async (args) =>
        output(
          args && Object.keys(args).length
            ? { status: "denied", reason: "UNKNOWN_ARGUMENT" }
            : boundary.read(origin),
        ),
    },
    {
      name: "swan_propose_change",
      description:
        "Stage one harmless notebook or inventory-note change for human review. This never approves or applies. Return the nonce; ask the wearer to use Confirm. Do not supply confirmed, authority or approval.",
      inputSchema: {
        type: "object",
        properties,
        required: ACTION_KEYS,
        additionalProperties: false,
      },
      annotations: { openWorldHint: false },
      execute: async (args) => output(boundary.stage(args, origin)),
    },
    {
      name: "swan_apply_approved_change",
      description:
        "Apply the exact previously proposed sandbox action only after page-owned human confirmation. Supply its unchanged action, body, recipient, revision and nonce. No approval arguments exist.",
      inputSchema: {
        type: "object",
        properties: { ...properties, nonce: { type: "string" } },
        required: [...ACTION_KEYS, "nonce"],
        additionalProperties: false,
      },
      annotations: { openWorldHint: false },
      execute: async (args) => output(boundary.apply(args, origin)),
    },
  ];
  const registered = [];
  try {
    for (const tool of tools) {
      host.registerTool(tool);
      registered.push(tool.name);
    }
  } catch (e) {
    for (const name of registered) host.unregisterTool?.(name);
    return {
      available: false,
      status: "Native tool registration failed",
      tools: [],
      reason: String(e),
    };
  }
  return {
    available: true,
    status: testStub
      ? "Isolated registration stub"
      : "WebMCP tools registered; Meta device unverified",
    tools: registered,
  };
}
