import {
  createLocalReceipt,
  decideProposal,
  INTERACTION_STATES,
  normalizeDestination,
  POLICY_VERSION,
  previewMatchesExecution,
} from "./decision-engine.mjs";
import { applyNeuraNice, assess, ProposalHistory } from "./neuranice.mjs";
import { checkPurpose, normalizePurpose } from "./passport.mjs";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function canonicalize(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("only finite numbers can be hashed");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("only JSON-compatible values can be hashed");
}

// FNV-1a is retained only for non-security corpus fingerprints and cache keys.
// Authority always binds canonical payloads and previews with secureHash.
export function fastHash(value) {
  let hash = 2166136261;
  for (const character of canonicalize(value)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `fnv1a-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

export const prototypeHash = fastHash;

// --- secureHash: SHA-256, pure JS, zero dependencies -----------------------
//
// This is the actual integrity primitive for this module. It has no import of
// any kind, so the exact same code path runs in Node and in the browser bundle
// that loads this file directly over HTTP (node:crypto does not resolve there,
// and this hash must stay synchronous everywhere it is called, so a lazy
// dynamic import of node:crypto was not used either). Every NEW security
// critical binding added by this fix uses secureHash, never prototypeHash:
// capability.previewHash (the artifact that ties an issued capability to the
// exact preview a human confirmed), its re-verification at execute() time, and
// the previewHash recorded on receipts in the append-only event log.
const SHA256_K = Object.freeze([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

function sha256Hex(message) {
  const bytes = new TextEncoder().encode(message);
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(bytes);
  buffer[bytes.length] = 0x80;
  const view = new DataView(buffer.buffer);
  // 64-bit big-endian bit length. Inputs here are canonicalized JSON strings
  // of local proposals and previews, nowhere near the 2^32 bit length where
  // the high word below would need to be anything but zero.
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);

  let h0 = 0x6a09e667,
    h1 = 0xbb67ae85,
    h2 = 0x3c6ef372,
    h3 = 0xa54ff53a;
  let h4 = 0x510e527f,
    h5 = 0x9b05688c,
    h6 = 0x1f83d9ab,
    h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i += 1)
      w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i += 1) {
      const s0 =
        rightRotate(w[i - 15], 7) ^
        rightRotate(w[i - 15], 18) ^
        (w[i - 15] >>> 3);
      const s1 =
        rightRotate(w[i - 2], 17) ^
        rightRotate(w[i - 2], 19) ^
        (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;
    for (let i = 0; i < 64; i += 1) {
      const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((word) => word.toString(16).padStart(8, "0"))
    .join("");
}

export function secureHash(value) {
  return `sha256-${sha256Hex(canonicalize(value))}`;
}

function validString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validateStringArray(value, code, errors) {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.some((item) => !validString(item)))
    errors.push(code);
}

export function validateProposal(proposal = {}) {
  const errors = [];
  if (!isPlainObject(proposal))
    return { valid: false, errors: ["PROPOSAL_MUST_BE_OBJECT"] };
  if (!validString(proposal.proposalId)) errors.push("MISSING_PROPOSAL_ID");
  // Defers to decideProposal's own INTERACTION_STATES rather than accepting
  // any non-empty string. Two independent notions of "valid state" is a drift
  // hazard: this validator used to be looser than decideProposal, which fails
  // closed either way today, but there is no guarantee a future change to one
  // side would be noticed without a shared source of truth.
  if (
    !validString(proposal.state) ||
    !INTERACTION_STATES.includes(proposal.state)
  )
    errors.push("INVALID_STATE");
  if (!validString(proposal.proposedOperation))
    errors.push("INVALID_OPERATION");
  if (proposal.destination !== null && proposal.destination !== undefined) {
    if (!validString(proposal.destination)) {
      errors.push("DESTINATION_MUST_BE_STRING");
    } else if (!normalizeDestination(proposal.destination).ok) {
      errors.push("DESTINATION_UNSAFE_CHARACTERS");
    }
  }
  validateStringArray(proposal.contextRefs, "INVALID_CONTEXT_REFS", errors);
  validateStringArray(
    proposal.inferredContextRefs,
    "INVALID_INFERRED_CONTEXT_REFS",
    errors,
  );
  if (
    proposal.confidence !== undefined &&
    (!Number.isFinite(proposal.confidence) ||
      proposal.confidence < 0 ||
      proposal.confidence > 1)
  ) {
    errors.push("INVALID_CONFIDENCE");
  }
  if (
    proposal.provenanceVerified !== undefined &&
    typeof proposal.provenanceVerified !== "boolean"
  ) {
    errors.push("INVALID_PROVENANCE_FLAG");
  }
  if (proposal.payload !== undefined) {
    try {
      canonicalize(proposal.payload);
    } catch {
      errors.push("INVALID_PAYLOAD");
    }
  }
  return { valid: errors.length === 0, errors };
}

function clone(value) {
  return structuredClone(value);
}

function validPreview(value) {
  return (
    isPlainObject(value) &&
    validString(value.proposalId) &&
    validString(value.operation) &&
    (value.destination === null || validString(value.destination)) &&
    validString(value.payloadHash) &&
    Array.isArray(value.disclosedContextRefs) &&
    value.disclosedContextRefs.every(validString)
  );
}

function previewFor(proposal, decision) {
  return {
    proposalId: proposal.proposalId.trim(),
    operation: proposal.proposedOperation.trim(),
    destination: normalizeDestination(proposal.destination).value,
    payloadHash: secureHash(proposal.payload ?? {}),
    disclosedContextRefs: [...decision.disclosedContextRefs],
  };
}

function invalidEvaluation(errors) {
  return {
    policyVersion: POLICY_VERSION,
    status: "deny",
    reasonCodes: ["INVALID_PROPOSAL", ...errors],
    authority: "none",
    preview: null,
  };
}

// Bound on how many confirm decisions the broker remembers for the purpose of
// refusing a second issueCapability against the same one. This is a deliberate
// memory safety valve, not a security hole: it only matters after this many
// OTHER confirmations have since been issued, at which point the evicted entry
// is operationally irrelevant, its own capability has long since expired, been
// used, or been revoked. Without a bound, a long lived broker embedding would
// grow this map forever.
const MAX_TRACKED_CONFIRMATIONS = 20_000;

export class ReferenceBroker {
  constructor({
    clock = () => Date.now(),
    idPrefix = "LUNA-CAP",
    storage = null,
    storageKey = "luna.event.log",
    ledger = null,
  } = {}) {
    if (typeof clock !== "function")
      throw new TypeError("clock must be a function");
    this.clock = clock;
    this.idPrefix = idPrefix;
    this.storage =
      storage &&
      typeof storage.getItem === "function" &&
      typeof storage.setItem === "function"
        ? storage
        : null;
    this.storageKey = storageKey;
    this.capabilities = new Map();
    this.sharePackets = new Map();
    this.events = this.readStoredEvents();
    this.sequence = 0;
    // Keyed on proposalId + previewHash (see issueCapability). Never deleted on
    // revoke or expiry, only bounded by trackConfirmation's eviction. See the
    // comment on issueCapability for why revocation and expiry do not free the
    // key for reuse.
    this.issuedConfirmations = new Map();
    // Ledger.create() is async (it may need to generate an Ed25519 keypair), so
    // it cannot be built here. A caller that wants the broker's events mirrored
    // into a tamper evident hash chain builds one with `await Ledger.create()`
    // and passes it in. Without one, the broker behaves exactly as before:
    // an in-memory (and optionally storage-backed) event log only.
    this.ledger = ledger;
    // Ledger.append() is fire-and-forget from appendEvent (see below), so a
    // rejected write cannot become an unhandled rejection. It is recorded here
    // instead, mirroring the pattern core/passport.mjs uses for passport.ledgerErrors.
    this.ledgerErrors = [];
    // One history for the lifetime of the broker. A new ProposalHistory per
    // evaluate() call would see no prior proposals, which would blind
    // detectPersuasion() to escalation, scope creep, and confidence inflation
    // across a session: the whole point of that detector is pattern matching
    // across calls on the SAME broker.
    this.history = new ProposalHistory();
  }

  readStoredEvents() {
    if (!this.storage) return [];
    try {
      const parsed = JSON.parse(this.storage.getItem(this.storageKey) || "[]");
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  persistEvents() {
    if (!this.storage) return;
    try {
      this.storage.setItem(this.storageKey, JSON.stringify(this.events));
    } catch {
      // Local persistence is best effort. The in-memory event log remains authoritative for this session.
    }
  }

  appendEvent(eventType, details = {}) {
    const event = {
      eventId: `LUNA-EVT-${String(this.events.length + 1).padStart(4, "0")}`,
      eventType,
      recordedAt: this.clock(),
      ...clone(details),
    };
    this.events.push(event);
    this.persistEvents();
    // Mirror into the tamper evident ledger, if one is attached. Ledger#append
    // is synchronous to call (it returns a Promise) but this method itself
    // must stay synchronous, because receipt() below depends on appendEvent's
    // RETURN VALUE to build the receipt it hands back. So this is fire and
    // forget from here: the ledger write happens in the background, and its
    // internal promise queue (see core/ledger.mjs) guarantees ordering even
    // under concurrent appends. A failed write is never allowed to become an
    // unhandled rejection; it is recorded on ledgerErrors instead.
    if (this.ledger && typeof this.ledger.append === "function") {
      const pending = this.ledger.append(eventType, event);
      if (pending && typeof pending.catch === "function") {
        pending.catch((error) => {
          this.ledgerErrors.push({
            type: eventType,
            message: error?.message || String(error),
            at: this.clock(),
          });
        });
      }
    }
    return clone(event);
  }

  eventLog() {
    return clone(this.events);
  }

  /**
   * Recompute and verify the attached ledger's whole hash chain from genesis.
   * Returns null when no ledger is attached, never a fabricated pass.
   */
  async verifyLedger() {
    return this.ledger ? this.ledger.verify() : null;
  }

  evaluate(proposal, context = {}) {
    // validateProposal, previewFor, and assess() all read fields directly off
    // the raw proposal, same as decideProposal does. decideProposal guards its
    // own reads (see decision-engine.mjs), but a hostile object (for example a
    // Proxy whose getters throw) can still reach any of the others here.
    // Fail closed the same way: never let a malformed or adversarial proposal
    // turn a policy decision into an uncaught exception.
    try {
      const validation = validateProposal(proposal);
      if (!validation.valid) return invalidEvaluation(validation.errors);
      const decision = decideProposal(proposal, context);
      const withPreview = {
        ...decision,
        preview: previewFor(proposal, decision),
      };
      // NeuraNice is layered on here, deliberately outside decideProposal, so
      // the engine's own monotonic restriction invariant stays testable in
      // isolation. assess() runs AFTER the preview is attached, so that if
      // applyNeuraNice restricts the decision it can null the preview out from
      // under a share_ready or confirm result that no longer applies.
      const assessment = assess(proposal, {
        history: this.history,
        sessionId: context.sessionId,
        config: context.neuraniceConfig,
      });
      const guarded = applyNeuraNice(withPreview, assessment);
      // Recorded AFTER the guarded decision is known, never before: the
      // persuasion detector's escalation_after_refusal signal reads the
      // recorded status of past proposals, so recording the pre-guard status
      // would let a proposal see its own restriction as if it were history.
      this.history.record(context.sessionId, proposal, guarded);
      return guarded;
    } catch {
      return invalidEvaluation(["INVALID_PROPOSAL"]);
    }
  }

  createSharePacket(
    decision,
    {
      packetId = `LUNA-SHARE-${String(++this.sequence).padStart(4, "0")}`,
      expiryMs = 86_400_000,
      purpose = null,
    } = {},
  ) {
    if (!decision || decision.status !== "share_ready")
      throw new Error("share packet requires a share_ready decision");
    if (!validString(packetId) || !Number.isFinite(expiryMs) || expiryMs <= 0)
      throw new Error("valid packet id and expiry are required");
    const createdAt = this.clock();
    // purpose uses the same normalization (trim, lower case) as
    // core/passport.mjs's checkPurpose, which is the function this packet is
    // checked against later. A packet with no declared purpose is not usable
    // for any purpose bound check: checkPurpose fails closed on that (see
    // PACKET_PURPOSE_UNBOUND), it never treats an absent purpose as "any".
    const normalizedPurpose = normalizePurpose(purpose);
    const packet = {
      packetId,
      policyVersion: decision.policyVersion,
      proposalId: decision.proposalId,
      destination: decision.destination,
      disclosedContextRefs: [...decision.disclosedContextRefs],
      excludedContextRefs: [...decision.excludedContextRefs],
      purpose: normalizedPurpose,
      createdAt,
      expiresAt: createdAt + expiryMs,
      delivery: "not_sent",
      revocable: true,
      revoked: false,
      revokedAt: null,
    };
    this.sharePackets.set(packetId, packet);
    this.appendEvent("share_packet_created", {
      packetId,
      proposalId: packet.proposalId,
      destination: packet.destination,
      purpose: packet.purpose,
      expiresAt: packet.expiresAt,
      disclosedContextRefs: packet.disclosedContextRefs,
      excludedContextRefs: packet.excludedContextRefs,
    });
    return clone(packet);
  }

  revokeSharePacket(packetId) {
    const packet = this.sharePackets.get(packetId);
    if (!packet) return false;
    if (!packet.revoked) {
      packet.revoked = true;
      packet.revokedAt = this.clock();
      this.appendEvent("share_packet_revoked", {
        packetId,
        revokedAt: packet.revokedAt,
      });
    }
    return true;
  }

  // purpose is optional. When supplied, availability is checked first (not
  // found, revoked, expired, exactly as before), and only a packet that
  // clears all three is then checked against the requested purpose via
  // core/passport.mjs's checkPurpose. A caller that never passes a purpose
  // gets exactly the old behaviour: this is purely additive.
  checkSharePacket(packetId, { purpose } = {}) {
    const packet = this.sharePackets.get(packetId);
    if (!packet) return { status: "denied", reason: "PACKET_NOT_FOUND" };
    if (packet.revoked)
      return { status: "denied", reason: "PACKET_REVOKED", packetId };
    if (this.clock() >= packet.expiresAt)
      return { status: "denied", reason: "PACKET_EXPIRED", packetId };
    if (purpose !== undefined) {
      const check = checkPurpose(packet, purpose, { now: this.clock() });
      if (!check.allowed)
        return { status: "denied", reason: check.reason, packetId, ...check };
    }
    return { status: "available", delivery: packet.delivery, packetId };
  }

  // Bounded FIFO cache: once full, the oldest tracked confirmation is evicted
  // to make room for the new one. See MAX_TRACKED_CONFIRMATIONS above.
  trackConfirmation(confirmationKey, capabilityId) {
    if (
      this.issuedConfirmations.size >= MAX_TRACKED_CONFIRMATIONS &&
      !this.issuedConfirmations.has(confirmationKey)
    ) {
      const oldestKey = this.issuedConfirmations.keys().next().value;
      this.issuedConfirmations.delete(oldestKey);
    }
    this.issuedConfirmations.set(confirmationKey, capabilityId);
  }

  issueCapability(
    decision,
    {
      confirmation = false,
      ttlMs = 60_000,
      capabilityId = `${this.idPrefix}-${String(++this.sequence).padStart(4, "0")}`,
    } = {},
  ) {
    if (
      !decision ||
      decision.status !== "confirm" ||
      decision.authority !== "one_time_capability"
    ) {
      throw new Error("capability requires a confirm decision");
    }
    if (confirmation !== true)
      throw new Error("explicit confirmation is required");
    if (
      !validString(capabilityId) ||
      !Number.isFinite(ttlMs) ||
      ttlMs <= 0 ||
      !decision.preview
    ) {
      throw new Error("valid capability id, ttl, and preview are required");
    }

    // One human confirmation authorizes at most one capability, ever, enforced
    // here in the broker rather than left to whatever calls it. Keyed on
    // proposalId plus previewHash: a genuinely different proposal, or the same
    // proposal producing a materially different preview (different approved
    // context, for instance), gets its own key and is unaffected.
    //
    // The key is never freed once a capability has been issued against it, not
    // on revoke and not on expiry:
    //   - Revoke: the human is withdrawing the "yes" they already gave. Letting
    //     a second issueCapability succeed after that would hand back exactly
    //     the authority the human just took away, using the same stale
    //     confirmation as justification. That undoes the withdrawal.
    //   - Expiry: the approval window lapsed unused. If the action is still
    //     wanted, that calls for a fresh human confirmation on a fresh
    //     proposal, not a silent re-mint from a confirmation the human gave
    //     for a window that has already closed. Re-minting on expiry would
    //     make "expires" mean nothing more than "briefly inconvenient to
    //     replay."
    // Both readings fail closed: once served, always served, regardless of
    // what later happens to the capability that was issued.
    const previewHash = secureHash(decision.preview);
    const confirmationKey = `${decision.proposalId}::${previewHash}`;
    if (this.issuedConfirmations.has(confirmationKey)) {
      return this.recordDeniedIssuance(
        "CONFIRMATION_ALREADY_CONSUMED",
        decision,
        previewHash,
      );
    }

    const issuedAt = this.clock();
    const capability = {
      capabilityId,
      preview: clone(decision.preview),
      previewHash,
      issuedAt,
      expiresAt: issuedAt + ttlMs,
      usesRemaining: 1,
      revoked: false,
      revokedAt: null,
    };
    this.capabilities.set(capabilityId, capability);
    this.trackConfirmation(confirmationKey, capabilityId);
    this.appendEvent("capability_issued", {
      capabilityId,
      proposalId: decision.proposalId,
      expiresAt: capability.expiresAt,
      previewHash: capability.previewHash,
    });
    return clone(capability);
  }

  recordDeniedIssuance(reason, decision, previewHash) {
    const result = {
      status: "denied",
      reason,
      proposalId: decision?.proposalId ?? null,
    };
    this.appendEvent("capability_issuance_denied", {
      reason,
      proposalId: decision?.proposalId ?? null,
      previewHash,
    });
    return result;
  }

  revoke(capabilityId) {
    const capability = this.capabilities.get(capabilityId);
    if (!capability) return false;
    if (!capability.revoked) {
      capability.revoked = true;
      capability.revokedAt = this.clock();
      this.appendEvent("capability_revoked", {
        capabilityId,
        revokedAt: capability.revokedAt,
      });
    }
    return true;
  }

  execute(capabilityId, executionPreview) {
    const capability = this.capabilities.get(capabilityId);
    if (!capability)
      return this.recordDeniedExecution("CAPABILITY_NOT_FOUND", capabilityId);
    if (capability.revoked)
      return this.recordDeniedExecution("CAPABILITY_REVOKED", capabilityId);
    if (this.clock() >= capability.expiresAt)
      return this.recordDeniedExecution("CAPABILITY_EXPIRED", capabilityId);
    if (capability.usesRemaining !== 1)
      return this.recordDeniedExecution("CAPABILITY_CONSUMED", capabilityId);
    if (!validPreview(executionPreview))
      return this.recordDeniedExecution("PREVIEW_INVALID", capabilityId);
    let matches = false;
    try {
      matches =
        previewMatchesExecution(capability.preview, executionPreview) &&
        secureHash(executionPreview) === capability.previewHash;
    } catch {
      return this.recordDeniedExecution("PREVIEW_INVALID", capabilityId);
    }
    if (!matches)
      return this.recordDeniedExecution("PREVIEW_MISMATCH", capabilityId);
    capability.usesRemaining = 0;
    const result = {
      status: "executed_local_simulation",
      outcome: "not_sent",
      capabilityId,
    };
    this.appendEvent("capability_executed_local_simulation", result);
    return result;
  }

  recordDeniedExecution(reason, capabilityId) {
    const result = { status: "denied", reason, capabilityId };
    this.appendEvent("capability_execution_denied", result);
    return result;
  }

  receipt(decision, options = {}) {
    const {
      eventData = {},
      // A default is generated here, not in createLocalReceipt, because only
      // the broker has the state (this.sequence) to make it unique and
      // monotonic. createLocalReceipt itself has no such state, so it fails
      // closed instead of guessing.
      receiptId = `LUNA-RCP-LOCAL-${String(++this.sequence).padStart(4, "0")}`,
      ...receiptOptions
    } = options;
    const receipt = createLocalReceipt(decision, {
      ...receiptOptions,
      receiptId,
    });
    const event = this.appendEvent("receipt_created", {
      receiptId: receipt.receiptId,
      proposalId: receipt.proposalId,
      outcome: receipt.outcome,
      ...eventData,
    });
    return {
      ...receipt,
      eventId: event.eventId,
      recordedAt: event.recordedAt,
      previewHash: decision?.preview ? secureHash(decision.preview) : null,
    };
  }
}
