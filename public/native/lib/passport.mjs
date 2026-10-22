// The Cognitive Passport as a real data structure.
//
// The audit found that the Cognitive Passport existed only as a 3D mesh in the interface: a
// metaphor with no data behind it and no purpose field. This module is the actual credential.
//
// THE ONE PROPERTY THAT MATTERS
// Stated facts and inferred facts are hard separated. A stated fact is something the user asserted.
// An inferred fact is something a machine guessed. They live in different arrays, they carry
// different required fields, and validation rejects a fact that appears in the wrong array. An
// inferred fact can only become a stated fact through promote(), which requires an explicit
// userConfirmed flag and a ledger to record the promotion in. There is no other path, so machine
// inference can never quietly become user assertion. Thoughts are not actions.
//
// PURPOSE BINDING
// A disclosure is scoped to a declared purpose. checkPurpose() refuses to let a packet approved for
// one purpose be reused for another. This closes the reuse gap that a share packet otherwise has:
// approving disclosure once should not approve it forever, for anything.
//
// PORTABILITY
// export() and import() round-trip through plain JSON. Import fails closed on any malformed value
// and on any unknown field, so a tampered or a future-versioned document is rejected rather than
// partially accepted. Canonical serialization is deterministic, so two passports with equal content
// produce an equal hash.
//
// Local and synthetic only. No network, no third party, nothing leaves the device.

export const PASSPORT_VERSION = "luna-passport-1.0.0";

export const FACT_SOURCE_STATED = "user_stated";
export const FACT_SOURCE_INFERRED = "machine_inferred";

// Exhaustive field lists. Import rejects anything not named here. Fail closed.
export const PASSPORT_FIELDS = Object.freeze([
  "passportId",
  "version",
  "statedFacts",
  "inferredFacts",
  "purposeBindings",
  "defaultPolicy",
  "createdAt",
]);
export const STATED_FACT_FIELDS = Object.freeze([
  "factId",
  "key",
  "value",
  "source",
  "assertedAt",
  "promotedFrom",
  "promotionEvent",
]);
export const STATED_FACT_REQUIRED_FIELDS = Object.freeze([
  "factId",
  "key",
  "value",
  "source",
  "assertedAt",
]);
export const INFERRED_FACT_FIELDS = Object.freeze([
  "factId",
  "key",
  "value",
  "source",
  "confidence",
  "inferredAt",
  "basis",
]);
export const INFERRED_FACT_REQUIRED_FIELDS = Object.freeze([
  "factId",
  "key",
  "value",
  "source",
  "confidence",
  "inferredAt",
]);
export const PURPOSE_BINDING_FIELDS = Object.freeze([
  "bindingId",
  "purpose",
  "packetId",
  "factIds",
  "boundAt",
  "expiresAt",
]);
export const PURPOSE_BINDING_REQUIRED_FIELDS = Object.freeze([
  "bindingId",
  "purpose",
  "packetId",
  "factIds",
  "boundAt",
]);
export const DEFAULT_POLICY_FIELDS = Object.freeze([
  "defaultState",
  "requireExplicitConfirmation",
  "allowInferredDisclosure",
  "maxPurposeTtlMs",
]);

// A brand new passport starts in the most restrictive posture the product supports: private state,
// confirmation always required, and inferred facts never disclosed.
export const DEFAULT_PASSPORT_POLICY = Object.freeze({
  defaultState: "private",
  requireExplicitConfirmation: true,
  allowInferredDisclosure: false,
  maxPurposeTtlMs: 86_400_000,
});

export const LEDGER_EVENT_PASSPORT_CREATED = "passport_created";
export const LEDGER_EVENT_FACT_STATED = "passport_fact_stated";
export const LEDGER_EVENT_FACT_INFERRED = "passport_fact_inferred";
export const LEDGER_EVENT_FACT_PROMOTED = "passport_fact_promoted";
export const LEDGER_EVENT_PURPOSE_BOUND = "passport_purpose_bound";

export const PURPOSE_REASONS = Object.freeze({
  MATCH: "PURPOSE_MATCH",
  PACKET_INVALID: "PACKET_INVALID",
  PURPOSE_REQUIRED: "PURPOSE_REQUIRED",
  PACKET_PURPOSE_UNBOUND: "PACKET_PURPOSE_UNBOUND",
  PURPOSE_MISMATCH: "PURPOSE_MISMATCH",
  PACKET_REVOKED: "PACKET_REVOKED",
  PACKET_EXPIRED: "PACKET_EXPIRED",
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isJsonScalarOrStructure(value) {
  try {
    canonicalizePassportValue(value);
    return true;
  } catch {
    return false;
  }
}

// Same deterministic key ordering the rest of the codebase uses, reimplemented locally so this
// module has zero repository dependencies and can be lifted out for independent verification.
export function canonicalizePassportValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("only finite numbers can be serialized");
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return `[${value.map(canonicalizePassportValue).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalizePassportValue(value[key])}`,
      )
      .join(",")}}`;
  }
  throw new TypeError("only JSON-compatible values can be serialized");
}

function unknownFields(object, allowed) {
  return Object.keys(object).filter((key) => !allowed.includes(key));
}

/**
 * Validate a passport document. Fails closed on unknown fields, wrong sources, and malformed values.
 * @returns {{valid: boolean, errors: string[]}}
 */
export function validatePassport(document) {
  const errors = [];
  if (!isPlainObject(document))
    return { valid: false, errors: ["passport_must_be_object"] };

  for (const field of unknownFields(document, PASSPORT_FIELDS))
    errors.push(`unknown_passport_field:${field}`);
  if (!nonEmptyString(document.passportId)) errors.push("passport_id_required");
  if (document.version !== PASSPORT_VERSION)
    errors.push("unsupported_passport_version");
  if (!Number.isFinite(document.createdAt))
    errors.push("created_at_must_be_finite_number");

  if (!Array.isArray(document.statedFacts)) {
    errors.push("stated_facts_must_be_array");
  } else {
    document.statedFacts.forEach((fact, index) =>
      validateStatedFact(fact, index, errors),
    );
  }

  if (!Array.isArray(document.inferredFacts)) {
    errors.push("inferred_facts_must_be_array");
  } else {
    document.inferredFacts.forEach((fact, index) =>
      validateInferredFact(fact, index, errors),
    );
  }

  if (!Array.isArray(document.purposeBindings)) {
    errors.push("purpose_bindings_must_be_array");
  } else {
    document.purposeBindings.forEach((binding, index) =>
      validatePurposeBinding(binding, index, errors),
    );
  }

  if (!isPlainObject(document.defaultPolicy)) {
    errors.push("default_policy_must_be_object");
  } else {
    for (const field of unknownFields(
      document.defaultPolicy,
      DEFAULT_POLICY_FIELDS,
    )) {
      errors.push(`unknown_default_policy_field:${field}`);
    }
    if (!nonEmptyString(document.defaultPolicy.defaultState))
      errors.push("default_state_required");
    if (
      typeof document.defaultPolicy.requireExplicitConfirmation !== "boolean"
    ) {
      errors.push("require_explicit_confirmation_must_be_boolean");
    }
    if (typeof document.defaultPolicy.allowInferredDisclosure !== "boolean") {
      errors.push("allow_inferred_disclosure_must_be_boolean");
    }
    if (
      !Number.isFinite(document.defaultPolicy.maxPurposeTtlMs) ||
      document.defaultPolicy.maxPurposeTtlMs <= 0
    ) {
      errors.push("max_purpose_ttl_must_be_positive_number");
    }
  }

  // Fact identifiers must be unique across BOTH arrays. Otherwise a duplicate identifier could make
  // an inferred fact resolve to a stated one.
  if (
    Array.isArray(document.statedFacts) &&
    Array.isArray(document.inferredFacts)
  ) {
    const ids = [...document.statedFacts, ...document.inferredFacts]
      .filter(isPlainObject)
      .map((fact) => fact.factId)
      .filter(nonEmptyString);
    if (new Set(ids).size !== ids.length)
      errors.push("fact_ids_must_be_unique_across_both_arrays");
  }

  return { valid: errors.length === 0, errors };
}

function validateStatedFact(fact, index, errors) {
  if (!isPlainObject(fact)) {
    errors.push(`stated_fact_${index}_must_be_object`);
    return;
  }
  for (const field of unknownFields(fact, STATED_FACT_FIELDS))
    errors.push(`unknown_stated_fact_field:${index}:${field}`);
  for (const field of STATED_FACT_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(fact, field))
      errors.push(`stated_fact_${index}_missing_${field}`);
  }
  if (!nonEmptyString(fact.factId))
    errors.push(`stated_fact_${index}_id_required`);
  if (!nonEmptyString(fact.key))
    errors.push(`stated_fact_${index}_key_required`);
  // This is the hard separation. A stated fact carrying any other source is rejected outright.
  if (fact.source !== FACT_SOURCE_STATED)
    errors.push(`stated_fact_${index}_source_must_be_${FACT_SOURCE_STATED}`);
  if (!Number.isFinite(fact.assertedAt))
    errors.push(`stated_fact_${index}_asserted_at_must_be_finite_number`);
  if (fact.value !== undefined && !isJsonScalarOrStructure(fact.value))
    errors.push(`stated_fact_${index}_value_must_be_json_compatible`);
  // A promoted fact must carry the ledger record that authorised the promotion. A stated fact
  // claiming it was promoted, with no recorded promotion event, is a forgery.
  const claimsPromotion = fact.promotedFrom !== undefined;
  const carriesEvent = fact.promotionEvent !== undefined;
  if (claimsPromotion !== carriesEvent)
    errors.push(`stated_fact_${index}_promotion_record_incomplete`);
  if (claimsPromotion && !nonEmptyString(fact.promotedFrom))
    errors.push(`stated_fact_${index}_promoted_from_must_be_string`);
  if (carriesEvent) {
    if (!isPlainObject(fact.promotionEvent)) {
      errors.push(`stated_fact_${index}_promotion_event_must_be_object`);
    } else {
      if (fact.promotionEvent.userConfirmed !== true)
        errors.push(
          `stated_fact_${index}_promotion_requires_user_confirmation`,
        );
      if (!nonEmptyString(fact.promotionEvent.entryHash))
        errors.push(
          `stated_fact_${index}_promotion_requires_ledger_entry_hash`,
        );
    }
  }
}

function validateInferredFact(fact, index, errors) {
  if (!isPlainObject(fact)) {
    errors.push(`inferred_fact_${index}_must_be_object`);
    return;
  }
  for (const field of unknownFields(fact, INFERRED_FACT_FIELDS))
    errors.push(`unknown_inferred_fact_field:${index}:${field}`);
  for (const field of INFERRED_FACT_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(fact, field))
      errors.push(`inferred_fact_${index}_missing_${field}`);
  }
  if (!nonEmptyString(fact.factId))
    errors.push(`inferred_fact_${index}_id_required`);
  if (!nonEmptyString(fact.key))
    errors.push(`inferred_fact_${index}_key_required`);
  if (fact.source !== FACT_SOURCE_INFERRED)
    errors.push(
      `inferred_fact_${index}_source_must_be_${FACT_SOURCE_INFERRED}`,
    );
  if (
    !Number.isFinite(fact.confidence) ||
    fact.confidence < 0 ||
    fact.confidence > 1
  ) {
    errors.push(
      `inferred_fact_${index}_confidence_must_be_between_zero_and_one`,
    );
  }
  if (!Number.isFinite(fact.inferredAt))
    errors.push(`inferred_fact_${index}_inferred_at_must_be_finite_number`);
  if (fact.value !== undefined && !isJsonScalarOrStructure(fact.value))
    errors.push(`inferred_fact_${index}_value_must_be_json_compatible`);
}

function validatePurposeBinding(binding, index, errors) {
  if (!isPlainObject(binding)) {
    errors.push(`purpose_binding_${index}_must_be_object`);
    return;
  }
  for (const field of unknownFields(binding, PURPOSE_BINDING_FIELDS))
    errors.push(`unknown_purpose_binding_field:${index}:${field}`);
  for (const field of PURPOSE_BINDING_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(binding, field))
      errors.push(`purpose_binding_${index}_missing_${field}`);
  }
  if (!nonEmptyString(binding.bindingId))
    errors.push(`purpose_binding_${index}_id_required`);
  if (!nonEmptyString(binding.purpose))
    errors.push(`purpose_binding_${index}_purpose_required`);
  if (!nonEmptyString(binding.packetId))
    errors.push(`purpose_binding_${index}_packet_id_required`);
  if (
    !Array.isArray(binding.factIds) ||
    !binding.factIds.every(nonEmptyString)
  ) {
    errors.push(`purpose_binding_${index}_fact_ids_must_be_strings`);
  }
  if (!Number.isFinite(binding.boundAt))
    errors.push(`purpose_binding_${index}_bound_at_must_be_finite_number`);
  if (binding.expiresAt !== undefined && !Number.isFinite(binding.expiresAt)) {
    errors.push(`purpose_binding_${index}_expires_at_must_be_finite_number`);
  }
}

export function normalizePurpose(purpose) {
  return nonEmptyString(purpose) ? purpose.trim().toLowerCase() : null;
}

/**
 * Decide whether a share packet may be used for a given purpose.
 *
 * PURE. Reads only its arguments. Fails closed: a packet with no declared purpose is refused rather
 * than treated as usable for anything.
 *
 * @param {object} packet   a share packet carrying a `purpose` field, and optionally `revoked` and `expiresAt`
 * @param {string} purpose  the purpose the caller now wants to use it for
 * @param {object} [options]
 * @param {number} [options.now] millisecond timestamp, defaults to Date.now()
 * @returns {{allowed: boolean, reason: string, packetPurpose: string|null, requestedPurpose: string|null}}
 */
export function checkPurpose(packet, purpose, options = {}) {
  const now = Number.isFinite(options.now) ? options.now : Date.now();
  const requested = normalizePurpose(purpose);
  const declared = isPlainObject(packet)
    ? normalizePurpose(packet.purpose)
    : null;
  const shell = { packetPurpose: declared, requestedPurpose: requested };

  if (!isPlainObject(packet))
    return { allowed: false, reason: PURPOSE_REASONS.PACKET_INVALID, ...shell };
  if (requested === null)
    return {
      allowed: false,
      reason: PURPOSE_REASONS.PURPOSE_REQUIRED,
      ...shell,
    };
  if (declared === null)
    return {
      allowed: false,
      reason: PURPOSE_REASONS.PACKET_PURPOSE_UNBOUND,
      ...shell,
    };
  if (packet.revoked === true)
    return { allowed: false, reason: PURPOSE_REASONS.PACKET_REVOKED, ...shell };
  if (Number.isFinite(packet.expiresAt) && now >= packet.expiresAt) {
    return { allowed: false, reason: PURPOSE_REASONS.PACKET_EXPIRED, ...shell };
  }
  if (declared !== requested)
    return {
      allowed: false,
      reason: PURPOSE_REASONS.PURPOSE_MISMATCH,
      ...shell,
    };
  return { allowed: true, reason: PURPOSE_REASONS.MATCH, ...shell };
}

function clone(value) {
  return structuredClone(value);
}

/**
 * A portable, serializable cognitive passport.
 *
 * const passport = new CognitivePassport({ passportId: 'LUNA-PASSPORT-0001', ledger });
 * passport.stateFact({ key: 'preferred_name', value: 'Sam' });
 * const guess = passport.inferFact({ key: 'timezone', value: 'Europe/Lisbon', confidence: 0.6 });
 * await passport.promote(guess.factId, { userConfirmed: true });   // requires the ledger
 */
export class CognitivePassport {
  #stated = [];
  #inferred = [];
  #bindings = [];
  #ledger;
  #clock;
  #counter = 0;

  constructor({
    passportId,
    createdAt,
    defaultPolicy,
    ledger = null,
    clock,
  } = {}) {
    this.#clock = typeof clock === "function" ? clock : () => Date.now();
    this.passportId = nonEmptyString(passportId)
      ? passportId.trim()
      : "LUNA-PASSPORT-LOCAL";
    this.version = PASSPORT_VERSION;
    this.createdAt = Number.isFinite(createdAt) ? createdAt : this.#clock();
    this.ledgerErrors = [];
    this.defaultPolicy = {
      ...DEFAULT_PASSPORT_POLICY,
      ...(isPlainObject(defaultPolicy) ? defaultPolicy : {}),
    };
    for (const field of unknownFields(
      this.defaultPolicy,
      DEFAULT_POLICY_FIELDS,
    )) {
      throw new TypeError(`unknown default policy field: ${field}`);
    }
    this.#ledger = ledger;
  }

  get ledger() {
    return this.#ledger;
  }

  attachLedger(ledger) {
    this.#ledger = ledger;
  }

  #nextId(prefix) {
    this.#counter += 1;
    return `${this.passportId}-${prefix}-${String(this.#counter).padStart(4, "0")}`;
  }

  // Best effort recording for the non-critical events. The ledger append is asynchronous, so any
  // failure is captured on ledgerErrors rather than becoming an unhandled rejection, and it is never
  // swallowed silently. promote() is the one operation that awaits the ledger and refuses to
  // proceed without it, because that is the one that changes a fact's provenance.
  #record(type, payload) {
    if (!this.#ledger || typeof this.#ledger.append !== "function") return null;
    const pending = this.#ledger.append(type, payload);
    if (pending && typeof pending.catch === "function") {
      pending.catch((error) => {
        this.ledgerErrors.push({
          type,
          message: error?.message || String(error),
        });
      });
    }
    return pending;
  }

  /** Record something the user asserted. This is the only way a fact enters statedFacts directly. */
  stateFact({ key, value, factId } = {}) {
    if (!nonEmptyString(key))
      throw new TypeError("a stated fact requires a non-empty key");
    if (value !== undefined && !isJsonScalarOrStructure(value))
      throw new TypeError("a stated fact value must be JSON compatible");
    const fact = {
      factId: nonEmptyString(factId) ? factId.trim() : this.#nextId("STATED"),
      key: key.trim(),
      value: value === undefined ? null : clone(value),
      source: FACT_SOURCE_STATED,
      assertedAt: this.#clock(),
    };
    this.#assertUniqueId(fact.factId);
    this.#stated.push(fact);
    this.#record(LEDGER_EVENT_FACT_STATED, {
      passportId: this.passportId,
      factId: fact.factId,
      key: fact.key,
    });
    return clone(fact);
  }

  /**
   * Record something a machine guessed. It goes into inferredFacts and it cannot reach statedFacts
   * from here. There is deliberately no factId collision path and no source override parameter.
   */
  inferFact({ key, value, confidence = 0.5, basis, factId } = {}) {
    if (!nonEmptyString(key))
      throw new TypeError("an inferred fact requires a non-empty key");
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      throw new TypeError(
        "an inferred fact requires a confidence between zero and one",
      );
    }
    if (value !== undefined && !isJsonScalarOrStructure(value))
      throw new TypeError("an inferred fact value must be JSON compatible");
    const fact = {
      factId: nonEmptyString(factId) ? factId.trim() : this.#nextId("INFERRED"),
      key: key.trim(),
      value: value === undefined ? null : clone(value),
      source: FACT_SOURCE_INFERRED,
      confidence,
      inferredAt: this.#clock(),
    };
    if (basis !== undefined) {
      if (!Array.isArray(basis) || !basis.every(nonEmptyString))
        throw new TypeError("basis must be an array of non-empty strings");
      fact.basis = [...basis];
    }
    this.#assertUniqueId(fact.factId);
    this.#inferred.push(fact);
    this.#record(LEDGER_EVENT_FACT_INFERRED, {
      passportId: this.passportId,
      factId: fact.factId,
      key: fact.key,
      confidence: fact.confidence,
    });
    return clone(fact);
  }

  #assertUniqueId(factId) {
    const clash = [...this.#stated, ...this.#inferred].some(
      (fact) => fact.factId === factId,
    );
    if (clash)
      throw new Error(`fact id already exists in this passport: ${factId}`);
  }

  statedFacts() {
    return clone(this.#stated);
  }

  inferredFacts() {
    return clone(this.#inferred);
  }

  purposeBindings() {
    return clone(this.#bindings);
  }

  findFact(factId) {
    const id = isPlainObject(factId) ? factId.factId : factId;
    const stated = this.#stated.find((fact) => fact.factId === id);
    if (stated) return { fact: clone(stated), source: FACT_SOURCE_STATED };
    const inferred = this.#inferred.find((fact) => fact.factId === id);
    if (inferred)
      return { fact: clone(inferred), source: FACT_SOURCE_INFERRED };
    return null;
  }

  /**
   * Promote an inferred fact to a stated fact.
   *
   * This is the ONLY route from inferredFacts to statedFacts. It requires:
   *   1. an explicit userConfirmed === true, and
   *   2. an attached ledger, so that the promotion is recorded and cannot be denied later.
   *
   * Anything else throws and nothing is mutated.
   *
   * @param {string|{factId: string}} factRef
   * @param {{userConfirmed: boolean, confirmedBy?: string}} confirmation
   * @returns {Promise<object>} the new stated fact
   */
  async promote(factRef, confirmation = {}) {
    const factId = isPlainObject(factRef) ? factRef.factId : factRef;
    if (!nonEmptyString(factId))
      throw new TypeError("promote requires a fact id");
    if (confirmation?.userConfirmed !== true) {
      throw new Error(
        "promotion requires an explicit user act: pass { userConfirmed: true }",
      );
    }
    if (!this.#ledger || typeof this.#ledger.append !== "function") {
      throw new Error(
        "promotion must be recorded, so an append-only ledger must be attached first",
      );
    }
    const index = this.#inferred.findIndex((fact) => fact.factId === factId);
    if (index === -1) throw new Error(`no inferred fact with id ${factId}`);
    const inferred = this.#inferred[index];

    const entry = await this.#ledger.append(LEDGER_EVENT_FACT_PROMOTED, {
      passportId: this.passportId,
      factId: inferred.factId,
      key: inferred.key,
      previousSource: FACT_SOURCE_INFERRED,
      newSource: FACT_SOURCE_STATED,
      inferredConfidence: inferred.confidence,
      userConfirmed: true,
      confirmedBy: nonEmptyString(confirmation.confirmedBy)
        ? confirmation.confirmedBy.trim()
        : "local_user",
    });
    if (!entry || !nonEmptyString(entry.hash)) {
      throw new Error(
        "the ledger did not return a hashed entry, so the promotion cannot be recorded",
      );
    }

    const promoted = {
      factId: this.#nextId("STATED"),
      key: inferred.key,
      value: clone(inferred.value),
      source: FACT_SOURCE_STATED,
      assertedAt: this.#clock(),
      promotedFrom: inferred.factId,
      promotionEvent: {
        userConfirmed: true,
        entryHash: entry.hash,
        sequence: entry.sequence,
        recordedAt: entry.timestamp,
      },
    };
    // Only mutate after the ledger write succeeded. If the ledger throws, nothing changed.
    this.#inferred.splice(index, 1);
    this.#stated.push(promoted);
    return clone(promoted);
  }

  /**
   * Bind a share packet to a declared purpose. Facts named here must exist, and inferred facts are
   * refused unless the passport policy explicitly allows inferred disclosure.
   */
  bindPurpose({ purpose, packetId, factIds = [], ttlMs, bindingId } = {}) {
    if (!nonEmptyString(purpose))
      throw new TypeError("a purpose binding requires a non-empty purpose");
    if (!nonEmptyString(packetId))
      throw new TypeError("a purpose binding requires a packet id");
    if (!Array.isArray(factIds) || !factIds.every(nonEmptyString))
      throw new TypeError("factIds must be an array of non-empty strings");
    for (const factId of factIds) {
      const found = this.findFact(factId);
      if (!found)
        throw new Error(`purpose binding names an unknown fact: ${factId}`);
      if (
        found.source === FACT_SOURCE_INFERRED &&
        this.defaultPolicy.allowInferredDisclosure !== true
      ) {
        throw new Error(
          `inferred facts cannot be disclosed under this passport policy: ${factId}`,
        );
      }
    }
    const boundAt = this.#clock();
    const requestedTtl =
      Number.isFinite(ttlMs) && ttlMs > 0
        ? ttlMs
        : this.defaultPolicy.maxPurposeTtlMs;
    const ttl = Math.min(requestedTtl, this.defaultPolicy.maxPurposeTtlMs);
    const binding = {
      bindingId: nonEmptyString(bindingId)
        ? bindingId.trim()
        : this.#nextId("PURPOSE"),
      purpose: purpose.trim(),
      packetId: packetId.trim(),
      factIds: [...factIds],
      boundAt,
      expiresAt: boundAt + ttl,
    };
    this.#bindings.push(binding);
    this.#record(LEDGER_EVENT_PURPOSE_BOUND, {
      passportId: this.passportId,
      bindingId: binding.bindingId,
      purpose: binding.purpose,
      packetId: binding.packetId,
      factIds: binding.factIds,
      expiresAt: binding.expiresAt,
    });
    return clone(binding);
  }

  /** Look up the binding for a packet and check it against a requested purpose. */
  checkPacketPurpose(packetId, purpose, options = {}) {
    const binding = this.#bindings.find((entry) => entry.packetId === packetId);
    if (!binding)
      return {
        allowed: false,
        reason: PURPOSE_REASONS.PACKET_PURPOSE_UNBOUND,
        packetPurpose: null,
        requestedPurpose: normalizePurpose(purpose),
      };
    return checkPurpose(
      { purpose: binding.purpose, expiresAt: binding.expiresAt },
      purpose,
      {
        now: Number.isFinite(options.now) ? options.now : this.#clock(),
      },
    );
  }

  /** Plain JSON, ready to write to disk or hand to another device. */
  export() {
    return {
      passportId: this.passportId,
      version: this.version,
      statedFacts: clone(this.#stated),
      inferredFacts: clone(this.#inferred),
      purposeBindings: clone(this.#bindings),
      defaultPolicy: { ...this.defaultPolicy },
      createdAt: this.createdAt,
    };
  }

  toJSON() {
    return this.export();
  }

  /** Deterministic canonical string. Equal content produces an equal string on any host. */
  canonical() {
    return canonicalizePassportValue(this.export());
  }

  /**
   * SHA-256 of the canonical form, via WebCrypto so it works in Node 22 and in the browser.
   * @returns {Promise<string>} "sha256:<hex>"
   */
  async hash(options = {}) {
    const subtle = options.subtle || globalThis.crypto?.subtle;
    if (!subtle || typeof subtle.digest !== "function")
      throw new Error("WebCrypto subtle.digest is required");
    const digest = await subtle.digest(
      "SHA-256",
      new TextEncoder().encode(this.canonical()),
    );
    let hex = "";
    for (const byte of new Uint8Array(digest))
      hex += byte.toString(16).padStart(2, "0");
    return `sha256:${hex}`;
  }

  /**
   * Rebuild a passport from a plain JSON document. Fails closed: any unknown field, any malformed
   * value, any fact in the wrong array, or any promoted fact without a recorded promotion event
   * throws rather than being partially accepted.
   */
  static import(document, options = {}) {
    const parsed =
      typeof document === "string" ? JSON.parse(document) : document;
    const { valid, errors } = validatePassport(parsed);
    if (!valid)
      throw new Error(`passport import rejected: ${errors.join(", ")}`);
    const passport = new CognitivePassport({
      passportId: parsed.passportId,
      createdAt: parsed.createdAt,
      defaultPolicy: parsed.defaultPolicy,
      ledger: options.ledger || null,
      clock: options.clock,
    });
    passport.#stated = clone(parsed.statedFacts);
    passport.#inferred = clone(parsed.inferredFacts);
    passport.#bindings = clone(parsed.purposeBindings);
    // Keep generated identifiers clear of anything already present in the imported document.
    passport.#counter =
      parsed.statedFacts.length +
      parsed.inferredFacts.length +
      parsed.purposeBindings.length;
    return passport;
  }
}

/** Convenience for the common flow of creating a passport and recording its creation. */
export async function createPassport(options = {}) {
  const passport = new CognitivePassport(options);
  if (passport.ledger && typeof passport.ledger.append === "function") {
    await passport.ledger.append(LEDGER_EVENT_PASSPORT_CREATED, {
      passportId: passport.passportId,
      version: passport.version,
      createdAt: passport.createdAt,
      defaultPolicy: passport.defaultPolicy,
    });
  }
  return passport;
}
