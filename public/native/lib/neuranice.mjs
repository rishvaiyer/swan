// NeuraNice: the protection algorithm inside Luna.
//
// WHAT THIS IS, STATED PRECISELY
// This is an explicit, deterministic, rule-based risk model with documented and injectable
// parameters. It is NOT a machine-learned model and this file never claims one. Six scorers each
// produce a continuous score in [0,1] together with structured evidence naming the rule that fired,
// the token that matched, and the threshold that was crossed. The scores are combined into an
// aggregate and a verdict, and the verdict gates the decision.
//
// Every threshold and weight below is a named exported constant with a written rationale, and every
// one of them can be overridden through the config argument so they can be tuned and later
// calibrated against data. The previous code contained bare 0.8 and 0.94 literals with no stated
// meaning. Those are now CONFIDENCE_CLARIFY_THRESHOLD and CONFIDENCE_HIGH_THRESHOLD.
//
// THE CORE RULE THIS FILE PROTECTS
// Thoughts are not actions. Machine inference never creates authority. NeuraNice can only ever make
// a decision MORE restrictive. It can turn confirm into clarify or deny. It can never turn deny into
// confirm, or clarify into share_ready. That invariant is enforced in code by restrictionRank(),
// not by convention, and it is covered by a property style test.
//
// PERSUASION DETECTION DETECTS STRUCTURE, NEVER PROSE
// The engine must never interpret natural language, because if text content could influence policy
// then text content becomes an attack surface. Persuasion here is behavioural pattern detection over
// proposal METADATA only: requested expiry values, retry counts, confidence deltas, reference set
// sizes, and which fields a caller keeps trying to set. No payload body is ever read.

const FALLBACK_POLICY_VERSION = "luna-policy-0.3.0";

// The repository is being restructured concurrently, so the engine may sit at ./decision-engine.mjs,
// ../core/decision-engine.mjs, or ../decision-engine.mjs. Try each and degrade to a literal rather
// than failing to load. NeuraNice does not need the engine to function, only its version stamp.
export const ENGINE_CANDIDATE_SPECIFIERS = Object.freeze([
  "./decision-engine.mjs",
  "../core/decision-engine.mjs",
  "../decision-engine.mjs",
]);

async function loadEngine() {
  for (const specifier of ENGINE_CANDIDATE_SPECIFIERS) {
    try {
      return { module: await import(specifier), specifier };
    } catch {
      // Try the next layout. Every failure mode is treated the same here on purpose: during the
      // restructure a candidate path can be missing, half written, or briefly unreadable.
    }
  }
  return { module: null, specifier: null };
}

const engine = await loadEngine();

// Exposed so an integrator can see whether the engine was actually found rather than assuming it.
// If this is false, POLICY_VERSION below is the literal fallback and not the engine's own value.
export const ENGINE_MODULE_RESOLVED = engine.module !== null;
export const ENGINE_MODULE_SPECIFIER = engine.specifier;

export const POLICY_VERSION =
  engine.module?.POLICY_VERSION || FALLBACK_POLICY_VERSION;
export const NEURANICE_VERSION = "neuranice-1.0.0";

// ---------------------------------------------------------------------------
// Restriction ordering. This is the safety spine of the module.
// ---------------------------------------------------------------------------

// Lower rank means more restrictive. confirm and share_ready share rank 2: neither is more
// permissive than the other, they are different kinds of least restrictive outcome, so NeuraNice is
// forbidden from converting one into the other in either direction.
export const RESTRICTION_RANK = Object.freeze({
  deny: 0,
  clarify: 1,
  confirm: 2,
  share_ready: 2,
});

// An unrecognised status is treated as more restrictive than anything known, which forces the
// fail-closed branch in applyNeuraNice rather than letting an unknown value pass through.
export const UNKNOWN_STATUS_RANK = -1;

export function restrictionRank(status) {
  return Object.prototype.hasOwnProperty.call(RESTRICTION_RANK, status)
    ? RESTRICTION_RANK[status]
    : UNKNOWN_STATUS_RANK;
}

export const VERDICTS = Object.freeze([
  "allow_with_confirmation",
  "require_clarification",
  "deny",
]);

// Maps a verdict to the most permissive status NeuraNice will tolerate. null means NeuraNice has no
// objection and leaves the engine decision exactly as it found it.
export const VERDICT_CEILING_STATUS = Object.freeze({
  allow_with_confirmation: null,
  require_clarification: "clarify",
  deny: "deny",
});

// ---------------------------------------------------------------------------
// Calibration constants. Every number in this section is named and justified.
// ---------------------------------------------------------------------------

// Below this reported confidence the engine already refuses to act and asks for clarification.
// NeuraNice reuses the same boundary so the two components cannot disagree about what "low
// confidence" means. Changing it here does not change the engine; keep them in step.
export const CONFIDENCE_CLARIFY_THRESHOLD = 0.8;

// Above this reported confidence the proposal is treated as well evidenced. The value is high on
// purpose: an action firewall should treat "probably right" as still uncertain. It is a starting
// point for calibration, not a measured operating point, and it is injectable for that reason.
export const CONFIDENCE_HIGH_THRESHOLD = 0.94;

// Uncertainty score at the two confidence boundaries. These anchor a continuous piecewise linear
// curve so that uncertainty never jumps discontinuously as confidence moves.
export const UNCERTAINTY_AT_HIGH_CONFIDENCE = 0.2;
export const UNCERTAINTY_AT_CLARIFY_THRESHOLD = 0.6;

// A proposal that names any context reference at all discloses something, even when no reference
// matches a sensitive category. This is the floor, not zero.
export const BASELINE_REF_SENSITIVITY = 0.25;

// Each additional context reference beyond the first adds this much sensitivity, because breadth of
// disclosure is itself a harm. Capped by SENSITIVITY_VOLUME_CAP so volume can never alone reach 1.
export const SENSITIVITY_VOLUME_STEP = 0.05;
export const SENSITIVITY_VOLUME_CAP = 0.3;

// Sensitivity is matched against context reference LABELS, which are enumerated identifiers such as
// "health_history" or "bank_balance". It is never matched against payload prose. A label is a key in
// a reference table, not user text, so matching it is structural.
export const SENSITIVE_REF_PATTERNS = Object.freeze([
  // Credentials are the only category where disclosure is unrecoverable in every case.
  {
    category: "credential",
    pattern: /(password|passphrase|secret|token|api[_-]?key|credential)/i,
    weight: 1,
  },
  // Health and neural data are special category data under most privacy regimes and are the core of
  // Luna's stated product promise, so they sit just below credentials.
  {
    category: "health_neural",
    pattern:
      /(health|medical|diagnos|therapy|prescription|neural|biometric|eeg)/i,
    weight: 0.9,
  },
  {
    category: "financial",
    pattern: /(financial|bank|salary|payment|card|invoice|tax|balance)/i,
    weight: 0.85,
  },
  {
    category: "identity",
    pattern:
      /(identity|passport|ssn|national[_-]?id|birthdate|home[_-]?address)/i,
    weight: 0.8,
  },
  // An explicit private marker is the user telling the system directly that this is off limits.
  {
    category: "private_marker",
    pattern:
      /(private|confidential|do[_-]?not[_-]?share|off[_-]?the[_-]?record)/i,
    weight: 0.75,
  },
  {
    category: "location",
    pattern: /(location|gps|geo|whereabouts|coordinates)/i,
    weight: 0.7,
  },
  {
    category: "relationship",
    pattern: /(relationship|partner|family|child|custody)/i,
    weight: 0.6,
  },
]);

// How much reaching outside the user's own device costs, by operation. An unknown operation gets
// UNKNOWN_OPERATION_EXTERNALITY, which is deliberately mid-high: unknown is not safe.
export const OPERATION_EXTERNALITY = Object.freeze({
  create_draft: 0.15,
  send_message: 0.8,
  publish: 0.95,
  purchase: 0.9,
  change_permission: 0.85,
  delete: 0.5,
});
export const UNKNOWN_OPERATION_EXTERNALITY = 0.6;

// Naming a concrete destination turns a hypothetical into a targeted disclosure.
export const DESTINATION_EXTERNALITY_INCREMENT = 0.15;

// How hard the operation is to take back. Unknown again fails toward caution.
export const OPERATION_IRREVERSIBILITY = Object.freeze({
  create_draft: 0.1,
  send_message: 0.7,
  publish: 0.85,
  purchase: 0.95,
  change_permission: 0.9,
  delete: 1,
});
export const UNKNOWN_OPERATION_IRREVERSIBILITY = 0.6;

// Provenance. An explicit false is a hard signal. An absent flag is NOT treated as verified: an
// unverified chain of custody is the exact condition this product exists to catch.
export const PROVENANCE_UNVERIFIED_SCORE = 1;
export const PROVENANCE_UNKNOWN_SCORE = 0.6;
export const PROVENANCE_VERIFIED_BASE = 0.05;

// Inferred references are machine guesses about the person. The larger their share of the proposal,
// the more of it rests on inference rather than on something the user actually said.
export const INFERRED_REF_PROVENANCE_WEIGHT = 0.5;

// Aggregate weights. They sum to 1. The heavier weights sit on the two dimensions that describe
// permanent harm (what is disclosed, and whether it can be undone).
export const DIMENSION_WEIGHTS = Object.freeze({
  sensitivity: 0.2,
  externality: 0.15,
  irreversibility: 0.2,
  uncertainty: 0.15,
  persuasion: 0.15,
  provenance: 0.15,
});

// The six dimensions split into two groups that mean different things, and conflating them is a
// calibration error. STAKE describes how much is at risk in the action the user actually asked for.
// DOUBT describes how much reason there is to distrust this particular proposal.
//
// A user asking to send a message is asking for externality on purpose. High stake alone is not a
// reason to refuse: it is exactly what the engine's confirm state exists to handle, by putting a
// human in the loop. What should escalate a decision is DOUBT, amplified by how much is at stake.
// An earlier version of this file took the maximum across all six dimensions, which made every
// ordinary send_message a deny and would have made the product unusable while looking calibrated.
export const STAKE_DIMENSIONS = Object.freeze([
  "sensitivity",
  "externality",
  "irreversibility",
]);
export const DOUBT_DIMENSIONS = Object.freeze([
  "uncertainty",
  "persuasion",
  "provenance",
]);

// A weighted mean can dilute one maxed doubt dimension into a comfortable average. This floor
// prevents that: doubt can never fall below this fraction of the single worst doubt dimension.
export const MAX_DOUBT_FLOOR_FACTOR = 0.8;

// How much stake contributes on its own, before any doubt is present. This keeps a high stake
// action visible in the risk label without letting it deny by itself.
export const STAKE_FLOOR_WEIGHT = 0.35;

// Doubt is amplified by stake. Even at zero stake, doubt still counts for this fraction, so a
// suspicious proposal is never invisible; at full stake it counts fully.
export const MIN_STAKE_COUPLING = 0.4;

// Verdict boundaries over the aggregate.
export const VERDICT_DENY_THRESHOLD = 0.75;
export const VERDICT_CLARIFY_THRESHOLD = 0.45;

// A dimension at or above this level is named in the decision reason codes so the user is told
// which specific thing was wrong rather than only being given a number.
export const EVIDENCE_REPORTING_THRESHOLD = 0.6;

// Risk label bands for display. This replaces the hardcoded UI string the audit found.
export const RISK_LABEL_BANDS = Object.freeze([
  { label: "high", min: 0.75 },
  { label: "elevated", min: 0.55 },
  { label: "guarded", min: 0.3 },
  { label: "low", min: 0 },
]);

// ---------------------------------------------------------------------------
// Persuasion detection constants.
// ---------------------------------------------------------------------------

// The normal lifetime Luna grants a share packet, taken from the reference broker default of one
// day. A caller asking for far less than the norm is applying time pressure.
export const NORMAL_EXPIRY_MS = 86_400_000;

// A requested expiry below this fraction of the norm counts as urgency pressure. One twentieth of a
// day is roughly seventy minutes, which is short enough that no ordinary workflow needs it.
export const URGENCY_EXPIRY_RATIO = 0.05;

// Context reference sets larger than this for a single operation are bundling: many disclosures
// travelling together under one approval.
export const BUNDLING_REF_COUNT_THRESHOLD = 6;

// A confidence rise of at least this much across retries of the same operation, with no new
// references supplied, is inflation rather than new evidence.
export const CONFIDENCE_INFLATION_DELTA = 0.05;

// Fields a proposal is never allowed to set, because they would be the caller granting itself
// authority. The engine already ignores them; repeated attempts to set them are a persuasion signal.
export const DISALLOWED_AUTHORITY_FIELDS = Object.freeze([
  "authority",
  "grantedAuthority",
  "capability",
  "capabilityId",
  "approved",
  "userConfirmed",
  "requiresExplicitConfirmation",
  "bypassConfirmation",
  "status",
  "policyVersion",
]);

// Severity assigned to each structural persuasion signal. Combined with a noisy-or so that several
// weak signals accumulate but can never exceed 1.
export const PERSUASION_SIGNAL_SEVERITY = Object.freeze({
  urgency_pressure: 0.6,
  escalation_after_refusal: 0.85,
  scope_creep: 0.5,
  confidence_inflation: 0.55,
  authority_field_probing: 0.8,
  bundling: 0.4,
  declared_by_caller: 0.3,
});

// Bounds on the in-memory session history. It is local, it holds metadata only, and it must not be
// able to grow without limit.
export const SESSION_MAX_PROPOSALS = 32;
export const SESSION_MAX_SESSIONS = 16;

export const DEFAULT_NEURANICE_CONFIG = Object.freeze({
  confidenceClarifyThreshold: CONFIDENCE_CLARIFY_THRESHOLD,
  confidenceHighThreshold: CONFIDENCE_HIGH_THRESHOLD,
  uncertaintyAtHighConfidence: UNCERTAINTY_AT_HIGH_CONFIDENCE,
  uncertaintyAtClarifyThreshold: UNCERTAINTY_AT_CLARIFY_THRESHOLD,
  baselineRefSensitivity: BASELINE_REF_SENSITIVITY,
  sensitivityVolumeStep: SENSITIVITY_VOLUME_STEP,
  sensitivityVolumeCap: SENSITIVITY_VOLUME_CAP,
  sensitiveRefPatterns: SENSITIVE_REF_PATTERNS,
  operationExternality: OPERATION_EXTERNALITY,
  unknownOperationExternality: UNKNOWN_OPERATION_EXTERNALITY,
  destinationExternalityIncrement: DESTINATION_EXTERNALITY_INCREMENT,
  operationIrreversibility: OPERATION_IRREVERSIBILITY,
  unknownOperationIrreversibility: UNKNOWN_OPERATION_IRREVERSIBILITY,
  provenanceUnverifiedScore: PROVENANCE_UNVERIFIED_SCORE,
  provenanceUnknownScore: PROVENANCE_UNKNOWN_SCORE,
  provenanceVerifiedBase: PROVENANCE_VERIFIED_BASE,
  inferredRefProvenanceWeight: INFERRED_REF_PROVENANCE_WEIGHT,
  dimensionWeights: DIMENSION_WEIGHTS,
  stakeDimensions: STAKE_DIMENSIONS,
  doubtDimensions: DOUBT_DIMENSIONS,
  maxDoubtFloorFactor: MAX_DOUBT_FLOOR_FACTOR,
  stakeFloorWeight: STAKE_FLOOR_WEIGHT,
  minStakeCoupling: MIN_STAKE_COUPLING,
  verdictDenyThreshold: VERDICT_DENY_THRESHOLD,
  verdictClarifyThreshold: VERDICT_CLARIFY_THRESHOLD,
  evidenceReportingThreshold: EVIDENCE_REPORTING_THRESHOLD,
  normalExpiryMs: NORMAL_EXPIRY_MS,
  urgencyExpiryRatio: URGENCY_EXPIRY_RATIO,
  bundlingRefCountThreshold: BUNDLING_REF_COUNT_THRESHOLD,
  confidenceInflationDelta: CONFIDENCE_INFLATION_DELTA,
  disallowedAuthorityFields: DISALLOWED_AUTHORITY_FIELDS,
  persuasionSignalSeverity: PERSUASION_SIGNAL_SEVERITY,
});

export function resolveConfig(overrides = {}) {
  if (
    overrides === null ||
    typeof overrides !== "object" ||
    Array.isArray(overrides)
  ) {
    return { ...DEFAULT_NEURANICE_CONFIG };
  }
  return { ...DEFAULT_NEURANICE_CONFIG, ...overrides };
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function uniqueStrings(values) {
  if (!Array.isArray(values)) return [];
  return [
    ...new Set(values.filter(nonEmptyString).map((value) => value.trim())),
  ];
}

function clamp01(value) {
  if (!Number.isFinite(value)) return 1; // A non-finite score fails toward maximum caution.
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function evidence(rule, dimension, detail, extra = {}) {
  return { rule, dimension, detail, ...extra };
}

// Combine independent signals so that each one can only add risk and the total stays inside [0,1].
function noisyOr(severities) {
  let remaining = 1;
  for (const severity of severities) remaining *= 1 - clamp01(severity);
  return clamp01(1 - remaining);
}

function operationKey(proposal) {
  const operation = nonEmptyString(proposal.proposedOperation)
    ? proposal.proposedOperation.trim()
    : "unknown";
  const destination = nonEmptyString(proposal.destination)
    ? proposal.destination.trim()
    : "none";
  return `${operation}|${destination}`;
}

// ---------------------------------------------------------------------------
// Session history. Bounded, local, metadata only.
// ---------------------------------------------------------------------------

/**
 * Bounded in-memory record of proposal METADATA for one or more sessions.
 *
 * WHAT IS STORED: proposalId, operation, destination, reported confidence, context reference LABELS,
 * reference count, requested expiry, the resulting decision status, and which disallowed authority
 * fields the caller tried to set.
 *
 * WHAT IS NEVER STORED: proposal payloads, message bodies, or any free text the user wrote. This
 * object exists to detect behavioural patterns, not to read anything.
 *
 * BOUNDS: at most maxProposalsPerSession records per session and at most maxSessions sessions. The
 * oldest record in a session and the least recently touched session are evicted first, so memory is
 * capped at maxSessions * maxProposalsPerSession records regardless of how long Luna runs.
 */
export class ProposalHistory {
  #sessions = new Map();

  constructor({
    maxProposalsPerSession = SESSION_MAX_PROPOSALS,
    maxSessions = SESSION_MAX_SESSIONS,
    clock = () => Date.now(),
  } = {}) {
    if (
      !Number.isSafeInteger(maxProposalsPerSession) ||
      maxProposalsPerSession < 1
    ) {
      throw new TypeError("maxProposalsPerSession must be a positive integer");
    }
    if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) {
      throw new TypeError("maxSessions must be a positive integer");
    }
    this.maxProposalsPerSession = maxProposalsPerSession;
    this.maxSessions = maxSessions;
    this.clock = typeof clock === "function" ? clock : () => Date.now();
  }

  #sessionKey(sessionId) {
    return nonEmptyString(sessionId) ? sessionId.trim() : "default";
  }

  /**
   * Record one proposal and the status the system returned for it.
   * @param {string} sessionId
   * @param {object} proposal
   * @param {object} [decision] the engine or NeuraNice decision, used to spot escalation after refusal
   */
  record(sessionId, proposal, decision = null) {
    const key = this.#sessionKey(sessionId);
    const bucket = this.#sessions.get(key) || [];
    // Re-inserting moves the session to the end of the Map, which makes eviction least recently used.
    this.#sessions.delete(key);

    const source = isPlainObject(proposal) ? proposal : {};
    const contextRefs = uniqueStrings(source.contextRefs);
    bucket.push({
      proposalId: nonEmptyString(source.proposalId)
        ? source.proposalId.trim()
        : null,
      operation: nonEmptyString(source.proposedOperation)
        ? source.proposedOperation.trim()
        : null,
      destination: nonEmptyString(source.destination)
        ? source.destination.trim()
        : null,
      operationKey: operationKey(source),
      confidence: Number.isFinite(source.confidence) ? source.confidence : null,
      contextRefs,
      refCount: contextRefs.length,
      requestedExpiryMs: Number.isFinite(source.requestedExpiryMs)
        ? source.requestedExpiryMs
        : null,
      probedAuthorityFields: probedAuthorityFields(
        source,
        DISALLOWED_AUTHORITY_FIELDS,
      ),
      status:
        isPlainObject(decision) && nonEmptyString(decision.status)
          ? decision.status
          : null,
      recordedAt: this.clock(),
    });

    while (bucket.length > this.maxProposalsPerSession) bucket.shift();
    this.#sessions.set(key, bucket);

    while (this.#sessions.size > this.maxSessions) {
      const oldest = this.#sessions.keys().next().value;
      this.#sessions.delete(oldest);
    }
    return bucket[bucket.length - 1];
  }

  entriesFor(sessionId) {
    return structuredClone(
      this.#sessions.get(this.#sessionKey(sessionId)) || [],
    );
  }

  sessionCount() {
    return this.#sessions.size;
  }

  size() {
    let total = 0;
    for (const bucket of this.#sessions.values()) total += bucket.length;
    return total;
  }

  clear(sessionId) {
    if (sessionId === undefined) {
      this.#sessions.clear();
      return;
    }
    this.#sessions.delete(this.#sessionKey(sessionId));
  }
}

function probedAuthorityFields(proposal, fields) {
  if (!isPlainObject(proposal)) return [];
  return fields.filter((field) =>
    Object.prototype.hasOwnProperty.call(proposal, field),
  );
}

// ---------------------------------------------------------------------------
// Persuasion detection. Structural facts only.
// ---------------------------------------------------------------------------

/**
 * Detect persuasion pressure from proposal metadata and session history.
 *
 * This is behavioural pattern detection over structured fields. It never reads, tokenizes, or
 * interprets the proposal payload or any natural language, because allowing text to influence policy
 * would make text an attack surface.
 *
 * @returns {Array<{signal: string, severity: number, evidence: object}>}
 */
export function detectPersuasion(proposal = {}, history = null, options = {}) {
  const config = resolveConfig(options.config);
  const sessionId = options.sessionId;
  const source = isPlainObject(proposal) ? proposal : {};
  const past =
    history && typeof history.entriesFor === "function"
      ? history.entriesFor(sessionId)
      : [];
  const signals = [];
  const severityOf = (name) =>
    config.persuasionSignalSeverity[name] ??
    PERSUASION_SIGNAL_SEVERITY[name] ??
    0.5;

  const contextRefs = uniqueStrings(source.contextRefs);
  const key = operationKey(source);
  const sameKey = past.filter(
    (entry) =>
      entry.operationKey === key ||
      (entry.proposalId && entry.proposalId === source.proposalId),
  );

  // 1. Urgency pressure: a requested lifetime far shorter than the norm for this operation.
  if (
    Number.isFinite(source.requestedExpiryMs) &&
    source.requestedExpiryMs > 0
  ) {
    const floor = config.normalExpiryMs * config.urgencyExpiryRatio;
    if (source.requestedExpiryMs < floor) {
      signals.push({
        signal: "urgency_pressure",
        severity: severityOf("urgency_pressure"),
        evidence: evidence(
          "requested_expiry_below_norm",
          "persuasion",
          "requested lifetime is far shorter than the norm for this operation",
          {
            observed: source.requestedExpiryMs,
            threshold: floor,
            normalExpiryMs: config.normalExpiryMs,
          },
        ),
      });
    }
  }

  // 2. Escalation after refusal: the same target was refused before and is now being retried with a
  // wider scope or a higher reported confidence.
  const refused = sameKey.filter(
    (entry) => entry.status === "deny" || entry.status === "clarify",
  );
  if (refused.length > 0) {
    const widest = Math.max(...refused.map((entry) => entry.refCount));
    const highestConfidence = Math.max(
      ...refused.map((entry) =>
        entry.confidence === null ? -1 : entry.confidence,
      ),
    );
    const currentConfidence = Number.isFinite(source.confidence)
      ? source.confidence
      : -1;
    const widened = contextRefs.length > widest;
    const raised = currentConfidence > highestConfidence;
    if (widened || raised) {
      signals.push({
        signal: "escalation_after_refusal",
        severity: severityOf("escalation_after_refusal"),
        evidence: evidence(
          "retry_after_refusal_with_growth",
          "persuasion",
          "a previously refused operation and destination pair was retried with a widened scope or a raised confidence",
          {
            priorRefusals: refused.length,
            priorWidestRefCount: widest,
            currentRefCount: contextRefs.length,
            priorHighestConfidence:
              highestConfidence < 0 ? null : highestConfidence,
            currentConfidence: currentConfidence < 0 ? null : currentConfidence,
            widenedScope: widened,
            raisedConfidence: raised,
          },
        ),
      });
    }
  }

  // 3. Scope creep: reference counts growing monotonically across successive proposals in the session.
  const sessionCounts = [
    ...past.map((entry) => entry.refCount),
    contextRefs.length,
  ];
  if (sessionCounts.length >= 3) {
    const tail = sessionCounts.slice(-3);
    if (tail[0] < tail[1] && tail[1] < tail[2]) {
      signals.push({
        signal: "scope_creep",
        severity: severityOf("scope_creep"),
        evidence: evidence(
          "reference_count_strictly_increasing",
          "persuasion",
          "requested context references grew on each of the last three proposals in this session",
          {
            observed: tail,
          },
        ),
      });
    }
  }

  // 4. Confidence inflation: confidence rising across retries with no new references supplied.
  if (Number.isFinite(source.confidence) && sameKey.length > 0) {
    const previous = sameKey[sameKey.length - 1];
    const sameEvidence =
      previous.refCount === contextRefs.length &&
      previous.contextRefs.every((ref) => contextRefs.includes(ref));
    const delta =
      previous.confidence === null
        ? 0
        : source.confidence - previous.confidence;
    if (sameEvidence && delta >= config.confidenceInflationDelta) {
      signals.push({
        signal: "confidence_inflation",
        severity: severityOf("confidence_inflation"),
        evidence: evidence(
          "confidence_rose_without_new_evidence",
          "persuasion",
          "reported confidence rose across retries while the supplied reference set was unchanged",
          {
            previousConfidence: previous.confidence,
            currentConfidence: source.confidence,
            delta,
            threshold: config.confidenceInflationDelta,
          },
        ),
      });
    }
  }

  // 5. Authority-adjacent field probing: repeated attempts to set fields only Luna may set.
  const probedNow = probedAuthorityFields(
    source,
    config.disallowedAuthorityFields,
  );
  const probedBefore = past.reduce(
    (total, entry) => total + (entry.probedAuthorityFields?.length || 0),
    0,
  );
  if (probedNow.length > 0 || probedBefore > 0) {
    signals.push({
      signal: "authority_field_probing",
      severity: severityOf("authority_field_probing"),
      evidence: evidence(
        "disallowed_authority_fields_present",
        "persuasion",
        "the caller attempted to set fields that only the firewall may set",
        {
          fieldsThisProposal: probedNow,
          priorAttemptCount: probedBefore,
        },
      ),
    });
  }

  // 6. Bundling: an unusually large reference set travelling under a single approval.
  if (contextRefs.length > config.bundlingRefCountThreshold) {
    signals.push({
      signal: "bundling",
      severity: severityOf("bundling"),
      evidence: evidence(
        "reference_set_above_bundling_threshold",
        "persuasion",
        "an unusually large context reference set was attached to a single operation",
        {
          observed: contextRefs.length,
          threshold: config.bundlingRefCountThreshold,
        },
      ),
    });
  }

  // 7. Signals declared by the caller. These can only add risk. A caller declaring an empty list can
  // never lower the score, because nothing below reads absence as reassurance.
  if (Array.isArray(source.persuasionSignals)) {
    for (const declared of source.persuasionSignals) {
      const label = nonEmptyString(declared)
        ? declared.trim()
        : nonEmptyString(declared?.signal)
          ? declared.signal.trim()
          : null;
      if (!label) continue;
      signals.push({
        signal: "declared_by_caller",
        severity: severityOf("declared_by_caller"),
        evidence: evidence(
          "caller_declared_persuasion_signal",
          "persuasion",
          "the caller itself declared a persuasion signal on this proposal",
          {
            declared: label,
          },
        ),
      });
    }
  }

  return signals;
}

// ---------------------------------------------------------------------------
// The six dimension scorers.
// ---------------------------------------------------------------------------

export function scoreSensitivity(
  proposal = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  const refs = uniqueStrings(proposal.contextRefs);
  const found = [];
  let peak = 0;
  for (const ref of refs) {
    for (const rule of config.sensitiveRefPatterns) {
      if (rule.pattern.test(ref)) {
        found.push(
          evidence(
            "sensitive_reference_label_matched",
            "sensitivity",
            `reference label matched the ${rule.category} category`,
            {
              matched: ref,
              category: rule.category,
              weight: rule.weight,
            },
          ),
        );
        if (rule.weight > peak) peak = rule.weight;
      }
    }
  }
  if (refs.length === 0) {
    return {
      score: 0,
      evidence: [
        evidence(
          "no_context_references",
          "sensitivity",
          "the proposal discloses no context references",
          { observed: 0 },
        ),
      ],
    };
  }
  const volume = Math.min(
    (refs.length - 1) * config.sensitivityVolumeStep,
    config.sensitivityVolumeCap,
  );
  const base = peak > 0 ? peak : config.baselineRefSensitivity;
  const items = found.length
    ? found
    : [
        evidence(
          "references_present_none_sensitive",
          "sensitivity",
          "context references were requested but none matched a sensitive category",
          {
            observed: refs.length,
            baseline: config.baselineRefSensitivity,
          },
        ),
      ];
  if (volume > 0) {
    items.push(
      evidence(
        "disclosure_volume",
        "sensitivity",
        "breadth of disclosure adds sensitivity beyond the single worst reference",
        {
          observed: refs.length,
          contribution: volume,
          cap: config.sensitivityVolumeCap,
        },
      ),
    );
  }
  return { score: clamp01(base + volume), evidence: items };
}

export function scoreExternality(
  proposal = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  const operation = nonEmptyString(proposal.proposedOperation)
    ? proposal.proposedOperation.trim()
    : null;
  const known =
    operation !== null &&
    Object.prototype.hasOwnProperty.call(
      config.operationExternality,
      operation,
    );
  const base = known
    ? config.operationExternality[operation]
    : config.unknownOperationExternality;
  const items = [
    evidence(
      known
        ? "operation_externality_table"
        : "unknown_operation_fails_toward_caution",
      "externality",
      known
        ? "the operation has a documented externality weight"
        : "the operation is not in the externality table, so the cautious default is used",
      {
        matched: operation,
        weight: base,
      },
    ),
  ];
  let score = base;
  if (nonEmptyString(proposal.destination)) {
    score += config.destinationExternalityIncrement;
    items.push(
      evidence(
        "concrete_destination_named",
        "externality",
        "a concrete destination turns a hypothetical into a targeted disclosure",
        {
          contribution: config.destinationExternalityIncrement,
        },
      ),
    );
  }
  return { score: clamp01(score), evidence: items };
}

export function scoreIrreversibility(
  proposal = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  const operation = nonEmptyString(proposal.proposedOperation)
    ? proposal.proposedOperation.trim()
    : null;
  const known =
    operation !== null &&
    Object.prototype.hasOwnProperty.call(
      config.operationIrreversibility,
      operation,
    );
  const score = known
    ? config.operationIrreversibility[operation]
    : config.unknownOperationIrreversibility;
  return {
    score: clamp01(score),
    evidence: [
      evidence(
        known
          ? "operation_irreversibility_table"
          : "unknown_operation_fails_toward_caution",
        "irreversibility",
        known
          ? "the operation has a documented irreversibility weight"
          : "the operation is not in the irreversibility table, so the cautious default is used",
        {
          matched: operation,
          weight: score,
        },
      ),
    ],
  };
}

export function scoreUncertainty(
  proposal = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  const raw = proposal.confidence;
  if (!Number.isFinite(raw)) {
    return {
      score: 1,
      evidence: [
        evidence(
          "confidence_absent",
          "uncertainty",
          "no confidence was reported, which is treated as maximum uncertainty",
          {},
        ),
      ],
    };
  }
  const confidence = clamp01(raw);
  const high = config.confidenceHighThreshold;
  const clarify = config.confidenceClarifyThreshold;
  const atHigh = config.uncertaintyAtHighConfidence;
  const atClarify = config.uncertaintyAtClarifyThreshold;
  let score;
  let rule;
  if (confidence >= high) {
    const span = 1 - high;
    score = span > 0 ? atHigh * (1 - (confidence - high) / span) : 0;
    rule = "confidence_above_high_threshold";
  } else if (confidence >= clarify) {
    const span = high - clarify;
    const position = span > 0 ? (confidence - clarify) / span : 1;
    score = atClarify - (atClarify - atHigh) * position;
    rule = "confidence_between_clarify_and_high_thresholds";
  } else {
    const position = clarify > 0 ? confidence / clarify : 1;
    score = 1 - (1 - atClarify) * position;
    rule = "confidence_below_clarify_threshold";
  }
  return {
    score: clamp01(score),
    evidence: [
      evidence(
        rule,
        "uncertainty",
        "uncertainty is a continuous piecewise linear function of reported confidence",
        {
          observed: confidence,
          clarifyThreshold: clarify,
          highThreshold: high,
        },
      ),
    ],
  };
}

export function scorePersuasion(
  signals = [],
  config = DEFAULT_NEURANICE_CONFIG,
) {
  void config;
  if (!Array.isArray(signals) || signals.length === 0) {
    return {
      score: 0,
      evidence: [
        evidence(
          "no_structural_persuasion_signals",
          "persuasion",
          "no structural persuasion pattern was found in this proposal or session history",
          {},
        ),
      ],
    };
  }
  return {
    score: noisyOr(signals.map((entry) => entry.severity)),
    evidence: signals.map((entry) => ({
      ...entry.evidence,
      signal: entry.signal,
      severity: entry.severity,
    })),
  };
}

export function scoreProvenance(
  proposal = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  if (proposal.provenanceVerified === false) {
    return {
      score: clamp01(config.provenanceUnverifiedScore),
      evidence: [
        evidence(
          "provenance_explicitly_unverified",
          "provenance",
          "the caller reported that provenance could not be verified",
          { observed: false },
        ),
      ],
    };
  }
  if (proposal.provenanceVerified !== true) {
    return {
      score: clamp01(config.provenanceUnknownScore),
      evidence: [
        evidence(
          "provenance_flag_absent",
          "provenance",
          "no provenance flag was supplied, and an unverified chain of custody is not treated as safe",
          {
            threshold: config.provenanceUnknownScore,
          },
        ),
      ],
    };
  }
  const refs = uniqueStrings(proposal.contextRefs);
  const inferred = uniqueStrings(proposal.inferredContextRefs);
  const total = new Set([...refs, ...inferred]).size;
  const ratio = total === 0 ? 0 : inferred.length / total;
  const items = [
    evidence(
      "provenance_verified",
      "provenance",
      "the caller reported verified provenance",
      { observed: true, base: config.provenanceVerifiedBase },
    ),
  ];
  if (inferred.length > 0) {
    items.push(
      evidence(
        "inferred_reference_share",
        "provenance",
        "part of this proposal rests on machine inference rather than on something the user stated",
        {
          inferredCount: inferred.length,
          totalCount: total,
          ratio,
          weight: config.inferredRefProvenanceWeight,
        },
      ),
    );
  }
  return {
    score: clamp01(
      config.provenanceVerifiedBase +
        ratio * config.inferredRefProvenanceWeight,
    ),
    evidence: items,
  };
}

// ---------------------------------------------------------------------------
// Aggregation, verdict, and the public assess() entry point.
// ---------------------------------------------------------------------------

function groupMean(scores, dimensions, weights) {
  let weighted = 0;
  let totalWeight = 0;
  let peak = 0;
  for (const dimension of dimensions) {
    const weight = weights[dimension] ?? 0;
    const score = clamp01(scores[dimension]);
    weighted += score * weight;
    totalWeight += weight;
    if (score > peak) peak = score;
  }
  // No usable weights means the caller has misconfigured the model. Fail toward caution.
  return { mean: totalWeight > 0 ? weighted / totalWeight : 1, peak };
}

/**
 * Split the six scores into stake and doubt, then combine them.
 *
 *   stake  = weighted mean of sensitivity, externality, irreversibility
 *   doubt  = weighted mean of uncertainty, persuasion, provenance, floored by the worst of them
 *   result = stakeFloorWeight * stake
 *          + (1 - stakeFloorWeight) * doubt * (minStakeCoupling + (1 - minStakeCoupling) * stake)
 *
 * The shape encodes the product rule: escalate on doubt, in proportion to what is at stake.
 * @returns {{stake: number, doubt: number, aggregate: number}}
 */
export function aggregateBreakdown(scores, config = DEFAULT_NEURANICE_CONFIG) {
  const weights = config.dimensionWeights;
  const stakeGroup = groupMean(scores, config.stakeDimensions, weights);
  const doubtGroup = groupMean(scores, config.doubtDimensions, weights);
  const stake = clamp01(stakeGroup.mean);
  // The floor stops one maxed doubt dimension being diluted into a comfortable average.
  const doubt = clamp01(
    Math.max(doubtGroup.mean, doubtGroup.peak * config.maxDoubtFloorFactor),
  );
  const coupling =
    config.minStakeCoupling + (1 - config.minStakeCoupling) * stake;
  const aggregate = clamp01(
    config.stakeFloorWeight * stake +
      (1 - config.stakeFloorWeight) * doubt * coupling,
  );
  return { stake, doubt, aggregate };
}

export function aggregateScores(scores, config = DEFAULT_NEURANICE_CONFIG) {
  return aggregateBreakdown(scores, config).aggregate;
}

export function verdictFor(
  aggregate,
  scores = {},
  config = DEFAULT_NEURANICE_CONFIG,
) {
  // Hard rule that does not depend on the aggregate: explicitly unverified provenance is a deny.
  // Luna's whole premise is that inference without a verified chain of custody creates no authority.
  if (clamp01(scores.provenance) >= config.provenanceUnverifiedScore)
    return "deny";
  if (aggregate >= config.verdictDenyThreshold) return "deny";
  if (aggregate >= config.verdictClarifyThreshold)
    return "require_clarification";
  return "allow_with_confirmation";
}

export function riskLabel(aggregate) {
  const value = clamp01(aggregate);
  for (const band of RISK_LABEL_BANDS) {
    if (value >= band.min) return band.label;
  }
  return "high";
}

// Translate the six continuous scores into the coarse low, medium, high vocabulary the existing
// engine risk field already uses, so a user interface can show a derived label instead of a
// hardcoded string.
export function toRiskBands(scores = {}) {
  const band = (value) => {
    const score = clamp01(value);
    if (score >= 0.66) return "high";
    if (score >= 0.33) return "medium";
    return "low";
  };
  return {
    sensitivity: band(scores.sensitivity),
    externality: band(scores.externality),
    irreversibility: band(scores.irreversibility),
    uncertainty: band(scores.uncertainty),
    persuasion: band(scores.persuasion),
    provenance: band(scores.provenance),
  };
}

/**
 * Assess a proposal.
 *
 * @param {object} proposal
 * @param {object} [context]
 * @param {ProposalHistory|null} [context.history]  bounded session history for persuasion detection
 * @param {string} [context.sessionId]
 * @param {object} [context.config]                 parameter overrides, see DEFAULT_NEURANICE_CONFIG
 * @returns {{scores: object, evidence: object[], aggregate: number, verdict: string,
 *            signals: object[], riskLabel: string, riskBands: object, neuraniceVersion: string}}
 */
export function assess(proposal = {}, context = {}) {
  const config = resolveConfig(context.config);

  // A proposal that is not an object, or that does not name an operation, cannot be reasoned about
  // at all. NeuraNice refuses rather than producing a score it cannot justify. Fail closed.
  const unassessable = !isPlainObject(proposal)
    ? "proposal_not_an_object"
    : !nonEmptyString(proposal.proposedOperation)
      ? "proposal_names_no_operation"
      : null;
  if (unassessable) {
    const denied = {
      sensitivity: 1,
      externality: 1,
      irreversibility: 1,
      uncertainty: 1,
      persuasion: 1,
      provenance: 1,
    };
    return {
      neuraniceVersion: NEURANICE_VERSION,
      policyVersion: POLICY_VERSION,
      scores: denied,
      evidence: [
        evidence(
          unassessable,
          "provenance",
          "the proposal could not be assessed, so every dimension fails toward maximum caution",
          {},
        ),
      ],
      signals: [],
      aggregate: 1,
      verdict: "deny",
      riskLabel: riskLabel(1),
      riskBands: toRiskBands(denied),
    };
  }

  const source = proposal;
  const signals = detectPersuasion(source, context.history || null, {
    sessionId: context.sessionId,
    config,
  });

  const parts = {
    sensitivity: scoreSensitivity(source, config),
    externality: scoreExternality(source, config),
    irreversibility: scoreIrreversibility(source, config),
    uncertainty: scoreUncertainty(source, config),
    persuasion: scorePersuasion(signals, config),
    provenance: scoreProvenance(source, config),
  };

  const scores = {};
  const items = [];
  for (const [dimension, part] of Object.entries(parts)) {
    scores[dimension] = clamp01(part.score);
    for (const item of part.evidence) items.push({ dimension, ...item });
  }

  const { stake, doubt, aggregate } = aggregateBreakdown(scores, config);
  items.push(
    evidence(
      "aggregate_stake_and_doubt",
      "provenance",
      "the aggregate escalates on doubt in proportion to what is at stake",
      {
        stake,
        doubt,
        aggregate,
        stakeDimensions: [...config.stakeDimensions],
        doubtDimensions: [...config.doubtDimensions],
      },
    ),
  );
  return {
    neuraniceVersion: NEURANICE_VERSION,
    policyVersion: POLICY_VERSION,
    scores,
    evidence: items,
    signals,
    stake,
    doubt,
    aggregate,
    verdict: verdictFor(aggregate, scores, config),
    riskLabel: riskLabel(aggregate),
    riskBands: toRiskBands(scores),
  };
}

function reasonCodesFor(assessment, config) {
  const codes = [];
  if (assessment.verdict === "deny") codes.push("NEURANICE_VERDICT_DENY");
  if (assessment.verdict === "require_clarification")
    codes.push("NEURANICE_VERDICT_CLARIFY");
  const scores = assessment.scores || {};
  for (const dimension of Object.keys(DIMENSION_WEIGHTS)) {
    if (clamp01(scores[dimension]) >= config.evidenceReportingThreshold) {
      codes.push(`NEURANICE_HIGH_${dimension.toUpperCase()}`);
    }
  }
  for (const signal of assessment.signals || []) {
    codes.push(`NEURANICE_SIGNAL_${String(signal.signal).toUpperCase()}`);
  }
  return [...new Set(codes)];
}

function denyShell(reasonCodes, assessment) {
  return {
    policyVersion: POLICY_VERSION,
    proposalId: null,
    state: null,
    operation: null,
    destination: null,
    status: "deny",
    requiresExplicitConfirmation: false,
    authority: "none",
    reasonCodes,
    excludedContextRefs: [],
    disclosedContextRefs: [],
    neuranice: assessment || null,
  };
}

/**
 * Apply an assessment to an existing engine decision.
 *
 * PURE. The input decision is never mutated; a new object is returned.
 *
 * MONOTONIC. The returned status is never less restrictive than the input status, measured by
 * RESTRICTION_RANK. deny can never become clarify, confirm, or share_ready. clarify can never become
 * confirm or share_ready. confirm and share_ready are never converted into each other. Authority is
 * never added, and requiresExplicitConfirmation is never turned on by this function.
 *
 * @param {object} decision   a decision from decideProposal(), optionally already carrying a preview
 * @param {object} assessment the result of assess()
 * @returns {object} a possibly more restrictive decision
 */
export function applyNeuraNice(decision, assessment) {
  const config = resolveConfig(assessment?.config);

  if (!isPlainObject(decision)) {
    return denyShell(
      ["NEURANICE_INVALID_DECISION"],
      isPlainObject(assessment) ? assessment : null,
    );
  }
  if (!isPlainObject(assessment) || !VERDICTS.includes(assessment.verdict)) {
    return {
      ...structuredClone(decision),
      status: "deny",
      requiresExplicitConfirmation: false,
      authority: "none",
      reasonCodes: [
        ...new Set([
          ...(Array.isArray(decision.reasonCodes) ? decision.reasonCodes : []),
          "NEURANICE_INVALID_ASSESSMENT",
        ]),
      ],
      neuranice: null,
    };
  }

  const originalStatus = decision.status;
  const originalRank = restrictionRank(originalStatus);
  const ceiling = VERDICT_CEILING_STATUS[assessment.verdict];

  let nextStatus = originalStatus;
  if (originalRank === UNKNOWN_STATUS_RANK) {
    // An unrecognised status is not something this module is willing to pass through.
    nextStatus = "deny";
  } else if (ceiling !== null && restrictionRank(ceiling) < originalRank) {
    nextStatus = ceiling;
  }

  // Belt and braces. Even if the branches above were ever changed incorrectly, this refuses to
  // return anything less restrictive than what the engine already decided.
  if (
    originalRank !== UNKNOWN_STATUS_RANK &&
    restrictionRank(nextStatus) > originalRank
  ) {
    nextStatus = originalStatus;
  }

  const changed = nextStatus !== originalStatus;
  const codes = [
    ...(Array.isArray(decision.reasonCodes) ? decision.reasonCodes : []),
  ];
  if (changed) codes.push("NEURANICE_RESTRICTED");
  for (const code of reasonCodesFor(assessment, config)) codes.push(code);

  const result = {
    ...structuredClone(decision),
    status: nextStatus,
    // Restricting a decision always removes authority. It is never granted here.
    requiresExplicitConfirmation: changed
      ? false
      : decision.requiresExplicitConfirmation === true,
    authority: changed ? "none" : decision.authority || "none",
    reasonCodes: [...new Set(codes)],
    neuranice: {
      neuraniceVersion: assessment.neuraniceVersion || NEURANICE_VERSION,
      verdict: assessment.verdict,
      aggregate: assessment.aggregate,
      scores: assessment.scores,
      evidence: assessment.evidence,
      signals: assessment.signals,
      riskLabel: assessment.riskLabel ?? riskLabel(assessment.aggregate),
      riskBands: assessment.riskBands ?? toRiskBands(assessment.scores || {}),
      restrictedFrom: changed ? originalStatus : null,
      restricted: changed,
    },
  };

  // A share packet must not survive a restriction, and a capability must not survive one either.
  if (changed && result.preview) result.preview = null;
  return result;
}

/**
 * Convenience wrapper: assess, apply, and record in one call.
 * Recording is separated from assess() on purpose so that assess() stays free of side effects.
 */
export function guard(decision, proposal, context = {}) {
  const assessment = assess(proposal, context);
  const guarded = applyNeuraNice(decision, assessment);
  if (context.history && typeof context.history.record === "function") {
    context.history.record(context.sessionId, proposal, guarded);
  }
  return { assessment, decision: guarded };
}
