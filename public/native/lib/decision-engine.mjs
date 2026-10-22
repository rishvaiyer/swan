export const POLICY_VERSION = "luna-policy-0.3.0";

export const INTERACTION_STATES = Object.freeze([
  "private",
  "reflect",
  "share",
  "act",
]);
const STATES = new Set(INTERACTION_STATES);
// Decision D-014: send_message is the single protected operation of the MVP.
// create_draft stays in the engine allowlist purely as a test fixture and is
// rejected by the product surface (local-firewall) before anything evaluates.
export const PROTECTED_OPERATION = "send_message";
const TEST_FIXTURE_OPERATIONS = new Set(["create_draft"]);
const ALLOWED_OPERATIONS = new Set([
  PROTECTED_OPERATION,
  ...TEST_FIXTURE_OPERATIONS,
]);
export { ALLOWED_OPERATIONS };
const HIGH_IMPACT_OPERATIONS = new Set([
  "send_message",
  "purchase",
  "delete",
  "publish",
  "change_permission",
]);

// Any Unicode control (Cc), format (Cf) or unassigned (Cn) code point. This one
// pattern covers C0/C1 controls (NUL, LF, CR and friends), bidirectional
// override and isolate controls, zero width space, zero width joiners and the
// byte order mark, plus anything not yet assigned a meaning. A destination is
// shown verbatim to a human for confirmation and burned into the one time
// capability and the audit receipt, so anything in this set is a way to make
// a person approve a string that is not the one they actually read.
const DESTINATION_UNSAFE_PATTERN = /[\p{Cc}\p{Cf}\p{Cn}]/u;

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function uniqueStrings(values) {
  if (!Array.isArray(values)) return [];
  return [
    ...new Set(values.filter(nonEmptyString).map((value) => value.trim())),
  ];
}

// Single source of truth for destination normalization and validation. Used by
// both decideProposal below and ReferenceBroker (core/reference-broker.mjs), so
// there is exactly one place that decides what a safe destination looks like.
// An absent or non-string destination is treated as "no destination", matching
// prior behavior for that case. A destination that is a non-empty string but
// contains an unsafe code point is rejected outright, never silently rewritten:
// silently stripping characters would let a human approve one string while the
// system stored another, which is its own trust problem.
export function normalizeDestination(value) {
  if (!nonEmptyString(value)) return { ok: true, value: null };
  const normalized = value.trim().normalize("NFC");
  if (DESTINATION_UNSAFE_PATTERN.test(normalized))
    return { ok: false, value: null };
  return { ok: true, value: normalized };
}

function invalidDecision(reasonCodes) {
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
    risk: {
      sensitivity: "high",
      externality: "high",
      irreversibility: "high",
      uncertainty: "high",
      persuasion: "high",
      provenance: "high",
    },
  };
}

// One definition of "sensitive reference", shared by the risk vector below and
// by the hard gate in decideProposalUnsafe. A reference is sensitive when its
// name itself declares a private category; approval must be explicit per ref.
const SENSITIVE_REF_PATTERN =
  /private|health|financial|identity|password|location/i;

function riskVector(proposal, confidence, operation) {
  const contextRefs = uniqueStrings(proposal.contextRefs);
  const sensitivity = contextRefs.some((ref) => SENSITIVE_REF_PATTERN.test(ref))
    ? "high"
    : contextRefs.length
      ? "medium"
      : "low";
  const externality =
    proposal.destination || HIGH_IMPACT_OPERATIONS.has(operation)
      ? "medium"
      : "low";
  const irreversibility = ["delete", "purchase", "change_permission"].includes(
    operation,
  )
    ? "high"
    : ["send_message", "publish"].includes(operation)
      ? "medium"
      : "low";
  const uncertainty =
    confidence < 0.8 ? "high" : confidence < 0.94 ? "medium" : "low";
  const persuasion =
    Array.isArray(proposal.persuasionSignals) &&
    proposal.persuasionSignals.length
      ? "medium"
      : "low";
  const provenance = proposal.provenanceVerified === false ? "high" : "low";
  return {
    sensitivity,
    externality,
    irreversibility,
    uncertainty,
    persuasion,
    provenance,
  };
}

// The actual decision logic. Kept separate from decideProposal so the export
// can wrap it in a try/catch: a hostile proposal (for example a Proxy whose
// property getters throw) must still resolve to a structured deny, never an
// uncaught exception. A throw is fail closed in the sense that no authority is
// granted, but it turns a policy decision into an availability problem and
// denies the caller a reason code, so we guard against it explicitly.
function decideProposalUnsafe(proposal, context) {
  if (!proposal || typeof proposal !== "object" || Array.isArray(proposal)) {
    return invalidDecision(["INVALID_PROPOSAL"]);
  }

  const state = proposal.state;
  if (!nonEmptyString(proposal.proposalId))
    return invalidDecision(["MISSING_PROPOSAL_ID"]);
  if (!STATES.has(state)) return invalidDecision(["INVALID_STATE"]);
  if (!nonEmptyString(proposal.proposedOperation))
    return invalidDecision(["INVALID_OPERATION"]);
  // Normalize the operation exactly once. Every downstream read (the allowlist
  // check right below, riskVector, the emitted decision, and the high impact
  // lookup in the act branch) uses this same trimmed value, so trailing or
  // leading whitespace on the operation can never make one part of the engine
  // disagree with another about what operation is actually being performed.
  const operation = proposal.proposedOperation.trim();
  if (!ALLOWED_OPERATIONS.has(operation))
    return invalidDecision(["UNSUPPORTED_OPERATION"]);
  if (
    proposal.confidence !== undefined &&
    (!Number.isFinite(proposal.confidence) ||
      proposal.confidence < 0 ||
      proposal.confidence > 1)
  ) {
    return invalidDecision(["INVALID_CONFIDENCE"]);
  }
  if (
    proposal.provenanceVerified !== undefined &&
    typeof proposal.provenanceVerified !== "boolean"
  ) {
    return invalidDecision(["INVALID_PROVENANCE_FLAG"]);
  }
  if (
    proposal.contextRefs !== undefined &&
    !Array.isArray(proposal.contextRefs)
  ) {
    return invalidDecision(["INVALID_CONTEXT_REFS"]);
  }
  if (
    proposal.inferredContextRefs !== undefined &&
    !Array.isArray(proposal.inferredContextRefs)
  ) {
    return invalidDecision(["INVALID_INFERRED_CONTEXT_REFS"]);
  }
  if (
    context.approvedContextRefs !== undefined &&
    !Array.isArray(context.approvedContextRefs)
  ) {
    return invalidDecision(["INVALID_APPROVED_CONTEXT"]);
  }
  const destinationCheck = normalizeDestination(proposal.destination);
  if (!destinationCheck.ok)
    return invalidDecision(["DESTINATION_UNSAFE_CHARACTERS"]);

  const confidence = proposal.confidence ?? 0.5;
  const contextRefs = uniqueStrings(proposal.contextRefs);
  const approvedContextRefs = uniqueStrings(context.approvedContextRefs);
  const inferredContextRefs = uniqueStrings(proposal.inferredContextRefs);
  const excludedContextRefs = uniqueStrings([
    ...inferredContextRefs,
    ...contextRefs.filter((ref) => !approvedContextRefs.includes(ref)),
  ]);
  const risk = riskVector(proposal, confidence, operation);
  const base = {
    policyVersion: POLICY_VERSION,
    proposalId: proposal.proposalId.trim(),
    state,
    operation,
    destination: destinationCheck.value,
    status: "deny",
    requiresExplicitConfirmation: false,
    authority: "none",
    reasonCodes: [],
    excludedContextRefs,
    disclosedContextRefs: approvedContextRefs.filter(
      (ref) => contextRefs.includes(ref) && !inferredContextRefs.includes(ref),
    ),
    risk,
  };

  // Absent provenance must be treated exactly like provenanceVerified: false,
  // not like true. Requiring the explicit affirmative (=== true) rather than
  // testing for the negative (=== false) means omitting the field is never
  // strictly better for a caller than honestly asserting it could not verify
  // the source: both paths land on the same deny, with the same reason code.
  if (proposal.provenanceVerified !== true) {
    base.reasonCodes.push("UNVERIFIED_PROVENANCE");
    return base;
  }
  if (confidence < 0.8) {
    base.status = "clarify";
    base.reasonCodes.push("LOW_CONFIDENCE");
    return base;
  }
  if (state === "private") {
    base.reasonCodes.push("PRIVATE_BOUNDARY");
    return base;
  }
  if (state === "reflect") {
    base.status = "clarify";
    base.reasonCodes.push("REFLECTION_ONLY");
    return base;
  }
  if (!base.destination) {
    base.status = "clarify";
    base.reasonCodes.push("MISSING_DESTINATION");
    return base;
  }
  // Risk gate 1: a stated sensitive reference the user never approved can no
  // longer ride along while the action proceeds. Before this gate such refs
  // were silently excluded from disclosure while share and act authority was
  // still granted, which hid exactly the context that made the action risky.
  // Inferred references keep their documented semantics (excluded from
  // disclosure, never authority-granting) and do not deny here.
  if (state === "share" || state === "act") {
    const unapprovedSensitive = contextRefs.filter(
      (ref) =>
        !approvedContextRefs.includes(ref) &&
        !inferredContextRefs.includes(ref) &&
        SENSITIVE_REF_PATTERN.test(ref),
    );
    if (unapprovedSensitive.length > 0) {
      base.reasonCodes.push("UNAPPROVED_SENSITIVE_CONTEXT");
      return base;
    }
  }
  const persuasionFlagged =
    Array.isArray(proposal.persuasionSignals) &&
    proposal.persuasionSignals.length > 0;
  if (state === "share") {
    base.status = "share_ready";
    base.reasonCodes.push("SCOPED_DISCLOSURE_ONLY");
    base.authority = "share_packet";
    return base;
  }
  if (state === "act") {
    base.status = "confirm";
    base.reasonCodes.push(
      HIGH_IMPACT_OPERATIONS.has(operation)
        ? "HIGH_IMPACT_CONFIRMATION"
        : "EXPLICIT_CONFIRMATION",
    );
    // Risk gate 2: a detected persuasion attempt must be visible on the exact
    // decision the human confirms. It does not deny by itself; it names its
    // trigger so the confirmation is informed rather than rubber-stamped.
    if (persuasionFlagged) {
      base.reasonCodes.push("PERSUASION_WARNING");
    }
    base.requiresExplicitConfirmation = true;
    base.authority = "one_time_capability";
    return base;
  }
  return base;
}

export function decideProposal(proposal = {}, context = {}) {
  try {
    return decideProposalUnsafe(proposal, context ?? {});
  } catch {
    return invalidDecision(["INVALID_PROPOSAL"]);
  }
}

export function previewMatchesExecution(preview = {}, execution = {}) {
  const fields = [
    "proposalId",
    "operation",
    "destination",
    "payloadHash",
    "disclosedContextRefs",
  ];
  return fields.every(
    (field) =>
      JSON.stringify(preview[field]) === JSON.stringify(execution[field]),
  );
}

export function createLocalReceipt(decision, options = {}) {
  if (!decision || typeof decision !== "object")
    throw new TypeError("decision is required");
  const receiptId = options.receiptId;
  // Fail closed rather than default. An append-only ledger must never mint an
  // identifier on its own behalf: a fixed constant default silently collides
  // every omitted-id receipt into the same identity, which defeats the point
  // of an append-only log. Callers with state that can generate a real unique
  // id (ReferenceBroker.receipt below) are expected to supply one explicitly.
  if (typeof receiptId !== "string" || receiptId.trim().length === 0) {
    throw new TypeError("receiptId is required and must be a non-empty string");
  }
  return {
    receiptId: receiptId.trim(),
    policyVersion: decision.policyVersion || POLICY_VERSION,
    proposalId: decision.proposalId || null,
    state: decision.state || null,
    status: decision.status || "deny",
    authority: decision.authority || "none",
    requiresExplicitConfirmation:
      decision.requiresExplicitConfirmation === true,
    disclosedContextRefs: [...(decision.disclosedContextRefs || [])],
    excludedContextRefs: [...(decision.excludedContextRefs || [])],
    reasonCodes: [...(decision.reasonCodes || [])],
    destination: decision.destination || null,
    outcome: options.outcome || "not_sent",
    signatureStatus: "not_signed_local_prototype",
  };
}
