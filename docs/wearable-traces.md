# Wearable trace audit

This offline auditor checks a synthetic, metadata-only event trace against a small set of lifecycle and action-approval rules. It is a development aid, not a Meta device interceptor, prompt-injection detector, certified security control, or proof that an action was blocked or safe. Findings identify a trace that violates the modeled policy. A clean report is not proof that the real device, app, or downstream action behaved safely.

## Local use

From the repository root, audit the benign example:

```sh
python -m app.wearable_cli examples/wearable-safe.json
```

Use `--format sarif` for SARIF 2.1.0 output, or `--output FILE` to save a report. Exit codes are `0` for no error-severity findings (warnings are allowed), `1` for error findings, and `2` for invalid input or an input failure. Reports contain event indexes as logical locations, not fabricated source paths. The auditor reads only the supplied trace, makes no network calls, and does not retain traces or reports by default.

All checked-in examples are synthetic. `platform: generic` describes their portable schema only; it does not claim Meta SDK compatibility. Event IDs and SHA-256 digests are fictional metadata. The hashes are claims over identifiers and content metadata, not proof of the underlying frame, transcript, message, or operation. Do not put names, URLs, raw OCR/QR text, transcripts, frame pixels, or other personal content in a trace.

The machine-readable [trace schema](../schemas/wearable-trace.schema.json) defines every field. [A standalone benign trace](../examples/wearable-safe.json) is ready for the CLI; files under `fixtures/wearables/` wrap traces with regression expectations and are intended for the review screen and test suite.

## Mapping a real integration into the schema

Build a native adapter against the current official [Wearables Device Access Toolkit documentation](https://wearables.developer.meta.com/docs/develop/), [iOS SDK repository](https://github.com/facebook/meta-wearables-dat-ios), and [Android SDK repository](https://github.com/facebook/meta-wearables-dat-android). The iOS and Android repositories describe different APIs; map each only from the matching current SDK reference and observed app callback. The public documentation landing page may require developer-center access. Meta's current [wearables FAQ](https://developers.meta.com/wearables/faq/) describes the supported toolkit and mock-device testing path.

- Keep registration, device discovery, session lifecycle, capability attachment, permission status, and stream state separate in the adapter. Registration or a selected/connected device does not itself mean that the camera permission is granted or that a camera stream is running. Emit fresh permission state after connection; do not carry a grant across a disconnect/reconnect boundary. The portable model allows one active device at a time.
- The portable `session_started` event means the adapter's capture-ready epoch. Native session creation alone is insufficient: emit it only after the selected device session is active and the camera capability/stream has started successfully. Emit `session_stopped` when capture readiness ends, and start a new epoch after reconnect. The trace schema folds native session and stream readiness into one state; it is not a one-to-one dump of DAT callbacks.
- For frame records, preserve both the source capture time (`captured_at_ms`) and the callback/observation time (`t_ms`) using one monotonic clock domain. A capture timestamp must follow both the relevant permission grant and the capture-ready session start; use the capture timestamp, not callback arrival time, to identify late frames. Late frames arriving after stream stop, revocation, disconnect, or reconnect must retain their original source time and epoch association. Do not relabel them as current frames. The auditor treats timestamps and lifecycle events as declared trace metadata.
- Emit `permission` only for an exact permission/status signal documented and exposed by the relevant platform SDK or app permission layer. The schema's `microphone` permission value is portable app metadata; its presence does not imply that DAT exposes a separate microphone-permission callback. OCR and QR use camera permission in this model.
- Assign pseudonymous, trace-local device, session, capture, approval, and action IDs. A device/session ID reused after reconnect does not merge epochs. Keep approval fingerprint inputs aligned with the action's exact operation, destination, ordered source capture IDs, and content digest; changing any of those requires a new approval.

The trace's `bystanders` field is self-reported metadata (`none`, `consented`, `unconsented`, or `unknown`). It does not detect people, establish consent, or establish that no bystander was present. Similarly, a capture event does not prove that bytes were received or analyzed. The adapter and its operators remain responsible for evidence quality, redaction, and retention outside this auditor.

## Modeled policy boundaries

The rules cover device/session epochs, sensor permission changes, capture age and source availability, action-bound approval, approval expiry and reuse, operation/destination pairing, bystander declarations for external sharing and memory writes, and OCR/QR retention warnings. `persist_memory` from OCR/QR is flagged even when the trace includes human approval. This is a policy warning over metadata, not a content scan or automatic storage block.

The trace contract rejects raw payload fields and unknown keys. `evidence_kind` and `platform` are caller-declared labels, not attested provenance. Audit reports omit raw IDs and digests; event indexes refer only to positions in the supplied trace.

## Comparison context

General exact-action and one-time approvals already appear in projects such as [Delego](https://github.com/Delego-Dev/delego) and [ActionAuth](https://github.com/CoffeeAnon/actionauth). [ActionProxy](https://github.com/ActionProxy/actionproxy) documents a broader approval gateway and notes that stored tool-call and audit payloads may contain sensitive raw data. [Meta LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) provides model/input and code-focused security scanners. This trace auditor's narrower design focus is wearable lifecycle and privacy metadata, with a synthetic offline fixture corpus; it does not replace semantic/model defenses. That scope is not a claim of novelty, production readiness, or superiority.
