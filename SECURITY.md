# Security boundaries

Swan is a local developer tool, not a security certification or Meta product.
The wearable auditor evaluates supplied metadata against a deterministic policy.
An error finding means the trace violates that policy; it does not mean Swan
stopped a real action. A clean result does not establish that a device, user,
application or captured content is trustworthy.

## Trusted inputs

The integrating application must supply complete, correctly ordered lifecycle,
permission, capture, approval and action events from a trustworthy observation
point. `recorded` is a caller declaration. Log omissions, false bystander labels,
fabricated approvals, digest claims and compromised hosts are not independently
detected. Approval hashes must be compared with the actual outbound payload at
an execution boundary; this offline reviewer does not perform that integration.
Camera and microphone permission are distinct. Registration is not permission.

The portable schema models lifecycle and consent; it is not an SDK event format.
No Meta SDK, authenticated hardware transport, wearer identity verification or
physical-glasses test is bundled. QR/OCR provenance is metadata, not a semantic
injection classifier. Bystander consent must come from the application, not an
assumed face detector. Local timestamps must use one monotonic clock domain.

## Local processing

The auditor uses no model or network. Inputs are limited to 2 MiB and 5,000
events. Reports omit input identifiers, content digests and raw media/text.
The CLI reads the named local file; it does not fetch URLs. No audit input is
stored by the review API. A user may explicitly export a report. Keep input
traces, browser sessions and exported files within the appropriate trust boundary.

The optional web app must remain bound to loopback. Host/origin checks and a
content-security policy are defense in depth, not multi-user authentication.
Earlier OCR/model experiments are separate routes with their own local uploads
and receipts. Those experiments retain local artifacts; the trace auditor's
no-retention behavior must not be generalized to them.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if available. If unavailable, open an
issue requesting a private reporting channel, without sensitive details. Include
an affected commit and a minimal synthetic reproduction through the private
channel. Do not upload real camera/audio data, credentials or personal traces.
Only the latest main branch is maintained. No response-time guarantee is implied.
