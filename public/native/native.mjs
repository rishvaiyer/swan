import { SwanBoundary, registerNativeTools } from "./boundary.mjs";
const $ = (id) => document.getElementById(id);
let boundary;
let currentSnapshot;
function render(snapshot) {
  currentSnapshot = snapshot;
  const { pending, state, events, approval } = snapshot;
  $("proposal").textContent =
    pending?.body ??
    "Ask a compatible WebMCP host to propose a sandbox note, or use the local harness below.";
  $("target").textContent = pending
    ? pending.action +
      " → " +
      pending.recipient +
      " · revision " +
      pending.expectedRevision
    : "";
  $("note").textContent = state.note + " / Inventory: " + state.inventoryNote;
  $("revision").textContent = "Revision " + state.revision;
  const event = events.at(-1);
  $("origin").textContent = event?.origin?.startsWith("native_")
    ? "WebMCP callback (identity unverified)"
    : event?.origin === "trusted_dom_activation"
      ? "Trusted DOM activation"
      : event
        ? "Explicit local harness"
        : "No request yet";
  $("result").textContent = snapshot.logLimitReached
    ? "Session event limit reached. Export the receipt, then reload to start a fresh demo."
    : approval === "approved_once" && !event?.data.reason
      ? "Approved once · expires in " +
        Math.max(0, Math.ceil((snapshot.expiresAt - Date.now()) / 1000)) +
        "s"
      : event
        ? (event.data.reason ?? event.data.status).replaceAll("_", " ")
        : "No approval has been granted.";
  $("stage").disabled = snapshot.logLimitReached;
  $("confirm").disabled =
    snapshot.logLimitReached || !pending || approval !== "not_approved";
  $("apply").disabled =
    snapshot.logLimitReached || approval !== "approved_once";
  $("mutate").disabled = snapshot.logLimitReached || !pending;
  if (pending) boundary.bindApproval($("confirm"), pending.nonce);
}
boundary = new SwanBoundary({ notify: render });
const host = registerNativeTools(document, boundary);
$("host-status").textContent = host.status;
$("stage").onclick = () =>
  boundary.stage({
    action: "save_note",
    body: "The blue notebook is on the second shelf.",
    recipient: "sandbox-notebook",
    expectedRevision: boundary.snapshot().state.revision,
  });
$("apply").onclick = () => boundary.apply(boundary.snapshot().pending);
$("mutate").onclick = () =>
  boundary.apply({
    ...boundary.snapshot().pending,
    body: "Changed after approval: orange notebook.",
  });
$("download").onclick = () => {
  const receipt = {
    ...boundary.snapshot(),
    chainValid: boundary.verify(),
    host,
    attested: false,
    limitation:
      "Local hash-chain consistency, no pinned identity or durable storage. API presence is not proof of a Meta call.",
  };
  const a = document.createElement("a");
  a.href = URL.createObjectURL(
    new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" }),
  );
  a.download = "swan-native-receipt.json";
  a.click();
  URL.revokeObjectURL(a.href);
};
document.addEventListener("keydown", (e) => {
  if (!["ArrowDown", "ArrowRight", "ArrowUp", "ArrowLeft"].includes(e.key))
    return;
  const controls = [...document.querySelectorAll("button:not(:disabled),a")];
  const i = controls.indexOf(document.activeElement);
  const step = ["ArrowDown", "ArrowRight"].includes(e.key) ? 1 : -1;
  controls[(i + step + controls.length) % controls.length]?.focus();
  e.preventDefault();
});
render(boundary.snapshot());

setInterval(() => {
  if (
    currentSnapshot?.approval === "approved_once" &&
    !currentSnapshot.logLimitReached
  )
    render(boundary.refresh());
}, 200);
