(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const state = {
    cases: [],
    selectedTrace: null,
    importedText: null,
    report: null,
    generation: 0,
    controller: null,
  };
  const types = new Set([
    "connected",
    "disconnected",
    "permission",
    "session_started",
    "session_stopped",
    "capture",
    "approval",
    "action",
  ]);

  function error(message = "") {
    $("error-message").textContent = message;
    $("error-message").hidden = !message;
  }
  function clearReport() {
    state.report = null;
    $("report-content").hidden = true;
    $("report-empty").hidden = false;
    $("report-empty").textContent = "Run a review to see policy findings.";
    $("finding-list").replaceChildren();
    $("report-summary").replaceChildren();
    $("limitation-list").replaceChildren();
    $("report-message").textContent = "";
    $("download-json").disabled = true;
    $("download-sarif").disabled = true;
  }
  function invalidate(message = "Input changed. Run a new review.") {
    state.generation += 1;
    state.controller?.abort();
    state.controller = null;
    clearReport();
    $("input-status").textContent = message;
    error();
  }
  function eventName(event) {
    const labels = {
      connected: "Device connected",
      disconnected: "Device disconnected",
      permission: "Permission changed",
      session_started: "Session started",
      session_stopped: "Session stopped",
      capture: "Capture metadata",
      approval: "Approval metadata",
      action: "Action metadata",
    };
    return types.has(event?.type) ? labels[event.type] : "Unrecognized event";
  }
  function eventSummary(event) {
    if (!event || typeof event !== "object")
      return "Event details are not shown.";
    if (event.type === "permission") {
      const cap = ["camera", "microphone"].includes(event.capability)
        ? event.capability
        : "sensor";
      const status = ["granted", "revoked"].includes(event.status)
        ? event.status
        : "changed";
      return (
        cap[0].toUpperCase() + cap.slice(1) + " permission " + status + "."
      );
    }
    if (event.type === "capture") {
      const channel = ["camera", "microphone", "ocr", "qr"].includes(
        event.channel,
      )
        ? event.channel.toUpperCase()
        : "SENSOR";
      return "Declared " + channel + " capture.";
    }
    if (event.type === "action") {
      const op = ["local_note", "external_send", "persist_memory"].includes(
        event.operation,
      )
        ? event.operation.replaceAll("_", " ")
        : "action";
      const dest = ["local", "external"].includes(event.destination)
        ? event.destination
        : "unknown";
      return "Claimed " + op + " to " + dest + ".";
    }
    if (event.type === "approval") return "Approval metadata supplied.";
    if (event.type === "connected" || event.type === "disconnected")
      return "Connection metadata supplied.";
    if (event.type === "session_started" || event.type === "session_stopped")
      return "Session metadata supplied.";
    return "Event details are not shown.";
  }
  function renderTimeline(trace) {
    const body = $("event-rows");
    body.replaceChildren();
    const events =
      Array.isArray(trace?.events) && trace.events.length <= 5000
        ? trace.events
        : [];
    $("event-count").textContent = events.length
      ? events.length + (events.length === 1 ? " event" : " events")
      : "No events";
    $("timeline-empty").hidden = events.length > 0;
    events.forEach((event, index) => {
      const row = document.createElement("tr");
      const time = document.createElement("td");
      const name = document.createElement("td");
      const summary = document.createElement("td");
      time.textContent =
        Number.isSafeInteger(event?.t_ms) && event.t_ms >= 0
          ? event.t_ms + " ms"
          : "Unavailable";
      name.textContent = index + 1 + ". " + eventName(event);
      summary.textContent = eventSummary(event);
      row.append(time, name, summary);
      body.append(row);
    });
  }
  function showTrace(trace, label) {
    renderTimeline(trace);
    $("source-kind").textContent = label;
    $("review-button").disabled = !trace && !state.importedText;
  }
  function text(parent, tag, value, className) {
    const node = document.createElement(tag);
    node.textContent = String(value ?? "");
    if (className) node.className = className;
    parent.append(node);
    return node;
  }
  function renderReport(report) {
    state.report = report;
    const summary = report.summary || {};
    const dl = $("report-summary");
    dl.replaceChildren();
    for (const [label, value] of [
      ["Events", summary.events],
      ["Findings", summary.findings],
      ["Errors", summary.errors],
      ["Warnings", summary.warnings],
    ]) {
      const pair = document.createElement("div");
      text(pair, "dt", label);
      text(pair, "dd", Number.isInteger(value) ? value : "Unavailable");
      dl.append(pair);
    }
    $("report-message").textContent =
      report.evidence_kind === "synthetic"
        ? "Synthetic trace. Findings compare declared events with the modeled policy."
        : "Recorded trace. Findings compare declared events with the modeled policy.";
    const list = $("finding-list");
    list.replaceChildren();
    const findings = Array.isArray(report.findings) ? report.findings : [];
    if (!findings.length)
      text(
        list,
        "li",
        "No policy findings in this trace. A clean report does not prove device behavior or safety.",
      );
    findings.forEach((finding) => {
      const li = document.createElement("li");
      const heading = document.createElement("div");
      heading.className = "finding-heading";
      const severity = ["error", "warning"].includes(finding.severity)
        ? finding.severity
        : "";
      text(
        heading,
        "span",
        String(finding.severity || "finding").toUpperCase(),
        "finding-severity " + severity,
      );
      text(heading, "code", finding.rule_id || "Rule");
      const i = Number.isInteger(finding.event_index)
        ? finding.event_index
        : null;
      const ev = i !== null ? state.selectedTrace?.events?.[i] : null;
      const loc =
        i === null
          ? "Trace-level finding"
          : "Event " +
            (i + 1) +
            (Number.isSafeInteger(ev?.t_ms) ? " · " + ev.t_ms + " ms" : "");
      text(heading, "span", loc, "finding-location");
      li.append(heading);
      text(li, "p", finding.message || "The trace violates a modeled rule.");
      text(
        li,
        "p",
        "Recommendation: " +
          (finding.recommendation || "Review the trace and its source."),
        "recommendation",
      );
      list.append(li);
    });
    const limits = $("limitation-list");
    limits.replaceChildren();
    (Array.isArray(report.limitations) ? report.limitations : []).forEach(
      (item) => text(limits, "li", item),
    );
    $("report-empty").hidden = true;
    $("report-content").hidden = false;
    $("download-json").disabled = false;
    $("download-sarif").disabled = false;
  }
  function saveFile(name, data) {
    const url = URL.createObjectURL(
      new Blob([data], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function loadCases() {
    const select = $("case-select");
    try {
      const response = await fetch("/api/wearables/cases", {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      state.cases = Array.isArray(payload.cases) ? payload.cases : [];
      select.replaceChildren();
      if (!state.cases.length) {
        const option = document.createElement("option");
        option.value = "";
        option.textContent = "No curated examples available";
        select.append(option);
        select.disabled = true;
        $("case-description").textContent =
          "Import a JSON trace when an example is not available.";
        $("input-status").textContent = "No curated trace loaded.";
        return;
      }
      state.cases.forEach((item) => {
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = item.title;
        select.append(option);
      });
      const preferred =
        state.cases.find((item) => item.id === "safe-local") ||
        state.cases.find(
          (item) =>
            /^(safe|benign)\b/i.test(item.title) &&
            item.trace?.events?.some(
              (ev) => ev?.type === "action" && ev.operation === "local_note",
            ),
        ) ||
        state.cases.find((item) =>
          item.trace?.events?.some(
            (ev) => ev?.type === "action" && ev.operation === "local_note",
          ),
        ) ||
        state.cases[0];
      select.value = preferred.id;
      select.disabled = false;
      state.selectedTrace = preferred.trace;
      $("case-description").textContent = preferred.description;
      $("input-status").textContent = "Ready for local review.";
      showTrace(
        preferred.trace,
        preferred.evidence_kind === "synthetic"
          ? "Synthetic example"
          : "Recorded example",
      );
    } catch {
      select.replaceChildren();
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "Examples unavailable";
      select.append(option);
      select.disabled = true;
      $("case-description").textContent =
        "Import a JSON trace or check the local service.";
      $("input-status").textContent = "Curated examples could not be loaded.";
      error("The local example list could not be loaded.");
    }
  }
  async function reviewTrace() {
    const body =
      state.importedText ??
      (state.selectedTrace ? JSON.stringify(state.selectedTrace) : "");
    if (!body) {
      error("Choose a curated trace or open a JSON file first.");
      return;
    }
    invalidate("Reviewing supplied metadata…");
    const id = state.generation;
    const controller = new AbortController();
    state.controller = controller;
    $("review-button").disabled = true;
    try {
      const response = await fetch("/api/wearables/audit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body,
        signal: controller.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (id !== state.generation) return;
      if (!response.ok) {
        const messages = {
          400: "The request could not be read.",
          411: "The local service requires a bounded body.",
          413: "The trace is larger than 2 MiB.",
          415: "Choose a JSON trace.",
          422: "The trace does not match the supported schema.",
          503: "The trace auditor is not available yet.",
        };
        throw new Error(
          messages[response.status] || "The local review failed.",
        );
      }
      state.selectedTrace = JSON.parse(body);
      renderTimeline(state.selectedTrace);
      renderReport(payload);
      $("input-status").textContent =
        "Review complete. This checks supplied metadata against a policy.";
    } catch (e) {
      if (e.name === "AbortError" || id !== state.generation) return;
      clearReport();
      error(e.message || "The local review failed.");
      $("input-status").textContent = "Review did not complete.";
    } finally {
      if (id === state.generation) {
        state.controller = null;
        $("review-button").disabled =
          !state.selectedTrace && !state.importedText;
      }
    }
  }
  function fileChanged() {
    invalidate();
    const file = $("trace-file").files?.[0];
    if (!file) {
      $("case-select").disabled = state.cases.length === 0;
      state.importedText = null;
      const item = state.cases.find(
        (entry) => entry.id === $("case-select").value,
      );
      state.selectedTrace = item?.trace || null;
      if (item) {
        $("case-description").textContent = item.description;
        showTrace(
          item.trace,
          item.evidence_kind === "synthetic"
            ? "Synthetic example"
            : "Recorded example",
        );
      }
      return;
    }
    $("case-select").disabled = true;
    state.selectedTrace = null;
    state.importedText = null;
    showTrace(null, "Imported trace");
    $("review-button").disabled = true;
    if (file.size > 2 * 1024 * 1024) {
      state.importedText = null;
      state.selectedTrace = null;
      showTrace(null, "Imported trace");
      error("This file is larger than 2 MiB.");
      $("input-status").textContent = "Choose a smaller JSON file.";
      return;
    }
    const reader = new FileReader();
    const readId = state.generation;
    reader.onload = () => {
      if (readId !== state.generation) return;
      state.importedText = String(reader.result || "");
      try {
        const preview = JSON.parse(state.importedText);
        state.selectedTrace =
          preview && Array.isArray(preview.events) ? preview : null;
      } catch {
        state.selectedTrace = null;
      }
      showTrace(state.selectedTrace, "Imported trace");
      $("case-description").textContent = state.selectedTrace
        ? "This file stays in your browser until you start a review, then goes only to the local service."
        : "The file loaded. The local service will check its JSON and trace schema.";
      $("input-status").textContent = "File ready for local review.";
      error();
    };
    reader.onerror = () => {
      if (readId !== state.generation) return;
      state.importedText = null;
      state.selectedTrace = null;
      showTrace(null, "Imported trace");
      error("The selected file could not be read.");
    };
    reader.readAsText(file);
  }
  function caseChanged() {
    invalidate();
    state.importedText = null;
    $("trace-file").value = "";
    const item = state.cases.find(
      (entry) => entry.id === $("case-select").value,
    );
    state.selectedTrace = item?.trace || null;
    $("case-description").textContent =
      item?.description || "Choose an example.";
    showTrace(
      item?.trace || null,
      item?.evidence_kind === "synthetic"
        ? "Synthetic example"
        : "Recorded example",
    );
  }
  async function downloadSarif() {
    if (!state.report) return;
    const body = state.importedText ?? JSON.stringify(state.selectedTrace);
    const id = ++state.generation;
    state.controller?.abort();
    const controller = new AbortController();
    state.controller = controller;
    $("download-sarif").disabled = true;
    error();
    try {
      const response = await fetch("/api/wearables/sarif", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body,
        signal: controller.signal,
      });
      const payload = await response.json().catch(() => ({}));
      if (id !== state.generation) return;
      if (!response.ok) throw new Error("SARIF export could not be created.");
      saveFile(
        "swan-wearable-review.sarif.json",
        JSON.stringify(payload, null, 2),
      );
    } catch (e) {
      if (e.name !== "AbortError" && id === state.generation)
        error(e.message || "SARIF export could not be created.");
    } finally {
      if (id === state.generation) {
        state.controller = null;
        $("download-sarif").disabled = !state.report;
      }
    }
  }
  $("case-select").addEventListener("change", caseChanged);
  $("trace-file").addEventListener("change", fileChanged);
  $("review-button").addEventListener("click", reviewTrace);
  $("download-json").addEventListener("click", () => {
    if (state.report)
      saveFile(
        "swan-wearable-review.json",
        JSON.stringify(state.report, null, 2),
      );
  });
  $("download-sarif").addEventListener("click", downloadSarif);
  loadCases();
})();
