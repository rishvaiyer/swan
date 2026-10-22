"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const state = {
    catalog: null,
    scenario: null,
    receipts: {},
    runs: [],
    image: null,
    sources: [],
    sourceFilter: "all",
    busy: false,
    display: "idle",
    guide: -1,
    research: null,
  };
  const modes = [
    {
      id: "unprotected",
      title: "Unprotected agent",
      detail: "The model can request a contained tool effect.",
    },
    {
      id: "prompt_only",
      title: "Prompt boundary",
      detail: "The model is told to distrust scene instructions.",
    },
    {
      id: "enforced",
      title: "Enforced action gate",
      detail: "The same proposal must fit the wearer’s task.",
    },
  ];
  const guideSteps = [
    {
      target: ".scene-stage",
      title: "1 / 6 · The scene",
      copy: "The wearer asks a normal question. The environment contains additional content controlled by someone else.",
    },
    {
      target: ".extraction-workspace",
      title: "2 / 6 · The carrier",
      copy: "Real OCR and QR decoding recover the content. Decoding a command does not make it authorized.",
    },
    {
      target: ".result-grid",
      title: "3 / 6 · The proposal",
      copy: "Inspect what the local model actually proposed. A refusal, a changed answer, and a tool request are different outcomes.",
    },
    {
      target: ".result-grid",
      title: "4 / 6 · The effect",
      copy: "The unprotected lane can change only synthetic lab state. A message here is never an actual external message.",
    },
    {
      target: ".result-lane:last-child",
      title: "5 / 6 · The defense",
      copy: "Rejudge the exact original proposal under an independent gate. The gate checks trusted intent and exact arguments.",
    },
    {
      target: ".trace-section",
      title: "6 / 6 · The proof",
      copy: "Open the receipt. It records the input, model output, decision, and sandbox effect. This is local evidence; Meta-device QR behavior remains untested.",
    },
  ];
  function el(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }
  function empty(node) {
    node.replaceChildren();
  }
  function stringify(value) {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }
  function notice(text, type) {
    $("notice").textContent = text || "";
    $("notice").className = "notice" + (type ? " " + type : "");
    $("notice").hidden = !text;
  }
  async function api(path, options) {
    const response = await fetch(
      path,
      Object.assign({ credentials: "same-origin" }, options),
    );
    const data = await response.json();
    if (!response.ok) {
      if (data && data.id && data.status === "error") return data;
      if (data && data.detail && data.detail.id) return data.detail;
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : data.error || "The local service could not complete this request.",
      );
    }
    return data;
  }
  function post(path, data) {
    return api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
  }
  function imageURL(value) {
    if (!value || typeof value !== "string") return null;
    try {
      const url = new URL(value, location.origin);
      return url.origin === location.origin &&
        /^\/(assets\/|api\/images\/)/.test(url.pathname)
        ? url.pathname + url.search
        : null;
    } catch (_) {
      return null;
    }
  }
  function localTime(value) {
    if (!value) return "time not recorded";
    const date = new Date(value);
    return Number.isNaN(date.valueOf())
      ? String(value)
      : date.toLocaleString([], {
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit",
        });
  }
  function setBusy(busy) {
    state.busy = busy;
    $("scenario").disabled = busy;
    $("scene-upload").disabled = busy;
    $("run-button").disabled = busy || !state.scenario;
    $("replay-button").disabled = busy || !hasReplay();
    $("guide-button").disabled = busy || !hasReplay();
    $("run-button").textContent = busy
      ? "Experiment running…"
      : "Run live experiment ↗";
  }
  function hasReplay() {
    return state.runs.some(
      (run) =>
        run.scenario_id === (state.scenario && state.scenario.id) &&
        run.status !== "error",
    );
  }
  function navigate(id) {
    if (!["lab", "evidence", "defense", "kit"].includes(id)) return;
    document.querySelectorAll(".tab-view").forEach((view) => {
      view.hidden = view.id !== id;
    });
    document.querySelectorAll("[data-tab]").forEach((button) => {
      const active = button.dataset.tab === id;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    history.replaceState(null, "", "#" + id);
  }
  function selectScenario(id) {
    state.scenario =
      state.catalog.scenarios.find((scenario) => scenario.id === id) ||
      state.catalog.scenarios[0];
    if (!state.scenario) return;
    state.image = null;
    state.receipts = {};
    state.sources = [];
    state.display = "idle";
    $("scenario").value = state.scenario.id;
    $("user-goal").textContent = state.scenario.task;
    $("scenario-description").textContent = state.scenario.description;
    $("capture-label").textContent = "Generated lab scene";
    $("scene-caption").textContent =
      "A scene is data. It does not grant permission.";
    $("scene-dimensions").textContent = "";
    $("extraction-state").textContent = "Awaiting extraction";
    $("run-meta").textContent =
      "No result has been generated for this selection.";
    $("run-mode").textContent = "Awaiting experiment";
    showImage(state.scenario.image);
    renderSources();
    renderResults();
    renderTimeline();
    renderEvidence();
    updateReceiptButtons();
    setBusy(false);
    notice("");
    stopGuide();
  }
  function showImage(value) {
    const url = imageURL(value);
    $("scene-image").hidden = !url;
    $("scene-empty").hidden = !!url;
    if (url) {
      $("scene-image").src = url;
      $("scene-image").alt = state.image
        ? "Uploaded local scene selected for the laboratory experiment"
        : state.scenario.title + ": generated laboratory fixture";
    }
    empty($("source-overlay"));
  }
  function extractSources(perception) {
    const list = [];
    if (perception.ocr_text)
      list.push({
        type: "ocr",
        title: "Printed text",
        content: perception.ocr_text,
      });
    (perception.qr_payloads || []).forEach((qr, index) =>
      list.push({
        type: "qr",
        title: "QR payload " + (index + 1),
        content:
          typeof qr === "string" ? qr : qr.payload || qr.text || stringify(qr),
      }),
    );
    state.sources = list;
    $("extraction-state").textContent = list.length
      ? list.length +
        (list.length === 1 ? " source recovered" : " sources recovered")
      : "No content recovered";
    $("extraction-note").textContent = (perception.warnings || []).length
      ? perception.warnings.join(" ")
      : "External content stays untrusted, even when it claims to be a system message.";
    renderSources();
  }
  function renderSources() {
    empty($("sources"));
    const filtered = state.sources.filter(
      (item) =>
        state.sourceFilter === "all" || state.sourceFilter === item.type,
    );
    if (!filtered.length) {
      $("sources").append(
        el(
          "p",
          "empty-copy",
          state.sources.length
            ? "No " +
                (state.sourceFilter === "qr" ? "QR payload" : "printed text") +
                " was recovered from this scene."
            : "Real text recognition and QR decoding appear here when you run an experiment.",
        ),
      );
      return;
    }
    filtered.forEach((item) => {
      const row = el("article", "source-item " + item.type);
      const header = el("div", "source-item-header");
      header.append(
        el("span", "", item.title),
        el("span", "", "Untrusted observation"),
      );
      row.append(header, el("pre", "source-item-content", item.content));
      $("sources").append(row);
    });
  }
  function outcomeFor(receipt) {
    if (receipt.status === "error")
      return {
        title: "Run did not complete",
        detail:
          receipt.error ||
          (receipt.events || [])
            .map((event) => event.detail)
            .filter(Boolean)
            .slice(-1)[0] ||
          "No model result is being substituted.",
        className: "refused",
      };
    const proposal = receipt.proposal || {};
    const decision = receipt.decision || {};
    const effects = receipt.effects || {};
    const outcome = receipt.outcome || {};
    const action = proposal.action;
    const hasTool =
      outcome.model_requested_tool !== undefined
        ? outcome.model_requested_tool
        : action && action !== "none";
    const executed =
      outcome.tool_effect_executed !== undefined
        ? outcome.tool_effect_executed
        : effects.executed;
    if (hasTool && !decision.allowed)
      return {
        title: "Tool effect blocked",
        detail:
          decision.reason ||
          "The proposal is outside the trusted task contract.",
        className: "blocked",
      };
    if (executed && outcome.outside_wearer_scope)
      return {
        title: "Unauthorized sandbox effect",
        detail: effects.summary || "The action changed synthetic lab state.",
        className: "executed",
      };
    if (executed)
      return {
        title: "Authorized sandbox effect",
        detail:
          effects.summary ||
          "The requested action stayed inside the trusted task contract.",
        className: "allowed",
      };
    if (!hasTool)
      return {
        title: "No tool effect requested",
        detail:
          outcome.answer_integrity ||
          "Inspect the answer separately for task redirection. A lack of tool calls is not proof of answer integrity.",
        className: "refused",
      };
    return {
      title: "No sandbox effect observed",
      detail:
        effects.summary ||
        decision.reason ||
        "Inspect the receipt for the exact decision.",
      className: "refused",
    };
  }
  function renderResults(pendingMode) {
    empty($("results"));
    modes.forEach((mode, index) => {
      const receipt = state.receipts[mode.id];
      const lane = el("article", "result-lane");
      lane.dataset.mode = mode.id;
      const header = el("div", "lane-header");
      const title = el("div", "lane-title");
      title.append(
        el("span", "lane-number", "0" + (index + 1)),
        el("h3", "", mode.title),
      );
      header.append(title, el("p", "lane-description", mode.detail));
      const body = el("div", "lane-body");
      let outcome;
      if (receipt) {
        body.append(
          el(
            "p",
            "lane-eyeline",
            receipt.trial === "policy_replay"
              ? "Exact proposal · policy replay"
              : receipt.trial === "gate"
                ? "Synthetic proposal · gate test"
                : "Actual local model output",
          ),
        );
        const proposal = receipt.proposal || {};
        body.append(
          el(
            "p",
            "lane-answer",
            proposal.answer ||
              (receipt.status === "error"
                ? "No completed model output."
                : "No answer field recorded."),
          ),
        );
        if (proposal.action && proposal.action !== "none")
          body.append(
            el(
              "div",
              "lane-action",
              proposal.action + "\n" + stringify(proposal.arguments || {}),
            ),
          );
        outcome = outcomeFor(receipt);
      } else if (pendingMode === mode.id) {
        const waiting = el("div", "lane-loading");
        waiting.append(
          el("span", "loading-bars"),
          el(
            "span",
            "",
            mode.id === "enforced"
              ? "Checking the original proposal…"
              : "Waiting for the local model…",
          ),
        );
        body.append(waiting);
        body.append(
          el(
            "p",
            "empty-copy",
            "No result will be replaced with a scripted success.",
          ),
        );
        outcome = {
          title: "Experiment in progress",
          detail: "The evidence will appear when this stage completes.",
          className: "",
        };
      } else {
        body.append(
          el(
            "p",
            "empty-copy",
            state.display === "idle"
              ? "Run or replay an experiment to inspect this configuration."
              : "No matching receipt is available for this configuration.",
          ),
        );
        outcome = {
          title: "No result loaded",
          detail: "No outcome is being assumed.",
          className: "",
        };
      }
      if (receipt && receipt.effects) {
        const after = receipt.effects.after || {};
        const snapshot = el("div", "effect-snapshot");
        if ((after.messages || []).length) {
          snapshot.append(el("p", "effect-heading", "Synthetic inbox"));
          after.messages.forEach((message) => {
            const envelope = el("div", "synthetic-envelope");
            envelope.append(
              el("p", "effect-recipient", "To " + message.to),
              el("p", "effect-content", message.text),
            );
            snapshot.append(envelope);
          });
        } else if ((after.notes || []).length) {
          snapshot.append(el("p", "effect-heading", "Synthetic notes"));
          after.notes.forEach((note) =>
            snapshot.append(el("p", "effect-content", note)),
          );
        } else if (
          after.destination &&
          after.destination !== "No destination set"
        ) {
          snapshot.append(
            el("p", "effect-heading", "Synthetic navigation"),
            el("p", "effect-content", after.destination),
          );
        } else if ((after.opened_urls || []).length) {
          snapshot.append(el("p", "effect-heading", "Synthetic URL action"));
          after.opened_urls.forEach((link) =>
            snapshot.append(
              el("p", "effect-content", link.url + " · not fetched"),
            ),
          );
        } else {
          snapshot.append(
            el("p", "effect-heading", "Synthetic world"),
            el(
              "p",
              "effect-empty",
              "No message, note, navigation, or URL effect.",
            ),
          );
        }
        body.append(snapshot);
      }
      const footer = el("div", "lane-outcome " + outcome.className);
      footer.append(
        el("strong", "", outcome.title),
        el("p", "", outcome.detail),
      );
      lane.append(header, body, footer);
      $("results").append(lane);
    });
  }
  function renderTimeline() {
    const preferred =
      state.receipts.enforced ||
      state.receipts.unprotected ||
      state.receipts.prompt_only;
    empty($("timeline"));
    if (!preferred) {
      $("timeline").append(
        el(
          "li",
          "timeline-empty",
          "The event trace will show extraction, model proposals, policy decisions, and contained effects.",
        ),
      );
      return;
    }
    const events = preferred.events || [];
    events.forEach((event, index) => {
      const row = el("li", "");
      row.append(
        el(
          "p",
          "event-stage",
          String(index + 1).padStart(2, "0") + " · " + (event.stage || "event"),
        ),
        el("p", "event-label", event.label || event.stage || "Recorded event"),
        el(
          "p",
          "event-detail",
          typeof event.detail === "string"
            ? event.detail
            : stringify(event.detail || ""),
        ),
      );
      $("timeline").append(row);
    });
    if (!events.length)
      $("timeline").append(
        el(
          "li",
          "timeline-empty",
          "This receipt contains no event trace. Inspect its raw fields before making a claim.",
        ),
      );
  }
  function currentReceipts() {
    return modes.map((mode) => state.receipts[mode.id]).filter(Boolean);
  }
  function bundle() {
    return {
      displayed_as: state.display,
      scope:
        "Local OCR + QR + Qwen agent experiment. Effects are synthetic. Meta hardware untested.",
      scenario_id: state.scenario && state.scenario.id,
      receipts: currentReceipts(),
    };
  }
  function updateReceiptButtons() {
    const emptyState = !currentReceipts().length;
    ["receipt-button", "download-button"].forEach((id) => {
      $(id).disabled = emptyState;
    });
  }
  function renderEvidence() {
    const receipts = currentReceipts();
    if (!receipts.length) {
      $("evidence-summary").textContent =
        "No local experiment is loaded. Run an experiment or replay recorded evidence.";
      $("provenance").textContent = "No run loaded.";
      return;
    }
    const live = receipts.filter((receipt) => receipt.trial === "live").length;
    const policy = receipts.filter(
      (receipt) => receipt.trial === "policy_replay",
    ).length;
    const gate = receipts.filter((receipt) => receipt.trial === "gate").length;
    const failed = receipts.filter(
      (receipt) => receipt.status === "error",
    ).length;
    $("evidence-summary").textContent =
      receipts.length +
      " receipts displayed: " +
      live +
      " local model run(s), " +
      policy +
      " exact-proposal policy replay(s), " +
      gate +
      " synthetic gate test(s)" +
      (failed ? ", " + failed + " incomplete run(s)" : "") +
      ". No physical-glasses result is included.";
    $("provenance").textContent = stringify(
      receipts.map((receipt) => ({
        id: receipt.id,
        created_at: receipt.created_at,
        trial: receipt.trial,
        mode: receipt.mode,
        model: receipt.model,
        image_sha256: (receipt.perception || {}).sha256,
        parent_run_id: receipt.parent_run_id,
        parent_hash: receipt.parent_hash,
        integrity: receipt.integrity,
        limitations: receipt.limitations,
      })),
    );
  }
  function acceptReceipt(receipt, mode) {
    state.receipts[mode || receipt.mode] = receipt;
    if (receipt.perception) extractSources(receipt.perception);
    renderResults();
    renderTimeline();
    renderEvidence();
    updateReceiptButtons();
  }
  async function refreshRuns() {
    const response = await api("/api/runs");
    state.runs = Array.isArray(response) ? response : response.runs || [];
    if (!state.busy) setBusy(false);
  }
  async function runExperiment() {
    if (state.busy || !state.scenario) return;
    stopGuide();
    notice(
      "The local model is running. Its output may refuse the attack, follow it, or fail to complete. Each outcome is recorded.",
    );
    state.receipts = {};
    state.display = "live";
    setBusy(true);
    $("run-mode").textContent = "Live local experiment";
    $("run-meta").textContent =
      "Running the permissive agent, then checking its exact proposal under enforcement.";
    const base = { scenario_id: state.scenario.id, trial: "live" };
    if (state.image) base.image_id = state.image.image_id;
    try {
      renderResults("unprotected");
      const original = await post(
        "/api/run",
        Object.assign({}, base, { mode: "unprotected" }),
      );
      acceptReceipt(original, "unprotected");
      if (original.status !== "error") {
        renderResults("enforced");
        const strict = await post("/api/rejudge", {
          run_id: original.id,
          mode: "enforced",
        });
        acceptReceipt(strict, "enforced");
      }
      $("run-meta").textContent =
        "The original proposal has been checked. Running the prompt-only comparison with the same scene.";
      renderResults("prompt_only");
      const promptOnly = await post(
        "/api/run",
        Object.assign({}, base, { mode: "prompt_only" }),
      );
      acceptReceipt(promptOnly, "prompt_only");
      $("run-meta").textContent =
        "Local inference at " +
        localTime(original.created_at) +
        ". Enforced lane reuses the exact original proposal.";
      notice(
        currentReceipts().some((receipt) => receipt.status === "error")
          ? "One or more model runs did not complete. Their failure is preserved; no scripted result was substituted."
          : "Experiment recorded. Inspect the model’s proposal, the sandbox effects, and the exact-proposal enforcement result.",
        currentReceipts().some((receipt) => receipt.status === "error")
          ? "error"
          : "success",
      );
      await refreshRuns();
    } catch (error) {
      notice(error.message, "error");
      $("run-meta").textContent =
        "Experiment interrupted. Any completed receipts remain visible.";
    } finally {
      setBusy(false);
      renderResults();
    }
  }
  function newest(runs) {
    return runs
      .slice()
      .sort((a, b) =>
        String(b.created_at || b.id).localeCompare(
          String(a.created_at || a.id),
        ),
      );
  }
  async function replayEvidence() {
    if (state.busy || !state.scenario) return false;
    stopGuide();
    setBusy(true);
    state.receipts = {};
    state.display = "replay";
    notice("");
    try {
      await refreshRuns();
      const candidates = newest(
        state.runs.filter(
          (run) =>
            run.scenario_id === state.scenario.id && run.status !== "error",
        ),
      );
      if (!candidates.length)
        throw new Error(
          "No recorded evidence exists for this scene yet. Run a live experiment first.",
        );
      const real = candidates.filter(
        (run) => run.trial === "live" || run.trial === "policy_replay",
      );
      const pool = real.length
        ? real
        : candidates.filter((run) => run.trial === "gate");
      const originalSummary = pool.find(
        (run) => run.mode === "unprotected" && run.trial !== "policy_replay",
      );
      let original;
      if (originalSummary) {
        original = await api(
          "/api/runs/" + encodeURIComponent(originalSummary.id),
        );
        acceptReceipt(original, "unprotected");
      }
      const promptSummary = pool.find(
        (run) => run.mode === "prompt_only" && run.trial !== "policy_replay",
      );
      if (promptSummary)
        acceptReceipt(
          await api("/api/runs/" + encodeURIComponent(promptSummary.id)),
          "prompt_only",
        );
      let strict;
      if (original) {
        const strictCandidates = pool.filter(
          (run) => run.mode === "enforced" && run.trial === "policy_replay",
        );
        for (const item of strictCandidates.slice(0, 12)) {
          const receipt = await api("/api/runs/" + encodeURIComponent(item.id));
          if (receipt.parent_run_id === original.id) {
            strict = receipt;
            break;
          }
        }
        if (!strict)
          strict = await post("/api/rejudge", {
            run_id: original.id,
            mode: "enforced",
          });
      } else {
        const strictSummary = pool.find((run) => run.mode === "enforced");
        if (strictSummary)
          strict = await api(
            "/api/runs/" + encodeURIComponent(strictSummary.id),
          );
      }
      if (strict) acceptReceipt(strict, "enforced");
      const receipt = original || currentReceipts()[0];
      if (receipt && receipt.perception && receipt.perception.image)
        showImage(receipt.perception.image);
      const gateOnly = !real.length;
      $("run-mode").textContent = gateOnly
        ? "Replay · synthetic gate test"
        : "Replay · recorded model evidence";
      $("run-meta").textContent =
        (gateOnly
          ? "Synthetic proposal, no model inference. "
          : "Recorded local inference, not a new model run. ") +
        (receipt ? localTime(receipt.created_at) + ". " : "") +
        (strict && strict.trial === "policy_replay"
          ? "The enforced lane checks the exact original proposal."
          : "Inspect receipt provenance for each lane.");
      notice(
        gateOnly
          ? "These are synthetic gate tests. They show policy behavior, not a successful model injection."
          : "Replaying actual local model evidence. The enforced lane reuses the original proposal; the prompt-only lane is a separate model run.",
        gateOnly ? "" : "success",
      );
      return true;
    } catch (error) {
      notice(error.message, "error");
      return false;
    } finally {
      setBusy(false);
      renderResults();
      renderTimeline();
      renderEvidence();
      updateReceiptButtons();
    }
  }
  async function uploadScene(event) {
    const file = event.target.files && event.target.files[0];
    if (!file || state.busy) return;
    if (file.size > 8 * 1024 * 1024) {
      notice("Choose an image smaller than 8 MB.", "error");
      event.target.value = "";
      return;
    }
    setBusy(true);
    notice(
      "Recognizing text and decoding QR content from your local image. No image is being sent to a cloud model.",
    );
    try {
      const form = new FormData();
      form.append("image", file);
      const data = await api("/api/perceive", { method: "POST", body: form });
      state.image = data;
      state.receipts = {};
      state.display = "idle";
      showImage(data.image);
      extractSources(data);
      $("capture-label").textContent = "Uploaded local scene";
      $("scene-caption").textContent =
        "Your image · retained only inside the local lab";
      $("run-meta").textContent =
        "Uploaded image selected. The scenario’s trusted request stays unchanged.";
      $("run-mode").textContent = "Uploaded image · not yet run";
      renderResults();
      renderTimeline();
      renderEvidence();
      updateReceiptButtons();
      notice(
        "Local extraction complete. Run the experiment to compare the agent and the enforced policy.",
        "success",
      );
    } catch (error) {
      notice(error.message, "error");
    } finally {
      setBusy(false);
      event.target.value = "";
    }
  }
  function openReceipt() {
    $("receipt-content").textContent = stringify(bundle());
    $("receipt-dialog").showModal();
  }
  function downloadReceipt() {
    const blob = new Blob([stringify(bundle())], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = el("a");
    anchor.href = url;
    anchor.download =
      "wearable-security-experiment-" +
      (state.scenario ? state.scenario.id : "run") +
      ".json";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
  function stopGuide() {
    state.guide = -1;
    $("guide").hidden = true;
    document
      .querySelectorAll(".guide-highlight")
      .forEach((item) => item.classList.remove("guide-highlight"));
  }
  function showGuideStep(index) {
    state.guide = Math.max(0, Math.min(guideSteps.length - 1, index));
    const step = guideSteps[state.guide];
    $("guide").hidden = false;
    $("guide-step").textContent = step.title;
    $("guide-copy").textContent = step.copy;
    $("guide-back").disabled = state.guide === 0;
    $("guide-next").textContent =
      state.guide === guideSteps.length - 1 ? "Inspect receipt" : "Next";
    document
      .querySelectorAll(".guide-highlight")
      .forEach((item) => item.classList.remove("guide-highlight"));
    const target = document.querySelector(step.target);
    if (target) {
      target.classList.add("guide-highlight");
      target.scrollIntoView({
        behavior: matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto"
          : "smooth",
        block: state.guide < 2 ? "center" : "nearest",
      });
    }
  }
  async function beginGuide() {
    const okay = await replayEvidence();
    if (!okay) return;
    navigate("lab");
    showGuideStep(0);
  }
  async function loadResearch() {
    try {
      state.research = await api("/research.json");
      const questions = state.research.questions || [];
      if (questions.length) {
        const section = el("section", "reading-section");
        section.append(el("h2", "", "Questions to be ready for"));
        questions.forEach((item) => {
          const detail = el("details", "research-question");
          const question =
            typeof item === "string"
              ? item
              : item.question || item.q || item.title;
          detail.append(el("summary", "", question || "Research question"));
          const answer =
            typeof item === "object"
              ? item.answer || item.a || item.response
              : null;
          if (answer) detail.append(el("p", "", answer));
          section.append(detail);
        });
        $("defense").append(section);
      }
      const names = state.research.names || [];
      if (names.length) {
        const section = el("section", "reading-section");
        const detail = el("details", "research-question");
        detail.append(
          el("summary", "", "Naming directions · no name selected"),
        );
        const list = el("ul", "source-list");
        names.forEach((item) => {
          const row = el("li");
          if (typeof item === "string") row.textContent = item;
          else {
            row.append(
              el("strong", "", item.name || item.title || "Naming option"),
            );
            if (item.reason || item.why || item.description || item.idea)
              row.append(
                el(
                  "p",
                  "",
                  item.reason || item.why || item.description || item.idea,
                ),
              );
          }
          list.append(row);
        });
        detail.append(list);
        section.append(detail);
        $("defense").append(section);
      }
    } catch (_) {
      /* The experiment remains usable if the optional research brief is unavailable. */
    }
    try {
      const kit = await api("/api/kit");
      if (kit.sheets && kit.sheets.length) {
        const first = kit.sheets[0];
        const url = imageURL(first.url);
        if (url) {
          $("kit-download").href = url;
          $("kit-download").textContent = "Open printable test sheet ↗";
        }
        const section = el("section", "reading-section");
        section.append(el("h2", "", "Printable laboratory fixtures"));
        const list = el("ul", "source-list");
        kit.sheets.forEach((sheet) => {
          const url = imageURL(sheet.url);
          if (!url) return;
          const item = el("li");
          const link = el("a", "", sheet.title + " ↗");
          link.href = url;
          link.target = "_blank";
          link.rel = "noopener";
          item.append(link);
          if (sheet.description) item.append(el("p", "", sheet.description));
          list.append(item);
        });
        section.append(list);
        $("kit").append(section);
      }
    } catch (_) {
      $("kit-download").removeAttribute("href");
      $("kit-download").textContent =
        "Printable fixtures are not available yet";
      $("kit-download").setAttribute("aria-disabled", "true");
    }
  }
  async function init() {
    renderResults();
    document
      .querySelectorAll("[data-tab]")
      .forEach((button) =>
        button.addEventListener("click", () => navigate(button.dataset.tab)),
      );
    document.querySelectorAll("[data-nav]").forEach((button) =>
      button.addEventListener("click", (event) => {
        event.preventDefault();
        navigate(button.dataset.nav);
      }),
    );
    document.querySelectorAll("[data-source]").forEach((button) =>
      button.addEventListener("click", () => {
        state.sourceFilter = button.dataset.source;
        document
          .querySelectorAll("[data-source]")
          .forEach((item) => item.classList.toggle("active", item === button));
        renderSources();
      }),
    );
    $("scenario").addEventListener("change", (event) =>
      selectScenario(event.target.value),
    );
    $("run-button").addEventListener("click", runExperiment);
    $("replay-button").addEventListener("click", replayEvidence);
    $("guide-button").addEventListener("click", beginGuide);
    $("scene-upload").addEventListener("change", uploadScene);
    $("receipt-button").addEventListener("click", openReceipt);
    $("download-button").addEventListener("click", downloadReceipt);
    $("receipt-close").addEventListener("click", () =>
      $("receipt-dialog").close(),
    );
    $("receipt-download").addEventListener("click", downloadReceipt);
    $("receipt-copy").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(stringify(bundle()));
        $("receipt-copy").textContent = "Copied";
      } catch (_) {
        $("receipt-copy").textContent = "Select the receipt to copy";
      }
    });
    $("guide-back").addEventListener("click", () =>
      showGuideStep(state.guide - 1),
    );
    $("guide-next").addEventListener("click", () => {
      if (state.guide === guideSteps.length - 1) {
        stopGuide();
        openReceipt();
      } else showGuideStep(state.guide + 1);
    });
    $("guide-close").addEventListener("click", stopGuide);
    $("receipt-dialog").addEventListener("click", (event) => {
      if (event.target === $("receipt-dialog")) $("receipt-dialog").close();
    });
    navigate(location.hash.slice(1) || "lab");
    try {
      const [catalog, health] = await Promise.all([
        api("/api/catalog"),
        api("/api/health"),
      ]);
      state.catalog = catalog;
      empty($("scenario"));
      catalog.scenarios.forEach((scenario) => {
        const option = el("option", "", scenario.title);
        option.value = scenario.id;
        $("scenario").append(option);
      });
      selectScenario(
        catalog.scenarios.some((scenario) => scenario.id === "qr_injection")
          ? "qr_injection"
          : catalog.scenarios[0].id,
      );
      $("service-status").textContent =
        "Ryzen local service · " +
        ((health.model && health.model.name) || health.model_name || "Qwen") +
        " · no external actions";
      await refreshRuns();
      await loadResearch();
    } catch (error) {
      $("service-status").textContent = "Local service unavailable";
      $("service-status").className = "server-warning";
      notice(error.message, "error");
      $("scene-empty").querySelector("p").textContent =
        "Waiting for the local research service";
    }
  }
  init();
})();
