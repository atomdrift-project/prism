(() => {
  const shell = document.querySelector("[data-upload-sha]");
  if (!shell) return;

  const sha = shell.dataset.uploadSha;
  const hasUploadProgress = shell.dataset.uploadProgress === "true";
  const started = Number(shell.dataset.uploadStarted || Date.now());
  const elapsed = document.getElementById("pending-elapsed");
  const phaseLabel = document.getElementById("pending-phase");
  const stateLabel = document.getElementById("pending-state");
  const current = document.getElementById("pending-current");
  const messageLabel = document.getElementById("pending-message");
  const detailLabel = document.getElementById("pending-detail");
  const events = document.getElementById("pending-events");
  const signal = document.getElementById("pending-signal");
  const levelLabel = document.getElementById("pending-level");
  const traitsLabel = document.getElementById("pending-traits");
  const route = document.getElementById("pending-route");
  const serverLabel = document.getElementById("pending-server");
  const requestHostLabel = document.getElementById("pending-request-host");
  let reloaded = false;
  let eventSource;
  let pollingStarted = false;
  let pollTimer;
  let elapsedTimer;

  const logPrefix = "[upload stream]";
  const log = (method, label, value) => {
    const fn = console[method] || console.log;
    fn.call(console, logPrefix, label, value);
  };

  function text(value) {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
  }

  function first(...values) {
    return values.map(text).find(Boolean) || "";
  }

  function parseEventData(event) {
    try {
      return { value: JSON.parse(event.data), raw: event.data };
    } catch (_) {
      return { value: null, raw: event.data };
    }
  }

  function frameSignal(frame) {
    const ml = frame.ml && typeof frame.ml === "object" ? frame.ml : {};
    const level = first(frame.level, ml.level, ml.lvl);
    let severity = first(
      frame.severity,
      frame.classification,
      frame.verdict,
      frame.risk_level,
      ml.severity,
      ml.classification,
      ml.verdict
    );
    // v6/v7 uses lvl:-1 as its explicit benign sentinel and a non-negative
    // level for a hostile reading. Give the live card the same verdict label
    // the completed result will show, even when the stream omits severity.
    if (!severity && level) {
      const numericLevel = Number(level);
      if (numericLevel === -1) severity = "benign";
      else if (Number.isFinite(numericLevel) && numericLevel >= 0) severity = "hostile";
    }
    return {
      level,
      severity,
    };
  }

  function traitText(value) {
    if (typeof value === "string") return value.trim();
    if (!value || typeof value !== "object") return "";
    return first(value.trait, value.name, value.title, value.description, value.desc, value.id);
  }

  function frameTraits(frame) {
    const ml = frame.ml && typeof frame.ml === "object" ? frame.ml : {};
    const source =
      frame.top_traits ||
      frame.traits ||
      frame.findings ||
      ml.top_traits ||
      ml.traits ||
      ml.findings;
    if (!Array.isArray(source)) return [];
    return source.map(traitText).filter(Boolean).slice(0, 3);
  }

  function normalSeverity(value) {
    const severity = value.toLowerCase();
    return ["benign", "suspicious", "hostile"].includes(severity) ? severity : "";
  }

  function setStep(active, completeThrough) {
    const order = ["received", "analysis", "archive", "result"];
    document.querySelectorAll(".pending-step").forEach((step) => {
      const key = step.dataset.step;
      const index = order.indexOf(key);
      step.classList.toggle("active", key === active);
      step.classList.toggle("complete", index >= 0 && index < completeThrough);
    });
  }

  function setCurrent(title, detail, waiting = false) {
    messageLabel.textContent = title;
    detailLabel.textContent = detail;
    current.classList.toggle("waiting", waiting);
  }

  function setBusyState(label, state = "In flight") {
    phaseLabel.textContent = label;
    stateLabel.textContent = state;
    stateLabel.classList.toggle("ready", state === "Ready");
    phaseLabel.classList.toggle("done", state === "Ready");
  }

  function showArchiveWait() {
    setBusyState("Reading complete", "Nearly ready");
    setStep("archive", 2);
    setCurrent("The reading is complete", "Waiting for the full result to arrive…", true);
  }

  function renderFrame(frame, raw) {
    const phase =
      first(frame.phase, frame.phase_state, frame.state, frame.stage, frame.status) || "starting";
    const phaseKey = phase.toLowerCase();
    const message = first(
      frame.message,
      frame.msg,
      frame.detail,
      frame.description,
      frame.phase_message
    );
    const terminal = phaseKey === "analyzed" || frame.status === "analyzed";

    if (terminal) {
      showArchiveWait();
    } else {
      const copy = {
        queued: ["A server has picked it up", "Your sample is waiting its turn."],
        ingesting: ["The handoff is underway", "The file is moving to the analysis server."],
        analyzing: ["The instruments are humming", "A server is reading the sample."],
        starting: ["Connecting the dots", "Opening the live analysis stream."],
        retrying: ["A tiny retry boomerang", "The server is taking another swing at the handoff."],
        progress: ["The sample is making progress", "A fresh signal just came in."],
      }[phaseKey] || ["The sample is in motion", "A fresh signal just came in."];
      setBusyState(copy[0], "In flight");
      setStep("analysis", 1);
      setCurrent(copy[0], message || copy[1]);
    }

    const { level, severity } = frameSignal(frame);
    const traits = frameTraits(frame);
    if (level || severity || traits.length) {
      signal.classList.add("visible");
      if (level || severity) {
        const severityClass = normalSeverity(severity);
        const severityLabel = severityClass ? severityClass.toUpperCase() : severity;
        levelLabel.textContent = [severityLabel, level ? `level ${level}` : ""]
          .filter(Boolean)
          .join(" · ");
        levelLabel.className = `pending-level ${severityClass}`;
      }
      if (traits.length) traitsLabel.textContent = `Fresh signals · ${traits.join(" · ")}`;
    }

    const item = document.createElement("li");
    const phaseNode = document.createElement("span");
    const messageNode = document.createElement("span");
    const rawNode = document.createElement("code");
    phaseNode.className = "phase";
    messageNode.className = "message";
    rawNode.className = "raw";
    phaseNode.textContent = phase;
    messageNode.textContent = message || "A fresh signal just came in.";
    rawNode.textContent = raw || JSON.stringify(frame);
    item.append(phaseNode, messageNode, rawNode);
    events.appendChild(item);
    while (events.children.length > 24) events.firstElementChild.remove();
  }

  function reloadOnce() {
    if (reloaded) return;
    reloaded = true;
    if (eventSource) eventSource.close();
    if (pollTimer) clearInterval(pollTimer);
    if (elapsedTimer) clearInterval(elapsedTimer);
    setBusyState("Result ready", "Ready");
    setStep("result", 3);
    setCurrent("All clear — opening the result", "The full report is ready.");
    setTimeout(() => window.location.replace(`/file/${encodeURIComponent(sha)}`), 180);
  }

  function showFailure(message = "The analysis could not be completed.") {
    if (reloaded) return;
    if (eventSource) eventSource.close();
    if (pollTimer) clearInterval(pollTimer);
    if (elapsedTimer) clearInterval(elapsedTimer);
    setBusyState("A hiccup happened", "Stopped");
    setCurrent("The sample needs another look", message, true);
    current.style.background = "#fff1f3";
    document.querySelector(".pending-stream")?.setAttribute("aria-busy", "false");
  }

  function renderServerInfo(data) {
    const server = first(data.server, data.source, data.request) || "server reported";
    const requestHost = first(data.request, data.host);
    route.hidden = false;
    serverLabel.textContent = server;
    requestHostLabel.textContent = requestHost || "not reported";
  }

  function startPolling() {
    if (pollingStarted) return;
    pollingStarted = true;
    log("warn", "falling back to status checks", { sha, endpoint: `/file/${sha}/status` });
    const tick = () =>
      fetch(`/file/${encodeURIComponent(sha)}/status`, { cache: "no-store" })
        .then((response) => response.json())
        .then((state) => {
          log("debug", "status response", state);
          if (state?.ready) reloadOnce();
          if (state?.failed) showFailure();
        })
        .catch((error) => log("warn", "status check failed", error));
    tick();
    pollTimer = setInterval(tick, 2000);
  }

  elapsedTimer = setInterval(() => {
    const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
    elapsed.textContent =
      seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  }, 1000);

  const endpoint = `/file/${encodeURIComponent(sha)}/${hasUploadProgress ? "events" : "wait"}`;
  log("info", "opening stream", { sha, endpoint, uploadProgress: hasUploadProgress });
  try {
    eventSource = new EventSource(endpoint);
    eventSource.addEventListener("open", () => log("info", "stream opened", { endpoint }));
    eventSource.addEventListener("server", (event) => {
      const parsed = parseEventData(event);
      log("info", "server handled request", { raw: parsed.raw, parsed: parsed.value });
      if (parsed.value && typeof parsed.value === "object") renderServerInfo(parsed.value);
    });
    eventSource.addEventListener("beamline", (event) => {
      const parsed = parseEventData(event);
      // Deliberately log every delivered frame, including repeats. The UI may
      // summarize them, but the console is the unabridged handoff diary.
      log("debug", "stream message", { raw: parsed.raw, parsed: parsed.value });
      if (parsed.value && typeof parsed.value === "object") renderFrame(parsed.value, parsed.raw);
    });
    eventSource.addEventListener("ready", (event) => {
      const parsed = parseEventData(event);
      log("info", "result ready", parsed.value ?? parsed.raw);
      reloadOnce();
    });
    eventSource.addEventListener("failed", (event) => {
      const parsed = parseEventData(event);
      log("error", "stream reported failure", parsed.value ?? parsed.raw);
      showFailure(parsed.value?.message || "The server could not complete this analysis.");
    });
    eventSource.addEventListener("missing", (event) => {
      log("error", "sample missing", event.data);
      showFailure("This analysis is no longer available.");
    });
    eventSource.addEventListener("error", (event) => {
      log("warn", "stream error", { readyState: eventSource.readyState, event });
      startPolling();
    });
  } catch (error) {
    log("error", "could not open stream", error);
    startPolling();
  }
})();
