(() => {
  const shell = document.querySelector("[data-upload-sha]");
  if (!shell) return;

  const sha = shell.dataset.uploadSha;
  const started = Number(shell.dataset.uploadStarted || Date.now());
  const elapsed = document.getElementById("pending-elapsed");
  const phaseLabel = document.getElementById("pending-phase");
  const messageLabel = document.getElementById("pending-message");
  const events = document.getElementById("pending-events");
  const signal = document.getElementById("pending-signal");
  const levelLabel = document.getElementById("pending-level");
  const traitsLabel = document.getElementById("pending-traits");
  let reloaded = false;
  let eventSource;
  let pollingStarted = false;

  const whimsy = {
    queued: "The sample has entered the beamline.",
    ingesting: "The sample is taking the scenic route.",
    analyzing: "The instruments are having a look.",
    analyzed: "Beamline has finished its pass; Hopper is folding in the details.",
    complete: "The evidence is settling into place.",
    error: "The beamline hit a snag while examining this sample.",
  };

  function text(value) {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
  }

  function first(...values) {
    return values.map(text).find(Boolean) || "";
  }

  function frameLevel(frame) {
    const ml = frame.ml && typeof frame.ml === "object" ? frame.ml : {};
    return first(
      frame.level,
      frame.severity,
      frame.classification,
      frame.verdict,
      frame.risk_level,
      ml.level,
      ml.severity,
      ml.lvl
    );
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

  function normalLevel(value) {
    const level = value.toLowerCase();
    if (level === "-1" || level === "benign" || level === "0") return "benign";
    if (level === "1" || level === "suspicious") return "suspicious";
    if (level === "2" || level === "hostile") return "hostile";
    return "";
  }

  function renderFrame(frame) {
    const phase = first(frame.phase, frame.stage, frame.status) || "beamline";
    const phaseKey = phase.toLowerCase();
    const message = first(
      frame.message,
      frame.msg,
      frame.detail,
      frame.description,
      frame.phase_message
    );
    phaseLabel.textContent = phase === "analyzed" ? "Beamline has a result" : `Beamline · ${phase}`;
    messageLabel.textContent =
      message || whimsy[phaseKey] || "The sample is moving through the instruments.";

    const level = frameLevel(frame);
    const traits = frameTraits(frame);
    if (level || traits.length) {
      signal.classList.add("visible");
      if (level) {
        levelLabel.textContent = `Level · ${level}`;
        levelLabel.className = `pending-level ${normalLevel(level)}`;
      }
      if (traits.length) traitsLabel.textContent = `Top traits · ${traits.join(" · ")}`;
    }

    const item = document.createElement("li");
    const phaseNode = document.createElement("span");
    const messageNode = document.createElement("span");
    phaseNode.className = "phase";
    messageNode.className = "message";
    phaseNode.textContent = phase;
    messageNode.textContent = message || whimsy[phaseKey] || "Beamline sent a progress note.";
    item.append(phaseNode, messageNode);
    events.appendChild(item);
    while (events.children.length > 8) events.firstElementChild.remove();
  }

  function reloadOnce() {
    if (reloaded) return;
    reloaded = true;
    if (eventSource) eventSource.close();
    window.location.replace(`/file/${encodeURIComponent(sha)}`);
  }

  function startPolling() {
    if (pollingStarted) return;
    pollingStarted = true;
    const tick = () =>
      fetch(`/file/${encodeURIComponent(sha)}/status`, { cache: "no-store" })
        .then((response) => response.json())
        .then((state) => {
          if (state?.ready) reloadOnce();
        })
        .catch(() => {
          /* polling is best effort */
        });
    tick();
    setInterval(tick, 2000);
  }

  setInterval(() => {
    const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
    elapsed.textContent =
      seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  }, 1000);

  try {
    eventSource = new EventSource(`/file/${encodeURIComponent(sha)}/events`);
    eventSource.addEventListener("beamline", (event) => {
      try {
        renderFrame(JSON.parse(event.data));
      } catch (_) {
        /* ignore malformed progress */
      }
    });
    eventSource.addEventListener("error", () => {
      if (eventSource.readyState === EventSource.CLOSED) startPolling();
    });
  } catch (_) {
    startPolling();
  }

  try {
    const wait = new EventSource(`/file/${encodeURIComponent(sha)}/wait`);
    wait.addEventListener("ready", () => {
      wait.close();
      reloadOnce();
    });
    wait.addEventListener("error", () => {
      if (wait.readyState === EventSource.CLOSED) startPolling();
    });
  } catch (_) {
    startPolling();
  }
})();
