// Rescan button — POSTs to /file/<sha>/rescan with a CSRF token, shows
// inline feedback, and (on success) waits for the worker to finish before
// reloading the page so the user sees fresh results without manual refresh.
// The button is rendered only when the last analysis is older than
// rescanCooldown; abuse is bounded server-side by CSRF, a global token
// bucket, and a per-SHA cooldown.

// Mirror status updates into the page-level live region so screen readers
// hear "Queuing…" / "Queued" / "Failed" without having to refocus the
// button. The button's own aria-label stays stable as the action name.
const liveEl = document.getElementById("a11y-live");
function announce(msg) {
  if (!liveEl) return;
  liveEl.textContent = "";
  requestAnimationFrame(() => {
    liveEl.textContent = msg;
  });
}

// Subscribe to /file/<sha>/wait — the same SSE channel the pending page
// uses while a worker is analyzing for the first time. We pass the pre-
// rescan analyzed_at timestamp as ?after=<unix-ms>; the server only
// fires `ready` once AnalyzedAt is strictly newer than that snapshot,
// so a stale "already analyzed once" state can't trigger an instant
// reload. Falls back to polling /status if EventSource isn't usable.
function watchForCompletion(sha, after, btn) {
  const qs = after ? "?after=" + encodeURIComponent(after) : "";
  const url = "/file/" + encodeURIComponent(sha) + "/wait" + qs;
  const onReady = () => {
    btn.textContent = "↻ reloading…";
    announce("Rescan complete. Reloading.");
    // Small delay so the SR announcement and the "reloading…" label are
    // perceivable before the navigation throws everything away.
    setTimeout(() => location.reload(), 300);
  };

  if (typeof EventSource === "function") {
    const es = new EventSource(url);
    let done = false;
    es.addEventListener("ready", () => {
      if (done) return;
      done = true;
      es.close();
      onReady();
    });
    es.addEventListener("missing", () => {
      if (done) return;
      done = true;
      es.close();
      btn.textContent = "✕ sample missing";
      btn.classList.add("is-error");
      announce("Rescan failed: sample no longer present.");
    });
    // When the server hits its own waitMaxDuration it just closes the
    // connection — natural EventSource behavior is to auto-reconnect,
    // which we want (analysis may take several minutes). Cap the total
    // session client-side at 10 minutes so a stuck job doesn't keep
    // reconnecting forever.
    setTimeout(
      () => {
        if (done) return;
        done = true;
        es.close();
      },
      10 * 60 * 1000,
    );
    return;
  }

  // Polling fallback: ask /status every 5s with the same `after=` so
  // we don't see the stale result. Give up after 10 minutes.
  const start = Date.now();
  const tick = async () => {
    if (Date.now() - start > 10 * 60 * 1000) return;
    try {
      const statusURL =
        "/file/" + encodeURIComponent(sha) + "/status" + qs;
      const r = await fetch(statusURL, { cache: "no-store" });
      if (r.ok) {
        const j = await r.json();
        if (j && j.ready) {
          onReady();
          return;
        }
      }
    } catch (_) {
      /* transient — try again */
    }
    setTimeout(tick, 5000);
  };
  setTimeout(tick, 5000);
}

document.querySelectorAll(".rescan-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const sha = btn.dataset.sha;
    const csrf = btn.dataset.csrf;
    // analyzed-at is a unix-ms timestamp the server rendered onto the
    // button. We capture it BEFORE the POST so the wait can recognize a
    // strictly-newer analysis. Zero is fine: omitting `after=` falls
    // back to the original "first ever analysis" semantics.
    const after = btn.dataset.analyzedAt || "";
    if (!sha || !csrf || btn.disabled) return;

    btn.disabled = true;
    btn.textContent = "↻ queuing…";
    btn.classList.remove("is-done", "is-error");
    announce("Queuing sample for rescan…");

    try {
      const body = new URLSearchParams({ csrf_token: csrf });
      const resp = await fetch("/file/" + encodeURIComponent(sha) + "/rescan", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!resp.ok) {
        let msg = "rescan failed (" + resp.status + ")";
        try {
          const j = await resp.json();
          if (j && j.error) msg = j.error;
        } catch (_) {
          /* non-JSON body */
        }
        btn.textContent = "✕ " + msg;
        btn.classList.add("is-error");
        btn.title = msg;
        announce(msg);
        return;
      }
      btn.textContent = "↻ waiting…";
      btn.classList.add("is-done");
      btn.title = "Sample has been re-queued; waiting for a fresh analysis.";
      announce("Sample queued. Waiting for analysis to finish.");
      // We only auto-reload when the user themselves triggered the rescan
      // on this page — visiting the same page in another tab won't poll
      // because that tab never observed a successful POST here.
      watchForCompletion(sha, after, btn);
    } catch (err) {
      btn.textContent = "✕ network error";
      btn.classList.add("is-error");
      btn.title = String(err);
      announce("Rescan failed: network error.");
    }
  });
});
