// Rescan button — POSTs to /file/<sha>/rescan with a CSRF token, shows
// inline feedback. The button is rendered only when the last analysis is
// older than rescanCooldown; abuse is bounded server-side by CSRF, a
// global token bucket, and a per-SHA cooldown.

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

document.querySelectorAll(".rescan-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const sha = btn.dataset.sha;
    const csrf = btn.dataset.csrf;
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
      btn.textContent = "✓ queued";
      btn.classList.add("is-done");
      btn.title = "Sample has been re-queued; the next worker will analyze it.";
      announce("Sample queued for rescan.");
    } catch (err) {
      btn.textContent = "✕ network error";
      btn.classList.add("is-error");
      btn.title = String(err);
      announce("Rescan failed: network error.");
    }
  });
});
