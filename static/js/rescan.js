// Operator rescan button — POSTs to /file/<sha>/rescan with a CSRF token,
// shows inline feedback. Rendered server-side only when the client IP is
// in a trusted subnet (see --trusted-subnets); the endpoint enforces the
// same check, so this client-side script is a UX layer, not a gate.

document.querySelectorAll('.rescan-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
        const sha = btn.dataset.sha;
        const csrf = btn.dataset.csrf;
        if (!sha || !csrf || btn.disabled) return;

        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = '↻ queuing…';
        btn.classList.remove('is-done', 'is-error');

        try {
            const body = new URLSearchParams({csrf_token: csrf});
            const resp = await fetch('/file/' + encodeURIComponent(sha) + '/rescan', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body,
            });
            if (!resp.ok) {
                let msg = 'rescan failed (' + resp.status + ')';
                try {
                    const j = await resp.json();
                    if (j && j.error) msg = j.error;
                } catch (_) { /* non-JSON body */ }
                btn.textContent = '✕ ' + msg;
                btn.classList.add('is-error');
                btn.title = msg;
                return;
            }
            btn.textContent = '✓ queued';
            btn.classList.add('is-done');
            btn.title = 'Sample has been re-queued; the next worker will analyze it.';
        } catch (err) {
            btn.textContent = '✕ network error';
            btn.classList.add('is-error');
            btn.title = String(err);
        }
        // Leave the button disabled in its final state so repeat clicks
        // don't queue duplicate work. Reload the page to issue another.
        void originalText;
    });
});
