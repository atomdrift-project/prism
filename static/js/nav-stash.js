// When the reader clicks into a sample from a feed, capture the visible
// result set so the detail page's j/k shortcuts can walk the same order the
// reader was looking at rather than a guess made after the fact.
//
// Per tab (sessionStorage) so independent tabs don't trample each other;
// cleared implicitly when the tab closes, or overwritten the next time the
// reader clicks through from any feed.
//
// This lives on its own rather than inside upload.js because every feed needs
// it and only one of them is the upload page: /fallout and / render
// fallout.html, /stream and /{ecosystem}/ render upload.html. Loaded by one
// and not the other, j/k works on some samples and silently does nothing on
// the rest — which is exactly what happened.

document.addEventListener("click", (ev) => {
  const link = ev.target.closest('a.file-link[href^="/file/"]');
  if (!link) return;
  const all = Array.from(document.querySelectorAll('a.file-link[href^="/file/"]'));
  const samples = all
    .map((a) => ({
      sha: (a.getAttribute("href") || "").replace(/^\/file\//, ""),
      label: (a.textContent || "").trim(),
    }))
    .filter((s) => /^[0-9a-f]{8,64}$/i.test(s.sha));
  try {
    sessionStorage.setItem(
      "prism_nav",
      JSON.stringify({
        returnUrl: location.pathname + location.search,
        // Fewer than two samples means there is nothing to iterate through,
        // so the detail page offers no j/k — but returnUrl is still worth
        // recording for a return to this exact feed view.
        samples: samples.length >= 2 ? samples : [],
        savedAt: Date.now(),
      })
    );
  } catch (_) {
    /* private mode / quota — ignore, and j/k simply stays inert */
  }
});
