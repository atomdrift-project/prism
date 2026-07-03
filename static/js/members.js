// Progressive loading of archive member content. A compacted-archive detail
// page first renders parent-only (verdict, provenance, member list, molecule
// placeholder); this fetches the reassembled Content + Traits HTML and the
// galaxy from /file/{sha}/members and injects them. Crawlers don't run JS, so
// the member DB work happens only for real viewers.
const membersSection = document.querySelector("[data-defer-members]");
if (membersSection) {
  const sha = membersSection.getAttribute("data-defer-members");
  fetch(`/file/${encodeURIComponent(sha)}/members`, {
    headers: { Accept: "application/json" },
  })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`members ${r.status}`))))
    .then((d) => {
      const traits = document.getElementById("tab-traits");
      if (traits && typeof d.traits_html === "string") {
        traits.innerHTML = d.traits_html;
      }
      const content = document.getElementById("tab-content");
      if (content) {
        content.innerHTML =
          d.has_content && typeof d.content_html === "string" && d.content_html.trim()
            ? d.content_html
            : '<p class="members-note">No per-file context for this archive.</p>';
      }
      // Always dispatch so the deferred molecule builds even when the galaxy is
      // empty (buildScene renders a neutral placeholder in that case).
      window.dispatchEvent(new CustomEvent("prism:molecule", { detail: d.galaxy || {} }));
    })
    .catch((err) => {
      const content = document.getElementById("tab-content");
      if (content) {
        content.innerHTML =
          '<p class="members-note">File contents could not be loaded — reload to try again.</p>';
      }
      // Still build the molecule from whatever we have so the canvas isn't stuck.
      window.dispatchEvent(new CustomEvent("prism:molecule", { detail: {} }));
      console.warn("member content load failed:", err);
    });
}
