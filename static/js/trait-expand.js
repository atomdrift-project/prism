// Expand/collapse trait cards using the WAI-ARIA disclosure pattern.
// Each expandable trait card has a <button class="finding-card-toggle">
// with aria-expanded, followed by a <div class="finding-detail" hidden>
// sibling. Clicking (or pressing Enter/Space — buttons handle that
// natively) flips both states so keyboard users and screen readers see
// the same change as sighted mouse users. The detail contains either
// evidence values (per-file) or a list of source files that fired this
// aggregated trait (archive level); links in there use `#file=<sha>`
// so files-tab.js's hashchange handler switches to the Files tab and
// selects the file.
document.addEventListener("click", (ev) => {
  const link = ev.target.closest("a.finding-source");
  if (link) {
    ev.stopPropagation();
    // Carry the originating trait into the hash so files-tab.js can
    // highlight the matching trait card and scroll to its first line.
    const card = link.closest(".finding-card");
    const tid = card && card.dataset.traitId;
    if (tid) {
      ev.preventDefault();
      const sha = link.dataset.sha || "";
      location.hash = "file=" + sha + "&trait=" + encodeURIComponent(tid);
    }
    return;
  }
  const toggle = ev.target.closest(".finding-card-toggle");
  if (!toggle) return;
  const card = toggle.closest(".finding-card");
  const detail = card && card.querySelector(":scope > .finding-detail");
  const open = toggle.getAttribute("aria-expanded") !== "true";
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (card) card.classList.toggle("open", open);
  if (detail) {
    if (open) detail.removeAttribute("hidden");
    else detail.setAttribute("hidden", "");
  }
});
