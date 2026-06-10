// Expand/collapse trait cards using the WAI-ARIA disclosure pattern.
// Each expandable trait card has a <button class="finding-card-toggle">
// with aria-expanded, followed by a <div class="finding-detail" hidden>
// sibling. Clicking (or pressing Enter/Space — buttons handle that
// natively) flips both states so keyboard users and screen readers see
// the same change as sighted mouse users. The detail lists each match
// as a filename — location — evidence row.
document.addEventListener("click", (ev) => {
  const toggle = ev.target.closest(".finding-card-toggle");
  if (!toggle) return;
  const card = toggle.closest(".finding-card");
  const detail = card?.querySelector(":scope > .finding-detail");
  const open = toggle.getAttribute("aria-expanded") !== "true";
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (card) card.classList.toggle("open", open);
  if (detail) {
    if (open) detail.removeAttribute("hidden");
    else detail.setAttribute("hidden", "");
  }
});
