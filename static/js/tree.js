// Structure tab: toggle a containment-tree node open/closed on click or
// keyboard. Delegated off the server-rendered rows so there are no inline
// handlers (CSP-clean). The tree itself is fully rendered at page load, so this
// only wires interactivity — nothing is fetched.

function toggle(row) {
  const node = row.closest(".tnode");
  if (!node) return;
  const collapsed = node.classList.toggle("collapsed");
  row.setAttribute("aria-expanded", collapsed ? "false" : "true");
}

for (const row of document.querySelectorAll(".ttree .trow.clickable")) {
  row.addEventListener("click", (event) => {
    // A click on the filename or the "fetched from" link should navigate, not
    // fold the node.
    if (event.target.closest("a")) return;
    toggle(row);
  });
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle(row);
    }
  });
}
