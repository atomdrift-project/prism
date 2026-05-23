// Expand/collapse trait rows. A click on `.finding-row.expandable` toggles
// the adjacent `.finding-detail` row, which contains either evidence values
// (per-file) or a list of source files that fired this aggregated trait
// (archive level). Source-file links use `#file=<sha>` so the existing
// hashchange handler in files-tab.js switches to the Files tab and selects
// the file.

document.addEventListener('click', ev => {
    const link = ev.target.closest('a.finding-source');
    if (link) {
        // Let the row-toggle handler skip this event; the browser will still
        // navigate to the hash, which fires hashchange and selects the file.
        ev.stopPropagation();
        return;
    }
    const row = ev.target.closest('tr.finding-row.expandable');
    if (!row) return;
    const detail = row.nextElementSibling;
    if (!detail || !detail.classList.contains('finding-detail')) return;
    const open = !row.classList.contains('open');
    row.classList.toggle('open', open);
    detail.hidden = !open;
});
