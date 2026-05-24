// Expand/collapse trait cards. A click on `.finding-card.expandable` toggles
// an `.open` class on the card; CSS reveals the `.finding-detail` panel
// inside. The detail contains either evidence values (per-file) or a list of
// source files that fired this aggregated trait (archive level). Source-file
// links use `#file=<sha>` so files-tab.js's hashchange handler switches to
// the Files tab and selects the file.

document.addEventListener('click', ev => {
    const link = ev.target.closest('a.finding-source');
    if (link) {
        // Let the card-toggle handler skip this event; the browser still
        // navigates to the hash, which fires hashchange and selects the file.
        ev.stopPropagation();
        return;
    }
    const card = ev.target.closest('.finding-card.expandable');
    if (!card) return;
    card.classList.toggle('open');
});
