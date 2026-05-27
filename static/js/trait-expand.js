// Expand/collapse trait cards. A click on `.finding-card.expandable` toggles
// an `.open` class on the card; CSS reveals the `.finding-detail` panel
// inside. The detail contains either evidence values (per-file) or a list of
// source files that fired this aggregated trait (archive level). Source-file
// links use `#file=<sha>` so files-tab.js's hashchange handler switches to
// the Files tab and selects the file.

document.addEventListener('click', ev => {
    const link = ev.target.closest('a.finding-source');
    if (link) {
        ev.stopPropagation();
        // Carry the originating trait into the hash so files-tab.js can
        // highlight the matching trait card and scroll to its first line.
        const card = link.closest('.finding-card');
        const tid = card && card.dataset.traitId;
        if (tid) {
            ev.preventDefault();
            const sha = link.dataset.sha || '';
            location.hash = 'file=' + sha + '&trait=' + encodeURIComponent(tid);
        }
        return;
    }
    const card = ev.target.closest('.finding-card.expandable');
    if (!card) return;
    card.classList.toggle('open');
});
