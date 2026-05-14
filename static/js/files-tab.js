// Two-pane archive Files tab. Lives in its own module so a Three.js init
// failure in molecule.js can't take down the click handlers — the tree is
// pure DOM work and has no WebGL dependency.

const tree = document.getElementById('files-tree');
const detail = document.getElementById('files-detail');
if (tree && detail) {
    const empty = detail.querySelector('.files-detail-empty');
    const headers = Array.from(detail.querySelectorAll('.files-detail-header-block'));
    const sectionBlocks = Array.from(detail.querySelectorAll('.files-detail-block'));
    const rows = Array.from(tree.querySelectorAll('.files-tree-row'));

    const placeholderLabels = {
        findings: 'No traits.',
        strings: 'No strings extracted.',
        symbols: 'No symbols found.',
        metrics: 'No metrics available.',
        kv: 'No metadata available.',
    };

    function placeholder(section) {
        const div = document.createElement('div');
        div.className = 'no-findings files-detail-placeholder';
        div.textContent = placeholderLabels[section] || 'No data.';
        return div;
    }

    function showSection(sha, section) {
        if (empty) empty.hidden = true;

        for (const r of rows) {
            r.classList.toggle('selected', r.dataset.fileSha === sha);
        }
        for (const h of headers) {
            h.hidden = h.dataset.fileSha !== sha;
        }

        const header = headers.find(h => h.dataset.fileSha === sha);
        if (header) {
            for (const btn of header.querySelectorAll('.files-subtab')) {
                btn.classList.toggle('active', btn.dataset.sub === section);
            }
        }

        let shown = null;
        for (const b of sectionBlocks) {
            const match = b.dataset.fileSha === sha && b.dataset.section === section;
            b.hidden = !match;
            if (match) shown = b;
        }

        for (const n of detail.querySelectorAll('.files-detail-placeholder')) {
            n.remove();
        }
        if (!shown && header) {
            header.parentNode.insertBefore(placeholder(section), header.nextSibling);
        }
    }

    for (const row of rows) {
        row.addEventListener('click', () => {
            const sha = row.dataset.fileSha;
            location.hash = `file=${sha}`;
            showSection(sha, 'findings');
        });
    }

    detail.addEventListener('click', ev => {
        const btn = ev.target.closest('.files-subtab');
        if (!btn) return;
        const headerBlock = btn.closest('.files-detail-header-block');
        if (!headerBlock) return;
        showSection(headerBlock.dataset.fileSha, btn.dataset.sub);
    });

    detail.addEventListener('click', ev => {
        const el = ev.target.closest('.files-detail-sha');
        if (!el) return;
        const full = el.dataset.sha || '';
        if (!full || !navigator.clipboard?.writeText) return;
        navigator.clipboard.writeText(full).then(() => {
            el.classList.add('copied');
            setTimeout(() => el.classList.remove('copied'), 1200);
        }).catch(() => {
            /* clipboard write rejected — silently ignore */
        });
    });

    const search = document.getElementById('files-search-input');
    if (search) {
        search.addEventListener('input', () => {
            const q = search.value.trim().toLowerCase();
            for (const r of rows) {
                if (!q) { r.hidden = false; continue; }
                r.hidden = !((r.dataset.display || '').toLowerCase().includes(q));
            }
        });
    }

    function applyHash() {
        const m = location.hash.replace(/^#/, '').match(/file=([0-9a-f]{8,64})/i);
        if (!m) return false;
        const sha = m[1];
        const row = rows.find(r => r.dataset.fileSha === sha);
        if (!row) return false;
        const filesTab = document.querySelector('.tab[data-tab="files"]');
        if (filesTab && !filesTab.classList.contains('active')) filesTab.click();
        showSection(sha, 'findings');
        row.scrollIntoView({ block: 'nearest' });
        return true;
    }
    window.addEventListener('hashchange', applyHash);

    // On load, prefer the URL fragment; otherwise auto-select the most
    // suspicious *inner* file so the sub-tabs land on useful content. Rows
    // are pre-sorted by prepareResultData with the container first (when
    // present) and children by severity, so the first non-container row is
    // the highest-risk inner file. For single-file archives the container
    // has been collapsed away — the lone payload is what the find returns.
    if (!applyHash()) {
        const target = rows.find(r => !r.classList.contains('files-tree-container')) || rows[0];
        if (target) {
            showSection(target.dataset.fileSha, 'findings');
        }
    }
}
