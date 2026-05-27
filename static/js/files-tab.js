// Archive Files tab — Miller-column file explorer.
//
// Reads the hierarchical tree from `<script id="file-tree-data">`, renders
// directory columns left-to-right, and updates the existing detail-pane
// blocks (kept in the DOM by the template) when a file is selected. Hash
// navigation (`#file=<sha>`) still works: we walk the tree to find the
// matching path and open columns leading to it.

const millerEl = document.getElementById('files-miller');
const treeDataEl = document.getElementById('file-tree-data');
const detail = document.getElementById('files-detail');

if (millerEl && treeDataEl && detail) {
    let tree = null;
    try {
        tree = JSON.parse(treeDataEl.textContent || 'null');
    } catch (err) {
        tree = null;
    }

    const empty = detail.querySelector('.files-detail-empty');
    const headers = Array.from(detail.querySelectorAll('.files-detail-header-block'));
    const sectionBlocks = Array.from(detail.querySelectorAll('.files-detail-block'));
    const sourceView = detail.querySelector('#files-source-view');
    const sourceEl = detail.querySelector('#fs-source');
    const contentsCache = new Map(); // sha -> { lines, isText, tooLarge, sizeStr, fileType }; bounded by CACHE_MAX
    let currentSourceSha = null;     // sha currently rendered in source view
    // trait ID -> { crit, lines: [] } for the file currently in source view.
    // Used by chip clicks and by `&trait=…` hash navigation.
    let currentTraitIndex = new Map();

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

    // Path stack: directory nodes currently expanded, root-first.
    // Always at least one entry (the synthetic root); columns past index 0
    // represent each drilled-into directory.
    const state = { pathStack: [tree], selectedSha: null, pendingTrait: null, pendingLine: null };

    function classForRisk(node) {
        const r = node.d ? (node.mr || '') : (node.r || '');
        if (r === 'hostile' || r === 'suspicious' || r === 'notable') return r;
        return 'clean';
    }

    function metaForRow(node) {
        if (node.d) {
            const n = node.fc || (node.c ? node.c.length : 0);
            return `${n}`;
        }
        return node.sz || '';
    }

    function renderColumn(parent, depth) {
        const col = document.createElement('div');
        col.className = 'files-miller-col';
        col.dataset.depth = String(depth);

        const head = document.createElement('div');
        head.className = 'files-miller-colhead';
        head.textContent = parent.n || (depth === 0 ? 'archive' : '');
        head.title = parent.p || '';
        col.appendChild(head);

        const list = document.createElement('ul');
        list.className = 'files-miller-list';

        const children = parent.c || [];
        // Selected child for this column = the next entry in the pathStack.
        const next = state.pathStack[depth + 1];

        for (const child of children) {
            const li = document.createElement('li');
            li.className = 'files-miller-row';
            li.setAttribute('role', 'treeitem');
            if (!child.d) li.classList.add('leaf');
            if (next && child === next) li.classList.add('selected');
            if (!child.d && state.selectedSha && child.sha === state.selectedSha) li.classList.add('selected');

            li.dataset.display = child.p || child.n || '';
            if (child.sha) li.dataset.fileSha = child.sha;

            const dot = document.createElement('span');
            dot.className = 'dot ' + classForRisk(child);
            li.appendChild(dot);

            const nm = document.createElement('span');
            nm.className = 'nm';
            nm.textContent = child.n;
            nm.title = child.p || child.n;
            li.appendChild(nm);

            if (!child.d && child.ty) {
                const ty = document.createElement('span');
                ty.className = 'meta';
                ty.textContent = child.ty;
                li.appendChild(ty);
            }

            const meta = document.createElement('span');
            meta.className = 'meta';
            meta.textContent = metaForRow(child);
            li.appendChild(meta);

            const chev = document.createElement('span');
            chev.className = 'chev';
            chev.textContent = child.d ? '›' : '';
            li.appendChild(chev);

            li.addEventListener('click', () => onPick(child, depth));
            list.appendChild(li);
        }

        if (!children.length) {
            const div = document.createElement('div');
            div.className = 'files-miller-hint';
            div.textContent = 'empty';
            col.appendChild(div);
        } else {
            col.appendChild(list);
        }
        return col;
    }

    function renderHintColumn() {
        const col = document.createElement('div');
        col.className = 'files-miller-col files-miller-col-fill';
        const hint = document.createElement('div');
        hint.className = 'files-miller-hint';
        const h = document.createElement('div');
        h.className = 'emph';
        h.textContent = 'Pick a file to inspect';
        hint.appendChild(h);
        const p = document.createElement('div');
        p.textContent = 'Folders show their worst-ranked child. Click a file to see its traits, strings, symbols, and metadata.';
        hint.appendChild(p);
        col.appendChild(hint);
        return col;
    }

    function render() {
        millerEl.innerHTML = '';
        for (let i = 0; i < state.pathStack.length; i++) {
            const parent = state.pathStack[i];
            if (!parent || !parent.c || !parent.c.length) break;
            millerEl.appendChild(renderColumn(parent, i));
        }
        // Hint column on the right if no file selected yet.
        if (!state.selectedSha) {
            millerEl.appendChild(renderHintColumn());
        }
        // Auto-scroll to the rightmost column so newly opened dirs come into view.
        millerEl.scrollLeft = millerEl.scrollWidth;
    }

    function showSection(sha, section) {
        if (empty) empty.hidden = true;
        for (const h of headers) {
            h.hidden = h.dataset.fileSha !== sha;
        }
        const header = headers.find(h => h.dataset.fileSha === sha);
        if (header) {
            for (const btn of header.querySelectorAll('.files-subtab')) {
                btn.classList.toggle('active', btn.dataset.sub === section);
            }
        }
        // The synthetic "source" section is a single shared element; toggle it
        // on/off and hide all the other per-section blocks when active.
        const isSource = section === 'source';
        if (sourceView) sourceView.classList.toggle('active', isSource && currentSourceSha === sha);
        let shown = isSource ? sourceView : null;
        for (const b of sectionBlocks) {
            const match = !isSource && b.dataset.fileSha === sha && b.dataset.section === section;
            b.hidden = !match;
            if (match) shown = b;
        }
        for (const n of detail.querySelectorAll('.files-detail-placeholder')) {
            n.remove();
        }
        if (!shown && header && !isSource) {
            header.parentNode.insertBefore(placeholder(section), header.nextSibling);
        }
    }

    function renderSourceLines(lines) {
        if (!sourceEl) return;
        const frag = document.createDocumentFragment();
        for (const ln of lines) {
            const div = document.createElement('div');
            div.className = 'fs-line' + (ln.Risk ? ' crit-' + ln.Risk : '');
            div.id = 'fs-line-' + ln.Number;
            if (ln.Traits && ln.Traits.length) {
                div.title = ln.Traits.join(', ');
                div.dataset.traits = ln.Traits.join('|');
            }
            const num = document.createElement('span');
            num.className = 'ln';
            num.textContent = ln.Number;
            div.appendChild(num);
            const gut = document.createElement('span');
            gut.className = 'gut';
            div.appendChild(gut);
            const code = document.createElement('span');
            code.className = 'code chroma';
            // Server emits a list of chroma tokens {c: className, t: text}
            // when a lexer matched; otherwise we render the raw text. We
            // always use textContent / className so attacker-controlled
            // source bytes can never produce HTML or event handlers.
            if (ln.Tokens && ln.Tokens.length) {
                for (const tok of ln.Tokens) {
                    if (tok.c) {
                        const span = document.createElement('span');
                        span.className = tok.c;
                        span.textContent = tok.t;
                        code.appendChild(span);
                    } else {
                        code.appendChild(document.createTextNode(tok.t));
                    }
                }
            } else {
                code.textContent = ln.Text || '';
            }
            div.appendChild(code);
            frag.appendChild(div);
        }
        sourceEl.innerHTML = '';
        sourceEl.appendChild(frag);
    }

    const RISK_RANK = { hostile: 3, suspicious: 2, notable: 1, baseline: 0 };

    function buildTraitIndex(lines) {
        // trait ID -> { crit: highest-risk-seen, lines: [] in source order }.
        const idx = new Map();
        for (const ln of lines) {
            if (!ln.Traits) continue;
            for (const t of ln.Traits) {
                if (!idx.has(t)) idx.set(t, { crit: ln.Risk || 'notable', lines: [] });
                const entry = idx.get(t);
                entry.lines.push(ln.Number);
                if ((RISK_RANK[ln.Risk] || 0) > (RISK_RANK[entry.crit] || 0)) entry.crit = ln.Risk;
            }
        }
        return idx;
    }

    function renderTopTraits(sha, idx) {
        // Top 3 chips by crit (suspicious+ only) then by line count, then alpha.
        const slot = detail.querySelector('.files-detail-toptraits[data-toptraits-for="' + sha + '"]');
        if (!slot) return;
        slot.innerHTML = '';
        const entries = Array.from(idx.entries())
            .filter(([_, info]) => (RISK_RANK[info.crit] || 0) >= 2)
            .sort((a, b) => {
                const ra = RISK_RANK[a[1].crit] || 0;
                const rb = RISK_RANK[b[1].crit] || 0;
                if (ra !== rb) return rb - ra;
                if (a[1].lines.length !== b[1].lines.length) return b[1].lines.length - a[1].lines.length;
                return a[0].localeCompare(b[0]);
            })
            .slice(0, 3);
        for (const [traitID, info] of entries) {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'fs-chip';
            chip.title = traitID + ' · ' + info.lines.length + (info.lines.length === 1 ? ' line' : ' lines');
            const dot = document.createElement('span');
            dot.className = 'fs-chip-dot ' + info.crit;
            chip.appendChild(dot);
            const id = document.createElement('span');
            id.className = 'fs-chip-id';
            id.textContent = traitID;
            chip.appendChild(id);
            const n = document.createElement('span');
            n.className = 'fs-chip-n';
            n.textContent = '×' + info.lines.length;
            chip.appendChild(n);
            chip.addEventListener('click', ev => {
                ev.stopPropagation();
                scrollToLine(info.lines[0], info.lines);
            });
            slot.appendChild(chip);
        }
    }

    function bestLineNumber(lines) {
        // criticality * confidence proxy: risk-rank (severity) weighted by
        // trait count on that line (more matches → more confidence).
        let bestN = null;
        let bestScore = 0;
        for (const ln of lines) {
            const rank = RISK_RANK[ln.Risk] || 0;
            if (rank === 0) continue;
            const score = rank * 100 + (ln.Traits ? ln.Traits.length : 0);
            if (score > bestScore) {
                bestScore = score;
                bestN = ln.Number;
            }
        }
        return bestN;
    }

    function scrollToLine(target, flashLines) {
        if (!sourceEl || !target) return;
        sourceEl.querySelectorAll('.fs-line.flash').forEach(l => l.classList.remove('flash'));
        const flashSet = flashLines && flashLines.length ? flashLines : [target];
        for (const n of flashSet) {
            const el = sourceEl.querySelector('#fs-line-' + n);
            if (el) el.classList.add('flash');
        }
        const anchor = sourceEl.querySelector('#fs-line-' + target);
        if (anchor) anchor.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }

    function setSourceSubtabAvailable(sha, available) {
        const header = headers.find(h => h.dataset.fileSha === sha);
        if (!header) return;
        const btn = header.querySelector('.files-subtab[data-sub="source"]');
        if (btn) btn.hidden = !available;
    }

    const FETCH_TIMEOUT_MS = 10000;
    const CACHE_MAX = 32;
    let activeFetch = null; // AbortController for the currently-in-flight contents fetch

    function cachePut(sha, data) {
        // Keep the cache bounded so a user clicking through a 100-file
        // archive doesn't accumulate every body in memory. Map iterates in
        // insertion order, so the first key is the oldest entry.
        if (contentsCache.size >= CACHE_MAX) {
            const oldest = contentsCache.keys().next().value;
            if (oldest) contentsCache.delete(oldest);
        }
        contentsCache.set(sha, data);
    }

    async function loadContents(sha, signal) {
        if (contentsCache.has(sha)) return contentsCache.get(sha);
        const tid = setTimeout(() => {
            // Surface a clean error rather than letting fetch hang forever.
            if (activeFetch === signal._ctl) activeFetch.abort('timeout');
        }, FETCH_TIMEOUT_MS);
        try {
            const r = await fetch('/file/' + sha + '/contents', { credentials: 'same-origin', signal });
            const data = await r.json().catch(() => null);
            if (!r.ok) {
                const msg = (data && data.error) || ('HTTP ' + r.status);
                throw new Error(msg);
            }
            cachePut(sha, data);
            return data;
        } finally {
            clearTimeout(tid);
        }
    }

    function renderSourceError(msg) {
        if (sourceEl) sourceEl.innerHTML = '<div class="fs-source-placeholder">Couldn’t load source: ' + msg + '</div>';
    }

    function clearTopTraits(sha) {
        const slot = detail.querySelector('.files-detail-toptraits[data-toptraits-for="' + sha + '"]');
        if (slot) slot.innerHTML = '';
    }

    async function maybeRenderSource(sha) {
        if (!sourceView || !sourceEl) return;
        // Cancel any earlier in-flight fetch so its eventual response can't
        // overwrite the file the user just selected.
        if (activeFetch) activeFetch.abort('superseded');
        const ctl = new AbortController();
        ctl.signal._ctl = ctl;
        activeFetch = ctl;

        let data;
        try {
            data = await loadContents(sha, ctl.signal);
        } catch (err) {
            if (ctl.signal.aborted) return; // a newer click took over; stay quiet
            setSourceSubtabAvailable(sha, false);
            // Only surface error UI if this is still the user's current file.
            if (state.selectedSha === sha) renderSourceError(err.message || 'unknown error');
            return;
        } finally {
            if (activeFetch === ctl) activeFetch = null;
        }
        // Did the user switch files while the fetch was in-flight?
        if (state.selectedSha !== sha) return;

        if (!data.isText) {
            setSourceSubtabAvailable(sha, false);
            clearTopTraits(sha);
            return;
        }
        setSourceSubtabAvailable(sha, true);
        if (data.tooLarge) {
            sourceEl.innerHTML = '<div class="fs-source-placeholder">File is ' + (data.sizeStr || 'large') + ' — too large to display inline. Use the ↗ link to open it in its own page.</div>';
            clearTopTraits(sha);
        } else {
            currentSourceSha = sha;
            const lines = data.lines || [];
            renderSourceLines(lines);
            currentTraitIndex = buildTraitIndex(lines);
            renderTopTraits(sha, currentTraitIndex);
            // Auto-show the source sub-tab when first available; user can switch away.
            const header = headers.find(h => h.dataset.fileSha === sha);
            const sub = header && header.querySelector('.files-subtab.active');
            if (sub && sub.dataset.sub === 'findings') {
                showSection(sha, 'source');
            }
            // Decide the initial scroll target. Priority:
            //   1. explicit &line=N from the hash
            //   2. &trait=<id> → first line of that trait
            //   3. highest-rank line (severity × trait count)
            let target = null;
            let flash = null;
            if (state.pendingLine) {
                target = state.pendingLine;
                state.pendingLine = null;
            } else if (state.pendingTrait) {
                const info = currentTraitIndex.get(state.pendingTrait);
                if (info && info.lines.length) {
                    target = info.lines[0];
                    flash = info.lines;
                }
                state.pendingTrait = null;
            }
            if (!target) target = bestLineNumber(lines);
            if (target) scrollToLine(target, flash);
        }
    }

    function onPick(node, depth) {
        if (node.d) {
            // Drilling into a directory: truncate stack past this column and
            // push the new dir.
            state.pathStack = state.pathStack.slice(0, depth + 1).concat([node]);
            render();
        } else {
            // File click: keep current pathStack but mark the file selected
            // and update the detail pane.
            state.selectedSha = node.sha;
            location.hash = `file=${node.sha}`;
            render();
            showSection(node.sha, 'findings');
            maybeRenderSource(node.sha);
        }
    }

    // Walk tree to find a leaf with the given SHA; return path of nodes from
    // root to that leaf (exclusive of root).
    function findShaPath(node, sha, acc) {
        if (!node) return null;
        if (!node.d && node.sha === sha) return acc.concat([node]);
        if (!node.c) return null;
        for (const c of node.c) {
            const p = findShaPath(c, sha, acc.concat([node]));
            if (p) return p;
        }
        return null;
    }

    function selectBySha(sha) {
        if (!sha || !tree) return false;
        const path = findShaPath(tree, sha, []);
        if (!path) return false;
        // path = [root, dir1, ..., file]. pathStack should be [root, dir1, ...]
        // (omitting the file leaf), then mark the file as selectedSha.
        state.pathStack = path.slice(0, -1);
        if (state.pathStack.length === 0) state.pathStack = [tree];
        state.selectedSha = sha;
        render();
        showSection(sha, 'findings');
        maybeRenderSource(sha);
        return true;
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
        }).catch(() => {});
    });

    // Search: when query is non-empty, replace columns with a flat list of
    // matching files. When cleared, restore the column view.
    const search = document.getElementById('files-search-input');
    if (search) {
        search.addEventListener('input', () => {
            const q = search.value.trim().toLowerCase();
            if (!q) {
                render();
                return;
            }
            const matches = [];
            (function walk(n) {
                if (!n) return;
                if (!n.d && n.sha) {
                    if ((n.p || '').toLowerCase().includes(q) || (n.n || '').toLowerCase().includes(q)) {
                        matches.push(n);
                    }
                }
                if (n.c) for (const c of n.c) walk(c);
            })(tree);

            millerEl.innerHTML = '';
            const col = document.createElement('div');
            col.className = 'files-miller-col files-miller-col-fill';
            const head = document.createElement('div');
            head.className = 'files-miller-colhead';
            head.textContent = `${matches.length} match${matches.length === 1 ? '' : 'es'}`;
            col.appendChild(head);
            const list = document.createElement('ul');
            list.className = 'files-miller-list';
            for (const m of matches) {
                const li = document.createElement('li');
                li.className = 'files-miller-row leaf';
                if (state.selectedSha === m.sha) li.classList.add('selected');
                li.dataset.fileSha = m.sha;
                li.dataset.display = m.p || m.n;
                const dot = document.createElement('span');
                dot.className = 'dot ' + classForRisk(m);
                li.appendChild(dot);
                const nm = document.createElement('span');
                nm.className = 'nm';
                nm.textContent = m.p || m.n;
                nm.title = m.p || m.n;
                li.appendChild(nm);
                if (m.ty) {
                    const ty = document.createElement('span');
                    ty.className = 'meta';
                    ty.textContent = m.ty;
                    li.appendChild(ty);
                }
                const meta = document.createElement('span');
                meta.className = 'meta';
                meta.textContent = m.sz || '';
                li.appendChild(meta);
                li.addEventListener('click', () => {
                    selectBySha(m.sha);
                    search.value = '';
                });
                list.appendChild(li);
            }
            col.appendChild(list);
            millerEl.appendChild(col);
        });
    }

    function applyHash() {
        const h = location.hash.replace(/^#/, '');
        const m = h.match(/file=([0-9a-f]{8,64})/i);
        if (!m) return false;
        const tm = h.match(/(?:^|&)trait=([^&]+)/);
        state.pendingTrait = tm ? decodeURIComponent(tm[1]) : null;
        const lm = h.match(/(?:^|&)line=(\d+)/);
        state.pendingLine = lm ? parseInt(lm[1], 10) : null;
        // Bring the Files tab forward — links from the Traits tab's expanded
        // sources rely on this to actually become visible.
        const filesTab = document.querySelector('.tab[data-tab="files"]');
        if (filesTab && !filesTab.classList.contains('active')) filesTab.click();
        return selectBySha(m[1]);
    }
    window.addEventListener('hashchange', applyHash);

    // Initial render: try hash, then auto-open the most suspicious leaf.
    if (!tree) {
        // No tree (non-archive page somehow ended up here): leave the pane
        // empty for the template's own fallback.
    } else if (!applyHash()) {
        // Auto-select the highest-probability leaf in the tree, if any.
        let best = null;
        (function walk(n) {
            if (!n.d && n.sha) {
                if (!best || n.pr > best.pr) best = n;
            }
            if (n.c) for (const c of n.c) walk(c);
        })(tree);
        if (best) {
            selectBySha(best.sha);
        } else {
            render();
        }
    }
}
