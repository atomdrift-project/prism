const input = document.getElementById('file-input');
const form = document.getElementById('upload-form');
const uploadStatus = document.getElementById('upload-status');
const filterForm = document.getElementById('filter-form');
const criticalityFilter = document.getElementById('criticality');
const ecosystemFilter = document.getElementById('ecosystem-filter');
const domainFilter = document.getElementById('domain-filter');
const searchForm = document.getElementById('search-form');
const searchInput = document.getElementById('search-input');
const maxSize = 100 * 1024 * 1024; // 100 MB

document.querySelectorAll('[data-gradient]').forEach(el => { el.style.background = el.getAttribute('data-gradient'); });

function setStatusText(message, className = '') {
    uploadStatus.className = 'top-upload-status' + (className ? ' ' + className : '');
    uploadStatus.textContent = message;
}

function setAnalyzingStatus(fileName) {
    uploadStatus.className = 'top-upload-status is-analyzing';
    uploadStatus.innerHTML = '<span class="analyzing-label">Analyzing</span><span class="analyzing-dots" aria-hidden="true"><span></span><span></span><span></span></span> <span class="analyzing-file"></span>';
    uploadStatus.querySelector('.analyzing-file').textContent = fileName;
}

// --- Search query language ----------------------------------------------
//
// The search box is the canonical view of the URL state. Supported tokens
// (whitespace-separated, case-insensitive keys):
//   sha256:<hex>   → /file/<hex> redirect
//   crit:<v>       → ?criticality=<v>   (hostile | suspicious | benign, or >2/>=2/=1/2)
//   ecosystem:<v>  → path /<v>/ (alias eco:)
//   domain:<v>     → ?domain=<v>
//   m:<formula>    → ?m=<formula>       (alias malecule:, formula:)
//   <64-hex>       → sha256:<hex> (paste a hash without prefix)
//   <bare token>   → ?q=<term> (filename substring or SHA prefix)
//
// Mirror of composeSearchQuery() in main.go — keep the prefixes in sync.

const SHA_RE = /^[a-f0-9]{64}$/i;
// Heuristic for a chemical formula like "C6H12O6" or "NaCl" — starts with
// a capital, then alternating element symbols and digit runs, no spaces.
const FORMULA_RE = /^([A-Z][a-z]?\d*)+$/;
const CRIT_NAMES = new Set(['hostile', 'suspicious', 'benign']);

function critFromNumeric(raw) {
    // crit:>2 → hostile, crit:>=2 → suspicious (lowest that satisfies),
    // crit:=N or crit:N → exact band. The backend takes a single
    // criticality, so >=N collapses to the threshold itself.
    const m = raw.match(/^(>=|<=|>|<|=)?\s*(\d+)$/);
    if (!m) return '';
    const op = m[1] || '=';
    const n = parseInt(m[2], 10);
    const byClass = { 3: 'hostile', 2: 'suspicious', 1: 'benign' };
    if (op === '>') return byClass[n + 1] || '';
    if (op === '<') return byClass[n - 1] || '';
    // >=, <=, = all collapse to the named band at N
    return byClass[n] || '';
}

function normalizeCrit(value) {
    const v = (value || '').trim().toLowerCase();
    if (CRIT_NAMES.has(v)) return v;
    return critFromNumeric(v);
}

function parseQuery(text) {
    const out = { crit: '', ecosystem: '', domain: '', m: '', q: '', sha: '' };
    if (!text) return out;
    const tokens = text.trim().split(/\s+/);
    const free = [];
    for (const tok of tokens) {
        const colonAt = tok.indexOf(':');
        if (colonAt > 0) {
            const key = tok.slice(0, colonAt).toLowerCase();
            const val = tok.slice(colonAt + 1);
            if (!val) continue;
            switch (key) {
                case 'sha256':
                case 'sha':
                    if (SHA_RE.test(val)) out.sha = val.toLowerCase();
                    continue;
                case 'crit':
                case 'criticality': {
                    const c = normalizeCrit(val);
                    if (c) out.crit = c;
                    continue;
                }
                case 'ecosystem':
                case 'eco':
                    out.ecosystem = val.toLowerCase();
                    continue;
                case 'domain':
                    out.domain = val.toLowerCase();
                    continue;
                case 'm':
                case 'malecule':
                case 'molecule':
                case 'formula':
                    out.m = val;
                    continue;
                case 'q':
                case 'filename':
                case 'file':
                    free.push(val);
                    continue;
                default:
                    free.push(tok);
                    continue;
            }
        }
        // Bare token. SHA paste > formula heuristic > free text.
        if (SHA_RE.test(tok)) {
            out.sha = tok.toLowerCase();
            continue;
        }
        if (!out.m && FORMULA_RE.test(tok) && /\d/.test(tok)) {
            out.m = tok;
            continue;
        }
        free.push(tok);
    }
    out.q = free.join(' ');
    return out;
}

function composeQueryString(parsed) {
    const parts = [];
    if (parsed.sha) return 'sha256:' + parsed.sha;
    if (parsed.crit) parts.push('crit:' + parsed.crit);
    if (parsed.ecosystem) parts.push('ecosystem:' + parsed.ecosystem);
    if (parsed.domain) parts.push('domain:' + parsed.domain);
    if (parsed.m) parts.push('m:' + parsed.m);
    if (parsed.q) parts.push(parsed.q);
    return parts.join(' ');
}

function buildURL(parsed) {
    const eco = parsed.ecosystem ? '/' + encodeURIComponent(parsed.ecosystem) + '/' : '/';
    const url = new URL(window.location.origin + eco);
    if (parsed.crit) url.searchParams.set('criticality', parsed.crit);
    if (parsed.domain) url.searchParams.set('domain', parsed.domain);
    if (parsed.m) url.searchParams.set('m', parsed.m);
    if (parsed.q) url.searchParams.set('q', parsed.q);
    return url.toString();
}

function navigateFromBox() {
    const parsed = parseQuery(searchInput ? searchInput.value : '');
    if (parsed.sha) {
        window.location = '/file/' + parsed.sha;
        return;
    }
    window.location = buildURL(parsed);
}

function updateFilter(key, value) {
    if (!searchInput) return;
    const parsed = parseQuery(searchInput.value);
    parsed[key] = value || '';
    // Picking from a structured dropdown invalidates any pending SHA paste.
    parsed.sha = '';
    searchInput.value = composeQueryString(parsed);
    window.location = buildURL(parsed);
}

if (searchForm) {
    searchForm.addEventListener('submit', function(ev) {
        ev.preventDefault();
        navigateFromBox();
    });
}

if (criticalityFilter) {
    criticalityFilter.addEventListener('change', function() {
        updateFilter('crit', criticalityFilter.value);
    });
}

if (ecosystemFilter) {
    ecosystemFilter.addEventListener('change', function() {
        updateFilter('ecosystem', ecosystemFilter.value);
    });
}

if (domainFilter) {
    domainFilter.addEventListener('change', function() {
        updateFilter('domain', domainFilter.value);
    });
}

// Suppress the legacy filter form's native submission — all navigation
// now flows through the search box parser so the dropdown change handler
// is the only path that touches the URL.
if (filterForm) {
    filterForm.addEventListener('submit', function(ev) {
        ev.preventDefault();
        navigateFromBox();
    });
}

if (input && form) {
    input.addEventListener('change', function() {
        if (input.files.length === 0) return;
        const file = input.files[0];
        if (file.size > maxSize) {
            uploadStatus.className = 'top-upload-status';
            uploadStatus.innerHTML = 'File exceeds 100 MB. Use <a href="https://codeberg.org/atomdrift/litmus">litmus CLI</a>.';
            input.value = '';
            return;
        }
        setAnalyzingStatus(file.name);
        form.submit();
    });

    form.addEventListener('submit', function() {
        setTimeout(function() {
            setStatusText('Waiting for analysis server to start up...');
        }, 3000);
        setTimeout(function() {
            setStatusText('Analysis server is starting up; this may take up to a minute.');
        }, 15000);
    });
}
