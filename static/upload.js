const input = document.getElementById("file-input");
const form = document.getElementById("upload-form");
const uploadStatus = document.getElementById("upload-status");
const filterForm = document.getElementById("filter-form");
const criticalityFilter = document.getElementById("criticality");
const ecosystemFilter = document.getElementById("ecosystem-filter");
const domainFilter = document.getElementById("domain-filter");
const searchForm = document.getElementById("search-form");
const searchInput = document.getElementById("search-input");
const maxSize = 100 * 1024 * 1024; // 100 MB

document.querySelectorAll("[data-gradient]").forEach((el) => {
  el.style.background = el.getAttribute("data-gradient");
});

// When the user clicks into a file from the feed, capture the visible
// result set into sessionStorage so the result page can render prev/next
// arrows that iterate through whatever query the user is browsing. Per-tab
// (sessionStorage) so independent tabs don't trample each other; cleared
// implicitly when the tab closes or the user lands on another feed page
// and re-clicks (overwrites the entry).
document.addEventListener("click", (ev) => {
  const link = ev.target.closest('a.file-link[href^="/file/"]');
  if (!link) return;
  const all = Array.from(document.querySelectorAll('a.file-link[href^="/file/"]'));
  const samples = all
    .map((a) => ({
      sha: (a.getAttribute("href") || "").replace(/^\/file\//, ""),
      label: (a.textContent || "").trim(),
    }))
    .filter((s) => /^[0-9a-f]{8,64}$/i.test(s.sha));
  try {
    sessionStorage.setItem(
      "prism_nav",
      JSON.stringify({
        returnUrl: location.pathname + location.search,
        // Fewer than 2 samples means nothing to iterate through, so the
        // result page renders no prev/next arrows — but we still record
        // returnUrl so the `x` shortcut returns to this exact feed view.
        samples: samples.length >= 2 ? samples : [],
        savedAt: Date.now(),
      })
    );
  } catch (_) {
    /* private mode / quota — ignore, fall back to no arrows */
  }
});

function setStatusText(message, className = "") {
  uploadStatus.className = `top-upload-status${className ? ` ${className}` : ""}`;
  uploadStatus.textContent = message;
}

function setAnalyzingStatus(fileName) {
  uploadStatus.className = "top-upload-status is-analyzing";
  uploadStatus.innerHTML =
    '<span class="analyzing-label">Analyzing</span><span class="analyzing-dots" aria-hidden="true"><span></span><span></span><span></span></span> <span class="analyzing-file"></span>';
  uploadStatus.querySelector(".analyzing-file").textContent = fileName;
}

// --- Search query language ----------------------------------------------
//
// The search box is the canonical view of the URL state. Supported tokens
// (whitespace-separated, case-insensitive keys):
//   sha256:<hex>   → /file/<hex> redirect
//   crit:<v>       → ?criticality=<v>   (hostile | suspicious | benign, or a
//                                        comparison over the class number:
//                                        N, =N, >=N, >N, <=N, <N where
//                                        0=benign, 1=suspicious, 2=hostile)
//   ecosystem:<v>  → path /<v>/ (alias eco:)
//   domain:<v>     → ?domain=<v>
//   m:<formula>    → ?m=<formula>       (alias malecule:, formula:)
//   purl:<coord>   → ?purl=<coord>      (package identity; pkg: added by server)
//   name:<name>    → ?name=<name>      (identity claim; rest of query, spaces OK)
//   signer:<org>   → ?signer=<org>     (identity claim by signer; rest of query)
//   <64-hex>       → sha256:<hex> (paste a hash without prefix)
//   <pkg:type/…>   → ?purl=<coord> (paste a PURL without the purl: prefix)
//   <bare token>   → ?q=<term> (filename substring or exact SHA-256)
//
// Mirror of composeSearchQuery() in main.go — keep the prefixes in sync.

const SHA_RE = /^[a-f0-9]{64}$/i;
// Heuristic for a chemical formula like "C6H12O6" or "NaCl" — starts with
// a capital, then alternating element symbols and digit runs, no spaces.
const FORMULA_RE = /^([A-Z][a-z]?\d*)+$/;
// "any" is an explicit token: the server defaults a missing ?criticality=
// to hostile, so the unfiltered view needs criticality=any in the URL.
const CRIT_NAMES = new Set(["hostile", "suspicious", "benign", "any"]);

function critFromNumeric(raw) {
  // Pass comparison expressions through verbatim — the server's
  // criticalityClasses() parses the same grammar (=N, >=N, >N, <=N,
  // <N) over the raw class number (0=benign, 1=suspicious, 2=hostile).
  // Bare digits become "=N" before we return, so the canonical URL
  // form is always "<op><digit>".
  const m = raw.match(/^(>=|<=|>|<|=)?\s*(\d+)$/);
  if (!m) return "";
  const op = m[1] || "=";
  const n = parseInt(m[2], 10);
  if (n < 0 || n > 9) return "";
  return op + n;
}

function normalizeCrit(value) {
  const v = (value || "").trim().toLowerCase();
  if (CRIT_NAMES.has(v)) return v;
  return critFromNumeric(v);
}

function parseQuery(text) {
  const out = {
    crit: "",
    ecosystem: "",
    domain: "",
    m: "",
    q: "",
    sha: "",
    purl: "",
    name: "",
    signer: "",
  };
  if (!text) return out;
  // A leading name:/signer: token consumes the rest of the query — identity
  // names and signers legitimately contain spaces ("Igor Pavlov"). Mirror of
  // claimTokenFromSearchQuery in main.go.
  const claim = text.trim().match(/^(name|signer):\s*(\S.*)$/i);
  if (claim) {
    out[claim[1].toLowerCase()] = claim[2].trim();
    return out;
  }
  const tokens = text.trim().split(/\s+/);
  const free = [];
  for (const tok of tokens) {
    const colonAt = tok.indexOf(":");
    if (colonAt > 0) {
      const key = tok.slice(0, colonAt).toLowerCase();
      const val = tok.slice(colonAt + 1);
      if (!val) continue;
      switch (key) {
        case "sha256":
        case "sha":
          if (SHA_RE.test(val)) out.sha = val.toLowerCase();
          continue;
        case "crit":
        case "criticality": {
          const c = normalizeCrit(val);
          if (c) out.crit = c;
          continue;
        }
        case "ecosystem":
        case "eco":
          out.ecosystem = val.toLowerCase();
          continue;
        case "domain":
          out.domain = val.toLowerCase();
          continue;
        case "m":
        case "malecule":
        case "molecule":
        case "formula":
          out.m = val;
          continue;
        case "purl":
          // The value keeps any pkg: scheme (sliced after the first colon
          // only); the server prepends it when absent and canonicalizes.
          out.purl = val;
          continue;
        case "pkg":
          // A bare PURL pasted without the purl: prefix: the pkg: scheme is
          // itself the token key, so keep the whole token as the coordinate.
          out.purl = tok;
          continue;
        case "q":
        case "filename":
        case "file":
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
  out.q = free.join(" ");
  return out;
}

function composeQueryString(parsed) {
  const parts = [];
  if (parsed.sha) return `sha256:${parsed.sha}`;
  if (parsed.name) return `name:${parsed.name}`;
  if (parsed.signer) return `signer:${parsed.signer}`;
  if (parsed.crit) parts.push(`crit:${parsed.crit}`);
  if (parsed.purl) parts.push(`purl:${parsed.purl}`);
  if (parsed.ecosystem) parts.push(`ecosystem:${parsed.ecosystem}`);
  if (parsed.domain) parts.push(`domain:${parsed.domain}`);
  if (parsed.m) parts.push(`m:${parsed.m}`);
  if (parsed.q) parts.push(parsed.q);
  return parts.join(" ");
}

function buildURL(parsed) {
  const eco = parsed.ecosystem ? `/${encodeURIComponent(parsed.ecosystem)}/` : "/";
  const url = new URL(window.location.origin + eco);
  if (parsed.crit) url.searchParams.set("criticality", parsed.crit);
  if (parsed.purl) url.searchParams.set("purl", parsed.purl);
  if (parsed.name) url.searchParams.set("name", parsed.name);
  if (parsed.signer) url.searchParams.set("signer", parsed.signer);
  if (parsed.domain) url.searchParams.set("domain", parsed.domain);
  if (parsed.m) url.searchParams.set("m", parsed.m);
  if (parsed.q) url.searchParams.set("q", parsed.q);
  return url.toString();
}

function navigateFromBox() {
  const parsed = parseQuery(searchInput ? searchInput.value : "");
  if (parsed.sha) {
    window.location = `/file/${parsed.sha}`;
    return;
  }
  window.location = buildURL(parsed);
}

function updateFilter(key, value) {
  if (!searchInput) return;
  const parsed = parseQuery(searchInput.value);
  parsed[key] = value || "";
  // Picking from a structured dropdown invalidates any pending SHA paste.
  parsed.sha = "";
  searchInput.value = composeQueryString(parsed);
  window.location = buildURL(parsed);
}

if (searchForm) {
  searchForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    navigateFromBox();
  });
}

if (criticalityFilter) {
  criticalityFilter.addEventListener("change", () => {
    updateFilter("crit", criticalityFilter.value);
  });
}

if (ecosystemFilter) {
  ecosystemFilter.addEventListener("change", () => {
    updateFilter("ecosystem", ecosystemFilter.value);
  });
}

if (domainFilter) {
  domainFilter.addEventListener("change", () => {
    updateFilter("domain", domainFilter.value);
  });
}

// The feeds checkbox rides the URL directly rather than the search-box
// language: it is a boolean view toggle (?feeds=1), not a query term.
const feedsFilter = document.getElementById("feeds-filter");
if (feedsFilter) {
  feedsFilter.addEventListener("change", () => {
    const url = new URL(window.location);
    if (feedsFilter.checked) {
      url.searchParams.set("feeds", "1");
    } else {
      url.searchParams.delete("feeds");
    }
    url.searchParams.delete("page");
    window.location = url;
  });
}

// Full SHA-256s click-copy — the fastest path from feed row to ticket or
// terminal. The copied state is a brief color flip; clipboard failures
// (permissions, http) degrade to the text simply staying selectable.
document.addEventListener("click", (ev) => {
  const sha = ev.target.closest(".file-sha");
  if (!sha || !navigator.clipboard) return;
  const text = (sha.textContent || "").trim();
  if (!/^[a-f0-9]{64}$/i.test(text)) return;
  navigator.clipboard
    .writeText(text)
    .then(() => {
      sha.classList.add("copied");
      setTimeout(() => sha.classList.remove("copied"), 1200);
    })
    .catch(() => {
      /* clipboard unavailable — the text stays selectable */
    });
});

// Suppress the legacy filter form's native submission — all navigation
// now flows through the search box parser so the dropdown change handler
// is the only path that touches the URL.
if (filterForm) {
  filterForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    navigateFromBox();
  });
}

if (input && form) {
  input.addEventListener("change", () => {
    if (input.files.length === 0) return;
    const file = input.files[0];
    if (file.size > maxSize) {
      uploadStatus.className = "top-upload-status";
      uploadStatus.innerHTML =
        'File exceeds 100 MB. Use <a href="https://github.com/atomdrift-project/litmus">litmus CLI</a>.';
      input.value = "";
      return;
    }
    setAnalyzingStatus(file.name);
    form.submit();
  });

  form.addEventListener("submit", () => {
    setTimeout(() => {
      setStatusText("Waiting for analysis server to start up...");
    }, 3000);
    setTimeout(() => {
      setStatusText("Analysis server is starting up; this may take up to a minute.");
    }, 15000);
  });
}

// --- Live "files indexed" counter ----------------------------------------
//
// The masthead shows the latest published estimate of how many files are in
// the index. A background poller on the server refreshes ~every 15s; the
// endpoint only serves that cached value (projected to the request clock), so
// a client never touches the database. Each response is an anchor {total,
// rate_per_min, as_of}; the rate is the exact 2h insert average, and we
// advance the digits at that speed between polls — capped at 15s so a stalled
// poller cannot invent more growth than the skew budget. Re-anchors follow
// the server in both directions (ANALYZE can correct downward). Each whole-
// number tick flicks the dot and kicks the peak meter. Progressive
// enhancement: the server-rendered value shows without JS; a failed poll
// holds after the 15s cap. Guarded so it no-ops on pages without the counter.
(() => {
  const el = document.getElementById("index-counter");
  if (!el) return;
  const numEl = document.getElementById("counter-num");
  const meterEl = document.getElementById("counter-meter");
  const dotEl = document.getElementById("counter-dot");
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  // Match statsPollInterval so the client re-anchors as soon as a fresh
  // snapshot is typically available, and never coasts further than one poll.
  const POLL_MS = 15000;
  const STALE_CAP_SEC = 15;

  const SEGMENTS = 10;
  const segs = [];
  if (meterEl) {
    for (let i = 0; i < SEGMENTS; i++) {
      const s = document.createElement("div");
      s.className = "peak-seg";
      meterEl.appendChild(s);
      segs.push(s);
    }
  }
  let level = 0.14;
  let peak = 0.14;

  // anchor: { total, ratePerSec, asOfMs }. displayed is the eased on-screen
  // value; started gates the loop until we have any anchor.
  let anchor = null;
  let displayed = 0;
  let lastWhole = 0;
  let started = false;

  const fmt = (n) => Math.floor(n).toLocaleString("en-US");

  // Projected value of an anchor at the current wall clock, capped at one
  // poll interval so a stale anchor can't run away.
  const projected = (a) => {
    if (!a) return displayed;
    const elapsed = Math.min(STALE_CAP_SEC, Math.max(0, (Date.now() - a.asOfMs) / 1000));
    return a.total + a.ratePerSec * elapsed;
  };

  const applyAnchor = (d) => {
    const next = {
      total: Number(d.total),
      ratePerSec: Number(d.rate_per_min || 0) / 60,
      asOfMs: Number(d.as_of),
    };
    if (!Number.isFinite(next.total) || !Number.isFinite(next.asOfMs)) return;
    anchor = next;
    started = true;
  };

  // Seed from the server-rendered attributes so the counter is live on first
  // paint, before the first poll returns.
  const seed = {
    total: parseFloat(el.getAttribute("data-total")),
    rate_per_min: parseFloat(el.getAttribute("data-rate")),
    as_of: parseFloat(el.getAttribute("data-asof")),
  };
  if (Number.isFinite(seed.total) && Number.isFinite(seed.as_of)) {
    applyAnchor(seed);
    displayed = projected(anchor);
    lastWhole = Math.floor(displayed);
    if (numEl) numEl.textContent = fmt(displayed);
  }

  const poll = () => {
    fetch("/_/stats", { headers: { Accept: "application/json" }, cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && typeof d.total === "number") applyAnchor(d);
      })
      .catch(() => {
        /* hold after the 15s cap — do not invent further digits */
      });
  };

  let lastFrame = performance.now();
  const frame = (now) => {
    const dt = Math.min(0.1, (now - lastFrame) / 1000);
    lastFrame = now;

    if (started) {
      const target = projected(anchor);
      const delta = target - displayed;
      if (reduceMotion || Math.abs(delta) < 0.5) {
        displayed = target;
      } else {
        displayed += delta * Math.min(1, dt * 3);
      }
      const whole = Math.floor(displayed);
      if (whole !== lastWhole) {
        const ticks = Math.abs(whole - lastWhole);
        lastWhole = whole;
        if (numEl) numEl.textContent = fmt(displayed);
        if (!reduceMotion) {
          level = Math.min(1, level + 0.26 * Math.min(ticks, 3));
          if (dotEl) {
            dotEl.classList.add("blip");
            setTimeout(() => dotEl.classList.remove("blip"), 110);
          }
        }
      } else if (numEl && displayed === target && numEl.textContent !== fmt(displayed)) {
        numEl.textContent = fmt(displayed);
      }
    }

    if (segs.length) {
      if (reduceMotion) {
        level = 0.4;
        peak = 0.6;
      } else {
        level *= 0.5 ** (dt / 0.55); // ~0.55s half-life
        peak = Math.max(level, peak * 0.5 ** (dt / 2.4)); // slow peak-hold
      }
      const lit = Math.max(1, Math.round(level * SEGMENTS));
      const pIdx = Math.min(SEGMENTS - 1, Math.max(0, Math.round(peak * SEGMENTS) - 1));
      for (let i = 0; i < SEGMENTS; i++) {
        const on = i < lit;
        segs[i].classList.toggle("on", on);
        segs[i].classList.toggle("hi", on && i >= SEGMENTS - 3);
        segs[i].classList.toggle("peak", i === pIdx && pIdx >= lit);
      }
    }
    requestAnimationFrame(frame);
  };

  poll();
  setInterval(poll, POLL_MS);
  requestAnimationFrame(frame);
})();
