// Hero prev/next iteration + global keyboard shortcuts. The arrows render
// only when the user landed on this sample by clicking through the feed —
// upload.js stashes the visible result set in sessionStorage on that
// click. j/k mirror the buttons (Gmail/GitHub convention: j = next,
// k = prev). r and d trigger the rescan and download buttons when they
// exist on the page, regardless of nav context. ? opens a help dialog
// listing every shortcut that's currently active.

const hero = document.querySelector(".hero");
let prev = null;
let next = null;
// Where the `x` shortcut and the "Analyze another" link return to. Defaults
// to the bare feed; upgraded to the exact query the user clicked in from
// (e.g. /?feeds=1) when upload.js stashed it. Same-origin only.
let returnUrl = "/";

let nav = null;
try {
  nav = JSON.parse(sessionStorage.getItem("prism_nav") || "null");
} catch (_) {
  nav = null;
}

// Guard against a poisoned sessionStorage value: only honor a relative path
// (a single leading slash), never an absolute or protocol-relative URL that
// would redirect off-site.
if (
  nav &&
  typeof nav.returnUrl === "string" &&
  nav.returnUrl.startsWith("/") &&
  !nav.returnUrl.startsWith("//")
) {
  returnUrl = nav.returnUrl;
  const backLink = document.querySelector(".back-link");
  if (backLink) backLink.setAttribute("href", returnUrl);
}

if (hero) {
  const samples = nav && Array.isArray(nav.samples) ? nav.samples : null;
  const m = location.pathname.match(/\/file\/([0-9a-f]{8,64})/i);
  const sha = m ? m[1].toLowerCase() : null;
  const i =
    samples && sha ? samples.findIndex((s) => s.sha.toLowerCase() === sha) : -1;

  if (i >= 0) {
    hero.classList.add("hero-has-nav");
    prev = i > 0 ? samples[i - 1] : null;
    next = i < samples.length - 1 ? samples[i + 1] : null;
    if (prev) hero.appendChild(makeArrow(prev, "prev"));
    if (next) hero.appendChild(makeArrow(next, "next"));
  }
}

wireKeys();
wireDownloadClipboard();

// Browser save dialogs default to the URL's basename — for our download
// route that's `<sha>.dl`, which is useless when the user actually wants
// the original filename. Copy the real basename to the clipboard on
// click (both mouse and the `d` shortcut route here, since the keyboard
// path calls `.click()`) so the user can paste it into the save dialog.
function wireDownloadClipboard() {
  const link = document.querySelector(".download-btn[data-basename]");
  if (!link) return;
  const live = document.getElementById("a11y-live");
  link.addEventListener("click", () => {
    const name = link.dataset.basename;
    if (!name || !navigator.clipboard?.writeText) return;
    // Fire-and-forget: we don't await this. Clipboard writes have to
    // happen synchronously inside the user-gesture handler, and the
    // download navigation continues regardless.
    navigator.clipboard.writeText(name).then(
      () => {
        link.classList.add("is-done");
        setTimeout(() => link.classList.remove("is-done"), 1500);
        if (live) {
          live.textContent = "";
          requestAnimationFrame(() => {
            live.textContent = "Filename " + name + " copied to clipboard.";
          });
        }
      },
      () => {
        /* clipboard write blocked (e.g. insecure origin) — let the
           download proceed silently */
      },
    );
  });
}

function makeArrow(target, dir) {
  const a = document.createElement("a");
  a.className = "hero-nav hero-nav-" + dir;
  a.href = "/file/" + target.sha;
  const glyph = dir === "prev" ? "‹" : "›";
  const word = dir === "prev" ? "Previous" : "Next";
  const key = dir === "prev" ? "k" : "j";
  a.setAttribute(
    "aria-label",
    word + " sample: " + target.label + " (press " + key + ")",
  );
  a.title =
    (dir === "prev" ? "← " : "") + target.label + (dir === "next" ? " →" : "");
  a.innerHTML = '<span aria-hidden="true">' + glyph + "</span>";
  return a;
}

function wireKeys() {
  document.addEventListener("keydown", (ev) => {
    if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
    const t = ev.target;
    if (
      t &&
      (t.tagName === "INPUT" ||
        t.tagName === "TEXTAREA" ||
        t.isContentEditable)
    )
      return;
    switch (ev.key) {
      case "j":
        if (next) {
          ev.preventDefault();
          location.href = "/file/" + next.sha;
        }
        break;
      case "k":
        if (prev) {
          ev.preventDefault();
          location.href = "/file/" + prev.sha;
        }
        break;
      case "r": {
        // Trigger the rescan button if present and not already disabled
        // mid-flight. rescan.js owns the click — we just synthesize one.
        const btn = document.querySelector(".rescan-btn:not([disabled])");
        if (btn) {
          ev.preventDefault();
          btn.click();
        }
        break;
      }
      case "d": {
        // The download is a plain <a> — .click() honors its href and
        // triggers the browser's normal download/navigate behavior.
        const link = document.querySelector(".download-btn");
        if (link) {
          ev.preventDefault();
          link.click();
        }
        break;
      }
      case "x":
        // Mirror the header's "Analyze another" link — quick exit back
        // to the feed the user came from (preserving its query), without
        // reaching for the mouse.
        ev.preventDefault();
        location.href = returnUrl;
        break;
      case "?":
        ev.preventDefault();
        openHelp();
        break;
    }
  });
}

// Lazily-built help dialog. Lists only shortcuts that have something to
// act on for this page, so users don't see "press r to rescan" when
// rescan isn't available right now.
let helpDialog = null;
function openHelp() {
  if (!helpDialog) helpDialog = buildHelpDialog();
  refreshHelpRows(helpDialog);
  if (typeof helpDialog.showModal === "function") helpDialog.showModal();
  else helpDialog.setAttribute("open", "");
}

function buildHelpDialog() {
  const d = document.createElement("dialog");
  d.className = "kbd-help";
  d.setAttribute("aria-labelledby", "kbd-help-title");
  d.innerHTML = `
    <form method="dialog" class="kbd-help-form">
      <div class="kbd-help-head">
        <h2 id="kbd-help-title">Keyboard shortcuts</h2>
        <button type="submit" class="kbd-help-close" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <dl class="kbd-help-list" id="kbd-help-list"></dl>
    </form>`;
  document.body.appendChild(d);
  // Click on the backdrop (outside the form) dismisses the dialog.
  d.addEventListener("click", (ev) => {
    if (ev.target === d) d.close();
  });
  return d;
}

function refreshHelpRows(dialog) {
  const list = dialog.querySelector("#kbd-help-list");
  if (!list) return;
  const rows = [];
  if (next) rows.push(["j", "Next sample"]);
  if (prev) rows.push(["k", "Previous sample"]);
  if (document.querySelector(".rescan-btn:not([disabled])"))
    rows.push(["r", "Re-queue analysis"]);
  if (document.querySelector(".download-btn"))
    rows.push(["d", "Download original bytes"]);
  rows.push(["x", "Back to the feed"]);
  rows.push(["?", "This help"]);
  rows.push(["Esc", "Close help"]);
  list.replaceChildren();
  for (const [key, label] of rows) {
    const dt = document.createElement("dt");
    const kbd = document.createElement("kbd");
    kbd.textContent = key;
    dt.appendChild(kbd);
    const dd = document.createElement("dd");
    dd.textContent = label;
    list.append(dt, dd);
  }
}
