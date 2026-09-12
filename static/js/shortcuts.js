// Keyboard shortcuts for the sample detail view.
//
//   j / k   next / previous sample, in the order the feed was showing
//   x       back to the feed this sample was opened from
//   d       download the original bytes
//   r       re-queue the sample for analysis
//
// Downloading also copies the sample's original filename to the clipboard.
//
// j/k only work when the reader arrived by clicking through a feed: upload.js
// stashes the visible result set under prism_nav on that click, so the order
// is the one they were actually looking at rather than a guess made here. No
// stash, or a sample that is not in it, means no j/k — the page never invents
// a neighbour.
//
// d and r are the two buttons the markup already advertises with
// aria-keyshortcuts, so this is what makes those attributes true.

const NAV_KEY = "prism_nav";

// Typing "d" into the search box must type a d. Modified keys belong to the
// browser: ctrl-r reloads, cmd-d bookmarks.
function isTypingTarget(el) {
  if (!el) return false;
  if (el.isContentEditable) return true;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

function readNav() {
  try {
    return JSON.parse(sessionStorage.getItem(NAV_KEY) || "null");
  } catch (_) {
    return null; // private mode, quota, or corrupt JSON
  }
}

function neighbours(nav) {
  const samples = nav && Array.isArray(nav.samples) ? nav.samples : [];
  const match = location.pathname.match(/^\/file\/([0-9a-f]{8,64})/i);
  if (!match || samples.length < 2) return { prev: null, next: null };
  const sha = match[1].toLowerCase();
  const at = samples.findIndex((s) => String(s.sha || "").toLowerCase() === sha);
  if (at < 0) return { prev: null, next: null };
  return {
    prev: at > 0 ? samples[at - 1] : null,
    next: at < samples.length - 1 ? samples[at + 1] : null,
  };
}

// A sha from sessionStorage is the reader's own history, but it still reaches
// us as a string we are about to put in location.href, so it is checked
// against the same shape the router accepts rather than trusted.
function go(sample) {
  const sha = String(sample?.sha ?? "");
  if (!/^[0-9a-f]{8,64}$/i.test(sha)) return;
  location.href = `/file/${sha}`;
}

// The feed to go back to. Same-origin paths only: this is a string from
// storage on its way into location.href, and "//evil.example" is a path to a
// browser but an origin to a user.
function returnURL(nav) {
  const url = String(nav?.returnUrl ?? "");
  if (!url.startsWith("/") || url.startsWith("//")) return "/";
  return url;
}

const nav = readNav();
const { prev, next } = neighbours(nav);

document.addEventListener("keydown", (ev) => {
  if (ev.metaKey || ev.ctrlKey || ev.altKey || ev.shiftKey) return;
  if (ev.defaultPrevented || isTypingTarget(ev.target)) return;

  switch (ev.key) {
    case "j":
      if (!next) return;
      ev.preventDefault();
      go(next);
      return;
    case "k":
      if (!prev) return;
      ev.preventDefault();
      go(prev);
      return;
    case "x":
      ev.preventDefault();
      location.href = returnURL(nav);
      return;
    case "d": {
      // Follow the link rather than navigating by href, so the browser sees a
      // user-activated click and the download attribute still applies.
      const dl = document.querySelector("a.download-btn[href]");
      if (!dl) return;
      ev.preventDefault();
      dl.click();
      return;
    }
    case "r": {
      const refresh = document.querySelector("button.refresh-btn:not([disabled])");
      if (!refresh) return;
      ev.preventDefault();
      refresh.click();
      return;
    }
    default:
  }
});

// Browser save dialogs default to the URL's basename — for the download route
// that is `<sha>.dl`, useless to a reader who wants the original filename. Copy
// the real basename on click so it can be pasted into the save dialog. The `d`
// shortcut lands here too, since it calls .click().
const downloadLink = document.querySelector("a.download-btn[data-basename]");
downloadLink?.addEventListener("click", () => {
  const name = downloadLink.dataset.basename;
  if (!name || !navigator.clipboard?.writeText) return;
  // Not awaited: the write has to start inside the user gesture, and the
  // download navigates regardless of how it settles.
  navigator.clipboard.writeText(name).then(
    () => {
      downloadLink.classList.add("is-done");
      setTimeout(() => downloadLink.classList.remove("is-done"), 1500);
      // Cleared first so a second download of the same name announces again.
      const live = document.getElementById("a11y-live");
      if (!live) return;
      live.textContent = "";
      requestAnimationFrame(() => {
        live.textContent = `Filename ${name} copied to clipboard.`;
      });
    },
    () => {
      /* clipboard blocked (insecure origin, denied permission) — the
         download still proceeds */
    }
  );
});
