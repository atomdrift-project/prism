// Hero prev/next iteration. Only renders when the user landed on this
// sample by clicking through the feed — upload.js stashes the visible
// result set in sessionStorage on that click. If we can't find the
// current SHA in that list (or there's no list), we render nothing.
//
// j / k keyboard shortcuts mirror the buttons: j = next (forward), k =
// previous (back) — matching Gmail/GitHub feed conventions.

const hero = document.querySelector(".hero");
if (hero) {
  let nav = null;
  try {
    nav = JSON.parse(sessionStorage.getItem("prism_nav") || "null");
  } catch (_) {
    nav = null;
  }

  const samples = nav && Array.isArray(nav.samples) ? nav.samples : null;
  const m = location.pathname.match(/\/file\/([0-9a-f]{8,64})/i);
  const sha = m ? m[1].toLowerCase() : null;
  const i =
    samples && sha ? samples.findIndex((s) => s.sha.toLowerCase() === sha) : -1;

  if (i >= 0) {
    // Hero is the absolute positioning context for the arrows. It already
    // has overflow:hidden via the design, so we tuck the arrows just
    // inside the rounded corner of the verdict bar.
    hero.classList.add("hero-has-nav");
    const prev = i > 0 ? samples[i - 1] : null;
    const next = i < samples.length - 1 ? samples[i + 1] : null;
    if (prev) hero.appendChild(makeArrow(prev, "prev"));
    if (next) hero.appendChild(makeArrow(next, "next"));
    wireKeys(prev, next);
  }
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
  a.title = (dir === "prev" ? "← " : "") + target.label + (dir === "next" ? " →" : "");
  a.innerHTML = '<span aria-hidden="true">' + glyph + "</span>";
  return a;
}

function wireKeys(prev, next) {
  document.addEventListener("keydown", (ev) => {
    if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
    const t = ev.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
    if (ev.key === "j" && next) {
      ev.preventDefault();
      location.href = "/file/" + next.sha;
    } else if (ev.key === "k" && prev) {
      ev.preventDefault();
      location.href = "/file/" + prev.sha;
    }
  });
}
