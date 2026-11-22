// The API page's "Try it" card: one tab per endpoint, and a Run button that
// sends the request shown and prints the answer. Without this script both
// examples stay on the page as plain curl lines.

const tabs = Array.from(document.querySelectorAll('[role="tab"]'));

function select(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute("aria-selected", String(on));
    document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
  }
}

for (const tab of tabs) {
  tab.addEventListener("click", () => select(tab));
}
if (tabs.length > 0) select(tabs[0]);

async function run(pane, button, out) {
  button.disabled = true;
  out.textContent = "…";
  try {
    const res = await fetch(pane.dataset.url, { headers: { Accept: "application/json" } });
    const text = await res.text();
    let body = text;
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      // Not JSON: show what came back as it is.
    }
    out.textContent = `${res.status}\n${body}`;
  } catch {
    out.textContent = "Unreachable.";
  } finally {
    button.disabled = false;
  }
}

for (const pane of document.querySelectorAll(".try")) {
  const button = pane.querySelector(".run");
  const out = pane.querySelector(".out");
  button.addEventListener("click", () => run(pane, button, out));
}
