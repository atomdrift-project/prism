// The API page's "Try it" card: a Run button that sends the request shown
// and prints the answer. Without this script the example stays on the page as
// a plain curl line.

async function run(pane, button, out) {
  button.disabled = true;
  out.hidden = false;
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
