// The parts the pages of serve share, the index page, the signing form, the setup code page and
// the token and certificate pages: element, which makes elements, picker, the dropdown chooser,
// withPopup, which shows a popup by an element, copying, the Copy button of a token or a code,
// and named, the name of a subject with its attributes.

// element returns a new element with the properties given and the children appended.
function element(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  node.append(...children.filter((child) => child !== null));
  return node;
}

// picker returns a dropdown chooser, labelled by the element labelledBy, of the choices, each a
// value and its label, with value chosen; a hidden input named name holds the value chosen, and
// onchange is called with a value chosen anew. The chooser is a details element with id, when
// given.
function picker({ name, id = "", labelledBy, choices, value, onchange = () => {} }) {
  const input = element("input", { type: "hidden", name, value });
  const current = element("span", { className: "truncate" });
  const list = element("ul", { role: "listbox",
    className: "absolute right-0 left-0 z-10 mt-1 max-h-80 overflow-y-auto rounded-lg border border-line bg-card py-1 text-sm shadow-lg" });
  const chooser = element("details", { id, className: "relative min-w-0" },
    element("summary", { className: "flex cursor-pointer list-none items-center justify-between gap-3 rounded-lg border border-field-line bg-field px-3 py-2 text-sm hover:border-action [&::-webkit-details-marker]:hidden" },
      current, element("span", { className: "shrink-0 text-muted", ariaHidden: "true",
        innerHTML: '<svg viewBox="0 0 16 16" width="16" height="16"><path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>' })),
    list);
  chooser.dataset.picker = "";
  chooser.querySelector("summary").setAttribute("aria-labelledby", labelledBy);
  list.setAttribute("aria-labelledby", labelledBy);
  const show = (chosen) => {
    input.value = chosen;
    current.textContent = (choices.find(([v]) => v === chosen) || ["", ""])[1];
    list.replaceChildren(...choices.map(([v, label]) => element("li", { role: "option", ariaSelected: String(v === chosen) },
      element("button", { type: "button", className: "flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-subtle" +
        (v === chosen ? " font-semibold" : ""), onclick: () => {
        chooser.open = false;
        chooser.querySelector("summary").focus();
        if (v !== input.value) {
          show(v);
          onchange(v);
        }
      } },
        element("span", { className: "w-3.5 shrink-0 text-link", textContent: v === chosen ? "\u2713" : "" }),
        element("span", { className: "truncate", textContent: label })))));
  };
  show(value);
  return element("div", { className: "min-w-0" }, input, chooser);
}

// withPopup shows popup, a fixed element, below target while the pointer is over target or target
// has the focus, and returns target.
function withPopup(target, popup) {
  const show = () => {
    const box = target.getBoundingClientRect();
    popup.style.left = `${box.left}px`;
    popup.style.top = `${box.bottom + 4}px`;
    popup.classList.remove("hidden");
  };
  const hide = () => popup.classList.add("hidden");
  target.addEventListener("mouseenter", show);
  target.addEventListener("mouseleave", hide);
  target.addEventListener("focus", show);
  target.addEventListener("blur", hide);
  return target;
}

// copying makes button copy the value of field, a token or a setup code shown once, to the
// clipboard, through the selection where the page is not a secure context, and say so for a
// moment; the field selects its value when it gets the focus.
function copying(button, field) {
  field.addEventListener("focus", () => field.select());
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(field.value);
    } catch {
      field.select();
      document.execCommand("copy");
    }
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = "Copy"; }, 2000);
  });
}

// named returns the name of a subject, with the popup of its attributes, each a type and a value,
// and the popup, to be placed together.
function named(name, attributes) {
  const popup = element("div", { role: "tooltip",
    className: "fixed z-20 hidden rounded-lg border border-line bg-card px-3 py-2 text-xs font-normal shadow-lg" },
    element("dl", { className: "grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5" },
      ...attributes.flatMap(([type, value]) => [
        element("dt", { className: "text-muted", textContent: type }), element("dd", { textContent: value })])));
  return [withPopup(element("span", { tabIndex: 0, textContent: name,
    className: "cursor-help underline decoration-muted decoration-dotted underline-offset-4" }), popup), popup];
}


// A popup placed by the page's position is hidden once the page scrolls.
addEventListener("scroll", () => {
  for (const popup of document.querySelectorAll('[role="tooltip"]')) {
    popup.classList.add("hidden");
  }
});

// An open chooser closes on a click outside it, and on Escape, which leaves its dialog open.
document.addEventListener("click", (event) => {
  for (const chooser of document.querySelectorAll("details[data-picker][open]")) {
    if (!chooser.contains(event.target)) {
      chooser.open = false;
    }
  }
});
document.addEventListener("keydown", (event) => {
  const chooser = document.querySelector("details[data-picker][open]");
  if (event.key === "Escape" && chooser) {
    event.preventDefault();
    chooser.open = false;
    chooser.querySelector("summary").focus();
  }
});
