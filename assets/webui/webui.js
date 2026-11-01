// The parts token webui and cert webui share. The page draws one CA from the API, sending the
// key, which the tab keeps, as its bearer token; the CA on the page is in the address as ?ca=. The
// script of the page, loaded after this one, defines showCA, which draws the CA.
const keyName = "simple-ca-webui-key";
const params = new URLSearchParams(location.search);
if (params.has("key")) {
  sessionStorage.setItem(keyName, params.get("key"));
  params.delete("key");
}
let caID = params.get("ca") || "";
let info = null;
const $ = (id) => document.getElementById(id);

// element returns a new element with the properties given and the children appended.
function element(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  node.append(...children.filter((child) => child !== null));
  return node;
}

// api sends a request of the API and returns its answer; a missing or wrong key asks for one.
async function api(method, path, body) {
  const headers = { Authorization: "Bearer " + (sessionStorage.getItem(keyName) || "") };
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, { method, headers, body: body && JSON.stringify(body) });
  const answer = await response.json().catch(() => ({}));
  if (response.status === 401) {
    askKey(sessionStorage.getItem(keyName) ? "This key is wrong. Start the page again for a new key." : "");
    throw new Error("no key");
  }
  if (!response.ok) {
    throw new Error(answer.error || response.statusText);
  }
  return answer;
}

// askKey shows the dialog asking for the key, with the error given.
function askKey(failure) {
  $("login-error").textContent = failure;
  $("login-error").classList.toggle("hidden", !failure);
  if (!$("login").open) {
    $("login").showModal();
  }
}
$("login").addEventListener("cancel", (event) => event.preventDefault());
$("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  sessionStorage.setItem(keyName, $("login-key").value.trim());
  $("login").close();
  load();
});

// say shows a message, or an error, above the CA, and hides the other.
function say(message, failure = "") {
  $("message").textContent = message;
  $("message").classList.toggle("hidden", !message);
  $("error").textContent = failure;
  $("error").classList.toggle("hidden", !failure);
}

// failed shows the error of a request, unless it is the missing key the page asks for.
function failed(error) {
  if (error.message !== "no key") {
    say("", error.message);
  }
}

// confirmed asks the question in the confirmation dialog, with the button named action and the
// elements of extra below the question.
function confirmed(question, action, ...extra) {
  return new Promise((resolve) => {
    const dialog = $("confirm");
    $("confirm-message").textContent = question;
    $("confirm-extra").replaceChildren(...extra);
    $("confirm-action").textContent = action;
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
    dialog.returnValue = "";
    dialog.showModal();
  });
}

// A dialog other than the one asking for the key closes on a click beside it.
for (const dialog of document.querySelectorAll("dialog:not(#login)")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
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
        element("span", { className: "w-3.5 shrink-0 text-link", textContent: v === chosen ? "✓" : "" }),
        element("span", { className: "truncate", textContent: label })))));
  };
  show(value);
  return element("div", { className: "min-w-0" }, input, chooser);
}

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

// load reads the CAs and shows the one in the address, the root CA for one that is not there.
async function load() {
  try {
    info = await api("GET", "/api/cas");
  } catch (error) {
    failed(error);
    return;
  }
  $("title").textContent = info.title + ", managed by simple-ca";
  if (!info.cas.some((ca) => ca.id === caID)) {
    caID = "";
  }
  $("chooser-row").classList.replace("hidden", "flex");
  await showCA();
}

// choose shows the CA id.
function choose(id) {
  caID = id;
  say("");
  showCA();
}

// currentCA puts the CA on the page in the address and the chooser, and returns it.
function currentCA() {
  params.set("ca", caID);
  history.replaceState(null, "", "/?" + params);
  $("ca-picker").replaceChildren(picker({ name: "ca", id: "ca-chooser", labelledBy: "ca-label",
    choices: info.cas.map((ca) => [ca.id, ca.label]), value: caID, onchange: choose }));
  return info.cas.find((ca) => ca.id === caID);
}

// The parts the pages draw their CA with.
const button = (label, onclick, primary = false) => element("button", { type: "button", onclick, textContent: label,
  className: primary ? "rounded-lg bg-action px-4 py-2 text-sm font-semibold text-action-ink shadow-sm hover:bg-action-hover"
    : "rounded-lg border border-field-line px-2.5 py-1 text-xs font-medium hover:bg-subtle" });
const badge = (text) => element("span", { className: "rounded-full bg-bad px-2 py-0.5 text-xs font-medium text-bad-ink", textContent: text });
const cell = (content, extra = "") => element("td", { className: "py-1.5 pr-3 " + extra }, content);
const time = (value) => new Date(value).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
const heading = (ca) => element("div", { className: "flex flex-wrap items-baseline justify-between gap-2" },
  element("h2", { className: "text-lg font-semibold", textContent: ca.subject }),
  element("span", { className: "rounded-full bg-subtle px-2.5 py-0.5 text-xs font-medium text-subtle-ink", textContent: ca.role }));
const table = (headings, rows) => element("div", { className: "overflow-x-auto" }, element("table", { className: "w-full text-left text-sm" },
  element("thead", { className: "text-muted" }, element("tr", {}, ...headings.map((h) =>
    element("th", { className: "py-1 pr-3 font-medium", textContent: h })))),
  element("tbody", { className: "divide-y divide-line" }, ...rows)));
const list = (text) => text.split(/[\s,]+/).filter(Boolean);

// start loads the page once the script of the page has defined showCA.
function start() {
  if (sessionStorage.getItem(keyName)) {
    load();
  } else {
    askKey("");
  }
}
