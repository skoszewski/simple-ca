// The parts token webui and cert webui share, after picker.js. The page draws one CA from the API,
// sending the key, which the tab keeps, as its bearer token; the CA on the page is in the address
// as ?ca=. The script of the page, loaded after this one, defines showCA, which draws the CA.
const keyName = "simple-ca-webui-key";
const params = new URLSearchParams(location.search);
if (params.has("key")) {
  sessionStorage.setItem(keyName, params.get("key"));
  params.delete("key");
}
let caID = params.get("ca") || "";
let info = null;
const $ = (id) => document.getElementById(id);

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
const heading = (ca) => {
  const popup = element("div", { role: "tooltip",
    className: "fixed z-20 hidden rounded-lg border border-line bg-card px-3 py-2 text-xs font-normal shadow-lg" },
    element("dl", { className: "grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5" },
      ...ca.subject_attributes.flatMap(([type, value]) => [
        element("dt", { className: "text-muted", textContent: type }), element("dd", { textContent: value })])));
  const name = withPopup(element("span", { tabIndex: 0, textContent: ca.name,
    className: "cursor-help underline decoration-muted decoration-dotted underline-offset-4" }), popup);
  return element("div", { className: "flex flex-wrap items-baseline justify-between gap-2" },
    element("h2", { className: "text-lg font-semibold" }, name, popup),
    element("span", { className: "rounded-full bg-subtle px-2.5 py-0.5 text-xs font-medium text-subtle-ink", textContent: ca.role }));
};
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
