// The parts the token and certificate pages share, after picker.js. The page draws one CA from
// the API, sending the token, which the tab keeps, as its bearer token; the CA on the page is in
// the address as ?ca=. The script of the page, loaded after this one, defines showCA, which draws
// the CA.
const tokenName = "simple-ca-webui-token";
const params = new URLSearchParams(location.search);
const base = location.pathname.replace(/\/$/, "");
const pageScope = base.endsWith("/certificates") ? "certs" : "tokens";
let caID = params.get("ca") || "";
let info = null;
const $ = (id) => document.getElementById(id);

// api sends a request of the API of the page, below its path, and returns its answer; a token
// refused asks for another.
async function api(method, path, body) {
  const headers = { Authorization: "Bearer " + (sessionStorage.getItem(tokenName) || "") };
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(base + path, { method, headers, body: body && JSON.stringify(body) });
  const answer = await response.json().catch(() => ({}));
  if (response.status === 401 || (response.status === 403 && path === "/api/cas")) {
    const refused = sessionStorage.getItem(tokenName) ? answer.error || response.statusText : "";
    sessionStorage.removeItem(tokenName);
    askToken(refused);
    throw new Error("no token");
  }
  if (!response.ok) {
    throw new Error(answer.error || response.statusText);
  }
  return answer;
}

// askToken shows the dialog asking for the token, with the error given.
function askToken(failure) {
  $("login-error").textContent = failure;
  $("login-error").classList.toggle("hidden", !failure);
  if (!$("login").open) {
    $("login").showModal();
  }
}
$("login").addEventListener("cancel", (event) => event.preventDefault());
// A token is kept and signs in; a setup code, a value without the dots of a JWT, is exchanged for
// its token first, which is shown once and signs in once its dialog is closed. A token without
// the scope of the page is shown once too, and the page asks for another token after that.
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const value = $("login-token").value.trim();
  $("login-token").value = "";
  if (value.includes(".")) {
    sessionStorage.setItem(tokenName, value);
    $("login").close();
    load();
    return;
  }
  const response = await fetch("/api/token-setup", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: value }) });
  const setup = await response.json().catch(() => ({}));
  if (!response.ok) {
    askToken(setup.error || response.statusText);
    return;
  }
  $("login").close();
  if (!setup.scopes.some((scope) => scope === pageScope || scope === "*")) {
    showOnce(`Your token ${setup.name} is shown this once; copy it now. It does not open this page, as it has `
      + `the scopes ${setup.scopes.join(", ")}, not ${pageScope}. The setup code it was made from no longer works.`,
      setup.token, () => askToken(`The token ${setup.name} does not have the scope ${pageScope}.`));
    return;
  }
  sessionStorage.setItem(tokenName, setup.token);
  showOnce(`Your token ${setup.name} is shown this once; copy it now to sign in again later. `
    + "The setup code it was made from no longer works.", setup.token, load);
});

// showOnce shows a token or a setup code once, with text, in its dialog; it leaves the page when
// the dialog closes, which then calls closed, when given.
function showOnce(text, value, closed) {
  $("shown-text").textContent = text;
  $("shown-value").value = value;
  if (closed) {
    $("shown").addEventListener("close", closed, { once: true });
  }
  $("shown").showModal();
}
$("shown").addEventListener("close", () => {
  $("shown-value").value = "";
  $("shown-text").textContent = "";
});
copying($("shown-copy"), $("shown-value"));
// The name of the signed-in token opens the dialog of its attributes.
$("user").addEventListener("click", () => $("user-dialog").showModal());
$("sign-out").addEventListener("click", () => {
  sessionStorage.removeItem(tokenName);
  $("user-row").classList.replace("flex", "hidden");
  askToken("");
});

// say shows a message, or an error, above the CA, and hides the other.
function say(message, failure = "") {
  $("message").textContent = message;
  $("message").classList.toggle("hidden", !message);
  $("error").textContent = failure;
  $("error").classList.toggle("hidden", !failure);
}

// failed shows the error of a request, unless it is the token the page asks for.
function failed(error) {
  if (error.message !== "no token") {
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

// A dialog other than the one asking for the token closes on a click beside it.
for (const dialog of document.querySelectorAll("dialog:not(#login)")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
}

// load reads the CAs and shows the one in the address, or the first CA the token opens.
async function load() {
  try {
    info = await api("GET", "/api/cas");
  } catch (error) {
    failed(error);
    return;
  }
  $("title").textContent = info.title + ", managed by simple-ca";
  $("user").textContent = "Signed in as " + info.user + (info.user_ca ? " of issuing CA " + info.user_ca : "");
  $("user-attributes").replaceChildren(...info.user_attributes.flatMap(([label, value]) => [
    element("dt", { className: "text-muted", textContent: label }), element("dd", { className: "break-all", textContent: value })]));
  $("user-row").classList.replace("hidden", "flex");
  if (!info.cas.some((ca) => ca.id === caID)) {
    caID = info.cas[0].id;
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

// currentCA puts the CA on the page in the address and the chooser, gives the page the colours of
// its theme, and returns it.
function currentCA() {
  params.set("ca", caID);
  history.replaceState(null, "", base + "/?" + params);
  $("ca-picker").replaceChildren(picker({ name: "ca", id: "ca-chooser", labelledBy: "ca-label",
    choices: info.cas.map((ca) => [ca.id, ca.label]), value: caID, onchange: choose }));
  const ca = info.cas.find((ca) => ca.id === caID);
  $("ca-theme").textContent = ca.theme;
  return ca;
}

// The parts the pages draw their CA with.
const button = (label, onclick, primary = false) => element("button", { type: "button", onclick, textContent: label,
  className: primary ? "rounded-lg bg-action px-4 py-2 text-sm font-semibold text-action-ink shadow-sm hover:bg-action-hover"
    : "rounded-lg border border-field-line px-2.5 py-1 text-xs font-medium hover:bg-subtle" });
const badge = (text) => element("span", { className: "rounded-full bg-bad px-2 py-0.5 text-xs font-medium text-bad-ink", textContent: text });
const cell = (content, extra = "") => element("td", { className: "py-1.5 pr-3 " + extra }, content);
const time = (value) => new Date(value).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
const heading = (ca) => {
  return element("div", { className: "flex flex-wrap items-baseline justify-between gap-2" },
    element("h2", { className: "text-lg font-semibold" }, ...named(ca.name, ca.subject_attributes)),
    element("span", { className: "rounded-full bg-subtle px-2.5 py-0.5 text-xs font-medium text-subtle-ink", textContent: ca.role }));
};
const table = (headings, rows) => element("div", { className: "overflow-x-auto" }, element("table", { className: "w-full text-left text-sm" },
  element("thead", { className: "text-muted" }, element("tr", {}, ...headings.map((h) =>
    element("th", { className: "py-1 pr-3 font-medium", textContent: h })))),
  element("tbody", { className: "divide-y divide-line" }, ...rows)));
const list = (text) => text.split(/[\s,]+/).filter(Boolean);

// start loads the page once the script of the page has defined showCA.
function start() {
  if (sessionStorage.getItem(tokenName)) {
    load();
  } else {
    askToken("");
  }
}
