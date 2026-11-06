// The parts the token, certificate and audit pages share, after picker.js. The page draws one CA from
// the API, sending the token, which the tab keeps, as its bearer token; the CA on the page is in
// the address as ?ca=. The script of the page, loaded after this one, defines showCA, which draws
// the CA.
const tokenName = "simple-ca-webui-token";
const params = new URLSearchParams(location.search);
const base = location.pathname.replace(/\/$/, "");
const pageScope = base.endsWith("/certificates") ? "certs" : base.endsWith("/audit") ? "audit" : "tokens";
let caID = params.get("ca") || "";
let info = null;
const $ = (id) => document.getElementById(id);

// api sends a request of the API of the page, below its path, and returns its answer; a token
// refused asks for another, and the tab forgets it only when it is invalid.
async function api(method, path, body) {
  const headers = { Authorization: "Bearer " + (sessionStorage.getItem(tokenName) || "") };
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(base + path, { method, headers, body: body && JSON.stringify(body) });
  const answer = await response.json().catch(() => ({}));
  if (response.status === 401 || (response.status === 403 && path === "/api/cas")) {
    const refused = sessionStorage.getItem(tokenName) ? answer.error || response.statusText : "";
    if (response.status === 401) {
      sessionStorage.removeItem(tokenName);
    }
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
// the scope of the page is shown once too and kept for the other pages, and the page asks for
// another token after that.
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
  sessionStorage.setItem(tokenName, setup.token);
  if (!setup.scopes.some((scope) => scope === pageScope || scope === "*")) {
    showOnce(`Your token ${setup.name} is shown this once; copy it now. It does not open this page, as it has `
      + `the scopes ${setup.scopes.join(", ")}, not ${pageScope}. The setup code it was made from no longer works.`,
      setup.token, () => askToken(`The token ${setup.name} does not have the scope ${pageScope}.`));
    return;
  }
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
// Cancel closes the question without its action.
$("confirm-cancel").addEventListener("click", () => $("confirm").close("cancel"));

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
  const u = info.user_token;
  const joined = (values, none) => (values || []).join(", ") || none;
  const attributes = [["Name", u.name], ["Status", "valid until " + time(u.expires)], ["Issued", time(u.issued)],
    ["Scopes", joined(u.scopes, "-")]];
  if (u.oidc) {
    attributes.push(["OIDC user", u.oidc.user], ["OIDC issuer", u.oidc.issuer]);
  }
  if (u.scopes.some((scope) => scope === "sign" || scope === "*")) {
    attributes.push(["Types", joined(u.types, "-")], ["Domains", joined(u.domains, "-")],
      ["IP addresses", joined((u.ips || []).map(address), "-")]);
  }
  attributes.push(["Used from", joined((u.clients || []).map(address), "any client")],
    ["Certificates", u.certs.length + (u.certs.length ? ": " + u.certs.join(", ") : "")]);
  $("user-attributes").replaceChildren(...attributes.flatMap(([label, value]) => [
    element("dt", { className: "text-muted", textContent: label }), element("dd", { className: "break-all", textContent: value })]));
  $("user-row").classList.replace("hidden", "flex");
  if (!info.cas.some((ca) => ca.id === caID)) {
    caID = info.cas[0].id;
  }
  // The audit page shows the log of the server, so it has no CA to choose.
  if (pageScope !== "audit") {
    $("chooser-row").classList.replace("hidden", "flex");
  }
  await showCA();
}

// choose shows the CA id.
function choose(id) {
  caID = id;
  say("");
  showCA();
}

// currentCA puts the CA in the address, the chooser and the page links, applies its theme, and
// returns it.
function currentCA() {
  params.set("ca", caID);
  history.replaceState(null, "", base + "/?" + params);
  const query = new URLSearchParams({ ca: caID });
  $("tokens-link").href = "/tokens/?" + query;
  $("certs-link").href = "/certificates/?" + query;
  $("audit-link").href = "/audit/?" + query;
  $("ca-picker").replaceChildren(picker({ name: "ca", id: "ca-chooser", labelledBy: "ca-label",
    choices: info.cas.map((ca) => [ca.id, caRole(ca) + ": " + subjectName(ca.subject)]), value: caID, onchange: choose }));
  const ca = info.cas.find((ca) => ca.id === caID);
  $("ca-theme").textContent = [[":root", ca.theme.light], [':root[data-theme="dark"]', ca.theme.dark]]
    .filter(([, colors]) => colors)
    .map(([selector, colors]) => `${selector} {${Object.entries(colors).map(([role, color]) => ` --${role}: ${color};`).join("")} }\n`)
    .join("");
  return ca;
}

// The parts the pages draw their CA with.
const button = (label, onclick, primary = false) => element("button", { type: "button", onclick, textContent: label,
  className: primary ? "rounded-lg bg-action px-4 py-2 text-sm font-semibold text-action-ink shadow-sm hover:bg-action-hover"
    : "rounded-lg border border-field-line px-2.5 py-1 text-xs font-medium hover:bg-subtle" });
const badge = (text) => element("span", { className: "rounded-full bg-bad px-2 py-0.5 text-xs font-medium text-bad-ink", textContent: text });
const cell = (content, extra = "") => element("td", { className: "py-1.5 pr-3 " + extra }, content);
const time = (value) => new Date(value).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
// A subject comes as its attributes, each a type and a value: it is named by its CN, or else by
// the whole subject in its one-line form.
const oneLine = (attributes) => attributes.map(([type, value]) => `/${type}=${value}`).join("");
const subjectName = (attributes) => attributes.find(([type]) => type === "CN")?.[1] ?? oneLine(attributes);
const caRole = (ca) => ca.id ? "issuing CA " + ca.id : "root CA";
// A prefix of a single address is shown as that address, and hex bytes are separated by colons.
const address = (prefix) => prefix.replace(prefix.includes(":") ? /\/128$/ : /\/32$/, "");
const colonHex = (hex) => (hex.match(/../g) || []).join(":");
const heading = (ca) => {
  return element("div", { className: "flex flex-wrap items-baseline justify-between gap-2" },
    element("h2", { className: "text-lg font-semibold" }, ...named(subjectName(ca.subject), ca.subject)),
    element("span", { className: "rounded-full bg-subtle px-2.5 py-0.5 text-xs font-medium text-subtle-ink", textContent: caRole(ca) }));
};
const list = (text) => text.split(/[\s,]+/).filter(Boolean);

// searchable returns the table of items with a search field, filter pickers and a count; the
// search and the filters are kept in the address. headings is a list, or a function of the items
// shown returning one, which row gets with its item, without the hidden ones; label gives the text
// of a heading. With shownColumns, the columns shown at first, a picker chooses the columns shown,
// which are kept in the address as ?columns= while they differ from shownColumns.
function searchable({ items, text, row, headings, filters, noun, label = (h) => h, shownColumns = null }) {
  const hideable = shownColumns !== null;
  const words = () => (params.get("q") || "").toLowerCase().split(/\s+/).filter(Boolean);
  const chosen = (name) => (params.get(name) || "").split(",").filter(Boolean);
  const head = element("tr", {});
  const body = element("tbody", { className: "divide-y divide-line" });
  const count = element("p", { className: "text-sm text-muted" });
  const keep = (name, value) => {
    if (value) {
      params.set(name, value);
    } else {
      params.delete(name);
    }
    history.replaceState(null, "", base + "/?" + params);
  };
  const columnPicker = element("div", { className: "min-w-0" });
  const visible = () => params.has("columns") ? chosen("columns") : shownColumns;
  let offered = "";
  const draw = () => {
    const wanted = words();
    const shown = items.filter((item) => {
      const haystack = text(item).join(" ").toLowerCase();
      return wanted.every((word) => haystack.includes(word))
        && filters.every(({ name, match }) => chosen(name).length === 0 || match(item, chosen(name)));
    });
    const all = typeof headings === "function" ? headings(shown) : headings;
    const columns = hideable ? all.filter((h) => visible().includes(h)) : all;
    // The picker is made again only when the columns offered change, so it stays open while used.
    if (hideable && all.join("\n") !== offered) {
      offered = all.join("\n");
      columnPicker.replaceChildren(picker({ name: "columns", labelledBy: "filter-columns",
        choices: all.map((h) => [h, label(h)]), value: columns, multiple: true, fit: true,
        summary: (picked) => picked.length === all.length ? "All" : picked.length === 0 ? "None" : "Some",
        onchange: (picked) => {
          // The columns shown that are not offered now stay shown.
          const next = [...visible().filter((h) => !all.includes(h)), ...picked];
          if (next.length === shownColumns.length && next.every((h) => shownColumns.includes(h))) {
            params.delete("columns");
          } else {
            params.set("columns", next.join(","));
          }
          history.replaceState(null, "", base + "/?" + params);
          draw();
        } }));
    }
    head.replaceChildren(...columns.map((h) => element("th", { className: "py-1 pr-3 font-medium", textContent: label(h) })));
    body.replaceChildren(...shown.map((item) => row(item, columns)));
    count.textContent = shown.length === items.length ? `${items.length} ${noun}`
      : `${shown.length} of ${items.length} ${noun}` + (shown.length === 0 ? "; none matches the search and the filters" : "");
  };
  const search = element("input", { type: "search", value: params.get("q") || "", placeholder: "Search",
    autocorrect: "off", autocapitalize: "off", spellcheck: false, ariaLabel: "Search " + noun,
    className: "w-full rounded-lg border border-field-line bg-field px-3 py-2 text-sm sm:max-w-sm",
    oninput: () => {
      keep("q", search.value.trim());
      draw();
    } });
  const pickers = filters.map(({ name, label, choices, multiple = false }) => {
    const values = chosen(name).filter((v) => choices.some(([c]) => c === v && c !== "")).slice(0, multiple ? undefined : 1);
    keep(name, values.join(","));
    return element("div", { className: "flex min-w-0 max-w-full items-center gap-2" },
      element("span", { id: "filter-" + name, className: "shrink-0 text-sm font-medium", textContent: label }),
      element("div", { className: "min-w-0" }, picker({ name: "filter-" + name, labelledBy: "filter-" + name, choices, multiple,
        value: multiple ? values : values[0] || "", fit: true, onchange: (value) => {
          keep(name, multiple ? value.join(",") : value);
          draw();
        } })));
  });
  draw();
  return element("div", { className: "space-y-3" },
    element("div", { className: "flex flex-wrap items-center gap-3" }, search, ...pickers,
      hideable ? element("div", { className: "flex min-w-0 max-w-full items-center gap-2" },
        element("span", { id: "filter-columns", className: "shrink-0 text-sm font-medium", textContent: "Columns" }),
        columnPicker) : null),
    element("div", { className: "overflow-x-auto" }, element("table", { className: "w-full text-left text-sm" },
      element("thead", { className: "text-muted" }, head), body)),
    count);
}

oidcButton($("login-oidc"), null, askToken);

// start loads the page once the script of the page has defined showCA, signing in with the token
// of an OIDC sign-in.
function start() {
  const taken = oidcTaken();
  if (taken) {
    sessionStorage.setItem(tokenName, taken.token);
  }
  if (taken && !taken.scopes.some((scope) => scope === pageScope || scope === "*")) {
    askToken(`Your token ${taken.name} does not have the scope ${pageScope}, which this page needs.`);
    return;
  }
  if (sessionStorage.getItem(tokenName)) {
    load();
  } else {
    askToken("");
  }
}
