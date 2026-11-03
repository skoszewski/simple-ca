// The token page of serve: the tokens of the CA, and the dialog creating a token.

// showToken shows a token created or renewed, or the setup code of a token created with one, once.
function showToken(answer) {
  if (answer.code) {
    showOnce(`The setup code of the token ${answer.name} is shown this once; hand it to the user of the token, `
      + "who exchanges it once for the token before it expires.", answer.code);
  } else {
    showOnce(`The token ${answer.name} is shown this once; copy it now. It is gone from the page once this dialog closes.`,
      answer.token);
  }
}

// tokenStatus returns the status of the token t: revoked, expired, pending while it waits for its
// setup code, or active.
const tokenStatus = (t) => t.revoked ? "revoked" : t.expired ? "expired" : t.pending ? "pending" : "active";
// allowsScope reports whether the scopes give the scope, named or by *.
const allowsScope = (scopes, scope) => scopes.includes(scope) || scopes.includes("*");

// showCA draws the tokens of the CA on the page, with the search and the filters of their list.
async function showCA() {
  const ca = currentCA();
  let tokens;
  try {
    tokens = (await api("GET", "/api/tokens?ca=" + encodeURIComponent(caID))).tokens;
  } catch (error) {
    failed(error);
    return;
  }
  const row = (t) => {
    const ended = t.revoked || t.expired;
    const managed = t.scopes.every((scope) => info.scopes.includes(scope));
    const expiry = t.revoked ? badge("revoked")
      : element("span", {}, time(t.expires), " ", t.expired ? badge("expired") : null,
        t.pending && !t.expired ? badge("setup code") : null);
    return element("tr", {},
      cell(t.oidc ? element("span", {}, t.name, element("span", { className: "block font-sans text-xs text-muted",
        textContent: "OIDC user " + t.oidc.user })) : t.name, "font-mono whitespace-nowrap"),
      cell(expiry, "whitespace-nowrap"),
      cell(t.scopes.join(", ")),
      cell((t.types || []).join(", ") || "-"),
      cell((t.domains || []).join(", ") || "-"),
      cell((t.ips || []).map(address).join(", ") || "-"),
      cell((t.clients || []).map(address).join(", ") || "any"),
      cell(String(t.certs.length)),
      element("td", { className: "py-1.5 text-right" }, !managed ? null : element("div", { className: "flex justify-end gap-2" },
        t.pending ? null : button("Renew", () => renew(t.name, ended)),
        ended
          ? button("Remove", () => change("purge", t.name, `Remove the token ${t.name}? It can no longer be renewed.`, "Remove"))
          : button("Revoke", () => change("revoke", t.name, t.pending
            ? `Revoke the token ${t.name}? Its setup code is refused from then on; the token is kept, to be renewed.`
            : `Revoke the token ${t.name}? Its JWT is refused from then on; the token is kept, to be renewed.`, "Revoke")))));
  };
  $("ca-section").replaceChildren(...[
    heading(ca),
    tokens.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No tokens." }) :
      searchable({ items: tokens, row, noun: "tokens",
        headings: ["Name", "Expires", "Scopes", "Types", "Names in certificates", "IP addresses in certificates", "Used from", "Certs", ""],
        text: (t) => [t.name, t.oidc ? t.oidc.user : "", tokenStatus(t), ...t.scopes, ...(t.types || []), ...(t.domains || []),
          ...(t.ips || []).map(address), ...(t.clients || []).map(address), ...t.certs],
        filters: [
          { name: "status", label: "Status", match: (t, value) => tokenStatus(t) === value,
            choices: [["", "all"], ["active", "active"], ["pending", "waiting for a setup code"], ["expired", "expired"], ["revoked", "revoked"]] },
          { name: "scope", label: "Scope", match: (t, value) => allowsScope(t.scopes, value),
            choices: [["", "all"], ...["sign", "tokens", "certs"].map((s) => [s, s])] },
          { name: "kind", label: "Made by", match: (t, value) => (value === "oidc") === Boolean(t.oidc),
            choices: [["", "all"], ["oidc", "OIDC sign-in"], ["other", "other"]] },
        ] }),
    tokens.length === 0 ? null : element("div", {}, element("button", { type: "button",
      className: "rounded-lg border border-field-line px-3 py-1.5 text-sm font-medium hover:bg-subtle",
      textContent: "Remove expired and revoked tokens",
      onclick: () => change("purge", "", "Remove all expired and revoked tokens of this CA? They can no longer be renewed.", "Remove") })),
    ca.has_key ? element("div", {}, button("Create a token", openCreate, true))
      : element("p", { className: "text-sm text-muted", textContent: "This CA's key is not on this server, so tokens cannot be created for it here." }),
  ].filter((child) => child !== null));
}

// renew renews the token name, once confirmed, with a setup code in place of its JWT when the box
// for it is checked; ended tells that the token is revoked or expired.
async function renew(name, ended) {
  const field = (attributes) => element("input", { autocorrect: "off", autocapitalize: "off", spellcheck: false,
    className: "w-full rounded-lg border border-field-line bg-field px-3 py-2 font-mono", ...attributes });
  const otc = element("input", { type: "checkbox" });
  const otcValid = field({ value: info.defaults.otc_valid, placeholder: "15m, 1h" });
  const otcNetworks = field({ placeholder: "192.168.1.0/24" });
  const label = (text, input) => element("label", { className: "block space-y-1 text-sm" },
    element("span", { className: "block font-medium", textContent: text }), input);
  const question = ended ? `Renew the token ${name}?`
    : `Renew the token ${name}? It gets a new JWT, and the JWT it has is refused from then on.`;
  if (!(await confirmed(question, "Renew", element("div", { className: "space-y-3" },
    element("label", { className: "flex items-center gap-1.5 text-sm" }, otc,
      " One-time setup code: hand out a code, exchanged once for the token"),
    label("Code valid for", otcValid), label("Code usable from: addresses or prefixes; empty for any", otcNetworks))))) {
    return;
  }
  try {
    const answer = await api("POST", "/api/tokens/renew", { ca: caID, name, otc: otc.checked,
      otc_valid: otc.checked ? otcValid.value : "", otc_networks: otc.checked ? list(otcNetworks.value) : [] });
    say("");
    showToken(answer);
  } catch (error) {
    failed(error);
  }
  showCA();
}

// change revokes or purges the token name, or every ended token for purge without a name, once
// question is confirmed.
async function change(what, name, question, action) {
  if (!(await confirmed(question, action))) {
    return;
  }
  try {
    const answer = await api("POST", "/api/tokens/" + what, name ? { ca: caID, name } : { ca: caID });
    if (what === "revoke") {
      say(`Token ${name} revoked.`);
    } else {
      say(name ? `Token ${name} removed.` : `${answer.removed} expired or revoked tokens removed.`);
    }
  } catch (error) {
    failed(error);
  }
  showCA();
}

// scopeHints tell what each scope opens.
const scopeHints = { sign: "request certificates", tokens: "this page", certs: "the certificate page", "*": "all scopes" };

// openCreate opens the form creating a token, filled with the defaults of simple-ca.json.
function openCreate() {
  const fields = $("create-form").elements;
  const ca = info.cas.find((ca) => ca.id === caID);
  $("create-title").textContent = "Create a token of " + subjectName(ca.subject);
  $("create-error").classList.add("hidden");
  fields.name.value = "";
  fields.valid.value = info.defaults.valid;
  fields.domains.value = (info.defaults.domains || []).join(", ");
  fields.ips.value = (info.defaults.ips || []).join(", ");
  fields.clients.value = (info.defaults.clients || []).join(", ");
  fields.localhost.checked = info.defaults.localhost;
  fields.otc.checked = false;
  fields.otc_valid.value = info.defaults.otc_valid;
  fields.otc_networks.value = "";
  $("create-scopes").replaceChildren(...info.scopes.map((scope) => element("label", { className: "flex items-center gap-1.5" },
    element("input", { type: "checkbox", name: "scope", value: scope, checked: info.defaults.scopes.includes(scope),
      onchange: signFields }), " " + scope + ": " + scopeHints[scope])));
  $("create-types").replaceChildren(...[...info.types, "*"].map((type) => element("label", { className: "flex items-center gap-1.5" },
    element("input", { type: "checkbox", name: "type", value: type, checked: info.defaults.types.includes(type),
      onchange: signFields }), " " + (type === "*" ? "*: all types" : type))));
  signFields();
  $("create-dialog").showModal();
}

// signFields turns the fields of the scope sign on with that scope or *, and off without them; a
// checked * of the scopes or the types turns the other boxes of its group off; the fields of the
// setup code are on with its box.
function signFields() {
  $("otc-fields").disabled = !$("create-form").elements.otc.checked;
  for (const name of ["scope", "type"]) {
    const all = $("create-form").querySelector(`input[name="${name}"][value="*"]`);
    for (const box of $("create-form").querySelectorAll(`input[name="${name}"]:not([value="*"])`)) {
      box.disabled = all !== null && all.checked;
    }
  }
  $("sign-fields").disabled = !$("create-form").querySelector('input[name="scope"]:is([value="sign"], [value="*"]):checked');
}
$("create-form").elements.otc.addEventListener("change", signFields);
$("create-cancel").addEventListener("click", () => $("create-dialog").close());
$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = event.target.elements;
  const checked = (name) => [...event.target.querySelectorAll(`input[name="${name}"]:checked:not(:disabled)`)].map((box) => box.value);
  const sign = !$("sign-fields").disabled;
  const otc = fields.otc.checked;
  try {
    const answer = await api("POST", "/api/tokens", {
      ca: caID, name: fields.name.value.trim(), valid: fields.valid.value, scopes: checked("scope"),
      types: sign ? checked("type") : [], domains: sign ? list(fields.domains.value) : [],
      ips: sign ? list(fields.ips.value) : [], clients: list(fields.clients.value), localhost: sign && fields.localhost.checked,
      otc, otc_valid: otc ? fields.otc_valid.value : "", otc_networks: otc ? list(fields.otc_networks.value) : [],
    });
    $("create-dialog").close();
    say("");
    showToken(answer);
    showCA();
  } catch (error) {
    if (error.message !== "no token") {
      $("create-error").textContent = error.message;
      $("create-error").classList.remove("hidden");
    }
  }
});

start();
