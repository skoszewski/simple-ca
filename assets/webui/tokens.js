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

// tokenStatus returns the status of the token t: revoked, expired, pending or active.
const tokenStatus = (t) => t.revoked ? "revoked" : t.expired ? "expired" : t.pending ? "pending" : "active";
// allowsScope reports whether the scopes give the scope, named or by *.
const allowsScope = (scopes, scope) => scopes.includes(scope) || scopes.includes("*");

// showCA draws the tokens of the CA on the page.
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
    const name = element("button", { type: "button", textContent: t.name, title: "Show the token as JSON",
      onclick: () => showJSON(t), className: "underline decoration-muted decoration-dotted underline-offset-4 hover:text-link" });
    return element("tr", {},
      cell(t.oidc ? element("span", {}, name, element("span", { className: "block font-sans text-xs text-muted",
        textContent: "OIDC user " + t.oidc.user })) : name, "font-mono whitespace-nowrap"),
      cell(expiry, "whitespace-nowrap"),
      cell(t.scopes.join(", ")),
      cell((t.types || []).join(", ") || "-"),
      cell((t.domains || []).join(", ") || "-"),
      cell((t.ips || []).map(address).join(", ") || "-"),
      cell((t.clients || []).map(address).join(", ") || "any"),
      cell(!t.federate ? "-" : element("button", { type: "button", textContent: typeLabel(t.federate.type),
        title: "Show the federation", onclick: () => showFederation(t),
        className: "underline decoration-muted decoration-dotted underline-offset-4 hover:text-link" })),
      cell(allowsScope(t.scopes, "sign") ? String(t.certs.length) : "-"),
      element("td", { className: "py-1.5 text-right" }, !managed ? null : element("div", { className: "flex justify-end gap-2" },
        t.pending && !t.expired ? null : button("Renew", () => renew(t, ended)),
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
        headings: ["Name", "Expires", "Scopes", "Cert types", "Names in certificates", "IP addresses in certificates", "Used from", "Federates", "Certs", ""],
        text: (t) => [t.name, t.oidc ? t.oidc.user : "", tokenStatus(t), ...t.scopes, ...(t.types || []), ...(t.domains || []),
          ...(t.ips || []).map(address), ...(t.clients || []).map(address), ...t.certs,
          ...(t.federate ? [t.federate.type, t.federate.audience || audienceOf(t.federate.type)] : [])],
        filters: [
          { name: "status", label: "Status", multiple: true, match: (t, values) => values.includes(tokenStatus(t)),
            choices: [["", "all"], ["active", "active"], ["pending", "waiting for a setup code"], ["expired", "expired"], ["revoked", "revoked"]] },
          { name: "scope", label: "Scope", multiple: true, match: (t, values) => values.every((scope) => allowsScope(t.scopes, scope)),
            choices: [["", "all"], ...["sign", "tokens", "certs", "audit", "federate"].map((s) => [s, s])] },
          { name: "federates", label: "Federates", multiple: true,
            match: (t, values) => values.includes(t.federate ? t.federate.type : "none"),
            choices: [["", "all"], ...info.token_types.map((type) => [type.name, typeLabel(type.name)]), ["none", "none"]] },
          { name: "kind", label: "Made by", match: (t, [value]) => (value === "oidc") === Boolean(t.oidc),
            choices: [["", "all"], ["oidc", "OIDC sign-in"], ["other", "other"]] },
        ] }),
    tokens.length === 0 ? null : element("div", {}, element("button", { type: "button",
      className: "rounded-lg border border-field-line px-3 py-1.5 text-sm font-medium hover:bg-subtle",
      textContent: "Remove expired and revoked tokens",
      onclick: () => change("purge", "", "Remove all expired and revoked tokens of this CA? They can no longer be renewed.", "Remove") })),
    ca.has_key ? element("div", {}, button("Create a token", openCreate, true))
      : element("p", { className: "text-sm text-muted", textContent: "No key of this CA on this server" }),
  ].filter((child) => child !== null));
}

// renew renews the token t, once confirmed, for the validity given, the one it had by default as
// for token renew, with a setup code in place of its JWT when the box for it is checked; ended
// tells that the token is revoked or expired.
async function renew(t, ended) {
  const name = t.name;
  const field = (attributes) => element("input", { autocorrect: "off", autocapitalize: "off", spellcheck: false,
    className: "w-full rounded-lg border border-field-line bg-field px-3 py-2 font-mono", ...attributes });
  const valid = field({ value: t.valid || info.defaults.valid, placeholder: "1h, 8h, 720h" });
  const otc = element("input", { type: "checkbox" });
  const otcValid = field({ value: info.defaults.otc_valid, placeholder: "15m, 1h" });
  const otcNetworks = field({ placeholder: "192.168.1.0/24" });
  const label = (text, input) => element("label", { className: "block space-y-1 text-sm" },
    element("span", { className: "block font-medium", textContent: text }), input);
  const question = ended ? `Renew the token ${name}?`
    : `Renew the token ${name}? It gets a new JWT, and the JWT it has is refused from then on.`;
  // The fields of the setup code show while its box is checked.
  const otcFields = element("div", { className: "hidden space-y-3" }, label("Code valid for", otcValid),
    label("Code usable from", otcNetworks));
  otc.addEventListener("change", () => otcFields.classList.toggle("hidden", !otc.checked));
  if (!(await confirmed(question, "Renew", element("div", { className: "space-y-3" },
    label("Valid for", valid),
    element("label", { className: "flex items-center gap-1.5 text-sm" }, otc, " One-time setup code"),
    otcFields)))) {
    return;
  }
  try {
    const answer = await api("POST", "/api/tokens/renew", { ca: caID, name, valid: valid.value.trim(), otc: otc.checked,
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
  fields.localhost.checked = false;
  fields.otc.checked = false;
  fields.otc_valid.value = info.defaults.otc_valid;
  fields.otc_networks.value = "";
  fields.audience.value = "";
  fields.claims.value = "";
  $("create-federate").replaceChildren();
  federateChoices = "";
  const choices = (values) => values.map((v) => [v, v === "*" ? "* (all)" : v]);
  $("create-scopes").replaceChildren(picker({ name: "scopes", labelledBy: "create-scopes-label", multiple: true, only: "*",
    choices: choices(info.scopes), value: info.defaults.scopes.filter((s) => info.scopes.includes(s)),
    placeholder: "none", onchange: signFields }));
  $("create-types").replaceChildren(picker({ name: "types", labelledBy: "create-types-label", multiple: true, only: "*",
    choices: choices([...info.types, "*"]), value: info.defaults.types.filter((t) => t === "*" || info.types.includes(t)),
    placeholder: "none", onchange: signFields }));
  signFields();
  $("create-dialog").showModal();
}

// chosen returns the values of the multiple picker named name of the form creating a token.
const chosen = (name) => $("create-form").elements[name].value.split(",").filter((v) => v !== "");

// showJSON shows the token t as GET /api/tokens answers with it, in its dialog.
function showJSON(t) {
  $("json-title").textContent = "Token " + t.name;
  $("json-text").textContent = JSON.stringify(t, null, 2);
  $("json-dialog").showModal();
}

// showFederation shows the token type, the audience and the claims of the JWTs of the token t,
// with the scope federate, in their dialog.
function showFederation(t) {
  const f = t.federate;
  const attributes = [["Token type", typeLabel(f.type)], ["Audience", f.audience || audienceOf(f.type) || "-"],
    ...Object.entries(f.claims || {}).sort().map(([name, value]) => ["Claim " + name, value])];
  $("federate-title").textContent = "Federation of " + t.name;
  $("federate-attributes").replaceChildren(...attributes.flatMap(([label, value]) => [
    element("dt", { className: "font-medium text-muted", textContent: label }),
    element("dd", { className: "font-mono text-xs break-all sm:pt-0.5", textContent: value })]));
  $("federate-dialog").showModal();
}

// typeLabel returns the token type named name followed by the built-in type it is based on, as
// gcp-wif (google), or the name alone for a built-in type or a type without a base.
function typeLabel(name) {
  const type = info.token_types.find((t) => t.name === name);
  return type && type.base && type.base !== name ? `${name} (${type.base})` : name;
}

// audienceOf returns the audience of the token type named name, empty for none.
const audienceOf = (name) => (info.token_types.find((t) => t.name === name) || {}).audience || "";

// claims returns the claims of the lines name=value of text, or throws for a line without =.
function claims(text) {
  const result = {};
  for (const line of text.split("\n").map((l) => l.trim()).filter((l) => l !== "")) {
    const at = line.indexOf("=");
    if (at < 1) {
      throw new Error(`claims: '${line}' is not a claim such as env=prod`);
    }
    result[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return result;
}

// showGroup shows the fieldset id of the form creating a token, its fields sent, with show, and
// hides it, its fields left out, without.
function showGroup(id, show) {
  $(id).disabled = !show;
  $(id).classList.toggle("contents", show);
  $(id).classList.toggle("hidden", !show);
}

// federateChoices are the choices of the token type picker drawn, as JSON, empty before one is.
let federateChoices = "";

// signFields shows the fields of the scopes sign and federate with that scope or *, and hides them
// without; the token type may be none, for a token that grants the scope federate and gets no
// JWTs, and the audience and the claims show once a type is chosen, the audience telling that of
// the type or that the type needs one. The fields of the setup code show with its box.
function signFields() {
  const fields = $("create-form").elements;
  const scopes = chosen("scopes");
  showGroup("otc-fields", fields.otc.checked);
  showGroup("sign-fields", scopes.some((scope) => allowsScope([scope], "sign")));
  const federate = scopes.some((scope) => allowsScope([scope], "federate"));
  showGroup("federate-fields", federate);
  const choices = [["", "none"], ...info.token_types.map((t) => [t.name, typeLabel(t.name)])];
  if (federate && JSON.stringify(choices) !== federateChoices) {
    const current = fields.federate ? fields.federate.value : "";
    federateChoices = JSON.stringify(choices);
    $("create-federate").replaceChildren(picker({ name: "federate", labelledBy: "create-federate-label", choices,
      value: choices.some(([v]) => v === current) ? current : choices[0][0], onchange: signFields }));
  }
  const type = federate && fields.federate ? info.token_types.find((t) => t.name === fields.federate.value) : null;
  $("federate-audience").classList.toggle("hidden", !type);
  $("federate-claims").classList.toggle("hidden", !type);
  fields.audience.disabled = fields.claims.disabled = !type;
  fields.audience.required = Boolean(type && type.needs_audience);
  fields.audience.placeholder = !type ? "" : type.needs_audience ? "required by the token type" : type.audience || "none";
}
$("create-form").elements.otc.addEventListener("change", signFields);
$("create-cancel").addEventListener("click", () => $("create-dialog").close());
$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = event.target.elements;
  const sign = !$("sign-fields").disabled;
  const federate = !$("federate-fields").disabled && fields.federate && fields.federate.value !== "";
  const otc = fields.otc.checked;
  try {
    const answer = await api("POST", "/api/tokens", {
      ca: caID, name: fields.name.value.trim(), valid: fields.valid.value, scopes: chosen("scopes"),
      federate: federate ? { type: fields.federate.value, audience: fields.audience.value.trim(), claims: claims(fields.claims.value) } : null,
      types: sign ? chosen("types") : [], domains: sign ? list(fields.domains.value) : [],
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
