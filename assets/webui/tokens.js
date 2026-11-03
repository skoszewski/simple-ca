// The token page of serve: the tokens of the CA, and the dialogs creating and showing a token.

// showToken shows a token created or renewed in its dialog; it leaves the page with it.
function showToken(answer) {
  $("new-token-name").textContent = answer.name;
  $("new-token").value = answer.token;
  $("token-dialog").showModal();
}
$("token-dialog").addEventListener("close", () => {
  $("new-token").value = "";
  $("new-token-name").textContent = "";
});
$("new-token").addEventListener("focus", () => $("new-token").select());
// Copy writes the token to the clipboard, through the selection where the page is not a secure
// context, and says so for a moment.
$("copy-token").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("new-token").value);
  } catch {
    $("new-token").select();
    document.execCommand("copy");
  }
  $("copy-token").textContent = "Copied";
  setTimeout(() => { $("copy-token").textContent = "Copy"; }, 2000);
});

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
  const rows = tokens.map((t) => {
    const ended = t.revoked || t.expired;
    const managed = t.scopes.every((scope) => info.scopes.includes(scope));
    return element("tr", {},
      cell(t.name, "font-mono whitespace-nowrap"),
      cell(t.revoked ? badge("revoked") : element("span", {}, time(t.expires), t.expired ? " " : "", t.expired ? badge("expired") : null), "whitespace-nowrap"),
      cell(t.scopes.join(", ")),
      cell((t.types || []).join(", ") || "-"),
      cell((t.domains || []).join(", ") || "-"),
      cell((t.ips || []).join(", ") || "-"),
      cell((t.clients || []).join(", ") || "any"),
      cell(String(t.certs)),
      element("td", { className: "py-1.5 text-right" }, !managed ? null : element("div", { className: "flex justify-end gap-2" },
        button("Renew", () => change("renew", t.name, ended ? null :
          `Renew the token ${t.name}? It gets a new JWT, and the JWT it has is refused from then on.`, "Renew")),
        ended
          ? button("Remove", () => change("purge", t.name, `Remove the token ${t.name}? It can no longer be renewed.`, "Remove"))
          : button("Revoke", () => change("revoke", t.name,
            `Revoke the token ${t.name}? Its JWT is refused from then on; the token is kept, to be renewed.`, "Revoke")))));
  });
  $("ca-section").replaceChildren(...[
    heading(ca),
    tokens.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No tokens." }) :
      table(["Name", "Expires", "Scopes", "Types", "Names in certificates", "IP addresses in certificates", "Used from", "Certs", ""], rows),
    tokens.length === 0 ? null : element("div", {}, element("button", { type: "button",
      className: "rounded-lg border border-field-line px-3 py-1.5 text-sm font-medium hover:bg-subtle",
      textContent: "Remove expired and revoked tokens",
      onclick: () => change("purge", "", "Remove all expired and revoked tokens of this CA? They can no longer be renewed.", "Remove") })),
    ca.has_key ? element("div", {}, button("Create a token", openCreate, true))
      : element("p", { className: "text-sm text-muted", textContent: "This CA's key is not on this server, so tokens cannot be created for it here." }),
  ].filter((child) => child !== null));
}

// change renews, revokes or purges the token name, or every ended token for purge without a name,
// once question, when given, is confirmed.
async function change(what, name, question, action) {
  if (question && !(await confirmed(question, action))) {
    return;
  }
  try {
    const answer = await api("POST", "/api/tokens/" + what, name ? { ca: caID, name } : { ca: caID });
    if (what === "renew") {
      say("");
      showToken(answer);
    } else if (what === "revoke") {
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
  $("create-title").textContent = "Create a token of " + ca.name;
  $("create-error").classList.add("hidden");
  fields.name.value = "";
  fields.valid.value = info.defaults.valid;
  fields.domains.value = (info.defaults.domains || []).join(", ");
  fields.ips.value = (info.defaults.ips || []).join(", ");
  fields.clients.value = (info.defaults.clients || []).join(", ");
  fields.localhost.checked = info.defaults.localhost;
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
// checked * of the scopes or the types turns the other boxes of its group off.
function signFields() {
  for (const name of ["scope", "type"]) {
    const all = $("create-form").querySelector(`input[name="${name}"][value="*"]`);
    for (const box of $("create-form").querySelectorAll(`input[name="${name}"]:not([value="*"])`)) {
      box.disabled = all !== null && all.checked;
    }
  }
  $("sign-fields").disabled = !$("create-form").querySelector('input[name="scope"]:is([value="sign"], [value="*"]):checked');
}
$("create-cancel").addEventListener("click", () => $("create-dialog").close());
$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = event.target.elements;
  const checked = (name) => [...event.target.querySelectorAll(`input[name="${name}"]:checked:not(:disabled)`)].map((box) => box.value);
  const sign = !$("sign-fields").disabled;
  try {
    const answer = await api("POST", "/api/tokens", {
      ca: caID, name: fields.name.value.trim(), valid: fields.valid.value, scopes: checked("scope"),
      types: sign ? checked("type") : [], domains: sign ? list(fields.domains.value) : [],
      ips: sign ? list(fields.ips.value) : [], clients: list(fields.clients.value), localhost: sign && fields.localhost.checked,
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
