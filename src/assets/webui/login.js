// The login dialog of the pages of serve and of the index page, after picker.js and oidc.js. A
// token given is kept for the tab; a setup code, a value without the dots of a JWT, is exchanged
// for its token first. Each page sets signedIn, run with the answer of the exchange, or null for a
// token, once the token is kept, and cancelLogin, run by Cancel.
const tokenName = "simple-ca-webui-token";
let signedIn = () => {};
let cancelLogin = () => document.getElementById("login").close();

// askToken shows the dialog asking for the token, with the error given.
function askToken(failure) {
  const error = document.getElementById("login-error");
  error.textContent = failure;
  error.classList.toggle("hidden", !failure);
  if (!document.getElementById("login").open) {
    document.getElementById("login").showModal();
  }
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const field = document.getElementById("login-token");
  const value = field.value.trim();
  field.value = "";
  if (value.includes(".")) {
    sessionStorage.setItem(tokenName, value);
    document.getElementById("login").close();
    signedIn(null);
    return;
  }
  const response = await fetch("/api/token-setup", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: value }) });
  const setup = await response.json().catch(() => ({}));
  if (!response.ok) {
    askToken(setup.error || response.statusText);
    return;
  }
  document.getElementById("login").close();
  sessionStorage.setItem(tokenName, setup.token);
  signedIn(setup);
});
document.getElementById("login-cancel").addEventListener("click", () => cancelLogin());

// showOnce shows a token or a setup code once, with text, in its dialog; it calls closed, when
// given, once the dialog closes.
function showOnce(text, value, closed) {
  document.getElementById("shown-text").textContent = text;
  document.getElementById("shown-value").value = value;
  if (closed) {
    document.getElementById("shown").addEventListener("close", closed, { once: true });
  }
  document.getElementById("shown").showModal();
}
document.getElementById("shown").addEventListener("close", () => {
  document.getElementById("shown-value").value = "";
  document.getElementById("shown-text").textContent = "";
  document.getElementById("shown-download").classList.add("hidden");
  document.getElementById("shown-download").onclick = null;
});
copying(document.getElementById("shown-copy"), document.getElementById("shown-value"));
oidcButton(document.getElementById("login-oidc"), null, askToken);

// time shows a time of the API in UTC, and address a prefix of a single address as that address.
const time = (value) => new Date(value).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
const address = (prefix) => prefix.replace(prefix.includes(":") ? /\/128$/ : /\/32$/, "");

// showUser shows who is signed in, the token name of the CA ca, empty for the root CA, and puts the
// attributes of the token u, as the API answers with it, in the dialog its name opens.
function showUser(name, ca, u) {
  document.getElementById("user").textContent = "Signed in as " + name + (ca ? " of issuing CA " + ca : "");
  const joined = (values, none) => (values || []).join(", ") || none;
  const attributes = [["Name", u.name], ["Status", "valid until " + time(u.expires)], ["Issued", time(u.issued)],
    ["Scopes", joined(u.scopes, "-")]];
  if (u.oidc) {
    attributes.push(["OIDC user", u.oidc.user], ["OIDC issuer", u.oidc.issuer]);
  }
  const signs = u.scopes.some((scope) => scope === "sign" || scope === "*");
  if (signs) {
    attributes.push(["Cert types", joined(u.types, "-")], ["Domains", joined(u.domains, "-")],
      ["IP addresses", joined((u.ips || []).map(address), "-")]);
  }
  if (u.federate) {
    attributes.push(["Federates", u.federate.type], ["Audience", u.federate.audience || "that of the token type"],
      ...Object.entries(u.federate.claims || {}).sort().map(([name, value]) => ["Claim " + name, value]));
  }
  attributes.push(["Used from", joined((u.clients || []).map(address), "any client")]);
  if (signs) {
    attributes.push(["Certificates", u.certs.length + (u.certs.length ? ": " + u.certs.join(", ") : "")]);
  }
  document.getElementById("user-attributes").replaceChildren(...attributes.flatMap(([label, value]) => [
    element("dt", { className: "text-muted", textContent: label }), element("dd", { className: "break-all", textContent: value })]));
}
// The name of the signed-in token opens the dialog of its attributes.
document.getElementById("user").addEventListener("click", () => document.getElementById("user-dialog").showModal());
