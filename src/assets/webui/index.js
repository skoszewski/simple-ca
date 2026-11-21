// The index page of serve, after picker.js: the name of a CA, given with the attributes of its
// subject as JSON in data-subject, shows them in a popup; the Info button of a CA opens the dialog
// of its details, and an address naming an issuing CA, /#NAME, opens the dialog of that CA.
for (const name of document.querySelectorAll("[data-subject]")) {
  name.replaceWith(...named(name.textContent, JSON.parse(name.dataset.subject)));
}
for (const button of document.querySelectorAll("button[data-info]")) {
  button.addEventListener("click", () => document.getElementById(button.dataset.info).showModal());
}
if (location.hash) {
  document.getElementById(decodeURIComponent(location.hash.slice(1)))?.querySelector("button[data-info]")?.click();
}

// The links of the header come from /api/links, which gives those of the webui pages only for a
// valid token, and "Get my certificate" follows them after an OIDC sign-in whose profile gives a
// user certificate. With the webui pages, after login.js, the header shows Login, which opens the
// login dialog, or who is signed in, with Sign out; a token refused is forgotten, with its error in
// the dialog.
const webui = typeof askToken === "function";
async function showLinks() {
  const token = webui ? sessionStorage.getItem(tokenName) : null;
  const certificateUser = webui ? sessionStorage.getItem(oidcCertificateKey) : null;
  const response = await fetch("/api/links", { headers: token ? { Authorization: "Bearer " + token } : {} });
  const answer = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (token) {
      sessionStorage.removeItem(tokenName);
      askToken(answer.error || response.statusText);
      showLinks();
    }
    return;
  }
  const links = [...answer.links, ...(certificateUser ? [{ label: "Get my certificate", href: "/oidc-certificate" }] : [])];
  document.getElementById("links").replaceChildren(...links.map((link) =>
    element("a", { className: "text-sm text-head-link hover:underline", href: link.href, textContent: link.label })));
  if (!webui) {
    return;
  }
  const user = answer.user || certificateUser;
  document.getElementById("user").textContent = user ?
    "Signed in as " + user + (answer.user_ca ? " of issuing CA " + answer.user_ca : "") : "";
  document.getElementById("user-row").classList.toggle("hidden", !user);
  document.getElementById("user-row").classList.toggle("flex", Boolean(user));
  document.getElementById("login-open").classList.toggle("hidden", Boolean(user));
}
if (webui) {
  // The token of a setup code is shown once, then signs in.
  signedIn = (setup) => {
    sessionStorage.removeItem(oidcCertificateKey);
    if (!setup) {
      showLinks();
      return;
    }
    showOnce(`Your token ${setup.name} is shown this once; copy it now to sign in again later. `
      + "The setup code it was made from no longer works.", setup.token, showLinks);
  };
  document.getElementById("login-open").addEventListener("click", () => askToken(""));
  document.getElementById("sign-out").addEventListener("click", () => {
    sessionStorage.removeItem(tokenName);
    sessionStorage.removeItem(oidcCertificateKey);
    showLinks();
  });
  // An OIDC sign-in keeps its token, when its profile gives one, and its user, when it gives a
  // certificate.
  const taken = oidcTaken();
  if (taken) {
    sessionStorage.removeItem(tokenName);
    sessionStorage.removeItem(oidcCertificateKey);
    if (taken.token) {
      sessionStorage.setItem(tokenName, taken.token);
    }
    if (taken.certificate) {
      sessionStorage.setItem(oidcCertificateKey, taken.user);
    }
  }
}
showLinks();
