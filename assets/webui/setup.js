// The setup code page of serve, after picker.js and oidc.js: the token shown once, with its Copy
// button.
const form = document.getElementById("setup-form");
const taken = form && oidcTaken();
if (taken) {
  const field = element("textarea", { id: "token", readOnly: true, rows: 6, autocorrect: "off", autocapitalize: "off",
    spellcheck: false, value: taken.token,
    className: "w-full rounded-lg border border-field-line bg-field px-3 py-2 font-mono text-xs" });
  const copy = element("button", { id: "copy", type: "button", textContent: "Copy",
    className: "rounded-lg bg-action px-4 py-2 text-sm font-semibold text-action-ink shadow-sm hover:bg-action-hover" });
  form.replaceWith(element("div", { className: "space-y-4 px-6 py-5" },
    element("p", { className: "text-sm", textContent: `Your token ${taken.name}` + (taken.ca ? ` of the issuing CA ${taken.ca}` : "")
      + ` with the scopes ${taken.scopes.join(", ")} is shown this once; copy it now. Signing in again makes a new one.` }),
    field,
    element("div", { className: "flex flex-wrap items-center justify-between gap-2" },
      element("a", { className: "text-sm text-link hover:underline", href: "/", textContent: "All CAs" }), copy)));
} else if (form) {
  oidcButton(document.getElementById("oidc-sign-in"), null, (text) => {
    document.getElementById("oidc-error").textContent = text;
    document.getElementById("oidc-error").classList.remove("hidden");
  });
}
if (document.getElementById("copy")) {
  copying(document.getElementById("copy"), document.getElementById("token"));
}
