// The signing form of serve, after picker.js and oidc.js: the certificate type is chosen with a
// picker made of the options of the form's type select, which it replaces. With the OIDC sign-in,
// the request and the type are kept while the browser is at the provider, and the token of the
// sign-in fills the token field once it is back.
const formKey = "simple-ca-sign-form";
const select = document.getElementById("type");
if (select) {
  const taken = oidcTaken();
  const kept = JSON.parse(sessionStorage.getItem(formKey) || "null");
  sessionStorage.removeItem(formKey);
  const note = document.getElementById("oidc-taken");
  const say = (text) => {
    note.textContent = text;
    note.classList.remove("hidden");
  };
  if (taken && kept) {
    document.getElementById("csr").value = kept.csr;
    if ([...select.options].some((option) => option.value === kept.type)) {
      select.value = kept.type;
    }
  }
  if (taken) {
    document.getElementById("token").value = taken.token;
    say(`Signed in: your token ${taken.name}` + (taken.ca ? ` of the issuing CA ${taken.ca}` : "") + " fills the field.");
  }
  select.replaceWith(picker({ name: "type", labelledBy: "type-label",
    choices: [...select.options].map((option) => [option.value, option.textContent]), value: select.value }));
  oidcButton(document.getElementById("oidc-sign-in"), () => sessionStorage.setItem(formKey, JSON.stringify({
    csr: document.getElementById("csr").value, type: document.querySelector('input[name="type"]').value })), say);
}
