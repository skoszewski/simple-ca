// The certificate page of serve, after picker.js and oidc.js: the choice of the key, the OIDC
// sign-in, which keeps the choice and the request, and the certificate it gives.
const certFormKey = "simple-ca-oidc-cert-form";
const $ = (id) => document.getElementById(id);

// fail shows the error text.
const fail = (text) => {
  $("cert-error").textContent = text;
  $("cert-error").classList.remove("hidden");
};

// mode returns the chosen way of the key, generate or csr, and shows its fields.
const mode = () => {
  const value = document.querySelector('input[name="mode"]:checked').value;
  $("generate-fields").classList.toggle("hidden", value !== "generate");
  $("csr-fields").classList.toggle("hidden", value !== "csr");
  return value;
};

// offer downloads bytes as the file name of type.
const offer = (bytes, name, type) => {
  const link = element("a", { href: URL.createObjectURL(new Blob([bytes], { type })), download: name });
  link.click();
  URL.revokeObjectURL(link.href);
};

// issue sends the ID token with the kept choice, and the certificate type when one is chosen, to
// /api/oidc-cert and shows the certificate; a profile of several types asks for the type first.
async function issue(idToken, kept, type = "") {
  const body = kept.mode === "csr" ? { id_token: idToken, csr: kept.csr }
    : { id_token: idToken, generate: true, ...(kept.keyType ? { key_type: kept.keyType } : {}) };
  if (type) {
    body.type = type;
  }
  const response = await fetch("/api/oidc-cert", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) }).catch(() => null);
  const answer = response ? await response.json().catch(() => ({})) : {};
  if (response && response.status === 409 && answer.types) {
    $("cert-form").classList.add("hidden");
    $("type-choice").classList.remove("hidden");
    $("type-picker").replaceChildren(picker({ name: "cert-type", labelledBy: "type-label",
      choices: answer.types.map((t) => [t, t]), value: answer.types[0] }));
    $("type-issue").onclick = () => issue(idToken, kept, document.querySelector('input[name="cert-type"]').value);
    return;
  }
  if (!response || !response.ok) {
    $("type-choice").classList.add("hidden");
    $("cert-form").classList.remove("hidden");
    fail(answer.error || (response ? response.statusText : "The server could not be reached."));
    return;
  }
  $("cert-form").classList.add("hidden");
  $("type-choice").classList.add("hidden");
  $("cert-result").classList.remove("hidden");
  $("cert-summary").textContent = `Your certificate ${answer.serial} of the type ${answer.type}`
    + (answer.ca ? ` of the issuing CA ${answer.ca}` : "")
    + " is issued. Signing in again issues another one; this one stays valid.";
  $("cert-pem").value = answer.chain;
  copying($("pem-copy"), $("cert-pem"));
  const base = answer.file ? answer.file.replace(/\.pfx$/, "") : answer.name + "-" + answer.serial;
  $("pem-download").onclick = () => offer(answer.chain, base + "_cert.pem", "application/x-pem-file");
  if (answer.pfx) {
    const bytes = Uint8Array.from(atob(answer.pfx), (char) => char.charCodeAt(0));
    $("pfx-password").value = answer.password;
    copying($("pfx-copy"), $("pfx-password"));
    $("pfx-result").classList.remove("hidden");
    $("pfx-download").classList.remove("hidden");
    $("pfx-download").onclick = () => offer(bytes, answer.file, "application/x-pkcs12");
  }
}

if ($("cert-form")) {
  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.addEventListener("change", mode);
  }
  $("csr-file").addEventListener("change", async () => {
    const file = $("csr-file").files[0];
    if (file) {
      $("csr").value = await file.text();
    }
  });
  const taken = oidcTaken();
  const kept = JSON.parse(sessionStorage.getItem(certFormKey) || "null");
  sessionStorage.removeItem(certFormKey);
  if (kept) {
    document.querySelector(`input[name="mode"][value="${kept.mode === "csr" ? "csr" : "generate"}"]`).checked = true;
    $("csr").value = kept.csr || "";
    $("key-type").value = kept.keyType || "";
  }
  const keyType = $("key-type");
  keyType.replaceWith(picker({ name: "key-type", labelledBy: "key-type-label",
    choices: [...keyType.options].map((option) => [option.value, option.textContent]), value: keyType.value }));
  mode();
  if (taken && taken.id_token && kept) {
    issue(taken.id_token, kept);
  }
  // A request is needed before the sign-in, which would spend the ID token on nothing.
  $("oidc-sign-in").addEventListener("click", (event) => {
    if (mode() === "csr" && !$("csr").value.includes("CERTIFICATE REQUEST")) {
      event.stopImmediatePropagation();
      fail("Upload or paste the certificate signing request first.");
    }
  });
  oidcSettings().then((settings) => $("cert-off").classList.toggle("hidden", Boolean(settings)));
  oidcButton($("oidc-sign-in"), () => sessionStorage.setItem(certFormKey, JSON.stringify({
    mode: mode(), csr: $("csr").value, keyType: document.querySelector('input[name="key-type"]').value })), fail, "certificate");
}
