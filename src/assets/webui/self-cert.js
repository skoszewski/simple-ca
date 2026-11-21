// The page of the user certificate of serve, after picker.js: for the token of the tab, made by the
// OIDC sign-in with the scope self-cert, the choice of the key, the certificate it gives, and the
// type of a profile of several types.
const webuiTokenKey = "simple-ca-webui-token";
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

// issue sends the request of the form, with the certificate type when one is chosen, to
// /api/self-cert with the token of the tab, and shows the certificate; a profile of several types
// asks for the type first.
async function issue(type = "") {
  const body = mode() === "csr" ? { csr: $("csr").value } : { generate: true };
  const keyType = document.querySelector('input[name="key-type"]').value;
  if (mode() !== "csr" && keyType) {
    body.key_type = keyType;
  }
  if (type) {
    body.type = type;
  }
  const response = await fetch("/api/self-cert", { method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + sessionStorage.getItem(webuiTokenKey) },
    body: JSON.stringify(body) }).catch(() => null);
  const answer = response ? await response.json().catch(() => ({})) : {};
  if (response && response.status === 409 && answer.types) {
    $("cert-form").classList.add("hidden");
    $("type-choice").classList.remove("hidden");
    $("type-picker").replaceChildren(picker({ name: "cert-type", labelledBy: "type-label",
      choices: answer.types.map((t) => [t, t]), value: answer.types[0] }));
    $("type-issue").onclick = () => issue(document.querySelector('input[name="cert-type"]').value);
    return;
  }
  if (!response || !response.ok) {
    $("type-choice").classList.add("hidden");
    $("cert-form").classList.remove("hidden");
    fail(response && response.status === 401 ? "Your sign-in has expired or was revoked; sign in again on the index page."
      : answer.error || (response ? response.statusText : "The server could not be reached."));
    return;
  }
  $("cert-form").classList.add("hidden");
  $("type-choice").classList.add("hidden");
  $("cert-result").classList.remove("hidden");
  $("cert-summary").textContent = `Your certificate ${answer.serial} of the type ${answer.type}`
    + (answer.ca ? ` of the issuing CA ${answer.ca}` : "")
    + " is issued. Issuing another one keeps this one valid.";
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

// The page serves a token of the tab with the scope self-cert alone; /api/links tells.
async function start() {
  const token = sessionStorage.getItem(webuiTokenKey);
  const response = token ? await fetch("/api/links", { headers: { Authorization: "Bearer " + token } }).catch(() => null) : null;
  const answer = response && response.ok ? await response.json().catch(() => ({})) : {};
  if (!answer.self_cert) {
    return;
  }
  $("cert-signin").classList.add("hidden");
  $("cert-form").classList.remove("hidden");
  $("cert-user").textContent = `Signed in as ${answer.user}.`;
  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.addEventListener("change", mode);
  }
  $("csr-file").addEventListener("change", async () => {
    const file = $("csr-file").files[0];
    if (file) {
      $("csr").value = await file.text();
    }
  });
  const keyType = $("key-type");
  keyType.replaceWith(picker({ name: "key-type", labelledBy: "key-type-label",
    choices: [...keyType.options].map((option) => [option.value, option.textContent]), value: keyType.value }));
  mode();
  $("cert-issue").addEventListener("click", () => {
    $("cert-error").classList.add("hidden");
    if (mode() === "csr" && !$("csr").value.includes("CERTIFICATE REQUEST")) {
      fail("Upload or paste the certificate signing request first.");
      return;
    }
    issue();
  });
}

if ($("cert-form")) {
  start();
}
