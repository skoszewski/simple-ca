// The certificate page of serve: the certificates and the CRL of the CA, and the dialog creating a
// certificate or signing a request. The certificates and the CRL are written to the CA directory,
// as the commands write them; the PKCS#12 file of a certificate with a key there is offered for
// download, with a new random password shown once.
let signing = false;

// lock returns the icon of a private key, ENC a locked padlock, PLAIN an open one, titled with
// the words it stands for, or - for a certificate without a key in the CA directory.
const lockPaths = {
  ENC: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  PLAIN: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/>',
};
const lockTitles = { ENC: "Encrypted private key", PLAIN: "Unencrypted private key" };
function lock(key) {
  if (!lockPaths[key]) {
    return element("span", { className: "text-muted", textContent: "-" });
  }
  return element("span", { title: lockTitles[key], className: "inline-flex align-middle " + (key === "ENC" ? "text-ink" : "text-muted"),
    innerHTML: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round" role="img" aria-label="' + lockTitles[key] + '">' + lockPaths[key] + "</svg>" });
}

// showCA draws the certificates of the CA on the page, and its CRL.
async function showCA() {
  const ca = currentCA();
  let answer;
  try {
    answer = await api("GET", "/api/certs?ca=" + encodeURIComponent(caID));
  } catch (error) {
    failed(error);
    return;
  }
  const row = (c) => element("tr", {},
    cell(c.status === "valid" ? "valid" : badge(c.status), "whitespace-nowrap"),
    cell(element("span", {}, ...named(subjectName(c.subject), c.subject)), "whitespace-nowrap"),
    cell(time(c.expires), "whitespace-nowrap"),
    cell(c.revoked ? time(c.revoked) + (c.reason ? ", " + c.reason : "") : "-", "whitespace-nowrap"),
    cell(lock(c.key)),
    element("td", { className: "py-1.5 text-right" }, element("div", { className: "flex justify-end gap-2" },
      c.has_key ? button("Download", () => download(c.serial)) : null,
      c.status === "revoked" ? null : button("Revoke", () => revoke(c)),
      button("Show", () => show(c)))));
  const crl = answer.crl
    ? element("span", {}, `CRL number ${answer.crl.number}, next update ${time(answer.crl.next_update)}`,
      answer.crl.overdue ? " " : "", answer.crl.overdue ? badge("overdue") : null)
    : "No CRL yet.";
  $("ca-section").replaceChildren(
    heading(ca),
    answer.certs.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No certificates." }) :
      searchable({ items: answer.certs, row, noun: "certificates", headings: ["Status", "Subject", "Expires", "Revoked", "Key", ""],
        text: (c) => [c.status, oneLine(c.subject), ...c.subject.map(([, value]) => value), c.serial, c.reason || ""],
        filters: [{ name: "status", label: "Status", multiple: true, match: (c, values) => values.includes(c.status),
          choices: [["", "all"], ["valid", "valid"], ["expired", "expired"], ["revoked", "revoked"]] }] }),
    element("div", { className: "flex flex-wrap items-center gap-3 text-sm" }, element("span", { className: "text-muted" }, crl),
      ca.has_key ? element("button", { type: "button", onclick: writeCRL, textContent: "Write the CRL",
        className: "rounded-lg border border-field-line px-3 py-1.5 text-sm font-medium hover:bg-subtle" }) : null),
    ca.has_key ? element("div", { className: "flex flex-wrap gap-2" },
      button("Create a certificate", () => openCert(false), true), button("Sign a request", () => openCert(true), true))
      : element("p", { className: "text-sm text-muted", textContent: "No key of this CA on this server" }));
}

// download makes the PKCS#12 file of the certificate with the serial number, with a new random
// password, shows the password once, and offers the file in the same dialog.
async function download(serial) {
  let answer;
  try {
    answer = await api("POST", "/api/certs/pfx", { ca: caID, serial });
  } catch (error) {
    failed(error);
    return;
  }
  const bytes = Uint8Array.from(atob(answer.pfx), (char) => char.charCodeAt(0));
  showOnce(`The password of ${answer.file}, shown once:`, answer.password);
  $("shown-download").classList.remove("hidden");
  $("shown-download").onclick = () => {
    const link = element("a", { href: URL.createObjectURL(new Blob([bytes], { type: "application/x-pkcs12" })), download: answer.file });
    link.click();
    URL.revokeObjectURL(link.href);
  };
}

// show shows the fields of the certificate c in its dialog.
async function show(c) {
  let answer;
  try {
    answer = await api("GET", "/api/certs/show?ca=" + encodeURIComponent(caID) + "&serial=" + encodeURIComponent(c.serial));
  } catch (error) {
    failed(error);
    return;
  }
  const d = answer.certificate;
  const each = (label, values) => (values || []).map((value) => [label, value]);
  const fields = [["Subject", oneLine(d.subject)], ["Issuer", oneLine(d.issuer)], ["Serial", d.serial],
    ["Valid from", time(d.not_before)], ["Valid until", time(d.not_after)], ["Validity", d.validity],
    ["Signature algorithm", d.signature_algorithm],
    ["Key", d.key.algorithm + (d.key.bits ? ` ${d.key.bits} bits` : d.key.curve ? " " + d.key.curve : "")],
    ["CA", d.ca ? "yes, path length " + (d.path_length ?? "unlimited") : "no"],
    ["Key usage", (d.key_usage || []).join(", ")], ["Extended key usage", (d.ext_key_usage || []).join(", ")],
    ...each("DNS name", d.dns_names), ...each("IP address", d.ip_addresses), ...each("Email address", d.email_addresses),
    ...each("URI", d.uris), ...each("Registered ID", d.registered_ids), ["Subject key ID", colonHex(d.subject_key_id || "")],
    ["Authority key ID", colonHex(d.authority_key_id || "")], ...each("AIA CA issuers", d.ca_issuers), ...each("AIA OCSP", d.ocsp),
    ...each("CRL distribution point", d.crl_distribution_points), ["SHA-256 fingerprint", colonHex(d.sha256_fingerprint)]]
    .filter(([, value]) => value);
  $("show-title").textContent = subjectName(c.subject);
  $("show-file").textContent = "From " + answer.file + " in the CA directory.";
  $("show-fields").replaceChildren(...fields.flatMap(([name, value]) => [
    element("dt", { className: "font-medium text-muted", textContent: name }),
    element("dd", { className: "font-mono text-xs break-all sm:pt-0.5", textContent: value })]),
  element("dt", { className: "font-medium text-muted", textContent: "Private key" }),
  element("dd", { className: "flex items-center gap-1.5 text-xs" }, lock(answer.key),
    { ENC: "encrypted", PLAIN: "unencrypted" }[answer.key] || ""));
  $("show-dialog").showModal();
}

// revoke revokes the certificate c, for the reason chosen in the confirmation dialog.
async function revoke(c) {
  const reason = picker({ name: "reason", labelledBy: "reason-label",
    choices: [["", "no reason"], ...info.reasons.map((r) => [r, r])], value: "" });
  const label = element("div", { className: "space-y-1 text-sm" },
    element("span", { id: "reason-label", className: "block font-medium", textContent: "Reason" }), reason);
  if (!(await confirmed(`Revoke the certificate ${subjectName(c.subject)}, serial ${c.serial}?`, "Revoke", label))) {
    return;
  }
  try {
    await api("POST", "/api/certs/revoke", { ca: caID, serial: c.serial, reason: reason.querySelector("input").value });
    say(`Certificate ${subjectName(c.subject)} revoked. Write the CRL to publish it.`);
  } catch (error) {
    failed(error);
  }
  showCA();
}

// writeCRL writes the CRL of the CA, valid for the days given in the confirmation dialog.
async function writeCRL() {
  const days = element("input", { type: "number", min: 1, value: info.defaults.crl_days,
    className: "w-full rounded-lg border border-field-line bg-field px-3 py-2 font-mono text-sm" });
  const label = element("label", { className: "block space-y-1 text-sm" },
    element("span", { className: "block font-medium", textContent: "Validity in days" }), days);
  if (!(await confirmed("Write a new CRL of this CA, listing the certificates it revoked?", "Write", label))) {
    return;
  }
  try {
    await api("POST", "/api/crl", { ca: caID, days: Number(days.value) });
    say("CRL written.");
  } catch (error) {
    failed(error);
  }
  showCA();
}

// openCert opens the form creating a certificate, or signing a request with sign.
function openCert(sign) {
  signing = sign;
  const form = $("cert-form");
  const fields = form.elements;
  const ca = info.cas.find((ca) => ca.id === caID);
  form.reset();
  $("cert-title").textContent = (sign ? "Sign a request with " : "Create a certificate of ") + subjectName(ca.subject);
  $("cert-submit").textContent = sign ? "Sign" : "Create";
  $("cert-error").classList.add("hidden");
  for (const node of form.querySelectorAll("[data-create]")) node.classList.toggle("hidden", sign);
  for (const node of form.querySelectorAll("[data-sign]")) node.classList.toggle("hidden", !sign);
  fields.subject.required = !sign;
  fields.name.required = sign;
  fields.csr.required = sign;
  $("cert-type").replaceChildren(picker({ name: "type", labelledBy: "cert-type-label",
    choices: info.types.map((type) => [type, type]), value: info.types.includes("server") ? "server" : info.types[0] }));
  fields.days.value = info.defaults.days;
  $("cert-dialog").showModal();
}
$("cert-cancel").addEventListener("click", () => $("cert-dialog").close());
$("cert-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = event.target.elements;
  const common = { ca: caID, type: fields.type.value, days: Number(fields.days.value),
    ku: list(fields.ku.value), eku: list(fields.eku.value) };
  let created = "";
  try {
    if (signing) {
      const answer = await api("POST", "/api/certs/sign", { ...common, name: fields.name.value.trim(), csr: fields.csr.value });
      say(`Request signed; the certificate was written to ${answer.file} in the CA directory.`);
    } else {
      const answer = await api("POST", "/api/certs", { ...common, subject: fields.subject.value.trim(), sans: list(fields.sans.value) });
      say(`Certificate ${answer.subject} and its key were written to the CA directory.`);
      created = answer.serial;
    }
    $("cert-dialog").close();
    showCA();
    if (created) {
      download(created);
    }
  } catch (error) {
    if (error.message !== "no token") {
      $("cert-error").textContent = error.message;
      $("cert-error").classList.remove("hidden");
    }
  }
});

start();
