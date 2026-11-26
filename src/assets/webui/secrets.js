// The secret page of serve: the secrets of the CA whose codes are not used, without their values,
// and the dialog creating a secret.

// showCA draws the secrets of the CA on the page.
async function showCA() {
  const ca = currentCA();
  let secrets;
  try {
    secrets = (await api("GET", "/api/secrets?ca=" + encodeURIComponent(caID))).secrets;
  } catch (error) {
    failed(error);
    return;
  }
  const row = (s) => element("tr", {},
    cell(s.name, "font-mono whitespace-nowrap"),
    cell(time(s.created), "whitespace-nowrap"),
    cell(time(s.expires), "whitespace-nowrap"),
    cell(s.clients.join(", ") || "any"),
    cell(s.creator || "-"),
    element("td", { className: "py-1.5 text-right" }, button("Revoke", () => revoke(s.name))));
  $("ca-section").replaceChildren(...[
    heading(ca),
    secrets.length === 0 ? element("p", { className: "text-sm text-muted", textContent: "No secrets." }) :
      searchable({ items: secrets, row, noun: "secrets", filters: [],
        headings: ["Name", "Created", "Code expires", "Code usable from", "Created by", ""],
        text: (s) => [s.name, s.creator, ...s.clients] }),
    element("div", {}, button("Create a secret", openCreate, true)),
  ]);
}

// revoke removes the secret name once confirmed.
async function revoke(name) {
  if (!(await confirmed(`Revoke the secret ${name}? Its code is refused from then on, and the secret is removed.`, "Revoke"))) {
    return;
  }
  try {
    await api("POST", "/api/secrets/revoke", { ca: caID, name });
    say(`Secret ${name} revoked.`);
  } catch (error) {
    failed(error);
  }
  showCA();
}

// openCreate opens the form creating a secret, with the default validity of its code.
function openCreate() {
  const fields = $("create-form").elements;
  const ca = info.cas.find((ca) => ca.id === caID);
  $("create-title").textContent = "Create a secret of " + subjectName(ca.subject);
  $("create-error").classList.add("hidden");
  fields.name.value = "";
  fields.secret.value = "";
  fields.valid.value = info.defaults.valid;
  fields.networks.value = "";
  $("create-dialog").showModal();
}

// The value leaves the form once the dialog closes.
$("create-dialog").addEventListener("close", () => {
  $("create-form").elements.secret.value = "";
});
$("create-cancel").addEventListener("click", () => $("create-dialog").close());
$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = event.target.elements;
  try {
    const answer = await api("POST", "/api/secrets", { ca: caID, name: fields.name.value.trim(), value: fields.secret.value,
      valid: fields.valid.value, networks: list(fields.networks.value) });
    $("create-dialog").close();
    say("");
    showOnce(`The code of the secret ${answer.name} is shown this once; hand it to the recipient, who opens the secret `
      + "once with it on the page Get a secret before it expires.", answer.code);
    showCA();
  } catch (error) {
    if (error.message !== "no token") {
      $("create-error").textContent = error.message;
      $("create-error").classList.remove("hidden");
    }
  }
});

start();
