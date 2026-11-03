// The index page of serve, after picker.js: the name of a CA, given with the attributes of its
// subject as JSON in data-subject, shows them in a popup; the Info button of a CA opens the dialog
// of its details, which closes on a click beside it, and an address naming an issuing CA, /#NAME,
// opens the dialog of that CA.
for (const name of document.querySelectorAll("[data-subject]")) {
  name.replaceWith(...named(name.textContent, JSON.parse(name.dataset.subject)));
}
for (const button of document.querySelectorAll("button[data-info]")) {
  button.addEventListener("click", () => document.getElementById(button.dataset.info).showModal());
}
for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
}
if (location.hash) {
  document.getElementById(decodeURIComponent(location.hash.slice(1)))?.querySelector("button[data-info]")?.click();
}
