// The signing form of serve, after picker.js: the certificate type is chosen with a picker made of
// the options of the form's type select, which it replaces.
const select = document.getElementById("type");
if (select) {
  select.replaceWith(picker({ name: "type", labelledBy: "type-label",
    choices: [...select.options].map((option) => [option.value, option.textContent]), value: select.value }));
}
