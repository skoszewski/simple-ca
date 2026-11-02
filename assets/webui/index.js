// The index page of serve: the name of a CA shows the attributes of its subject in a popup while
// the pointer is over it or it has the focus; the Info button of a CA opens the dialog of its
// details, which closes on a click beside it, and an address naming an issuing CA, /#NAME, opens
// the dialog of that CA.
for (const name of document.querySelectorAll("[data-subject]")) {
  const popup = document.getElementById(name.dataset.subject);
  const show = () => {
    const box = name.getBoundingClientRect();
    popup.style.left = `${box.left}px`;
    popup.style.top = `${box.bottom + 4}px`;
    popup.classList.remove("hidden");
  };
  const hide = () => popup.classList.add("hidden");
  name.addEventListener("mouseenter", show);
  name.addEventListener("mouseleave", hide);
  name.addEventListener("focus", show);
  name.addEventListener("blur", hide);
}
// A popup placed by the page's position is hidden once the page scrolls.
addEventListener("scroll", () => {
  for (const popup of document.querySelectorAll('[role="tooltip"]')) {
    popup.classList.add("hidden");
  }
});
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
