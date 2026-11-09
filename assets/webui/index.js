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

// The copy button after a link, its URL in data-copy, copies the URL, as copying does, and shows a
// check mark for two seconds.
const copyIcons = {
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  copied: '<path d="M5 12l5 5 9-10"/>',
};
const copyIcon = (button, name) => {
  button.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + copyIcons[name] + "</svg>";
};
for (const button of document.querySelectorAll("button[data-copy]")) {
  copyIcon(button, "copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
    } catch {
      // Without a secure context, as over plain HTTP, the text is copied from a field selected.
      const field = element("textarea", { value: button.dataset.copy, className: "fixed -left-full" });
      document.body.append(field);
      field.select();
      document.execCommand("copy");
      field.remove();
    }
    copyIcon(button, "copied");
    button.title = button.ariaLabel = "Copied";
    setTimeout(() => {
      copyIcon(button, "copy");
      button.title = button.ariaLabel = "Copy the link";
    }, 2000);
  });
}

// With the webui pages, the token kept in the tab by them is named by the first page accepting
// it, and Sign out forgets it; a token refused as invalid is forgotten.
const userRow = document.getElementById("user-row");
const tokenName = "simple-ca-webui-token";
if (userRow && sessionStorage.getItem(tokenName)) {
  document.getElementById("sign-out").addEventListener("click", () => {
    sessionStorage.removeItem(tokenName);
    userRow.classList.replace("flex", "hidden");
  });
  (async () => {
    for (const page of ["/tokens", "/certificates", "/audit"]) {
      const response = await fetch(page + "/api/cas", { headers: { Authorization: "Bearer " + sessionStorage.getItem(tokenName) } });
      if (response.status === 401) {
        sessionStorage.removeItem(tokenName);
        return;
      }
      if (response.ok) {
        const info = await response.json();
        document.getElementById("user").textContent = "Signed in as " + info.user + (info.user_ca ? " of issuing CA " + info.user_ca : "");
        userRow.classList.replace("hidden", "flex");
        return;
      }
    }
  })();
}
