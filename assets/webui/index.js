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
