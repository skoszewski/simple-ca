// The theme of the pages of serve, loaded in the head so the page is drawn in it at once: light,
// dark, or that of the browser, as chosen with any button with data-theme-switch, which goes
// through system, light and dark, and kept in localStorage.
const themeKey = "simple-ca-theme";
const themeChoices = ["system", "light", "dark"];
const darkScheme = matchMedia("(prefers-color-scheme: dark)");

// themeIcons are the outlines of the switch for each choice: a screen, a sun and a moon.
const themeIcons = {
  system: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  light: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4' +
    'M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  dark: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
};

// applyTheme sets the theme of the page from the choice kept, and shows it on the switches.
function applyTheme() {
  const choice = themeChoices.includes(localStorage.getItem(themeKey)) ? localStorage.getItem(themeKey) : "system";
  const dark = choice === "dark" || (choice === "system" && darkScheme.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  for (const button of document.querySelectorAll("[data-theme-switch]")) {
    button.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + themeIcons[choice] + "</svg>";
    button.title = button.ariaLabel = "Theme: " + choice;
  }
}
darkScheme.addEventListener("change", applyTheme);
applyTheme();
document.addEventListener("DOMContentLoaded", () => {
  for (const button of document.querySelectorAll("[data-theme-switch]")) {
    button.addEventListener("click", () => {
      const choice = localStorage.getItem(themeKey) || "system";
      localStorage.setItem(themeKey, themeChoices[(themeChoices.indexOf(choice) + 1) % themeChoices.length]);
      applyTheme();
    });
  }
  applyTheme();
});
