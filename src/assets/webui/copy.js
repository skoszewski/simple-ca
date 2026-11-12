// The copy button, its text in data-copy, copies the text, as copying does, and shows a check mark
// for two seconds before its title returns.
const copyIcons = {
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  copied: '<path d="M5 12l5 5 9-10"/>',
};
const copyIcon = (button, name) => {
  button.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + copyIcons[name] + "</svg>";
};
for (const button of document.querySelectorAll("button[data-copy]")) {
  const title = button.title;
  copyIcon(button, "copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
    } catch {
      // Without a secure context, as over plain HTTP, the text is copied from a field selected.
      const field = document.createElement("textarea");
      field.value = button.dataset.copy;
      field.className = "fixed -left-full";
      document.body.append(field);
      field.select();
      document.execCommand("copy");
      field.remove();
    }
    copyIcon(button, "copied");
    button.title = button.ariaLabel = "Copied";
    setTimeout(() => {
      copyIcon(button, "copy");
      button.title = button.ariaLabel = title;
    }, 2000);
  });
}
