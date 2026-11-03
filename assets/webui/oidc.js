// The OIDC sign-in of the pages of serve, a public client with the authorization code flow and
// PKCE: oidcButton shows the button that starts it on a page, oidcTaken gives that page the token
// of the sign-in once the browser is back, and the callback page, oidc-callback.html, redeems the
// code at the provider and exchanges the ID token for the token at /api/oidc-token.
const oidcFlowKey = "simple-ca-oidc-flow";
const oidcResultKey = "simple-ca-oidc-result";

// oidcSettings returns the OIDC sign-in of serve, or null when it is off.
async function oidcSettings() {
  const response = await fetch("/api/oidc").catch(() => null);
  return response && response.ok ? response.json() : null;
}

const oidcBase64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const oidcRandom = () => oidcBase64url(crypto.getRandomValues(new Uint8Array(32)));

// oidcButton makes button, hidden, sign in with the provider when the sign-in is on; save, when
// given, is called before the page is left for the provider, and failed with an error that stops
// the sign-in.
async function oidcButton(button, save, failed) {
  const settings = await oidcSettings();
  if (!settings) {
    return;
  }
  button.textContent = "Sign in with " + settings.label;
  button.classList.remove("hidden");
  button.addEventListener("click", async () => {
    if (!crypto.subtle) {
      failed("The sign-in with " + settings.label + " needs this page over HTTPS, or on localhost.");
      return;
    }
    if (save) {
      save();
    }
    const verifier = oidcRandom();
    const state = oidcRandom();
    const nonce = oidcRandom();
    const challenge = oidcBase64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    sessionStorage.setItem(oidcFlowKey, JSON.stringify({ verifier, state, nonce, back: location.pathname + location.search }));
    const url = new URL(settings.authorization_endpoint);
    for (const [key, value] of Object.entries({ response_type: "code", client_id: settings.client_id,
      redirect_uri: location.origin + settings.redirect_path, scope: settings.scopes.join(" "), state, nonce,
      code_challenge: challenge, code_challenge_method: "S256" })) {
      url.searchParams.set(key, value);
    }
    location.assign(url);
  });
}

// oidcTaken returns, once, the answer of /api/oidc-token the callback page left for this page:
// the CA ID, the name, the token and the scopes of the token of the sign-in; or null.
function oidcTaken() {
  const result = sessionStorage.getItem(oidcResultKey);
  sessionStorage.removeItem(oidcResultKey);
  return result ? JSON.parse(result) : null;
}

// oidcCallback redeems the code the provider sent the browser back with, checks that the ID token
// answers the sign-in started on this browser tab, exchanges it for the token, and goes back to
// the page the sign-in was started on, which takes the token with oidcTaken; an error is shown.
async function oidcCallback() {
  const message = document.getElementById("oidc-message");
  const back = document.getElementById("oidc-back");
  const flow = JSON.parse(sessionStorage.getItem(oidcFlowKey) || "null");
  sessionStorage.removeItem(oidcFlowKey);
  if (flow) {
    back.href = flow.back;
  }
  const fail = (text) => {
    message.textContent = text;
    message.className = "rounded-lg border border-bad-line bg-bad px-4 py-3 text-sm text-bad-ink";
    back.classList.remove("hidden");
  };
  const query = new URLSearchParams(location.search);
  history.replaceState(null, "", location.pathname);
  if (query.get("error")) {
    fail("The provider refused the sign-in: " + (query.get("error_description") || query.get("error")));
    return;
  }
  if (!flow || query.get("state") !== flow.state || !query.get("code")) {
    fail("This sign-in was not started on this browser tab; start it again.");
    return;
  }
  const settings = await oidcSettings();
  if (!settings) {
    fail("The OIDC sign-in is off.");
    return;
  }
  const redeemed = await fetch(settings.token_endpoint, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: query.get("code"), client_id: settings.client_id,
      redirect_uri: location.origin + settings.redirect_path, code_verifier: flow.verifier }) }).catch(() => null);
  if (!redeemed) {
    fail("The provider could not be reached to redeem the sign-in; it must allow this origin, " + location.origin + ".");
    return;
  }
  const tokens = await redeemed.json().catch(() => ({}));
  if (!redeemed.ok || !tokens.id_token) {
    fail("The provider did not give an ID token: " + (tokens.error_description || tokens.error || redeemed.statusText));
    return;
  }
  const payload = tokens.id_token.split(".")[1] || "";
  const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0))));
  if (claims.nonce !== flow.nonce) {
    fail("The ID token does not answer this sign-in; start it again.");
    return;
  }
  const exchanged = await fetch("/api/oidc-token", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id_token: tokens.id_token }) });
  const answer = await exchanged.json().catch(() => ({}));
  if (!exchanged.ok) {
    fail(answer.error || exchanged.statusText);
    return;
  }
  sessionStorage.setItem(oidcResultKey, JSON.stringify(answer));
  location.replace(flow.back);
}

if (document.getElementById("oidc-callback")) {
  oidcCallback();
}
