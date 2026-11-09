#!/usr/bin/env node
/**
 * Step 5 of google.md: get a JWT from simple-ca serve with the federate token of the machine, and
 * exchange it with Google's Security Token Service for an access token, printed to the output.
 *
 * Usage: google-access-token.mjs CA_URL TOKEN_FILE PROVIDER
 *
 * CA_URL is the URL of the CA, such as https://pki.example.com/gcp-wif; PROVIDER is the provider's
 * name, //iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/ID.
 */

import { readFileSync } from "node:fs";

const [caURL, tokenFile, provider] = process.argv.slice(2);
if (!provider) {
  console.error("Usage: google-access-token.mjs CA_URL TOKEN_FILE PROVIDER");
  process.exit(1);
}

// 1. The JWT, from simple-ca serve.
const token = readFileSync(tokenFile, "utf8").trim();
const federation = await fetch(`${caURL}/api/federation-token`, {
  method: "POST", headers: { Authorization: `Bearer ${token}` } });
if (!federation.ok) {
  console.error(`${caURL}/api/federation-token: ${federation.status} ${await federation.text()}`);
  process.exit(1);
}
const { token: jwt } = await federation.json();

// 2. The access token, from Google's Security Token Service.
const sts = await fetch("https://sts.googleapis.com/v1/token", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
    audience: provider,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    subjectToken: jwt,
  }) });
if (!sts.ok) {
  console.error(`https://sts.googleapis.com/v1/token: ${sts.status} ${await sts.text()}`);
  process.exit(1);
}
console.log((await sts.json()).access_token);
