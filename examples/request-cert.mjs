#!/usr/bin/env node
/**
 * Request a server certificate from the signing API of simple-ca serve.
 *
 * Usage: SIMPLE_CA_TOKEN=TOKEN request-cert.mjs CA_URL CN [DNS_NAME ...]
 *        SIMPLE_CA_TOKEN_FILE=FILE request-cert.mjs CA_URL CN [DNS_NAME ...]
 *        [SIMPLE_CA_TOKEN_FILE=NEW_FILE] request-cert.mjs --setup-code CODE CA_URL CN [DNS_NAME ...]
 *
 * A setup code is exchanged for the token at /api/token-setup of the server of CA_URL first; the
 * token is written to SIMPLE_CA_TOKEN_FILE, a file that does not exist yet, when it is set.
 *
 * The openssl command makes an EC P-256 key and a certificate signing request for the CN, with
 * the CN and the DNS names as its DNS names. The request is sent to the signing API of the CA at
 * CA_URL, such as https://pki.example.com/servers, with a token made by simple-ca token create, in
 * SIMPLE_CA_TOKEN or in the file SIMPLE_CA_TOKEN_FILE names, and the certificate type in
 * SIMPLE_CA_TYPE, the first type of the token when it is unset. The key, the certificate and the
 * chain are written to CN_key.pem, CN_cert.pem and CN_chain.pem, a wildcard CN *.NAME as
 * wildcard.NAME; the key only once the certificate is signed.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

let token = process.env.SIMPLE_CA_TOKEN ?? "";
const tokenFile = process.env.SIMPLE_CA_TOKEN_FILE ?? "";
const args = process.argv.slice(2);
const code = args[0] === "--setup-code" ? args.splice(0, 2)[1] ?? "" : "";
const [caURL, cn, ...names] = args;
if (!cn || !(token || tokenFile || code)) {
  console.error("Usage: SIMPLE_CA_TOKEN=TOKEN request-cert.mjs CA_URL CN [DNS_NAME ...]\n" +
    "       SIMPLE_CA_TOKEN_FILE=FILE request-cert.mjs CA_URL CN [DNS_NAME ...]\n" +
    "       [SIMPLE_CA_TOKEN_FILE=NEW_FILE] request-cert.mjs --setup-code CODE CA_URL CN [DNS_NAME ...]");
  process.exit(1);
}
const url = caURL.replace(/\/$/, "").replace(/\/api\/sign$/, "") + "/api/sign";
if (token && (tokenFile || code)) {
  console.error("set SIMPLE_CA_TOKEN or SIMPLE_CA_TOKEN_FILE, or give --setup-code, not two of them");
  process.exit(1);
}
if (code && tokenFile && existsSync(tokenFile)) {
  console.error(`SIMPLE_CA_TOKEN_FILE: ${tokenFile} exists; the token of --setup-code is written to a new file`);
  process.exit(1);
}
if (code) {
  let setupURL;
  try {
    setupURL = new URL("/api/token-setup", caURL).href;
  } catch {
    console.error(`${caURL} is not a URL such as https://pki.example.com/servers`);
    process.exit(1);
  }
  let response;
  let text = "";
  try {
    response = await fetch(setupURL, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    text = await response.text();
  } catch (e) {
    console.error(`${setupURL}: ${e.cause?.message ?? e.message}`);
    process.exit(1);
  }
  let answer = {};
  try {
    answer = JSON.parse(text);
  } catch {}
  if (!response.ok || !answer.token) {
    console.error(`${setupURL}: ${response.status} ${answer.error ?? text.trim()}`);
    process.exit(1);
  }
  token = answer.token;
  if (tokenFile) {
    writeFileSync(tokenFile, token + "\n", { mode: 0o600 });
    console.log(`Token written to ${tokenFile}`);
  }
} else if (tokenFile) {
  try {
    token = readFileSync(tokenFile, "utf8").trim();
  } catch (e) {
    console.error(`SIMPLE_CA_TOKEN_FILE: ${e.message}`);
    process.exit(1);
  }
  if (!token) {
    console.error(`SIMPLE_CA_TOKEN_FILE: ${tokenFile} is empty`);
    process.exit(1);
  }
}
const prefix = cn.startsWith("*.") ? "wildcard." + cn.slice(2) : cn;
const keyPath = `${prefix}_key.pem`;
const certPath = `${prefix}_cert.pem`;
const chainPath = `${prefix}_chain.pem`;
if (existsSync(keyPath)) {
  console.error(`${keyPath} exists`);
  process.exit(1);
}

const tmp = mkdtempSync(".request-cert-");
try {
  const newKey = join(tmp, "key.pem");
  const sans = [...new Set([cn, ...names])].map((n) => "DNS:" + n).join(",");
  let csr;
  try {
    csr = execFileSync("openssl", ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", newKey, "-subj", "/CN=" + cn, "-addext", "subjectAltName=" + sans],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    console.error(`openssl req failed:\n${e.stderr ?? e.message}`);
    rmSync(tmp, { recursive: true, force: true });
    process.exit(1);
  }

  const body = { csr };
  if (process.env.SIMPLE_CA_TYPE) {
    body.type = process.env.SIMPLE_CA_TYPE;
  }
  let response;
  let text = "";
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify(body),
    });
    text = await response.text();
  } catch (e) {
    console.error(`${url}: ${e.cause?.message ?? e.message}`);
    rmSync(tmp, { recursive: true, force: true });
    process.exit(1);
  }
  if (!response.ok) {
    // The API answers with {"error": ...}; a URL that is not the API answers with text.
    let message = text.trim();
    try {
      message = JSON.parse(text).error ?? message;
    } catch {}
    console.error(`${url}: ${response.status} ${message}`);
    process.exitCode = 1;
  } else {
    const result = JSON.parse(text);
    writeFileSync(certPath, result.certificate);
    writeFileSync(chainPath, result.chain);
    renameSync(newKey, keyPath);
    console.log(`Certificate ${result.serial} written to ${certPath}, its chain to ${chainPath} and its key to ${keyPath}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
