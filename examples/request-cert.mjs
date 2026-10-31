#!/usr/bin/env node
/**
 * Request a server certificate from the signing API of simple-ca serve.
 *
 * Usage: SIMPLE_CA_TOKEN=TOKEN request-cert.mjs API_URL CN [DNS_NAME ...]
 *        SIMPLE_CA_TOKEN_FILE=FILE request-cert.mjs API_URL CN [DNS_NAME ...]
 *
 * The openssl command makes an EC P-256 key and a certificate signing request for the CN, with
 * the CN and the DNS names as its DNS names. The request is sent to API_URL, such as
 * https://pki.example.com/servers/api/sign, with the token of make-token in SIMPLE_CA_TOKEN, or
 * in the file SIMPLE_CA_TOKEN_FILE names, and the certificate type in SIMPLE_CA_TYPE, the first
 * type of the token when it is unset. The key, the certificate and the chain are written to
 * CN_key.pem, CN_cert.pem and CN_chain.pem, a wildcard CN *.NAME as wildcard.NAME; the key only
 * once the certificate is signed.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

let token = process.env.SIMPLE_CA_TOKEN ?? "";
const tokenFile = process.env.SIMPLE_CA_TOKEN_FILE ?? "";
const [url, cn, ...names] = process.argv.slice(2);
if (!cn || !(token || tokenFile)) {
  console.error("Usage: SIMPLE_CA_TOKEN=TOKEN request-cert.mjs API_URL CN [DNS_NAME ...]\n" +
    "       SIMPLE_CA_TOKEN_FILE=FILE request-cert.mjs API_URL CN [DNS_NAME ...]");
  process.exit(1);
}
if (token && tokenFile) {
  console.error("set SIMPLE_CA_TOKEN or SIMPLE_CA_TOKEN_FILE, not both");
  process.exit(1);
}
if (tokenFile) {
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
