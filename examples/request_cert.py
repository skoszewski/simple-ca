#!/usr/bin/env python3
"""Request a server certificate from the signing API of simple-ca serve.

Usage: SIMPLE_CA_TOKEN=TOKEN request_cert.py API_URL CN [DNS_NAME ...]
       SIMPLE_CA_TOKEN_FILE=FILE request_cert.py API_URL CN [DNS_NAME ...]
       [SIMPLE_CA_TOKEN_FILE=NEW_FILE] request_cert.py --setup-code CODE API_URL CN [DNS_NAME ...]

A setup code is exchanged for the token at /api/token-setup of the server of API_URL first; the
token is written to SIMPLE_CA_TOKEN_FILE, a file that does not exist yet, when it is set. The
openssl command makes an EC P-256 key and a certificate signing request for the CN, with the
CN and the DNS names as its DNS names. The request is sent to API_URL, such as
https://pki.example.com/servers/api/sign, with a token made by simple-ca token create, in
SIMPLE_CA_TOKEN or in the file SIMPLE_CA_TOKEN_FILE names, and the certificate type in
SIMPLE_CA_TYPE, the first type of the token when it is unset. The key, the certificate and the
chain are written to CN_key.pem, CN_cert.pem and CN_chain.pem, a wildcard CN *.NAME as
wildcard.NAME; the key only once the certificate is signed.
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def main():
    token, token_file = os.environ.get("SIMPLE_CA_TOKEN", ""), os.environ.get("SIMPLE_CA_TOKEN_FILE", "")
    args, code = sys.argv[1:], ""
    if args[:1] == ["--setup-code"] and len(args) >= 2:
        code, args = args[1], args[2:]
    if len(args) < 2 or not (token or token_file or code):
        sys.exit(__doc__.split("\n\n")[1])
    if token and (token_file or code):
        sys.exit("set SIMPLE_CA_TOKEN or SIMPLE_CA_TOKEN_FILE, or give --setup-code, not two of them")
    if code and token_file and os.path.exists(token_file):
        sys.exit(f"SIMPLE_CA_TOKEN_FILE: {token_file} exists; the token of --setup-code is written to a new file")
    if code:
        parts = urllib.parse.urlsplit(args[0])
        if not parts.scheme or not parts.netloc:
            sys.exit(f"{args[0]} is not a URL such as https://pki.example.com/servers/api/sign")
        setup_url = f"{parts.scheme}://{parts.netloc}/api/token-setup"
        request = urllib.request.Request(setup_url, data=json.dumps({"code": code}).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as response:
                token = json.load(response)["token"]
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            try:
                text = json.loads(text)["error"]
            except (ValueError, KeyError, TypeError):
                pass
            sys.exit(f"{setup_url}: {e.code} {text.strip()}")
        except urllib.error.URLError as e:
            sys.exit(f"{setup_url}: {e.reason}")
        if token_file:
            with open(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(token + "\n")
            print(f"Token written to {token_file}")
    elif token_file:
        try:
            with open(token_file) as f:
                token = f.read().strip()
        except OSError as e:
            sys.exit(f"SIMPLE_CA_TOKEN_FILE: {e}")
        if not token:
            sys.exit(f"SIMPLE_CA_TOKEN_FILE: {token_file} is empty")
    url, cn, *names = args
    prefix = "wildcard." + cn[2:] if cn.startswith("*.") else cn
    key_path, cert_path, chain_path = f"{prefix}_key.pem", f"{prefix}_cert.pem", f"{prefix}_chain.pem"
    if os.path.exists(key_path):
        sys.exit(f"{key_path} exists")

    with tempfile.TemporaryDirectory(dir=".") as tmp:
        new_key = os.path.join(tmp, "key.pem")
        sans = ",".join("DNS:" + n for n in dict.fromkeys([cn, *names]))
        made = subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                               "-nodes", "-keyout", new_key, "-subj", "/CN=" + cn,
                               "-addext", "subjectAltName=" + sans], capture_output=True, text=True)
        if made.returncode != 0:
            sys.exit(f"openssl req failed:\n{made.stderr}")

        body = {"csr": made.stdout}
        if os.environ.get("SIMPLE_CA_TYPE"):
            body["type"] = os.environ["SIMPLE_CA_TYPE"]
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(request) as response:
                result = json.load(response)
        except urllib.error.HTTPError as e:
            # The API answers with {"error": ...}; a URL that is not the API answers with text.
            text = e.read().decode(errors="replace")
            try:
                text = json.loads(text)["error"]
            except (ValueError, KeyError, TypeError):
                pass
            sys.exit(f"{url}: {e.code} {text.strip()}")
        except urllib.error.URLError as e:
            sys.exit(f"{url}: {e.reason}")

        with open(cert_path, "w") as f:
            f.write(result["certificate"])
        with open(chain_path, "w") as f:
            f.write(result["chain"])
        os.replace(new_key, key_path)
    print(f"Certificate {result['serial']} written to {cert_path}, its chain to {chain_path} and its key to {key_path}")


if __name__ == "__main__":
    main()
