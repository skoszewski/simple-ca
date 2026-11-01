#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2026 Slawomir Koszewski
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Simple CA Mini: a root CA, issuing CAs, certificates, PFX bundles and an HTTP server of the
CA certificates, made with the openssl command."""

import argparse
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VERSION = "1.3.0"
CONFIG_FILE = "simple-ca.json"
PFX_PASSWORD_ENV = "SIMPLE_CA_MINI_PFX_PASSWORD"

HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[!-+\--?A-~]+@[!-+\--?A-~]+\.[!-+\--?A-~]+$")
OID_RE = re.compile(r"^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+$")
KEBAB_CASE_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")

# Certificate types: name rules, key usages and extended key usages.
CERT_TYPES = {
    "server": ("server", ["digitalSignature", "keyEncipherment"], ["serverAuth", "clientAuth"]),
    "user": ("user", ["digitalSignature", "contentCommitment"],
             ["clientAuth", "emailProtection", "codeSigning"]),
    "none": ("server", [], []),
}

openssl_path = "openssl"


class CAError(Exception):
    """An error reported to the user as ERROR: message."""


# ---- openssl ----------------------------------------------------------------

def openssl(args, input_data=None, env=None):
    """Run openssl with args and return its standard output as bytes."""
    result = subprocess.run([openssl_path] + args, input=input_data, env=env,
                            capture_output=True, check=False)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise CAError(f"openssl {args[0]} failed: {message}")
    return result.stdout


def cert_info(path):
    """Return the subject, issuer, validity dates and SHA-256 fingerprint of the certificate at
    path, as a dict keyed by the field names openssl prints."""
    out = openssl(["x509", "-in", path, "-noout", "-subject", "-issuer", "-dates",
                   "-fingerprint", "-sha256", "-nameopt", "RFC2253,-esc_msb",
                   "-dateopt", "iso_8601"])
    info = {}
    for line in out.decode("utf-8", "replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info[key.strip().lower()] = value.strip()
    return info


def write_private(path, data):
    """Write data to path, readable by the owner alone."""
    if os.path.exists(path):
        os.remove(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def make_key(path):
    """Generate an RSA 4096 key and write it to path as an unencrypted PKCS#8 PEM file."""
    write_private(path, openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"]))


def make_cert_file(cert_path, key_path, subject, days, extensions, ca_cert=None, ca_key=None):
    """Write the certificate of the key at key_path to cert_path, with the subject and extensions
    given, self-signed or signed by ca_cert and ca_key."""
    serial = 0
    while serial == 0:
        serial = secrets.randbits(159)
    args = ["req", "-x509", "-new", "-config", os.devnull, "-utf8", "-key", key_path,
            "-subj", subject, "-days", str(days), "-set_serial", f"0x{serial:X}", "-out", cert_path]
    for ext in extensions:
        args += ["-addext", ext]
    if ca_cert:
        args += ["-CA", ca_cert, "-CAkey", ca_key]
    openssl(args)


def subject_arg(cn, email):
    """Return the -subj argument of a subject with the CN and the emailAddress given."""
    subject = ""
    for name, value in (("CN", cn), ("emailAddress", email)):
        if value:
            subject += f"/{name}=" + re.sub(r"([\\/+])", r"\\\1", value)
    return subject


# ---- CA directories ---------------------------------------------------------

def resolve_ca_dir(value):
    """Return the --ca-dir value, else $SIMPLE_CA_DIR, else the working directory."""
    return value or os.environ.get("SIMPLE_CA_DIR") or os.getcwd()


def locate_ca(ca_dir):
    """Return the root CA directory of the CA in ca_dir and the name of that CA as an issuing CA,
    empty for the root CA."""
    path = os.path.abspath(ca_dir)
    cert_path = os.path.join(path, "ca_cert.pem")
    if not os.path.isfile(cert_path):
        raise CAError(f"CA certificate not found in {ca_dir}")
    info = cert_info(cert_path)
    if info["subject"] == info["issuer"]:
        return path, ""
    return os.path.dirname(path), os.path.basename(path)


def issuing_cas(root_dir):
    """Return the names of the issuing CA directories of the root CA, sorted."""
    return sorted(e.name for e in os.scandir(root_dir)
                  if e.is_dir() and os.path.isfile(os.path.join(e.path, "ca_cert.pem")))


def rebuild_ca_bundle(root_dir):
    """Write ca_bundle.pem of the root CA certificate followed by the issuing CA certificates."""
    paths = [os.path.join(root_dir, "ca_cert.pem")]
    paths += [os.path.join(root_dir, name, "ca_cert.pem") for name in issuing_cas(root_dir)]
    bundle = b""
    for path in paths:
        with open(path, "rb") as f:
            bundle += f.read()
    with open(os.path.join(root_dir, "ca_bundle.pem"), "wb") as f:
        f.write(bundle)


def load_config(root_dir):
    """Return simple-ca.json of the root CA directory as a dict, empty when it does not exist."""
    path = os.path.join(root_dir, CONFIG_FILE)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise CAError(f"could not read {path}: {e}") from e
    if not isinstance(cfg, dict):
        raise CAError(f"could not read {path}: not a JSON object")
    return cfg


def config_days(cfg, name, default):
    """Return days.name of simple-ca.json when it is a positive integer, else default."""
    days = cfg.get("days", {}).get(name)
    if isinstance(days, int) and days > 0:
        return days
    return default


# ---- ca create --------------------------------------------------------------

def make_ca(ca_dir, ca_name, days, issuing_ca, base_url):
    """Create the root CA in ca_dir, or the issuing CA ca_dir/issuing_ca, a kebab-case name, signed
    by it; a CA that exists is skipped."""
    if not os.path.isdir(ca_dir):
        raise CAError(f"CA directory {ca_dir} does not exist")
    if not ca_name:
        raise CAError("CA name is required")
    if issuing_ca and not KEBAB_CASE_RE.fullmatch(issuing_ca):
        raise CAError(f"issuing CA name '{issuing_ca}' is not a kebab-case name, such as servers or "
                      "lab-servers")
    if base_url and "," in base_url:
        raise CAError(f"invalid base URL '{base_url}': must not contain a comma")
    root_cert = os.path.join(ca_dir, "ca_cert.pem")
    root_key = os.path.join(ca_dir, "ca_key.pem")
    if os.path.isfile(root_cert):
        root_dir, name = locate_ca(ca_dir)
        if name:
            raise CAError(f"{ca_dir} holds the issuing CA '{name}'; run ca create with --ca-dir of "
                          f"its root CA, {root_dir}")

    cfg = load_config(ca_dir)
    if base_url:
        cfg["ca_publish_base_url"] = base_url
        with open(os.path.join(ca_dir, CONFIG_FILE), "w", encoding="utf-8") as f:
            f.write(json.dumps(cfg, indent=2) + "\n")
    base_url = cfg.get("ca_publish_base_url", "")
    if days is None:
        days = config_days(cfg, "ca", 3650)
    if days < 1:
        raise CAError("--days must be a positive integer")
    ca_extensions = ["subjectKeyIdentifier=hash", "keyUsage=critical,keyCertSign,cRLSign"]

    # Root CA.
    if not os.path.isfile(root_cert) or not os.path.isfile(root_key):
        if issuing_ca:
            raise CAError(f"cannot create issuing CA '{ca_name}' without existing root CA. "
                          "Please create the root CA first")
        print(f"Generating root CA certificate '{ca_name}' and key...")
        make_key(root_key)
        make_cert_file(root_cert, root_key, subject_arg(ca_name, ""), days,
                       ca_extensions + ["basicConstraints=critical,CA:TRUE,pathlen:1"])
        rebuild_ca_bundle(ca_dir)
        return
    if not issuing_ca:
        print(f"Root CA already exists in {ca_dir}, skipping.")
        return

    # Issuing CA.
    issuing_dir = os.path.join(ca_dir, issuing_ca)
    issuing_cert = os.path.join(issuing_dir, "ca_cert.pem")
    issuing_key = os.path.join(issuing_dir, "ca_key.pem")
    if os.path.isfile(issuing_cert) and os.path.isfile(issuing_key):
        print(f"Issuing CA '{issuing_ca}' already exists in {issuing_dir}, skipping.")
    else:
        print(f"Generating issuing CA certificate '{ca_name}' and key...")
        os.makedirs(issuing_dir, exist_ok=True)
        extensions = ca_extensions + ["authorityKeyIdentifier=keyid",
                                      "basicConstraints=critical,CA:TRUE,pathlen:0"]
        if base_url:
            extensions.append(f"authorityInfoAccess=caIssuers;URI:{base_url}/ca_cert.crt")
        make_key(issuing_key)
        make_cert_file(issuing_cert, issuing_key, subject_arg(ca_name, ""), days, extensions,
                       root_cert, root_key)
    rebuild_ca_bundle(ca_dir)


# ---- cert create ------------------------------------------------------------

def parse_ip(value):
    """Return value as an IPv4 or IPv6 address without a zone, or None."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if getattr(addr, "scope_id", None):
        return None
    return addr


def is_oid(value):
    """Report whether value is a numeric OID."""
    if not OID_RE.match(value):
        return False
    arcs = [int(a) for a in value.split(".")]
    return arcs[0] <= 2 and (arcs[0] == 2 or arcs[1] < 40)


def is_hostname(value):
    """Report whether value is a hostname or an FQDN whose last label is not all digits, and
    neither an IP address nor an OID."""
    if parse_ip(value) or is_oid(value):
        return False
    last = value.rsplit(".", 1)[-1]
    return len(value) <= 253 and bool(HOSTNAME_RE.match(value)) and not last.isdigit()


def make_cert(subject_name, sans, ca_dir, cert_dir, cert_type, days):
    """Issue a certificate of cert_type signed by the CA in ca_dir and write it with its key to
    cert_dir; a certificate that exists is skipped.

    By the server name rules, subject_name is the CN, a hostname or FQDN, which is also the first
    DNS name; sans are hostnames, FQDNs, IPv4 and IPv6 addresses and numeric OIDs. By the user
    name rules, subject_name is the CN or the emailAddress, and the first of sans, when given, is
    the other of the two; the emailAddress is also the first email SAN, and the rest of sans are
    email addresses and numeric OIDs.
    """
    if not os.path.isdir(ca_dir):
        raise CAError(f"CA directory {ca_dir} does not exist")
    if not subject_name:
        raise CAError("subject name is required")
    root_dir, issuing_ca = locate_ca(ca_dir)
    cfg = load_config(root_dir)
    if days is None:
        days = config_days(cfg, "cert", 365)
    if days < 1:
        raise CAError("--days must be a positive integer")
    names, key_usage, ext_key_usage = CERT_TYPES[cert_type]
    user_names = names == "user"

    # The subject and the SANs, by the name rules of the certificate type.
    cn = email = ""
    dns_names, emails, ips, oids = [], [], [], []
    rest = list(sans)
    if not user_names:
        if not is_hostname(subject_name):
            raise CAError(f"invalid CN '{subject_name}': a {cert_type} certificate's CN must be a "
                          "hostname or FQDN")
        cn = subject_name
        dns_names.append(cn)
    else:
        if EMAIL_RE.match(subject_name):
            email = subject_name
        else:
            cn = subject_name
        if rest:
            following = rest.pop(0)
            if not email and not EMAIL_RE.match(following):
                raise CAError(f"invalid emailAddress '{following}': the CN is '{cn}', so the second "
                              "argument must be the email address")
            if not email:
                email = following
            elif EMAIL_RE.match(following):
                raise CAError(f"invalid CN '{following}': the emailAddress is '{email}', so the "
                              "second argument must be the CN")
            else:
                cn = following
        if email:
            emails.append(email)
    for entry in rest:
        ip = parse_ip(entry)
        if not user_names and ip:
            ips.append(ip)
        elif is_oid(entry):
            oids.append(entry)
        elif not user_names and is_hostname(entry):
            dns_names.append(entry)
        elif user_names and EMAIL_RE.match(entry):
            emails.append(entry)
        elif not user_names:
            raise CAError(f"invalid SAN '{entry}': must be a hostname, FQDN, IPv4 or IPv6 address, "
                          "or numeric OID")
        else:
            raise CAError(f"invalid SAN '{entry}': must be an email address or numeric OID")

    cert_dir = cert_dir or ca_dir
    if not os.path.isdir(cert_dir):
        raise CAError(f"certificate directory {cert_dir} does not exist")
    ca_cert = os.path.join(ca_dir, "ca_cert.pem")
    ca_key = os.path.join(ca_dir, "ca_key.pem")
    if not os.path.isfile(ca_cert) or not os.path.isfile(ca_key):
        raise CAError(f"CA certificate and key not found in {ca_dir}. Please point --ca-dir to a "
                      "CA directory")
    base_url = cfg.get("ca_publish_base_url", "")
    if base_url and issuing_ca:
        base_url += "/" + issuing_ca

    # The files are named after the hostname CN up to its first dot, or the user CN, or the local
    # part of the emailAddress, each run of characters besides letters, digits, - and _ as one _.
    if cn and not user_names:
        cert_name = cn.split(".", 1)[0]
    else:
        cert_name = cn or email.split("@", 1)[0]
    cert_name = re.sub(r"[^A-Za-z0-9_-]+", "_", cert_name).strip("_")
    if not cert_name:
        raise CAError(f"'{cn or email}' gives no file name: it needs a letter or a digit")

    described = ([f"email:{e}" for e in emails] + [f"DNS:{d}" for d in dns_names]
                 + [f"IP:{ip}" for ip in ips] + [f"RID:{oid}" for oid in oids])
    if cn:
        print(f"Generating {cert_type} certificate for CN '{cn}'", end="")
    else:
        print(f"Generating {cert_type} certificate for emailAddress '{email}'", end="")
    print(" with SANs:" if described else ".")
    for d in described:
        print(f"  - {d}")

    cert_out = os.path.join(cert_dir, cert_name + "_cert.pem")
    key_out = os.path.join(cert_dir, cert_name + "_key.pem")
    if os.path.isfile(cert_out) and os.path.isfile(key_out):
        print(f"Certificate already exists in {cert_dir}, skipping.")
        return

    print("Generating certificate and key...")
    extensions = ["subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid",
                  "basicConstraints=critical,CA:FALSE"]
    if key_usage:
        extensions.append("keyUsage=critical," + ",".join(key_usage))
    if ext_key_usage:
        extensions.append("extendedKeyUsage=" + ",".join(ext_key_usage))
    if described:
        extensions.append("subjectAltName=" + ",".join(described))
    if base_url:
        extensions.append(f"authorityInfoAccess=caIssuers;URI:{base_url}/ca_cert.crt")
    make_key(key_out)
    make_cert_file(cert_out, key_out, subject_arg(cn, email), days, extensions, ca_cert, ca_key)


# ---- cert pfx ---------------------------------------------------------------

def make_pfx(cert_path, ca_dir, password):
    """Write a PKCS#12 bundle of the certificate at cert_path, its key and the chain of the CA in
    ca_dir that signed it next to the certificate."""
    cert_dir = os.path.dirname(cert_path) or "."
    base = os.path.basename(cert_path)
    cert_name = base[:-len("_cert.pem")] if base.endswith("_cert.pem") else base
    key_path = os.path.join(cert_dir, cert_name + "_key.pem")
    pfx_path = os.path.join(cert_dir, cert_name + ".pfx")
    if not os.path.isdir(ca_dir):
        raise CAError(f"CA directory {ca_dir} does not exist")
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        raise CAError("certificate or key not found")
    root_dir, issuing_ca = locate_ca(ca_dir)
    if os.path.exists(pfx_path):
        raise CAError("PKCS#12 (PFX) file already exists, aborting generation")

    print("Generating PKCS#12 (PFX) file...", end="", flush=True)
    chain = [cert_path, os.path.join(root_dir, "ca_cert.pem")]
    if issuing_ca:
        chain.append(os.path.join(ca_dir, "ca_cert.pem"))
    pem = b""
    for path in chain:
        with open(path, "rb") as f:
            pem += f.read()
    env = dict(os.environ, **{PFX_PASSWORD_ENV: password})
    pfx = openssl(["pkcs12", "-export", "-inkey", key_path, "-passout", f"env:{PFX_PASSWORD_ENV}"],
                  input_data=pem, env=env)
    write_private(pfx_path, pfx)
    print("done.")


# ---- serve ------------------------------------------------------------------

class CAServer(ThreadingHTTPServer):
    """The HTTP server of the CA certificates."""

    daemon_threads = True


class CAHandler(BaseHTTPRequestHandler):
    """Serves the index page, the CA certificates and the CA bundle of the root CA in root_dir."""

    root_dir = ""
    server_version = f"simple-ca-mini/{VERSION}"

    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def method_not_allowed(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = method_not_allowed

    def respond(self, with_body):
        """Send the page or the file of the request path, 404 for any other path."""
        path = urlsplit(self.path).path
        parts = path.strip("/").split("/")
        try:
            if path == "/":
                body, content_type = self.index_page(), "text/html; charset=utf-8"
            elif len(parts) == 1:
                body, content_type = self.read_cert(self.root_dir, parts[0])
            elif len(parts) == 2 and parts[0] in issuing_cas(self.root_dir):
                body, content_type = self.read_cert(os.path.join(self.root_dir, parts[0]), parts[1])
            else:
                body = content_type = None
        except (CAError, OSError) as e:
            self.log_error("%s", e)
            self.send_error(500)
            return
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    @staticmethod
    def read_cert(directory, name):
        """Return the content and type of the file name of directory, (None, None) when it is not
        served or does not exist."""
        if name not in ("ca_cert.pem", "ca_cert.crt", "ca_bundle.pem"):
            return None, None
        pem_path = os.path.join(directory, "ca_cert.pem" if name == "ca_cert.crt" else name)
        if not os.path.isfile(pem_path):
            return None, None
        if name == "ca_cert.crt":
            return openssl(["x509", "-in", pem_path, "-outform", "DER"]), "application/pkix-cert"
        with open(pem_path, "rb") as f:
            return f.read(), "application/x-pem-file"

    def index_page(self):
        """Return the HTML index page of the root CA and its issuing CAs."""
        now = datetime.now(timezone.utc)
        sections = []
        for name in [""] + issuing_cas(self.root_dir):
            prefix = f"/{name}" if name else ""
            info = cert_info(os.path.join(self.root_dir, name, "ca_cert.pem"))
            not_after = datetime.strptime(info["notafter"], "%Y-%m-%d %H:%M:%SZ").replace(
                tzinfo=timezone.utc)
            days_left = (not_after - now).days
            rows = [("Subject", info["subject"]), ("Issuer", info["issuer"]),
                    ("Valid from", info["notbefore"]), ("Valid until", info["notafter"]),
                    ("Days left", str(days_left)),
                    ("SHA-256 fingerprint", info["sha256 fingerprint"])]
            table = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
                            for k, v in rows)
            title = f"Issuing CA {name}" if name else "Root CA"
            sections.append(
                f"<section><h2>{html.escape(title)}</h2><table>{table}</table>"
                f"<p><a href=\"{html.escape(prefix)}/ca_cert.crt\">Certificate (DER)</a> "
                f"<a href=\"{html.escape(prefix)}/ca_cert.pem\">Certificate (PEM)</a></p></section>")
        page = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Simple CA Mini</title><style>"
            "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;color:#222}"
            "section{border:1px solid #ccc;border-radius:6px;padding:0 1rem 1rem;margin:1rem 0}"
            "th{text-align:left;padding-right:1rem;vertical-align:top;white-space:nowrap}"
            "td{word-break:break-all}a{margin-right:1rem}"
            "</style></head><body><h1>Simple CA Mini</h1>"
            "<p><a href=\"/ca_bundle.pem\">CA bundle (PEM)</a></p>"
            + "".join(sections) + "</body></html>")
        return page.encode("utf-8")


def serve(ca_dir, address, port):
    """Serve the CA certificates of the root CA of ca_dir over HTTP until interrupted."""
    if not 1 <= port <= 65535:
        raise CAError(f"--port must be from 1 to 65535, got {port}")
    root_dir, _ = locate_ca(ca_dir)
    CAHandler.root_dir = root_dir
    CAServer.address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with CAServer((address, port), CAHandler) as server:
        host = f"[{address}]" if ":" in address else address
        print(f"Serving the CAs of {root_dir} on http://{host}:{port}/")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


# ---- CLI --------------------------------------------------------------------

def main():
    """Parse the command line and run the command."""
    parser = argparse.ArgumentParser(
        prog="simple-ca-mini",
        description="Create a simple Certificate Authority with the openssl command.")
    parser.add_argument("--version", action="version", version=f"simple-ca-mini version {VERSION}")
    groups = parser.add_subparsers(dest="group", required=True, metavar="GROUP")

    # Each command sets run, called with the parsed arguments and the CA directory.
    ca = groups.add_parser("ca", help="create root and issuing CAs").add_subparsers(
        dest="command", required=True, metavar="COMMAND")
    p = ca.add_parser("create", help="create a root or issuing CA")
    p.add_argument("--ca-dir", help="directory of the root CA")
    p.add_argument("--days", type=int, help="validity period in days (default: 3650)")
    p.add_argument("--ca-url", metavar="URL",
                   help="base URL for the AIA extension, stored in simple-ca.json")
    # The former name of --ca-url, accepted and left out of the help.
    p.add_argument("--ca-publish-base-url", dest="ca_url", help=argparse.SUPPRESS)
    p.add_argument("--issuing-ca", metavar="NAME", help="create an issuing CA in this directory")
    p.add_argument("ca_name", metavar="CA_NAME")
    p.set_defaults(run=lambda a, ca_dir: make_ca(ca_dir, a.ca_name, a.days, a.issuing_ca, a.ca_url))

    cert = groups.add_parser("cert", help="create certificates and PFX bundles").add_subparsers(
        dest="command", required=True, metavar="COMMAND")
    p = cert.add_parser("create", help="create a server, user or none certificate")
    p.add_argument("--ca-dir", help="directory of the signing CA, the root CA or an issuing CA")
    p.add_argument("--cert-dir", help="output directory (default: the CA directory)")
    p.add_argument("--days", type=int, help="validity period in days (default: 365)")
    p.add_argument("--type", default="server", choices=sorted(CERT_TYPES),
                   help="certificate type (default: server)")
    p.add_argument("subject", metavar="CN|EMAIL")
    p.add_argument("sans", metavar="SAN", nargs="*",
                   help="EMAIL|CN for user certificates, then subject alternative names")
    p.set_defaults(run=lambda a, ca_dir: make_cert(a.subject, a.sans, ca_dir, a.cert_dir, a.type,
                                                   a.days))

    p = cert.add_parser("pfx", help="create a PKCS#12 (PFX) bundle of a certificate")
    p.add_argument("--ca-dir", help="directory of the CA that signed the certificate")
    p.add_argument("--password", default="changeit", help="PFX password (default: changeit)")
    p.add_argument("cert_path", metavar="CERT_PATH")
    p.set_defaults(run=lambda a, ca_dir: make_pfx(a.cert_path, ca_dir, a.password))

    p = groups.add_parser("serve", help="serve the CA certificates over HTTP")
    p.add_argument("--ca-dir", help="directory of the root CA or of one of its issuing CAs")
    p.add_argument("--address", default="127.0.0.1",
                   help="address to listen on; 0.0.0.0 for all interfaces (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="TCP port (default: 8080)")
    p.set_defaults(run=lambda a, ca_dir: serve(ca_dir, a.address, a.port))

    args = parser.parse_args()
    global openssl_path
    try:
        openssl_path = shutil.which("openssl")
        if not openssl_path:
            raise CAError("the openssl command is required on PATH")
        args.run(args, resolve_ca_dir(args.ca_dir))
    except (CAError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
