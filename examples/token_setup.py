#!/usr/bin/env python3
"""Exchange a setup code of simple-ca serve for its token, and print the token."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("code", help="the setup code")
parser.add_argument("--url", default=os.environ.get("SIMPLE_CA_URL"),
                    help="URL of the server, such as https://pki.example.com; a path is left out (default: $SIMPLE_CA_URL)")
args = parser.parse_args()
parts = urllib.parse.urlsplit(args.url or "")
if not parts.scheme or not parts.netloc:
    parser.error("give --url or set SIMPLE_CA_URL to a URL such as https://pki.example.com")

request = urllib.request.Request(f"{parts.scheme}://{parts.netloc}/api/token-setup",
                                 data=json.dumps({"code": args.code}).encode(), headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request) as response:
        print(json.load(response)["token"])
except urllib.error.HTTPError as e:
    sys.exit(f"{e.code} {e.read().decode(errors='replace').strip()}")
except (urllib.error.URLError, ValueError, KeyError) as e:
    sys.exit(f"{args.url}: {e}")
