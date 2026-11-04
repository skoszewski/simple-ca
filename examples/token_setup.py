#!/usr/bin/env python3
"""Exchange a setup code of simple-ca serve for its token, and print the token."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("code", help="the setup code")
parser.add_argument("--url", default=os.environ.get("SIMPLE_CA_URL"), help="URL of the server (default: $SIMPLE_CA_URL)")
args = parser.parse_args()
if not args.url:
    parser.error("give --url or set SIMPLE_CA_URL")

request = urllib.request.Request(args.url.rstrip("/") + "/api/token-setup", data=json.dumps({"code": args.code}).encode(),
                                 headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request) as response:
        print(json.load(response)["token"])
except urllib.error.HTTPError as e:
    sys.exit(f"{e.code} {e.read().decode(errors='replace').strip()}")
except (urllib.error.URLError, ValueError, KeyError) as e:
    sys.exit(f"{args.url}: {e}")
