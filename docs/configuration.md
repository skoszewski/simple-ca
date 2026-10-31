# simple-ca.json

The settings of the root CA and its issuing CAs, in the root CA directory; a command working with
an issuing CA reads the file of its root CA. The file is optional: `ca create --ca-publish-base-url`
writes it, and it can be written or edited by hand. A setting not described here is an error.

```json
{
  "ca_publish_base_url": "http://pki.example.com",
  "days": {"cert": 90, "crl": 7},
  "types": {
    "device": {
      "key_usage": ["digitalSignature"],
      "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]
    },
    "person": {
      "names": "user",
      "key_usage": ["digitalSignature", "keyEncipherment"],
      "ext_key_usage": []
    },
    "user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}
  },
  "acme": {"domains": ["example.com", "lab.example.org"], "days": 30}
}
```

- `ca_publish_base_url` - base URL for the AIA and CRL Distribution Point extensions.
- `acme` - the [ACME](acme.md) server of `serve`:
  - `domains` - the domains whose names and the names below them it issues certificates for;
    without them, `serve` has no ACME server;
  - `days` - the validity of its certificates, 90 days by default.
- `days` - defaults for `--days`: `ca`, `cert`, `crl`.
- `types` - certificate types for `cert create --type` and `cert sign --type`, by name, of
  letters, digits and underscores. A type named `server`, `user` or `none` redefines the built-in
  type, and any other name defines a new type. Each type has:
  - `names` - the name rules of the subject and SANs, `server` or `user`, as described under
    [cert create](usage.md#cert-create); a new type has the server rules without it;
  - `key_usage` - its key usages;
  - `ext_key_usage` - its extended key usages, names or numeric OIDs.

  The names are those of `--ku` and `--eku`. A field left out keeps its value of the built-in
  type, none for a new type, and `[]` gives the type none. `--ku` and `--eku` add to the usages of
  the type.
