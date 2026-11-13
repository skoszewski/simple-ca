---
title: Workload identity federation
---

simple-ca issues JWTs for parties other than itself that verify them with the public key of a CA,
such as Google Cloud Workload Identity Federation or Microsoft Entra workload identity
federation, which exchange them for their own credentials. A workload reaches the cloud without a
stored cloud secret. The setup of each cloud, step by step, is in its own guide:

- [Google Cloud workload identity federation](workload-identity/google.md);
- [Microsoft Entra ID workload identity federation](workload-identity/entra.md).

Such a JWT has a token type, and is not a token of simple-ca: it is not stored in
`tokens-db.json`, and simple-ca refuses it. A workload gets it in one of two ways:

- **From `serve`.** A token of simple-ca with the scope `federate`, made for one token type, gets
  a new JWT of that type at `/api/federation-token` whenever it asks, without an operator. The
  token decides what the JWT holds; the request sets nothing.
- **From `token issue`.** It prints one such JWT on the CA host, for manual use.

## The JWT

The JWT is signed with the CA key, RS256 for an RSA key and ES256 for an EC key, as
`ca create --key-type` made it; the guide of each cloud names the algorithms it accepts. The
header names the CA key by its `kid`, the JWK thumbprint of RFC 7638 (SHA-256), as the header of
every token of simple-ca does. The claims are:

- `jti` - the JWT ID, new for each JWT;
- `iss` - the issuer of the CA, see [The issuer](#the-issuer);
- `sub` - the subject, the subject template of the token type with the token name;
- `aud` - the audience, of the token type or of `--audience`;
- `iat` and `exp` - when it was issued and when it expires;
- the claims of the token type and of `--claim`, as strings.

It has no `scope`, and simple-ca refuses a JWT with an issuer or an audience, so it never opens
the signing API or the pages.

## Token types

| Type | Audience | Subject | Validity | Longest validity |
|---|---|---|---|---|
| `google` | given with `--audience` | the name, at most 127 bytes | 1h | 24h |
| `azure` | `api://AzureADTokenExchange` | the name, at most 600 bytes | 1h | any |

`--audience` replaces the audience of the type, and `--claim NAME=VALUE`, which may be specified
multiple times, adds a claim, or replaces a claim of the type. A claim name is snake_case, and
`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` and `scope` are refused.

`federation.types` of [simple-ca.json](configuration.md) of the root CA redefines a built-in type
or defines a new one, which starts from the built-in type of `base`; the root CA and its issuing
CAs share the types:

```json
{
  "federation": {
    "issuer": "https://pki.example.com",
    "types": {
      "gcp-deploy": {
        "base": "google",
        "audience": "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca",
        "subject": "simple-ca:{ca}:{name}",
        "valid": "30",
        "max_valid": "8h",
        "claims": {"env": "lab"}
      }
    }
  }
}
```

The subject template takes `{name}`, the token name, and `{ca}`, the issuing CA, empty for the
root CA. `valid` is the validity of the JWTs `serve` issues, and `max_valid`, at most that of the
base, the longest one `token issue --valid` may ask: `google` keeps the 24 hours Google allows.

## The scope federate

`token create --scope federate --federate-type TYPE` makes an api token of simple-ca with the scope
`federate` and one token type, with `--audience` and `--claim` for its JWTs. It is a token like any
other: listed, described, renewed, revoked and removed, with `--host` and `--network` limiting the
clients it is used from. The token page makes it too, with the Token type, Audience and Claims of
the Federation group of its create dialog.

A token with the scope `federate` and no token type gets no JWTs. It grants the scope on the token
page, as any scope a token holds: a person who creates the tokens of the machines there signs in
with such a token, made by `token create` or by an OIDC profile with the scope `federate`.

```sh
CA_DIR=/etc/simple-ca/servers
NETWORK=10.20.0.0/16

simple-ca token create --ca-dir "$CA_DIR" --scope federate --federate-type gcp-deploy \
  --valid 2160h --network "$NETWORK" deploy > deploy.token
```

The workload asks `serve` for a JWT with the token as its bearer token, and an empty body:

```sh
CA_URL=https://pki.example.com:8443/servers

curl -sS -X POST -H "Authorization: Bearer $(cat deploy.token)" "$CA_URL/api/federation-token" |
  jq -r .token > deploy.jwt
```

`request-token jwt` does the same, and its other subcommands exchange the JWT for the access
token of Google or Microsoft Entra ID, as the guide of each cloud shows; its settings come from
`federation.json`, the environment and its options, see
[Requesting tokens with request-token](examples.md#requesting-tokens-with-request-token):

```sh
CA_URL=https://pki.example.com:8443/servers

request-token jwt --ca-url "$CA_URL" --token-file deploy.token > deploy.jwt
```

The JWT is valid for the `valid` of the type, and never after the token expires. Each JWT is
recorded as `token.issue` in the [audit log](audit.md), with the token, the type, the audience,
the subject and the `jti`. [Federation tokens](signing-api.md#federation-tokens) describes the
answer and its errors.

`token issue` prints a JWT on the CA host without a token, for the name given:

```sh
CA_DIR=/etc/simple-ca/servers
AUDIENCE=https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca

simple-ca token issue --ca-dir "$CA_DIR" --token-type google --audience "$AUDIENCE" --valid 2h \
  backup > backup.jwt
```

## The issuer

The issuer of the JWTs of a CA is `federation.issuer` of `simple-ca.json` of the root CA, or else
`ca_publish_base_url`, for the root CA, and that URL followed by `/NAME` for the issuing CA
`NAME`. Both settings are URLs of scheme and host only, `federation.issuer` an `https` one, so
`/NAME` is the only path of an issuer. Without either, no JWT is issued. Each CA has its own key, so a cloud provider is set up
for the issuer of one CA.

The issuer is a name the verifier compares with the `iss` claim. A verifier given the keys never
contacts it, so it need not be reachable. A verifier that fetches the keys from the issuer needs
the discovery document and the key set at the issuer's URL, over public HTTPS with a publicly
trusted certificate: from `serve`, or as [static files](#static-files) on any web host.

`serve` publishes, at the paths of the issuer, the OpenID Connect discovery document and the keys
of the CA, so the issuer is reachable as one when `serve` answers at its URL:

| Path | Content |
|---|---|
| `/.well-known/openid-configuration` | `issuer`, `jwks_uri`, `id_token_signing_alg_values_supported` (`RS256` or `ES256`, by the CA key), `response_types_supported` and `subject_types_supported` |
| `/jwks.json` | the JSON Web Key Set of the CA |
| `/NAME/.well-known/openid-configuration`, `/NAME/jwks.json` | the same of the issuing CA `NAME` |

Both are `404 Not Found` without an issuer. `token jwks` prints the same key set:

```sh
CA_DIR=/etc/simple-ca/servers

simple-ca token jwks --ca-dir "$CA_DIR" > jwks.json
```

The key set holds the public key of the CA with `kty`, `use`, `alg` and `kid`, and `n` and `e`
for an RSA key or `crv` (`P-256`), `x` and `y` for an EC key, without the `x5c` and `x5t` that
Google refuses.

### Static files

The two documents change only with the issuer or the key of the CA, so a verifier that fetches
them can read copies from any public HTTPS host, such as a static website of a cloud storage
account, while `serve` stays on the internal network, where the workloads get their JWTs. Set
`federation.issuer` to the base URL of the host, and copy the documents of the issuing CA `NAME`
to its paths `NAME/.well-known/openid-configuration` and `NAME/jwks.json`:

```sh
SERVE_URL=http://127.0.0.1:8080
CA_DIR=/etc/simple-ca
NAME=servers

mkdir -p "static/$NAME/.well-known"
curl -fsS "$SERVE_URL/$NAME/.well-known/openid-configuration" > "static/$NAME/.well-known/openid-configuration"
simple-ca token jwks --ca-dir "$CA_DIR/$NAME" > "static/$NAME/jwks.json"
```

`serve` builds the `issuer` and the `jwks_uri` of the discovery document from `federation.issuer`,
so the copy points at the host. Serve both files as `application/json`, and copy them again when
the issuer or the key of the CA changes. The issuer of the CA, `BASE/NAME`, is then the issuer of
the verifier.

## Revocation

Revoking the token with the scope `federate` stops `serve` from issuing it new JWTs at once. A
verifier checks a JWT with the key alone and never asks simple-ca about it, so a JWT already
issued is accepted until it expires, within the `valid` of its type. A JWT of `token issue`
cannot be revoked: keep its `--valid` short.
