---
title: Workload identity federation
---

A token of simple-ca is a JWT signed with the CA key. Its token type shapes the JWT for a party
other than simple-ca that verifies it with the public key of the CA, such as Google Cloud
Workload Identity Federation or Microsoft Entra workload identity federation, which exchange it
for their own credentials. A workload holding such a token reaches the cloud without a stored
cloud secret.

The token stays a token of `tokens-db.json`: it has its scopes and limits, `sign` and a domain
in the examples below, works with simple-ca as well, and is listed, described, renewed, revoked
and removed as any token.

## The JWT

Every token's header names the CA key by its `kid`, the JWK thumbprint of RFC 7638 (SHA-256).
Its claims are:

- `jti` - the JWT ID, new for each JWT of the token;
- `iss` - the issuer, for a token with an audience, see [The issuer](#the-issuer);
- `sub` - the subject: the token name, or the subject template of the token type;
- `aud` - the audience, of the token type or of `--audience`;
- `scope` - the scopes, separated by spaces;
- `iat` and `exp` - when it was issued and when it expires;
- `simple_ca_token` - the token name, when the subject is not the name;
- the claims of the token type and of `--claim`, as strings.

The issuer, the audience, the subject and the claims are kept in `tokens-db.json` when the token
is made, so a renewed token has the same, also after `simple-ca.json` changes.

## Token types

`token create --token-type` picks the type; `api` is the default, unless `tokens.token_type` of
[simple-ca.json](configuration.md) names another:

| Type | Audience | Subject | Longest validity |
|---|---|---|---|
| `api` | none | the name | any |
| `google` | given with `--audience` | the name, at most 127 bytes | 24h |
| `azure` | `api://AzureADTokenExchange` | the name, at most 600 bytes | any |

`--audience` replaces the audience of the type, and `--claim NAME=VALUE`, which may be specified
multiple times, adds a claim, or replaces a claim of the type. A claim name is snake_case, and the
claims simple-ca writes itself are refused. The token page has the same in its create dialog.

`token_types` of [simple-ca.json](configuration.md) redefines a built-in type or defines a new
one, which starts from the built-in type of `base`:

```json
{
  "ca_publish_base_url": "https://pki.example.com",
  "token_types": {
    "gcp-deploy": {
      "base": "google",
      "audience": "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab/providers/simple-ca",
      "subject": "simple-ca:{ca}:{name}",
      "max_valid": "8h",
      "claims": {"env": "lab"}
    }
  }
}
```

The subject template takes `{name}`, the token name, and `{ca}`, the issuing CA, empty for the
root CA. `max_valid` is at most that of the base: `google` keeps the 24 hours Google allows. A
token whose validity is longer than that of its type is refused, at creation and at renewal.

## The issuer

A token with an audience carries an issuer: `tokens.issuer` of `simple-ca.json`, or else
`ca_publish_base_url`, for the root CA, and that URL followed by `/NAME` for the issuing CA
`NAME`. A token type with an audience is refused without either. Each CA has its own key, so a
cloud provider is set up for the issuer of one CA.

`serve` publishes, at the paths of the issuer, the OpenID Connect discovery document and the keys
of the CA, so the issuer is reachable as one when `serve` answers at its URL:

| Path | Content |
|---|---|
| `/.well-known/openid-configuration` | `issuer`, `jwks_uri`, `id_token_signing_alg_values_supported` (`RS256`), `response_types_supported` and `subject_types_supported` |
| `/jwks.json` | the JSON Web Key Set of the CA |
| `/NAME/.well-known/openid-configuration`, `/NAME/jwks.json` | the same of the issuing CA `NAME` |

Both are `404 Not Found` without an issuer. `token jwks` prints the same key set:

```sh
simple-ca token jwks --ca-dir /etc/simple-ca/servers > jwks.json
```

The key set holds the RSA public key with `kty`, `use`, `alg`, `kid`, `n` and `e`, without the
`x5c` and `x5t` that Google refuses.

## Google Cloud

Google verifies the JWT with keys uploaded to the provider, so `serve` need not be reachable from
Google. The provider's issuer is the issuer of the CA, and its audience the default one, which
starts with `https://iam.googleapis.com/`.

```sh
PROJECT_ID=lab-project
PROJECT_NUMBER=123456789
POOL_ID=lab
PROVIDER_ID=simple-ca
CA_DIR=/etc/simple-ca/servers
ISSUER=https://pki.example.com/servers
AUDIENCE=https://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID

simple-ca token jwks --ca-dir "$CA_DIR" > jwks.json
gcloud iam workload-identity-pools create "$POOL_ID" --project="$PROJECT_ID" --location=global
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" --project="$PROJECT_ID" \
  --location=global --workload-identity-pool="$POOL_ID" --issuer-uri="$ISSUER" \
  --attribute-mapping=google.subject=assertion.sub,attribute.env=assertion.env \
  --jwk-json-path=jwks.json
simple-ca token create --ca-dir "$CA_DIR" --token-type google --audience "$AUDIENCE" \
  --valid 8h --claim env=lab --domain deploy.example.com deploy > deploy.token
```

The subject `deploy` is the principal
`principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/subject/deploy`,
which is given roles on the resources it uses. Security Token Service exchanges the JWT for a
Google access token; its `audience` is the provider's name starting with `//iam.googleapis.com/`:

```sh
PROJECT_NUMBER=123456789
POOL_ID=lab
PROVIDER_ID=simple-ca

jq -n --rawfile token deploy.token \
  --arg audience "//iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID" \
  '{grantType: "urn:ietf:params:oauth:grant-type:token-exchange", audience: $audience,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: ($token | rtrimstr("\n"))}' |
  curl -sS -H 'Content-Type: application/json' --data @- https://sts.googleapis.com/v1/token
```

`gcloud iam workload-identity-pools providers update-oidc --jwk-json-path` replaces the uploaded
keys, at most 8, when the CA key changes.

## Microsoft Entra

Microsoft Entra fetches the keys from the discovery document of the issuer, so `serve` must
answer at the issuer's URL over public HTTPS, with a certificate Microsoft trusts, which a
certificate of the CA itself is not: run `serve` behind a reverse proxy with a public
certificate. A federated identity credential of an app registration names the issuer, the subject
and the audience, which match the JWT exactly:

```sh
APP_ID=00000000-0000-0000-0000-000000000000
CA_DIR=/etc/simple-ca/servers
ISSUER=https://pki.example.com/servers

jq -n --arg issuer "$ISSUER" '{name: "simple-ca-deploy", issuer: $issuer, subject: "deploy",
  audiences: ["api://AzureADTokenExchange"]}' > credential.json
az ad app federated-credential create --id "$APP_ID" --parameters credential.json
simple-ca token create --ca-dir "$CA_DIR" --token-type azure --domain deploy.example.com \
  deploy > deploy.token
```

The JWT is the client assertion of the client credentials flow:

```sh
TENANT_ID=11111111-1111-1111-1111-111111111111
APP_ID=00000000-0000-0000-0000-000000000000

curl -sS "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$APP_ID" \
  --data-urlencode scope=https://graph.microsoft.com/.default \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$(cat deploy.token)"
```

## Revocation

Revoking a token in simple-ca stops simple-ca from accepting it. Google and Microsoft Entra
verify the JWT with the key alone and never ask simple-ca about it, so they accept it until it
expires: keep
the validity of these tokens short, with `--valid` or the `max_valid` of their type, and renew
them as needed.
