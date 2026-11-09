---
title: Google Cloud workload identity federation
---

A machine authenticates with Google Cloud with JWTs that simple-ca issues, without a stored
Google key. It holds a token of simple-ca with the scope `federate`, asks `serve` for a JWT
whenever it needs one, and exchanges the JWT with Google's Security Token Service for a Google
access token. [Workload identity federation](../workload-identity.md) describes the
settings and the requests in full.

The steps below use the root CA in `/etc/simple-ca` and its issuing CA `gcp-wif`, made for the
federation alone:

```sh
CA_DIR=/etc/simple-ca

simple-ca ca create --ca-dir "$CA_DIR" --issuing-ca gcp-wif "Google WIF"
```

Its key may be `rsa`, the default, or `ec` (`--key-type ec`): Google accepts RS256 and ES256.

## 1. The issuer

Choose the issuer, and set it as `federation.issuer` in `simple-ca.json` of the root CA:

```json
{
  "federation": {
    "issuer": "https://pki.example.com"
  }
}
```

The issuing CA `gcp-wif` gets the issuer `https://pki.example.com/gcp-wif`. Google gets the keys
uploaded, so it never contacts the issuer: it is a name the `iss` claim of the JWTs and the
provider of Google must share, and Google requires it to start with `https://`.

## 2. The pool and the provider of Google

Export the public key of the CA, and create the workload identity pool and its OIDC provider,
with the issuer of step 1 and the key uploaded:

```sh
PROJECT_ID=lab-project
POOL_ID=lab
PROVIDER_ID=simple-ca
CA_DIR=/etc/simple-ca/gcp-wif
ISSUER=https://pki.example.com/gcp-wif

simple-ca token jwks --ca-dir "$CA_DIR" > jwks.json
gcloud iam workload-identity-pools create "$POOL_ID" --project="$PROJECT_ID" --location=global
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" --project="$PROJECT_ID" \
  --location=global --workload-identity-pool="$POOL_ID" --issuer-uri="$ISSUER" \
  --attribute-mapping=google.subject=assertion.sub --jwk-json-path=jwks.json
```

The audience of the provider, the `aud` claim of the JWTs, is the provider's full name with
`https://`. It is made of the project number, the pool and the provider:

```sh
PROJECT_ID=lab-project
POOL_ID=lab
PROVIDER_ID=simple-ca

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
echo "https://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID"
```

## 3. The token type

Add the token type `gcp-wif` to the `federation` section, with the audience of step 2:

```json
{
  "federation": {
    "issuer": "https://pki.example.com",
    "types": {
      "gcp-wif": {
        "base": "google",
        "audience": "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab/providers/simple-ca"
      }
    }
  }
}
```

`google` limits a JWT to 24 hours, and the type issues JWTs valid for 1 hour; `valid` and
`max_valid` change that, and `subject` and `claims` shape the `sub` claim and add others.

## 4. The token of the machine

On the CA host, make the token of the machine, `build-01`, with the scope `federate` and the token
type `gcp-wif`, used from the network of the machine alone:

```sh
CA_DIR=/etc/simple-ca/gcp-wif
NAME=build-01
NETWORK=10.20.0.0/16

simple-ca token create --ca-dir "$CA_DIR" --scope federate --federate-type gcp-wif \
  --valid 2160h --network "$NETWORK" "$NAME" > "$NAME.token"
```

Hand `build-01.token` to the machine. With `--otc`, `token create` prints a one-time setup code
instead, which the machine exchanges once for the token with `token-setup`, so the token itself
is never handed over.

The subject of its JWTs is the name of the token, so in Google the machine is the principal:

```text
principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/lab/subject/build-01
```

Give that principal the roles it needs on the resources it uses.

## 5. On the machine

The machine asks `serve` for a JWT with its token, and exchanges the JWT for a Google access
token. It needs to reach `serve`; Google does not.

`request-jwt`, which the release archives of simple-ca hold, does both. Put its settings in
`federation.json` of its working directory, with the token in `build-01.token` beside it:

```json
{
  "ca_url": "https://pki.example.com/gcp-wif",
  "token_file": "build-01.token",
  "provider": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab/providers/simple-ca"
}
```

```sh
ACCESS_TOKEN=$(request-jwt)
```

The same with curl and jq, step by step:

```sh
CA_URL=https://pki.example.com/gcp-wif
TOKEN_FILE=build-01.token
PROVIDER=//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab/providers/simple-ca

JWT=$(curl -sS -X POST -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  "$CA_URL/api/federation-token" | jq -r .token)
jq -n --arg token "$JWT" --arg audience "$PROVIDER" \
  '{grantType: "urn:ietf:params:oauth:grant-type:token-exchange", audience: $audience,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: $token}' |
  curl -sS -H 'Content-Type: application/json' --data @- https://sts.googleapis.com/v1/token |
  jq -r .access_token
```

The `audience` of this request is the provider's name with `//iam.googleapis.com/`, unlike the
`aud` claim of the JWT, which has `https://`. Each JWT lasts an hour, and the machine asks for a
new one when it needs one.

## Later

- `simple-ca token renew --ca-dir /etc/simple-ca/gcp-wif build-01` renews the token of the
  machine before its 90 days end.
- `simple-ca token revoke --ca-dir /etc/simple-ca/gcp-wif build-01` stops it from getting JWTs at
  once; a JWT issued before lasts until it expires, within the hour.
- Each JWT issued is a `token.issue` record of the audit log:
  `simple-ca audit list --ca-dir /etc/simple-ca --event token.issue --ca gcp-wif`.
- When the key of the CA changes, upload the new key set with
  `gcloud iam workload-identity-pools providers update-oidc --jwk-json-path`.
