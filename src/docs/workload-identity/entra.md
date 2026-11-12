---
title: Microsoft Entra ID workload identity federation
---

A machine authenticates with Microsoft Entra ID, and through it with Azure, with JWTs that
simple-ca issues, without a stored client secret or certificate. It holds an api token of
simple-ca with the scope `federate`, asks `serve` for a JWT whenever it needs one, and sends the
JWT to Entra ID as the client assertion of an application, which answers with an access token.
[Workload identity federation](../workload-identity.md) describes the JWT, the token types, the
scope `federate` and the issuer, which are the same for every cloud.

The steps below use the root CA in `/etc/simple-ca`, its issuing CA `entra-wif`, made for the
federation alone, and the machine `build-01`, whose token has its name:

```sh
CA_DIR=/etc/simple-ca

simple-ca ca create --ca-dir "$CA_DIR" --issuing-ca entra-wif "Entra WIF"
```

Keep its key `rsa`, the default: Microsoft documents RS256 as the one algorithm it has tested.

## 1. The issuer

Entra ID has no upload of keys: it reads the discovery document of the issuer, and the key set it
names, over public HTTPS, with a certificate Microsoft trusts, which a certificate of the CA
itself is not. Choose a public HTTPS URL for them, such as the static website of a storage
account, and set it as `federation.issuer` in `simple-ca.json` of the root CA:

```json
{
  "federation": {
    "issuer": "https://pki.example.com"
  }
}
```

The issuing CA `entra-wif` gets the issuer `https://pki.example.com/entra-wif`. Publish its two
documents there: run `serve` behind a reverse proxy with a public certificate at that URL, or copy
them as [static files](../workload-identity.md#static-files) with `NAME=entra-wif`, and upload the
folder `static` to the root of the host, so that
`https://pki.example.com/entra-wif/.well-known/openid-configuration` and
`https://pki.example.com/entra-wif/jwks.json` answer with them, as `application/json`. Copy them
again when the issuer or the key of the CA changes.

## 2. The application and its federated credential

Register an application with its service principal, and give it a federated credential for the
machine: the issuer of step 1, the subject `build-01`, the name of the machine's token, and the
audience `api://AzureADTokenExchange`, the one of the built-in token type `azure`. Entra ID
compares the issuer and the subject with the `iss` and `sub` claims of the JWT exactly:

```sh
APP_NAME=simple-ca-build-01
ISSUER=https://pki.example.com/entra-wif
NAME=build-01

APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId --output tsv)
az ad sp create --id "$APP_ID"
jq -n --arg issuer "$ISSUER" --arg subject "$NAME" \
  '{name: "simple-ca", issuer: $issuer, subject: $subject,
    audiences: ["api://AzureADTokenExchange"]}' > credential.json
az ad app federated-credential create --id "$APP_ID" --parameters credential.json
echo "client ID: $APP_ID, tenant ID: $(az account show --query tenantId --output tsv)"
```

Give the service principal the roles it needs on the resources it uses:

```sh
APP_ID=00000000-0000-0000-0000-000000000000
ROLE=Reader
SCOPE=/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/lab

az role assignment create --assignee "$APP_ID" --role "$ROLE" --scope "$SCOPE"
```

## 3. The token type

The built-in token type `azure` has the audience `api://AzureADTokenExchange` and the token name
as the subject, so it needs no settings. A type of `federation.types` in `simple-ca.json`, based on
`azure`, changes them, such as the subject template, which then must be the subject of the
federated credential of step 2.

## 4. The token of the machine

On the CA host, make the token of the machine, `build-01`, with the scope `federate` and the token
type `azure`, used from the network of the machine alone:

```sh
CA_DIR=/etc/simple-ca/entra-wif
NAME=build-01
NETWORK=10.20.0.0/16

simple-ca token create --ca-dir "$CA_DIR" --scope federate --federate-type azure \
  --valid 2160h --network "$NETWORK" "$NAME" > "$NAME.token"
```

Hand `build-01.token` to the machine. With `--otc`, `token create` prints a one-time setup code
instead, which the machine exchanges once for the token with `request-token api` (step 5), so the
token itself is never handed over.

## 5. On the machine

The machine needs to reach `serve`, which Entra ID never does, and Entra ID. `request-token`,
which the release archives of simple-ca hold, makes the requests. Put its settings in
`federation.json` of its working directory, with the token in `build-01.token` beside it, the
tenant ID and the client ID of step 2, and the scope of the resource it calls, here Azure Resource
Manager. `ca_url` is the URL of `serve` the machine reaches, which may differ from the public
issuer:

```json
{
  "ca_url": "https://pki.example.com/entra-wif",
  "token_file": "build-01.token",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "scope": "https://management.azure.com/.default"
}
```

With a setup code of step 4 in place of the token, `request-token api` writes the token to
`build-01.token`, a new file of mode 0600, once:

```sh
SETUP_CODE=K7QF-M2XA-JP4D-W5ZR

request-token api "$SETUP_CODE"
```

`request-token entra-id` asks `serve` for a JWT, and prints the access token of Entra ID it gets
with it:

```sh
ACCESS_TOKEN=$(request-token entra-id)
```

Each JWT lasts an hour, and the machine asks for a new token when it needs one.
[Appendix](#appendix-the-requests-of-request-token) shows the requests `request-token entra-id`
makes.

## Later

- `simple-ca token renew --ca-dir /etc/simple-ca/entra-wif build-01` renews the token of the
  machine before its 90 days end.
- `simple-ca token revoke --ca-dir /etc/simple-ca/entra-wif build-01` stops it from getting JWTs
  at once; a JWT issued before lasts until it expires, within the hour.
- Each JWT issued is a `token.issue` record of the audit log:
  `simple-ca audit list --ca-dir /etc/simple-ca --event token.issue --ca entra-wif`.
- When the key of the CA changes, publish the new key set at the issuer.

## Appendix: the requests of request-token

`request-token entra-id` makes two requests. With curl and jq, and the settings of
`federation.json` of step 5:

1. the JWT, from `/api/federation-token` of `serve`, with the api token as the bearer token;
2. the access token, from the token endpoint of the tenant, by the client credentials flow, with
   the JWT as the client assertion.

```sh
CA_URL=https://pki.example.com/entra-wif
TOKEN_FILE=build-01.token
TENANT_ID=11111111-1111-1111-1111-111111111111
CLIENT_ID=00000000-0000-0000-0000-000000000000
SCOPE=https://management.azure.com/.default

JWT=$(curl -sS -X POST -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  "$CA_URL/api/federation-token" | jq -r .token)
ACCESS_TOKEN=$(curl -sS "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "scope=$SCOPE" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" | jq -r .access_token)
```
