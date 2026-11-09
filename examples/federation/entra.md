# Microsoft Entra ID workload identity federation

A machine authenticates with Microsoft Entra ID, and through it with Azure, with JWTs that
simple-ca issues, without a stored client secret or certificate. It holds an api token of
simple-ca with the scope `federate`, asks `serve` for a JWT whenever it needs one, and sends the
JWT to Entra ID as the client assertion of an application, which answers with an access token.
[Workload identity federation](../../docs/workload-identity.md) describes the settings and the
requests in full.

The steps below use the root CA in `/etc/simple-ca` and its issuing CA `entra-wif`, made for the
federation alone:

```sh
CA_DIR=/etc/simple-ca

simple-ca ca create --ca-dir "$CA_DIR" --issuing-ca entra-wif "Entra WIF"
```

Keep its key `rsa`, the default: Microsoft documents RS256 as the one algorithm it has tested.

## 1. The issuer

Entra ID has no upload of keys: it reads the discovery document of the issuer, and the key set it
names, over public HTTPS, with a certificate Microsoft trusts. Choose a public HTTPS URL for them,
such as the static website of a storage account, and set it as `federation.issuer` in
`simple-ca.json` of the root CA:

```json
{
  "federation": {
    "issuer": "https://pki.example.com"
  }
}
```

The issuing CA `entra-wif` gets the issuer `https://pki.example.com/entra-wif`. Publish its two
documents there: run `serve` behind a reverse proxy with a public certificate at that URL, or copy
them as static files:

```sh
SERVE_URL=http://127.0.0.1:8080
CA_DIR=/etc/simple-ca
NAME=entra-wif

mkdir -p "static/$NAME/.well-known"
curl -fsS "$SERVE_URL/$NAME/.well-known/openid-configuration" > "static/$NAME/.well-known/openid-configuration"
simple-ca token jwks --ca-dir "$CA_DIR/$NAME" > "static/$NAME/jwks.json"
```

Upload the folder `static` to the root of the host, so that
`https://pki.example.com/entra-wif/.well-known/openid-configuration` and
`https://pki.example.com/entra-wif/jwks.json` answer with them, as `application/json`. Copy them
again when the issuer or the key of the CA changes.

## 2. The application and its federated credential

Register an application with its service principal, and give it a federated credential for the
token of the machine of step 4, `build-01`: its issuer, its subject, the name of the token, and
the audience `api://AzureADTokenExchange`, the one of the built-in token type `azure`:

```sh
APP_NAME=simple-ca-build-01
ISSUER=https://pki.example.com/entra-wif
NAME=build-01

APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId --output tsv)
az ad sp create --id "$APP_ID"
jq -n --arg issuer "$ISSUER" --arg subject "$NAME" \
  '{name: "simple-ca", issuer: $issuer, subject: $subject, audiences: ["api://AzureADTokenExchange"]}' \
  > credential.json
az ad app federated-credential create --id "$APP_ID" --parameters credential.json
echo "client ID: $APP_ID, tenant ID: $(az account show --query tenantId --output tsv)"
```

Entra ID compares the issuer and the subject with the `iss` and `sub` claims of the JWT exactly.
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
instead, which the machine exchanges once for the token, so the token itself is never handed
over.

## 5. On the machine

The machine asks `serve` for a JWT with its token, and gets an access token of Entra ID with it.
It needs to reach `serve`, which Entra ID never does, and Entra ID.

`request-jwt`, which the release archives of simple-ca hold, does both. Put its settings in
`federation.json` of its working directory, with the token in `build-01.token` beside it, the
tenant ID and the client ID of step 2, and the scope of the resource it calls, here Azure Resource
Manager:

```json
{
  "ca_url": "https://pki.example.com/entra-wif",
  "token_file": "build-01.token",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "scope": "https://management.azure.com/.default"
}
```

```sh
ACCESS_TOKEN=$(request-jwt)
```

`ca_url` is the URL of `serve` the machine reaches, which may differ from the public issuer. The
same with curl, step by step:

```sh
CA_URL=https://pki.example.com/entra-wif
TOKEN_FILE=build-01.token
TENANT_ID=11111111-1111-1111-1111-111111111111
CLIENT_ID=00000000-0000-0000-0000-000000000000
SCOPE=https://management.azure.com/.default

JWT=$(curl -sS -X POST -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  "$CA_URL/api/federation-token" | jq -r .token)
curl -sS "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  --data-urlencode grant_type=client_credentials --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "scope=$SCOPE" \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" | jq -r .access_token
```

Each JWT lasts an hour, and the machine asks for a new one when it needs one.

## Later

- `simple-ca token renew --ca-dir /etc/simple-ca/entra-wif build-01` renews the token of the
  machine before its 90 days end.
- `simple-ca token revoke --ca-dir /etc/simple-ca/entra-wif build-01` stops it from getting JWTs
  at once; a JWT issued before lasts until it expires, within the hour.
- Each JWT issued is a `token.issue` record of the audit log:
  `simple-ca audit list --ca-dir /etc/simple-ca --event token.issue --ca entra-wif`.
- When the key of the CA changes, publish the new key set at the issuer.
