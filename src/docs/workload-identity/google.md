---
title: Google Cloud workload identity federation
---

A machine authenticates with Google Cloud with JWTs that simple-ca issues, without a stored
Google key. It holds an api token of simple-ca with the scope `federate`, asks `serve` for a JWT
whenever it needs one, and exchanges the JWT with Google's Security Token Service for a
federated access token. With that token it calls Google Cloud as itself, or gets the access
token of a service account it impersonates.
[Workload identity federation](../workload-identity.md) describes the JWT, the token types, the
scope `federate` and the issuer, which are the same for every cloud.

The steps below use the root CA in `/etc/simple-ca`, its issuing CA `gcp-wif`, made for the
federation alone, the Google project `lab-project`, whose number is `123456789`, and the machine
`build-01`:

```sh
CA_DIR=/etc/simple-ca

simple-ca ca create --ca-dir "$CA_DIR" --issuing-ca gcp-wif "Google WIF"
```

Its key may be `rsa`, the default, or `ec` (`--key-type ec`): Google accepts RS256 and ES256.

## With simple-ca-wif

`simple-ca-wif`, on the CA host, does steps 1 to 5 with two commands, through the Google REST
APIs. `google setup` does steps 1 to 3, and `google machine` steps 4 and 5 for one machine. The
machine then goes on with step 6. The steps below do the same by hand. The CA is that of
`--ca-dir`, else of `SIMPLE_CA_DIR`, else of the working directory.

### Credentials

`simple-ca-wif` calls Google with an access token, from the first of these it finds:

- `--access-token`, or `GOOGLE_OAUTH_ACCESS_TOKEN`;
- Application Default Credentials: the file named by `GOOGLE_APPLICATION_CREDENTIALS`, of the
  type `authorized_user` or `service_account`, or else the file that
  `gcloud auth application-default login` writes in the gcloud configuration directory:
  `CLOUDSDK_CONFIG` when it is set, else `~/.config/gcloud`, or `%APPDATA%\gcloud` on Windows.

The metadata server is not used. The account of the credentials needs these IAM roles in the
project:

- `roles/iam.workloadIdentityPoolAdmin`, for the pool and the provider;
- `roles/iam.serviceAccountAdmin`, for the service account and the principals that may
  impersonate it;
- `roles/resourcemanager.projectIamAdmin`, for the roles granted on the project.

A user signs in for Application Default Credentials with:

```sh
gcloud auth application-default login
```

### The pool, the provider and the token type

`google setup` sets the issuer of step 1, creates the pool and the provider of step 2 with the
keys of the CA, and adds the token type of step 3:

```sh
CA_DIR=/etc/simple-ca/gcp-wif
PROJECT_ID=lab-project
POOL_ID=lab-pool
ISSUER=https://pki.example.com

simple-ca-wif google setup --ca-dir "$CA_DIR" --project "$PROJECT_ID" --pool "$POOL_ID" \
  --issuer "$ISSUER"
```

- `--issuer` is `federation.issuer` of the root CA. It is needed when `simple-ca.json` has none.
- `--provider` names the provider, by default `simple-ca`.
- `--type` names the token type, by default `gcp-wif`. Its other settings are kept.
- `--attribute-mapping` is the mapping of a new provider, by default
  `google.subject=assertion.sub`.

Each step prints one line: created, updated or unchanged. The command leaves alone what exists,
so it can be run again. It refuses an `--issuer` other than the one `simple-ca.json` has, a
provider with another issuer, and a pool or a provider that is deleted; undelete it first. A
provider whose keys differ from those of the CA gets the current keys.

### The token and the access of a machine

`google machine` makes the token of step 4 and gives the machine the access of step 5. Here
`build-01` acts as the service account `build-01`, with the role `roles/browser`:

```sh
CA_DIR=/etc/simple-ca/gcp-wif
PROJECT_ID=lab-project
NAME=build-01
NETWORK=10.20.0.0/16
ROLE=roles/browser

simple-ca-wif google machine --ca-dir "$CA_DIR" --project "$PROJECT_ID" \
  --service-account "$NAME" --role "$ROLE" --network "$NETWORK" "$NAME"
```

- The token has the scope `federate` and the token type of `--type`, by default `gcp-wif`, which
  `google setup` added. It asks for the passphrase of the key as `token create` does.
- `--valid`, by default 2160h, `--host` and `--network` are those of `token create`.
- The token goes to `build-01.token`, a new file of mode 0600. With `--otc`, the command prints a
  one-time setup code instead; `--otc-valid` and `--otc-network` are those of `token create`.
- `--service-account` creates the service account when it is missing, with the display name
  `simple-ca build-01` or that of `--display-name`. The principal may impersonate it, and it gets
  each `--role`.
- Without `--service-account`, the principal gets each `--role`.
- `--role` may be given more than once. A member already in a role binding is left alone.
- `--project` is needed with `--service-account` or `--role`; without either, the command makes
  no call to Google.
- `--output-dir` is the directory of the token and of `federation.json`, by default the working
  directory.

The command also writes `federation.json` of step 6, whose `ca_url` is that of `--ca-url`, by
default the issuer of the CA:

```json
{
  "ca_url": "https://pki.example.com/gcp-wif",
  "token_file": "build-01.token",
  "provider": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca",
  "service_account": "build-01@lab-project.iam.gserviceaccount.com"
}
```

Without `--service-account`, the file has no `service_account`. Before it changes anything, the
command refuses an existing `federation.json`, an existing `build-01.token`, a token `build-01` the
CA already has, and an `--output-dir` it cannot write to. Without the token
type in `simple-ca.json`, or without the audience of a provider in it, it asks to run
`google setup` first. It makes `build-01.token` and `federation.json` as new empty files first,
and removes them when a later step fails. Each step prints one line. It makes the changes in
Google before the token and `federation.json`, so after a failed step it is run again as it was.

Hand `build-01.token`, or the setup code, and `federation.json` to the machine, which goes on
with step 6.

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

## 2. The pool and the provider

Export the public key of the CA, and create the workload identity pool and its OIDC provider,
with the issuer of step 1 and the key uploaded:

```sh
PROJECT_ID=lab-project
POOL_ID=lab-pool
PROVIDER_ID=simple-ca
CA_DIR=/etc/simple-ca/gcp-wif
ISSUER=https://pki.example.com/gcp-wif

simple-ca token jwks --ca-dir "$CA_DIR" > jwks.json
gcloud iam workload-identity-pools create "$POOL_ID" --project="$PROJECT_ID" --location=global
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" --project="$PROJECT_ID" \
  --location=global --workload-identity-pool="$POOL_ID" --issuer-uri="$ISSUER" \
  --attribute-mapping=google.subject=assertion.sub --jwk-json-path=jwks.json
```

The next steps need the resource name of the provider, which holds the number of the project:

```sh
PROJECT_ID=lab-project
POOL_ID=lab-pool
PROVIDER_ID=simple-ca

gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --project="$PROJECT_ID" \
  --location=global --workload-identity-pool="$POOL_ID" --format='value(name)'
```

```text
projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca
```

## 3. The token type

Add the token type `gcp-wif` to the `federation` section of `simple-ca.json`. Its audience, the
`aud` claim of the JWTs, is the one the provider accepts: `https://iam.googleapis.com/` and the
resource name of step 2:

```json
{
  "federation": {
    "issuer": "https://pki.example.com",
    "types": {
      "gcp-wif": {
        "base": "google",
        "audience": "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca"
      }
    }
  }
}
```

The type issues JWTs valid for 1 hour, with the name of the token as the subject. Its other
settings are optional:

- `valid` and `max_valid` change the validity, within the 24 hours of `google`;
- `subject` is a template of the subject: `simple-ca:{ca}:{name}` makes the subject of the token
  `build-01` `simple-ca:gcp-wif:build-01`, which is then the subject of the principal of step 5;
- `claims` adds claims: `"env": "lab"` reaches the conditions and the principal sets of Google as
  an attribute when the provider of step 2 maps it, with
  `--attribute-mapping=google.subject=assertion.sub,attribute.env=assertion.env`.

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
instead, which the machine exchanges once for the token in step 6, so the token itself is never
handed over.

## 5. The access of the machine

The subject of its JWTs, the name of the token, makes the machine this principal in Google, with
the number of the project, not its ID:

```text
principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/subject/build-01
```

The machine gets its access in one of two ways.

### As the principal

Google recommends giving the principal the roles on the resources the machine uses. The machine
then calls Google Cloud with its federated access token:

```sh
PROJECT_ID=lab-project
PRINCIPAL=principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/subject/build-01
ROLE=roles/browser

gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="$PRINCIPAL" --role="$ROLE"
```

### As a service account

A machine that calls an API endpoint which Google lists with a limitation for federated identities
acts as a service account instead. Create one for the machine, let the principal impersonate it
with the role `roles/iam.workloadIdentityUser`, and give the service account the roles on the
resources the machine uses:

```sh
PROJECT_ID=lab-project
SA_NAME=build-01
SA_DISPLAY_NAME="simple-ca build-01"
SA_EMAIL=build-01@lab-project.iam.gserviceaccount.com
PRINCIPAL=principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/subject/build-01
ROLE=roles/browser

gcloud iam service-accounts create "$SA_NAME" --project="$PROJECT_ID" \
  --display-name="$SA_DISPLAY_NAME"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project="$PROJECT_ID" \
  --role=roles/iam.workloadIdentityUser --member="$PRINCIPAL"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA_EMAIL" \
  --role="$ROLE"
```

`gcloud iam service-accounts create` prints the email of the service account. A new role binding
may take a few minutes to apply.

## 6. On the machine

The machine needs to reach `serve`; Google does not. `request-token`, which the release archives
of simple-ca hold, makes the requests. Put its settings in `federation.json` of its working
directory:

```json
{
  "ca_url": "https://pki.example.com/gcp-wif",
  "token_file": "build-01.token",
  "provider": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca",
  "service_account": "build-01@lab-project.iam.gserviceaccount.com"
}
```

- `ca_url` is the URL of the issuing CA at `serve`, as the machine reaches it.
- `token_file` is the file of the token of step 4, here beside `federation.json`.
- `provider` is `//iam.googleapis.com/` and the resource name of step 2. It starts with `//`,
  unlike the audience of step 3.
- `service_account` is the email of the service account of step 5. Leave it out for a machine
  that acts as the principal.

A machine that got a setup code in step 4 exchanges it once; `request-token api` writes the token
to `token_file`, a new file of mode 0600:

```sh
SETUP_CODE=K7QF-M2XA-JP4D-W5ZR

request-token api "$SETUP_CODE"
```

A machine that acts as the principal gets its federated access token with `google-wif`:

```sh
ACCESS_TOKEN=$(request-token google-wif)
```

A machine that acts as the service account gets the access token of the service account with
`google-access-token`:

```sh
ACCESS_TOKEN=$(request-token google-access-token)
```

Each command prints the access token alone. A JWT lasts an hour, and the access token of a
service account an hour by default, so the machine runs the command again when it needs a new
one. [Appendix A](#appendix-a-the-requests-of-request-token) shows the requests the commands
make, and [Appendix B](#appendix-b-a-test-call) a call that tests the access token.

## Application Default Credentials and gcloud

Google's client libraries and `gcloud` get their access tokens themselves, from a credential file
that names the provider and where to read the JWT. `request-token google-cred-config` writes it
from `federation.json` of step 6: the provider, and the service account to impersonate when
`service_account` is set. It writes a new file, `cred.json` or that of `--output-file`, and never
replaces one. The JWT comes from one of two sources; choose one.

### The JWT from request-token

By default, the credential file holds the command
`request-token jwt --google-executable --config FILE`, with the absolute paths of `request-token`
and of `federation.json`, and Google's client libraries run it whenever they need a JWT. They run
it only with `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. A program that uses Application
Default Credentials finds the credential file with `GOOGLE_APPLICATION_CREDENTIALS`:

```sh
CRED_FILE=$PWD/cred.json

request-token google-cred-config --output-file "$CRED_FILE"
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1
export GOOGLE_APPLICATION_CREDENTIALS="$CRED_FILE"
```

### The JWT from a file

With `--credential-source file`, the credential file names a file of the JWT, which
`request-token jwt --output` writes. The JWT lasts an hour, so a systemd timer or cron runs that
command again well within the hour:

```sh
CRED_FILE=$PWD/cred.json
JWT_FILE=/var/lib/build-01/simple-ca.jwt

request-token jwt --output "$JWT_FILE"
request-token google-cred-config --credential-source file --jwt-file "$JWT_FILE" \
  --output-file "$CRED_FILE"
export GOOGLE_APPLICATION_CREDENTIALS="$CRED_FILE"
```

`gcloud` signs in with this credential file:

```sh
CRED_FILE=$PWD/cred.json
PROJECT_ID=lab-project

gcloud auth login --cred-file="$CRED_FILE"
gcloud projects describe "$PROJECT_ID"
```

## Later

- `simple-ca token renew --ca-dir /etc/simple-ca/gcp-wif build-01` renews the token of the
  machine before its 90 days end.
- `simple-ca token revoke --ca-dir /etc/simple-ca/gcp-wif build-01` stops it from getting JWTs at
  once; a JWT issued before lasts until it expires, within the hour.
- Each JWT issued is a `token.issue` record of the audit log:
  `simple-ca audit list --ca-dir /etc/simple-ca --event token.issue --ca gcp-wif`.
- When the key of the CA changes, run `simple-ca-wif google setup` again, which uploads the new
  key set, or upload it with
  `gcloud iam workload-identity-pools providers update-oidc --jwk-json-path`; the provider holds
  at most 8 keys.

## Appendix A: the requests of request-token

`request-token google-access-token` makes three requests, and `google-wif` the first two:

1. the JWT, from `/api/federation-token` of `serve`, with the api token as the bearer token;
2. the federated access token, from Google's Security Token Service, for the JWT, with the
   provider as the `audience`;
3. the access token of the service account, from `generateAccessToken` of the IAM Service Account
   Credentials API, with the federated access token as the bearer token.

The same with curl and jq, with the settings of `federation.json` of step 6:

```sh
CA_URL=https://pki.example.com/gcp-wif
TOKEN_FILE=build-01.token
PROVIDER=//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca
SA_EMAIL=build-01@lab-project.iam.gserviceaccount.com

JWT=$(curl -sS -X POST -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
  "$CA_URL/api/federation-token" | jq -r .token)
FEDERATED_TOKEN=$(jq -n --arg token "$JWT" --arg audience "$PROVIDER" \
  '{grantType: "urn:ietf:params:oauth:grant-type:token-exchange", audience: $audience,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: $token}' |
  curl -sS -H 'Content-Type: application/json' --data @- https://sts.googleapis.com/v1/token |
  jq -r .access_token)
ACCESS_TOKEN=$(jq -n '{scope: ["https://www.googleapis.com/auth/cloud-platform"]}' |
  curl -sS -H "Authorization: Bearer $FEDERATED_TOKEN" -H 'Content-Type: application/json' \
    --data @- "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SA_EMAIL}:generateAccessToken" |
  jq -r .accessToken)
```

## Appendix B: a test call

With the role `roles/browser` of step 5, the access token of step 6 reads the project from the
Resource Manager API:

```sh
PROJECT_NUMBER=123456789
ACCESS_TOKEN=$(request-token google-access-token)

curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v3/projects/${PROJECT_NUMBER}"
```
