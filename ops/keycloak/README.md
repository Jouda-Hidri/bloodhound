# Keycloak realm

`realm-bloodhound.json` is imported on first start. JSON has no comment syntax and Keycloak
rejects unknown fields outright — `Unrecognized field "//comment"` — so the reasoning lives here
instead.

## Users

| user | password | role | exists to prove |
|---|---|---|---|
| `viewer` | `viewer` | VIEWER | read-only access works |
| `analyst` | `analyst` | ANALYST | triage works, containment does not |
| `responder` | `responder` | RESPONDER | containment works |
| `nobody` | `nobody` | *none* | **authentication is not authorisation** |

`nobody` is the interesting one. It authenticates perfectly — valid credentials, valid token —
and is permitted to do nothing at all. A system that conflates "who are you" with "what may you
do" passes every test until the day someone with a legitimate account does something they should
not have been able to.

## Two clients, two jobs

- **`bloodhound-responder`** is `bearerOnly`. It validates tokens and never issues them, has no
  login flow, and holds no credentials. If it is compromised, no tokens can be minted with it.
- **`bloodhound-cli`** is a public client with the password grant enabled, so `make token` can
  fetch a token without a browser.

The password grant is discouraged for real applications — it hands the client the user's actual
credentials, which is the thing OAuth exists to avoid — and is acceptable here only because this
is a lab CLI driven by `curl`. A real console would use the authorisation code flow with PKCE.

## The audience mapper is not optional

Without `bloodhound-responder-audience`, tokens come back with `"aud": "account"`.

A resource server that checks audience would reject them, so the tempting fix is to stop checking
audience. That is the wrong fix: it makes the responder accept *any* token from this realm,
including one minted for a completely different application by a user who never intended it to be
used here. That is the confused-deputy problem. Audience is what scopes a token to the service it
was issued for, and the mapper is what puts it there.

## Token lifetime: 5 minutes

`accessTokenLifespan: 300`, which is aggressive.

A stolen access token is only useful while it is valid, so the lifetime is the blast radius of
token theft. Five minutes is the difference between a stolen token being an incident and being a
disaster — and this platform has a detection (`session_hijack`, T1539) for exactly the attack
that short lifetimes mitigate. Setting the lifetime to eight hours because refreshing is
inconvenient would be arguing against the platform's own threat model.

## The issuer string must match exactly

`KC_HOSTNAME: http://localhost:8280` is baked into the `iss` claim of every token, and the
resource server compares it byte for byte.

Tokens minted as `http://keycloak:8080` are rejected by a validator configured for
`http://localhost:8280`, even though both reach the same server. This is the single most common
OIDC-in-Docker failure, and the error message — an opaque signature or issuer mismatch — points
nowhere near the cause.

The consequence here: the responder runs on the host and reaches Keycloak via `localhost:8280`,
so that is the hostname Keycloak must advertise. A responder running *inside* Docker would need
the issuer and the network address to be reconciled, usually by making both `localhost` via
`extra_hosts` or by putting Keycloak behind a single stable URL.

## What this still is not

- One realm, no identity federation, no MFA.
- The admin password is `bloodhound`, in the compose file.
- `sslRequired: none`. Tokens cross the wire in plaintext, which on a real network means anyone
  who can see the traffic holds RESPONDER.
- Role assignment is static in the realm file rather than coming from a directory.
