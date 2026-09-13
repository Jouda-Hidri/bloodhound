# 0007 — Real identity, and the end of shared API keys

Status: accepted
Date: 2026-09-13

## Context

Week 18 shipped API-key RBAC and said so: keys in a config file, no expiry, no rotation, shared
between everyone holding them. It got least privilege right and everything else wrong.

The failure that matters is not theoretical. This platform can disable user accounts. When
somebody asks *"why was this account locked out at 3am"*, the audit trail said:

```
actor=responder@apikey   action_executed   disable_account
```

Which is: someone holding a string that four people know. That is not an answer, and on the day it
is asked for real it will not be good enough.

## Decision

OIDC against Keycloak, with the API keys retained as a fallback mode.

Same audit query, after:

```
actor=analyst     alert_triaged
actor=responder   alert_triaged
```

### Three modes, not a replacement

`bloodhound.responder.auth.mode` is `oidc`, `apikey` or `none`.

The default stays `apikey` so that `make up` + four services still works without an identity
provider — a contributor who wants to see the pipeline should not first have to run Keycloak.
Keeping both also makes the comparison concrete: the same authorisation matrix, one mechanism
that names a person and one that does not.

### Audience is validated, not just issuer

Spring validates signature and issuer by default. It does not validate audience, and the path of
least resistance is to leave it that way — Keycloak's default `aud` is `account`, so the check
fails and removing it makes the error go away.

That would make the responder accept **any token this realm ever issued**, including one minted
for a completely different application by a user who never intended it to be used here. That is
the confused-deputy problem. The realm has an audience mapper; the resource server checks it.

### 401 and 403 mean different things

- **401** — no credentials, or credentials that did not verify. *Authenticate and try again.*
- **403** — authenticated successfully, and still not permitted.

The first implementation returned 403 for both, because the role resolver returned null in both
cases. That sends a client with an expired token off to debug its permissions, and a client with
no token off to request a role it already has.

Measured, and now part of `make authz-matrix`:

| | `/alerts` | triage | approve |
|---|---|---|---|
| viewer | 200 | 403 | 403 |
| analyst | 200 | 200 | 403 |
| responder | 200 | 200 | 404 |
| **nobody** | **403** | **403** | **403** |
| no token | 401 | 401 | 401 |
| garbage token | 401 | 401 | 401 |

`404` for responder/approve means authorisation passed and the handler ran — action 99999 does
not exist.

### The `nobody` user exists on purpose

It authenticates perfectly and is authorised for nothing.

Authentication answers *who are you*; authorisation answers *what may you do*. A system that
conflates them passes every test until the day someone with a legitimate account does something
they should not have been able to. Having a user that holds those two questions apart means the
distinction is tested rather than assumed — `oidcRole()` returns null rather than defaulting to
VIEWER precisely because of this account.

### Roles are filtered to the three this platform models

Keycloak attaches `offline_access`, `uma_authorization` and a `default-roles-*` to every user.
Admitting every realm role as an authority would mean an authorisation model shaped by whatever
the identity provider happens to include.

### Token lifetime is 5 minutes

A stolen access token is useful only while valid, so the lifetime is the blast radius of token
theft. This platform has a detection for exactly that attack (`session_hijack`, T1539); setting
an eight-hour lifetime because refreshing is inconvenient would be arguing against its own threat
model.

## Two bugs worth recording

**Spring Boot auto-registers every `Filter` bean.** `ApiKeyAuthFilter` is a `@Component`
extending `OncePerRequestFilter`, so it ran on every request regardless of the security filter
chain — in `oidc` mode it rejected valid bearer tokens with `missing or invalid X-Api-Key
header`, a 401 naming the wrong mechanism entirely. The fix is a `FilterRegistrationBean` with
`setEnabled(false)`, which leaves the filter available to be added to the chain deliberately.

**Keycloak rejects unknown fields in a realm import.** JSON has no comments, and
`"//comment": "..."` produces `Unrecognized field "//comment"` and a container that will not
start. The reasoning moved to `ops/keycloak/README.md`.

## What this is still not

- One realm, no federation, **no MFA** — which is conspicuous on a platform that detects
  credential attacks for a living.
- `sslRequired: none`. Tokens cross the wire in plaintext; on a real network anyone who can see
  the traffic holds RESPONDER.
- Keycloak's admin password is `bloodhound`, in the compose file.
- The password grant is enabled for `bloodhound-cli` so `make token` works without a browser. It
  hands the client the user's actual credentials, which is the thing OAuth exists to avoid. A
  real console would use authorisation code with PKCE.
- Roles are static in the realm file rather than coming from a directory, and nothing revokes a
  session when someone leaves.
- No service-to-service authentication: the detector, consumer and producer APIs remain open.
  The responder was done first because it is the one that can lock accounts out.
