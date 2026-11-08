# MDM Platform — source tree

Build started 4 November 2026. Fifteen sprints so far: the tenant isolation
foundation, the gateway, the console, the command pipeline, the wiring
between them, sign-in, enrolment, policy, the device agent, the page the
people carrying the devices actually see, and telling somebody when it
matters, by chat or by email, from the tenant's own domain.

Someone can now open their organisation's own console hostname, sign in
against their own Microsoft Entra or Google Workspace tenant, invite a device,
watch it enrol and collect an identity certificate from their organisation's
own authority, write a policy, see the device judged against it with the
reasons spelled out, and ask for a lock or a wipe that a second person has to
approve. What they cannot do is have anything reach a device,
because that needs the Apple MDM vendor certificate. That seam is
`command.PushProvider` and nothing else waits on it.

Companion documents, all in `../_outputs/`:

- `MDM_Platform_Technical_Architecture_and_Build_Spec_v01.docx`
- `MDM_Platform_Application_Design_v01.docx`

## Why this and nothing else

The specification names one thing that has to exist before anything else:
`tenant_id` and row-level security in the first migration, even while the
console is single-tenant. Retrofitting tenancy is the named failure mode for
this product class, and it is the only part of Phase 1 that cannot be added
later without rewriting everything above it.

It is also the only substantial part of Phase 1 with **no dependency on Apple,
Google or Microsoft**, which matters while Phase 0 is still open.

## Status

| Part | State |
|---|---|
| Tenant schema, roles, row-level security | Built, running, proven |
| Append-only hash-chained audit log | Built, running, proven |
| T13 cross-tenant isolation suite (SQL) | Built, 14 assertions, passing |
| Negative control for the SQL suite | Built, confirmed it catches a removed policy |
| Signed tenant claim (mint and verify) | Built, running, proven |
| Data layer with tenant context propagation | Built, running, proven |
| T13 extended into the Go layer | Built, passing |
| Role matrix (F16, R12), one implementation | Built, 5 tests, passing |
| Tenant directory, operator-scoped, own role | Built, proven it cannot read devices |
| Gateway: resolution, claim minting, roles, rate limit | Built, running, proven |
| T13 extended to HTTP | Built, passing |
| Per-tenant branding with a contrast guard (T4) | Built, 6 tests, passing |
| Console: dashboard, devices, device, audit | Built, server rendered, proven |
| T12 brand-leak gate | Built, fails the build on a foreign brand |
| Command pipeline: F12-F15, R1, R4, R6, R8 | Built, passing |
| Pipeline wired to the API and the console | Built, passing |
| Cross-site request protection on console forms | Built, passing |
| Identity provider adapter (OpenID Connect, per tenant) | Built, passing |
| Sign-in, sessions, idle and absolute expiry, sign-out | Built, passing |
| Group-to-role mapping, no default (R11, F16) | Built, passing |
| Tenant-wide session revocation | Built, passing |
| Sealed storage for identity provider secrets | Built, passing |
| Per-tenant certificate authority | Built, passing |
| Enrolment: one-time token, state machine, re-enrolment | Built, passing |
| **Device certificates verified rather than assumed** | **Built, passing** |
| Certificate revocation, checked on every request | Built, passing |
| Policy engine: catalogue, strictest-wins merge, scope | Built, passing |
| Device self-reporting and compliance verdicts | Built, passing |
| Policy versioning, retirement, effective view | Built, passing |
| Device agent: enrol, report, obey, acknowledge | Built, passing |
| **Device certificates no longer carry admin rights** | **Fixed, proven** |
| End-to-end over real TLS with a real client certificate | Built, passing |
| Employee self-service, scoped per person | Built, passing |
| Device assignment, made at enrolment | Built, passing |
| Report a device lost (flags, executes nothing) | Built, passing |
| Notifications: outbox, retry, per-tenant targets | Built, passing |
| **The limiter now tells someone, as it always claimed** | **Fixed, proven** |
| **R1's refusal record survives the request** | **Fixed, proven** |
| Email notifications over SMTP, with STARTTLS | Built, passing |
| Header-injection refusal, checked at the form | Built, passing |
| Per-tenant sending domains, proven by DNS | Built, passing |
| DKIM signing, aligned with the From address | Built, passing |
| Agent packaging: five platforms, launchd, systemd | Built, binaries produced |
| `agent doctor`, permission checks on a real install | Built, passing |
| Certificate renewal, and a warning when it is not happening | Built, passing |
| Negative controls, thirty-one of them | All confirmed to catch their own protection |
| SCEP, NanoMDM spike, signed Apple profile | Not started |

303 Go tests across thirteen packages, plus 14 SQL assertions. All passing, all
run against real PostgreSQL in Docker, with the sign-in tests running against
a real OpenID Connect provider over real HTTP and the enrolment tests issuing
real certificates from a real authority.

## Running it

Needs Docker. Nothing else: no local PostgreSQL, no Go toolchain.

```
./db/run.sh                 # migrate, run the SQL suite, expect a pass
./db/run.sh --break-rls     # remove the protection first, expect a FAILURE
./db/run.sh --break-personrls # remove the database's half of person isolation, expect a FAILURE

./run_go.sh                 # run every Go test, expect a pass
./run_go.sh --break-claim   # stop WithTenant setting the tenant, expect a FAILURE
./run_go.sh --break-host    # stop the gateway comparing tenant to hostname, expect a FAILURE
./run_go.sh --break-brand   # render one brand for every tenant, expect a FAILURE
./run_go.sh --break-approval # let a full wipe pass on one approval, expect a FAILURE
./run_go.sh --break-csrf    # stop checking the form token, expect a FAILURE
./run_go.sh --break-rolemap # give an unmapped person a role, expect a FAILURE
./run_go.sh --break-audience # accept a token minted for another app, expect a FAILURE
./run_go.sh --break-revocation # ignore tenant-wide revocation, expect a FAILURE
./run_go.sh --break-certtrust # trust any device certificate, expect a FAILURE
./run_go.sh --break-csrsubject # sign the subject that was asked for, expect a FAILURE
./run_go.sh --break-reenrol # leave the old certificate valid, expect a FAILURE
./run_go.sh --break-merge   # let a looser policy win, expect a FAILURE
./run_go.sh --break-unknownrule # skip an unknown rule name, expect a FAILURE
./run_go.sh --break-silence # count a missing field as a pass, expect a FAILURE
./run_go.sh --break-quarantine # let a report release a quarantined device, expect a FAILURE
./run_go.sh --break-devicerole # make a device an administrator again, expect a FAILURE
./run_go.sh --break-devicescope # show a device the whole queue, expect a FAILURE
./run_go.sh --break-ack     # acknowledge work that failed, expect a FAILURE
./run_go.sh --break-mine    # show an employee a colleague's device, expect a FAILURE
./run_go.sh --break-lostowner # let anyone report anyone's device lost, expect a FAILURE
./run_go.sh --break-ssrf    # let a webhook reach inside the network, expect a FAILURE
./run_go.sh --break-refusal # roll back the limiter's record, expect a FAILURE
./run_go.sh --break-dedupe  # queue one event twice, expect a FAILURE
./run_go.sh --break-headers # allow a line break into a mail header, expect a FAILURE
./run_go.sh --break-cleartext # send a password unencrypted, expect a FAILURE
./run_go.sh --break-dnsproof # verify a domain without proof, expect a FAILURE
./run_go.sh --break-alignment # sign as one domain, send as another, expect a FAILURE
./run_go.sh --break-tokenfile # accept a readable token file, expect a FAILURE
./run_go.sh --break-doctor  # ignore a replaceable binary, expect a FAILURE
./run_go.sh --break-renewrevoked # let a revoked certificate renew, expect a FAILURE
./run_go.sh --break-renewwindow # let any certificate renew, expect a FAILURE
./run_go.sh --break-operatorreach # let the operator's role read devices, expect a FAILURE
./run_go.sh --break-signupreuse # let a sign-up link be used twice, expect a FAILURE
./run_go.sh --break-signupexpiry # let a sign-up link last forever, expect a FAILURE
./run_go.sh --break-signupcap # remove the sign-up caps, expect a FAILURE
./run_go.sh --break-signupfreemail # let a gmail address sign up, expect a FAILURE
./run_go.sh --break-proxytrust # believe X-Forwarded-For from anyone, expect a FAILURE
./run_go.sh --break-brake   # quarantine a whole failing fleet, expect a FAILURE
./run_go.sh --break-optin   # quarantine without a policy asking, expect a FAILURE
./run_go.sh --break-releasepath # release without telling the database, expect a FAILURE
./run_go.sh --break-scopedbrake # measure the brake over the fleet only, expect a FAILURE
./run_go.sh --break-tokenrevoked # honour a revoked integration token, expect a FAILURE
./run_go.sh --break-networkrole # let a network token list devices, expect a FAILURE
./run_go.sh --break-feeddeny # let the access feed allow a quarantined device, expect a FAILURE
./run_go.sh --break-feedunknown # let the access feed allow a device that never reported, expect a FAILURE
./run_go.sh --break-androidstate # bind an enterprise from a callback nobody started, expect a FAILURE
./run_go.sh --break-androidwipe # send a selective Android wipe as a full one, expect a FAILURE
./run_go.sh --break-androidjudged # drop undeliverable Android rules silently, expect a FAILURE
./run_go.sh --break-googlewords   # dump Google's refusal as raw JSON, expect a FAILURE
./run_go.sh --break-projectid     # create a sign-up URL without naming the project, expect a FAILURE
./run_go.sh --break-callbackbase  # ignore the https callback base, expect a FAILURE
./run_go.sh --break-fakehttps     # let the fake accept a plain-http callback, expect a FAILURE
./run_go.sh --break-seats         # never check the administrator seat count, expect a FAILURE
./run_go.sh --break-seatlapse     # a seat held for ever, expect a FAILURE
./run_go.sh --break-invitelink    # invite with a console link instead of Google's, expect a FAILURE
./run_go.sh --break-inviteaddress # mail an invitation without checking the address, expect a FAILURE
./run_go.sh --break-expiryfield   # read the token expiry from a field Google does not send, expect a FAILURE
./run_go.sh --break-sharedwake    # keep the wake inside one instance, expect a FAILURE
./run_go.sh --break-resealhalt    # skip an unopenable key during master rotation, expect a FAILURE
./run_go.sh --break-previousmaster # forget the master being rotated out, expect a FAILURE
./run_go.sh --break-sharedrate    # count the rate limit per instance, expect a FAILURE
./run_go.sh --break-importcounts  # commit an import that does not add up, expect a FAILURE
./run_go.sh --break-importtenant  # import a row into another tenant, expect a FAILURE
./run_go.sh --break-agentverify   # let the agent skip the command signature, expect a FAILURE
./run_go.sh --break-sealedsigning # store the signing key in the clear, expect a FAILURE
./run_go.sh --break-emailescape   # show the email body as markup, expect a FAILURE
./run_go.sh --break-emailbrand    # leave the brand off every email, expect a FAILURE
./run_go.sh --break-templates     # drop the Android template, expect a FAILURE
./run_go.sh --break-persignout    # ignore a person's sign-out stamp, expect a FAILURE
./run_go.sh --break-coalesce      # never coalesce notifications, expect a FAILURE
./run_go.sh --break-rplogout      # leave the provider's session alive on sign-out, expect a FAILURE
./run_go.sh --break-saml          # take a SAML assertion for any request, expect a FAILURE
./run_go.sh --break-samlhost      # finish a SAML sign-in on another tenant's hostname, expect a FAILURE
./run_go.sh --break-remediate     # mark every failure for the device to act on, whatever the policy said, expect a FAILURE
./run_go.sh --break-nativebounds  # let any number from the server reach a command line, expect a FAILURE
./run_go.sh --break-vaulthttp     # fetch the platform keys from a vault over plain http, expect a FAILURE
./run_go.sh --break-keydescribe   # print the platform keys on the start-up line, expect a FAILURE
./run_go.sh --break-keyfilemode   # read a key file other users can read, expect a FAILURE
./run_go.sh --break-freemailsuffix # take a free-mail provider's subdomain as a company, expect a FAILURE
./run_go.sh --break-macnormalise  # match a MAC address only as written, expect a FAILURE
./run_go.sh --break-macmove       # leave an address with the first device that reported it, expect a FAILURE
./run_go.sh --break-isecompliance # tell Cisco ISE every registered device is compliant, expect a FAILURE
./run_go.sh --break-emailreuse    # let a leaver's address answer for the next hire, expect a FAILURE
./run_go.sh --break-leftmark      # offboard a leaver's devices and keep the person active, expect a FAILURE
./run_go.sh --break-historychange # write a history row on every report, expect a FAILURE
./run_go.sh --break-trendcount    # take the trend from a different count than the dashboard, expect a FAILURE
./run_go.sh --break-personsql     # let an employee's transaction read the whole tenant, expect a FAILURE
./run_go.sh --break-slosig        # act on a provider's logout request without its signature, expect a FAILURE
./run_go.sh --break-lockout       # let five wrong passwords go unnoticed, expect a FAILURE
./run_go.sh --break-totpreplay    # accept a second-step code twice, expect a FAILURE
./run_go.sh --break-lastadmin     # let the last Super Admin be removed, expect a FAILURE
./run_go.sh --break-enumeration   # tell a stranger an address has no account, expect a FAILURE
./run_go.sh --break-localtoken    # let a spent invitation or reset link be used again, expect a FAILURE
./run_go.sh --break-mfarequired   # let an administrator in on a password alone, expect a FAILURE
./run_go.sh --break-localprotocol # take a password at an identity-provider tenant, expect a FAILURE
./run_go.sh --break-sessionsend   # leave a person's sessions when their access changes, expect a FAILURE
./run_go.sh --break-reserved      # let a customer take the short name app or www, expect a FAILURE
./run_go.sh --break-qrpayload     # draw the bare token in the QR code instead of the link, expect a FAILURE
./run_go.sh --break-qrowner       # show a company phone the personal phone's QR code, expect a FAILURE
./run_go.sh --break-selfwho       # make a self-service code for the address typed, not the person, expect a FAILURE
./run_go.sh --break-selfoff       # ignore the switch: self-enrol while it is off, expect a FAILURE
./run_go.sh --break-selfcap       # remove the five-codes-a-day limit, expect a FAILURE
./run_go.sh --break-selfowner     # let a personal-only person ask for a company phone, expect a FAILURE
./run_go.sh --break-selfleaver    # let somebody who has left enrol a phone, expect a FAILURE
./run_go.sh --break-unverifiedemail # believe an email the provider calls unverified, expect a FAILURE
./run_go.sh --break-joincode      # let a join link in without its code, expect a FAILURE
./run_go.sh --break-joinlock      # never pause a link after wrong codes, expect a FAILURE
./run_go.sh --break-joincap       # let a join link enrol more devices than its limit, expect a FAILURE
./run_go.sh --break-joinexpiry    # let a join link outlive its time, expect a FAILURE
./run_go.sh --break-joincancel    # let a cancelled join link keep working, expect a FAILURE
./run_go.sh --break-rotategrace   # end every open session at a key rotation, expect a FAILURE
./run_go.sh --break-keysdiffer    # let one key do all three jobs, expect a FAILURE
./run_go.sh --break-bucketssrf    # send the export to any address a name resolves to, expect a FAILURE
./run_go.sh --break-lostbrand # show the operator's name on a lost phone, expect a FAILURE
./run_go.sh --break-lostcontact # drop who to call from a lost phone, expect a FAILURE
./run_go.sh --break-reportbrand # put the operator's name on the compliance PDF, expect a FAILURE
./run_go.sh --break-reportaudit # export a report with no audit record, expect a FAILURE
./run_go.sh --break-rollbackinplace # roll a policy back by editing history, expect a FAILURE
./run_go.sh --break-devicecap # let a tenant past its device cap, expect a FAILURE
./run_go.sh --break-featureflag # give every plan every feature, expect a FAILURE
./run_go.sh --break-rolloutall # put every device in every stage, expect a FAILURE
./run_go.sh --break-rolloutshuffle # re-decide a device's stage on every report, expect a FAILURE
./run_go.sh --break-siemcursor # move the SIEM cursor past undelivered events, expect a FAILURE
./run_go.sh --break-siembrand # name the operator as the CEF vendor, expect a FAILURE
./run_go.sh --break-offboardretire # leave an offboarding device enrolled after its wipe, expect a FAILURE
./run_go.sh --break-tokenscope # give the HR token the network role, expect a FAILURE
./run_go.sh --break-offboardscope # let the offboarding permission reach a full wipe, expect a FAILURE
./run_go.sh --break-offboardactive # offboard a tenant that was never suspended, expect a FAILURE
./run_go.sh --break-offboardresidue # leave the audit log behind and report success, expect a FAILURE
./run_go.sh --break-exportsecret # put sealed secrets in the export, expect a FAILURE
./run_go.sh --break-rotatereseal # rotate a tenant's key and re-seal nothing, expect a FAILURE
./run_go.sh --break-keyscope # seal every tenant under the one master key, expect a FAILURE
./run_go.sh --break-wake    # stop a pushed command waking the device's poll, expect a FAILURE
./run_go.sh --break-revealaudit # reveal a recovery key with no audit record, expect a FAILURE
./run_go.sh --break-revealrole # let the help desk reveal recovery keys, expect a FAILURE
./run_go.sh --break-logosniff # serve any upload as a brand image, expect a FAILURE
./run_go.sh --break-hostpolicy # issue certificates for any hostname, expect a FAILURE
./run_go.sh --break-ticketssrf # let the ticketing client dial inside the network, expect a FAILURE
./run_go.sh --break-partnerscope # show one partner another's tenants, expect a FAILURE
./run_go.sh --break-region  # serve a tenant from the wrong region, expect a FAILURE

./build_agent.sh            # cross-compile the agent for five platforms

GOTESTFLAGS=-v ./run_go.sh  # the same, with every test named
```

Each spins up a throwaway `postgres:17-alpine`, applies the migrations in
order, runs, and removes the container afterwards. The Go tests additionally
run inside `golang:1.23-alpine`, so no Go toolchain is installed on the host.
Every `--break-` run copies the source aside and patches the copy; the source
on disk is never modified.

## The two build gates this proves

**Cross-tenant isolation (T13).** The fixture is two tenants carrying
deliberately overlapping data: the same device name, the same serial, the same
policy name. If separation ever came to depend on values happening to differ,
these assertions would catch it. Fourteen assertions across reads, writes,
failing closed, append-only audit, and the structure of the schema itself.

**Append-only audit (R9).** Two independent protections. `UPDATE` and `DELETE`
are never granted to the application role, which stops us. Each row also
carries the hash of its predecessor within the same tenant, which makes a
deletion performed outside the application detectable rather than merely
prevented. The second is the one being sold to an auditor.

## Why there is a negative control

A suite that has never failed proves nothing. `--break-rls` drops the
isolation policy and runs the same suite, and the run is only considered good
if the suite **fails**. Confirmed on 4 November 2026: with the policy removed,
tenant A saw all five devices and assertion 1.1 caught it.

## Design notes worth keeping

**`FORCE ROW LEVEL SECURITY`, not just `ENABLE`.** Without `FORCE`, a table
owner silently bypasses every policy. "We remembered to set it" is not a
control, so assertion 5.2 checks both flags on every tenant-scoped table.

**Fails closed.** `app.current_tenant()` returns `NULL` when the setting is
missing or empty. `NULL` compared to anything is not true, so a connection
with no tenant set sees nothing rather than everything. Assertion 2.1.

**The one rule this rests on.** The tenant is set from the signed tenant claim
on the request, by the data layer, never from anything a user can type. The
database cannot enforce that, so `data.Store.WithTenant` is where it is
enforced, and it is the single function in the platform most worth reviewing.

**The pool is unexported and never returned.** There is no path from
application code to a query that has not first been given a verified claim.
That is what "no application path that disables it" has to mean in practice:
not a rule people follow, a type they cannot get around. No repository
function takes a tenant id, because a function that accepted one would be a
function someone could pass the wrong value to.

**Transaction-scoped, not session-scoped.** The tenant is set with
`set_config(..., is_local => true)`. Connections are pooled and reused, so a
session-scoped setting would carry one tenant's context into the next request
to borrow that connection. `TestPooledConnectionCarriesNoTenantBetweenTransactions`
runs alternating tenants through a pool of exactly one to prove it.

**Everything fails closed.** The negative control is instructive here: with the
tenant unset, reads return zero rows and writes are refused by the row-level
security check. Nothing silently widens.

**Uniqueness is per tenant.** `UNIQUE (tenant_id, serial)`, never
`UNIQUE (serial)`. Two tenants may legitimately hold the same device serial,
and the fixture depends on that being true.

**Audit chains are per tenant.** One tenant's history is independent of every
other's, so a chain verification is a tenant-scoped answer.

## The gateway's one rule

**The hostname decides the tenant. A session or a device certificate must
agree with it.** Where they disagree the request is refused rather than
resolved in anyone's favour, because a gateway that picks a winner between two
tenant claims is a cross-tenant vulnerability with a preference.

A device certificate is authoritative when present, because it arrives from
the TLS handshake and cannot be set by a header. The tenant is in the
certificate's organisational unit and the device in its common name, which is
also why certificates carry a tenant identifier and never a vendor name (T12).

Two further rules worth keeping:

**Another tenant's object is not found, never forbidden.** A forbidden answer
confirms the object exists, which is itself a cross-tenant leak. Row-level
security makes the row invisible, so the handler genuinely cannot tell "not
yours" from "not there". There is a test for it, and a companion assertion
that the same identifier *is* found from its own tenant, so the test could not
pass on a handler that simply 404s everything.

**A route cannot be registered without naming the action it needs.** `guard`
is the only way to mount a handler, and it takes an `authz.Action`.

## The console

Server rendered, which is a deliberate departure from the specification's
"TypeScript and React" line. The reason is T4: the design document's own rule
is that the theme is "resolved per request from tenant_branding into CSS
custom properties. No build step, no per-tenant bundle." Rendering on the
server is the shortest path to that and removes the flash of the wrong brand
that a client-resolved theme produces.

The seam is the handlers, not the markup. If richer interaction is wanted,
these routes become JSON and a React application renders them, with none of
the resolution, role or isolation work changing.

What it proves today:

- **The brand is a column.** Tenant A renders in its own name, colour and
  legal footer; tenant B, deliberately unbranded, renders the placeholder and
  a banner saying setup is not finished. One deployment, one stylesheet.
- **A colour nobody can read is refused.** `branding.Validate` computes the
  WCAG contrast of white text on the brand colour and refuses below 4.5 to 1,
  naming the ratio and the requirement. Accessibility is not something a
  tenant can switch off by choosing badly.
- **Navigation is built from the role matrix.** A section a role may not use
  is absent, not disabled. A disabled control still advertises a capability
  and invites a request for it.
- **T12 is a build gate.** A page carrying another tenant's brand, or any
  operator word, fails the test. The design document said to write this in
  Phase 1 and let it fail the build from the beginning, because by Phase 3 a
  product name is in email templates, PDF footers and error strings.

## The command pipeline

Every outbound instruction passes through it. The instructions are F12 to F15;
the rules around them are the product.

**Two approvals, two distinct roles, neither the requester.** Enforced by a
database trigger, not only in Go, because the specification's own words are
that the hold is "a state in the command lifecycle, not a user-interface
confirmation, so it cannot be bypassed by calling the API directly". A rule
living only in a handler is a rule one new handler can forget.

**Only one command type is irreversible.** A test asserts that, and that it is
the only one needing two approvals. Adding a second irreversible type fails
the build until someone decides what approving it should cost.

**Pushed is never done.** Only Acknowledged means the device ran it, and that
is what the console shows. A pushed command with no acknowledgement is a
command that has not happened.

**An expired command is never retried.** A fresh request is a fresh decision
with fresh approvals. A wipe arriving an hour after everyone assumed it had
failed is worse than one that never arrived.

**The one-time code is checked three ways** on acknowledgement: it must match,
it must not have been used, and it must not have expired. A replay is refused
and recorded.

**The limiter counts from the commands table**, not a separate tally, so there
is one source of truth and it survives a restart. It is per admin, so one
person working an incident does not lock out their colleagues.

### Reachable now

The pipeline is wired to both surfaces. The API has lock, wipe, list, approve,
refuse and acknowledge; the console has the actions on a device page and an
approvals queue for roles that may approve.

Three rules the wiring had to carry, not just the package:

- **The reversible action sits beside the irreversible one**, and `scope=work`
  is the default. The design rule is that the default on that screen is never
  the one that cannot be undone.
- **A reason is required before the device is looked up.** That ordering is
  deliberate: validating the reason first means a 404 cannot be used to probe
  which devices exist, because every reasonless request stops at 400 first.
- **The console never says done.** `saidAbout` has a sentence per state, and
  queued says the command has not reached the device and why.

### Cross-site request protection

Added this sprint, because until now nothing wrote and there was nothing to
protect. A token derived from the session, in a hidden field, checked on every
POST.

It is required **only when the credential is ambient**. A browser attaches a
cookie by itself, so a form on another site would otherwise carry real
authority. A caller who set an `Authorization` header cannot be made to by
another site, so requiring a token there would be ceremony rather than
protection. `Resolution.FromCookie` is what decides.

Its honest limit: the token does not rotate per request, so one leaked from a
page is good until the session ends.

## Sign-in

Every tenant brings their own identity provider. Kalesi signs in against their
Microsoft Entra tenant, Arbor against theirs, and neither has an account here.
We never hold a password, never run a password reset, and when a tenant
disables someone's account they are disabled here at their next sign-in
without anyone telling us. That is requirement R11 and it is also the only
shape that survives an enterprise security review.

Three routes sit outside the authenticated middleware, and they are the whole
unauthenticated surface of the platform:

```
GET  /signin           resolve the tenant from the hostname, send them to their provider
GET  /signin/callback  verify everything, map a group to a role, start a session
POST /signout          clear the cookie
```

What the callback checks, in order, before anything is trusted:

1. the signed flow cookie verifies, and names this hostname's tenant
2. the `state` matches the one in that cookie
3. the identity token's signature verifies against the provider's published keys
4. its issuer is the configured one
5. its audience is this tenant's client id
6. its nonce is the one we sent
7. the PKCE code verifier matches the challenge we sent

Items 3 to 5 are go-oidc's. Item 5 is the one people leave out, and leaving it
out means an identity token minted for any other application at the same
provider signs someone in here. `--break-audience` removes it and proves the
tests notice.

### A group becomes a role

`tenant_role_map` maps a claim value from the provider to a role in the
matrix. Two rules:

- **Several mapped groups give the highest-ranked role.** Nobody is in one
  group, and the alternative is an answer that depends on map iteration order.
- **No mapped group means no role, and no sign-in.** A default here is a
  silent grant to every account at the tenant. `--break-rolemap` replaces the
  refusal with a default and proves the tests catch it.

A person refused this way gets a page saying which groups they hold matched
nothing and that their own administrator can fix it, because an unexplained
403 turns a group-membership problem into a support ticket for us.

### Sessions

A session is a signed token in a cookie, not a row. The reasoning both ways is
at the top of `internal/session/session.go`; the short version is that a
stored session would have to be looked up **before** the tenant is known,
which is a cross-tenant read path in the one place the design exists to avoid
having one.

| | |
|---|---|
| Absolute lifetime | 12 hours, never extended by use |
| Idle timeout | 30 minutes |
| Renewed | when the token is more than 5 minutes old |
| Revoked | per tenant, all at once, via `sessions_invalid_before` |

Renewal moves `IssuedAt` but never `StartedAt`, and revocation is compared
against `StartedAt`. Without that, an open browser would refresh its way
straight through a revocation, which is the case revocation exists for.

### Setting a tenant up

There is no wizard yet. Seal the client secret, then write two rows:

```
MDM_SEALING_KEY=... go run ./cmd/sealsecret      # paste the secret, get a bytea literal
```

```sql
INSERT INTO tenant_identity
  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim)
VALUES ('<tenant>',
        'https://login.microsoftonline.com/<their-entra-tenant>/v2.0',
        '<application (client) id>',
        '\x...',                                   -- from sealsecret
        'https://mdm.theirdomain.example/signin/callback',
        'groups');

INSERT INTO tenant_role_map (tenant_id, claim_value, role) VALUES
  ('<tenant>', 'MDM-Owners',    'super_admin'),
  ('<tenant>', 'IT-Operations', 'it_admin'),
  ('<tenant>', 'Security-Team', 'security_manager'),
  ('<tenant>', 'All-Staff',     'employee');
```

Verified 2026-11-04: Entra publishes its metadata at
`https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`
and Google at `https://accounts.google.com/.well-known/openid-configuration`.
Group claims in Entra are **off by default** and are switched on per
application registration; Google Workspace does not emit group membership in
the identity token at all. That is why `role_claim` is configurable and why
the wizard will have to ask rather than assume.

### The one carve-out in the isolation model

The directory role can read `tenant_identity` across every tenant. It has to:
a browser at `/signin` holds nothing, and we cannot send it to the right
provider without knowing which provider that tenant uses, with no claim to
scope the read by. Every product with per-tenant sign-in has this read; the
choice is whether it is written down.

It is `SELECT` only, on one table, for one named role that has no write grant
here and no read grant on any other tenant table. The only sensitive column is
`client_secret_sealed`, which is ciphertext whose key lives in the gateway
process and never in the database. `tenant_role_map` is deliberately **not**
in the carve-out: by the time it is read the identity token has verified, so
the tenant is known, a claim is minted and the read goes through row-level
security like every other tenant read.

`TestTheDirectoryRoleReadsIdentityConfigAndOnlyThat` proves the carve-out is
exactly that wide, and the probe list beside it proves it is no wider.

### Where the enrolment tests live

`internal/enrol` has no test file of its own, which is deliberate rather than
an oversight. Every function in it needs a tenant-scoped transaction, so a
package-level test would have to stand up the same database, the same seed
and the same claim the gateway tests already have, and would then exercise
the code one layer below where it actually runs. The tests are in
`internal/gateway/enrolment_test.go` and go through the real HTTP routes with
real certificate signing requests.

What is tested at package level is `internal/pki`, because its rules are
pure: the subject is discarded, a request must be signed by its own key, a
device certificate cannot serve or sign, and one tenant's certificate does
not verify against another's authority. Those need no database and are
clearer without one.

### Testing against a real provider

`internal/identity/idptest` is a working OpenID Connect provider: real
discovery, a real JWKS, a real RSA signature, a real PKCE exchange, over real
HTTP. A fake adapter would have tested nothing, because it would have skipped
the four checks that make the real one safe. It also **refuses an
authorization request without PKCE**, so an adapter that stopped sending a
challenge would fail every sign-in test rather than quietly getting weaker.

The gateway's sign-in tests drive it with a real `http.Client`, a real cookie
jar and redirect following. The only thing simulated is DNS.

## QR codes and self-service enrolment

### The QR code

An Android invitation used to print Google's provisioning payload as raw text
and suggest pasting it into somebody else's QR generator. It now draws the
code itself (`internal/qr`, a PNG inside a `data:` URL, so the secret in it is
never fetched from or sent to anywhere). There are two kinds, and they are not
interchangeable:

| Phone | The code holds | Read by |
|---|---|---|
| a personal phone, already in use | Google's enrolment link | the phone's camera, which opens it |
| a company phone, new or reset | Google's provisioning payload | the welcome screen, after six taps |

A link-code on a company phone scans and leads nowhere, because a welcome
screen has no browser, so the page never shows one (`--break-qrowner`). The
tests do not trust the encoder: `internal/qr/qrtest` reads the picture back
with an independent decoder, from the real page, and the text has to be
exactly right (`--break-qrpayload` draws the bare token and is caught).

### One link for everybody

For a few hundred people, making a token each is a week of typing. An
administrator (Super Admin or IT Admin) turns on **Let people enrol their own
phone** on the Android page, in one of three settings, and sends **one link**,
`https://<the organisation's host>/enrol`, in an all-staff message:

| Setting | A person may |
|---|---|
| off (the default) | nothing; the menu entry is absent |
| personal | enrol their own phone as a work profile |
| any | that, or set up a new company phone at the welcome screen |

A person opens the link, is sent to sign in and brought back, asks for a code,
and gets the QR code (or, if the page is open on an Android phone, a button).
The phone lands on their own page under Your devices within about fifteen
minutes, which is the sync interval. The rules that make this safe, each with
a test and a control:

- **Whose it is.** The address on the code is the signed-in person's, from the
  session. The form has no such field, so a forged one is ignored
  (`--break-selfwho`). A session with no address, such as a bearer token, gets
  no code.
- **Off means off.** Nothing is made, and Google is asked for nothing, while the
  setting is off (`--break-selfoff`). One organisation's setting never applies
  to another's.
- **Five a day.** One person may ask for five codes in 24 hours, counted per
  person under a lock so two clicks at once cannot both slip under
  (`--break-selfcap`). Each code works once and lasts an hour. An administrator
  issuing tokens is not counted: the limit is for the self-service page.
- **Personal means personal.** In personal mode a person cannot ask for a
  company phone (`--break-selfowner`).
- **Leavers.** Somebody the platform has been told has left is refused, judged
  by their subject and not their address, because an address passes to the next
  hire and the next hire is not the leaver (`--break-selfleaver`). One case the
  subject cannot cover: HR can name somebody who never signed in, a record with
  an address and no subject. That record cannot tell the leaver from a later hire
  given the same address, so whoever signs in with it is refused and an
  administrator makes the token by hand.
- **The address is only as honest as the provider.** An address the provider
  marks unverified (`email_verified` false) is not used, and the provider's own
  fallbacks (`preferred_username`, `upn`) are used instead (`--break-unverifiedemail`).
  A provider that sends no `email_verified` at all is believed, because most
  do not send it. **What that leaves open:** at a provider where people can edit
  their own email, and which does not send `email_verified` (Microsoft Entra's
  `email` claim is the known case), a person could present somebody else's
  address and get a phone recorded against it. It is attributable (the token
  records who really asked, and the request is audited), and it shows on the
  other person's page, but it is not prevented. The fix is per provider, by
  telling the tenant's identity setup to read the address from a claim the
  provider controls, and is not built.

The permission is new, `device.enrol_own`, with its reason written beside it
in `authz.go`: `device.enrol` lets its holder invite any device for anyone and
is held by two roles, so an Employee cannot have it; this one is narrow by
construction. Every role a person signs in as holds it; machines, the operator
and the feeds do not.

Migration `0045` adds the `tenant_enrolment` table (row-level security like
every tenant table) and a `source` on Android tokens, `admin` or `self`.

### Join links: no account needed

Self-service asks everyone to sign in, which is right for staff and wrong for a
phone handed to somebody with no account, or a team of five hundred. A **join
link** is for them. An administrator makes one on the Android page: a name, how
many devices it will set up, how long it lasts (1 day, 2 days, 1 week, 2 weeks or
30 days), whether the phones are personal or company, and optionally one named
person if it is for a single device. The page shows the **link** and a
**six-digit code, once**. The administrator sends them by different routes, for
example the link by email and the code by phone or chat. Nothing is emailed by the
platform.

Anybody can open the link, with no account. It asks for the code. Only a right
code shows the way in (the QR code above, or a button on the phone), and each
right code makes a fresh one-hour Google token and counts one use. The code is the
link's code, so it stops working when the link does: at the device limit, at the
expiry, or on cancel. One device is a link with a limit of one.

The rules, each with a test and a control:

- **No code, no way in.** Google is asked for nothing and the page shows no
  link or picture until the code is right (`--break-joincode`).
- **Guessing is limited.** Six digits is a million possibilities, so ten wrong
  codes in an hour pause the link for an hour. The count is per link, because the
  people holding a team link are strangers to each other, and each address is also
  slowed to 20 tries a minute (`--break-joinlock`).
- **The limit is real.** One SQL statement checks the state, the clock and the
  limit and counts the use, so the last place cannot be taken twice. A test sends
  fourteen people at five places at once and exactly five get in
  (`--break-joincap`, `--break-joinexpiry`).
- **Cancel is instant** (`--break-joincancel`). Devices already set up stay.
- **Nothing is stored that can be read back.** The link's secret is kept only
  as a SHA-256 and the code only as an argon2id hash (slow on purpose, since six
  digits is a small space). The page that holds the secret in its address is
  `no-store` with `Referrer-Policy: no-referrer`.
- **One organisation's link is nothing at another's address.**

The devices from a team link have no named owner, because the code is shared.
They arrive unassigned and numbered (`Kano field team 17`), and each one is
recorded against its link. The older direct Google token is still on the page,
under Advanced, for a single device with no code.

**Why a new public route and a new table** (the standing rule asks for the
written reason): every other route needs a session and the person holding a join
link has no account, so `GET/POST /join/{secret}` sit with the other public
routes. The limits and the code's state do not fit on an existing record: a token
is per device and has no count, a code or a lock, so there is a `join_links` table
(migration `0046`). There is no new tag, command or scheduled job.

### Not built yet

- Assigning the devices from a team link to people afterwards (a CSV of serial
  number to person).
- Showing, on a device's own page, which link it came through.
- Laptops: the join link covers Android only. The laptop link on the Enrolments
  page is still a token for the agent, not a page.
- Windows: there is no Windows enrolment yet, so no Windows QR.

## Enrolment

### The gap this closed

From the gateway sprint until this one, a request arriving with a client
certificate whose organisational unit was a tenant and whose common name was
a device was trusted as that device. Nothing issued those certificates and
nothing checked that we had. The trust anchor was dangling: correct in shape,
attached to nothing. Anyone who could reach the endpoint could mint a
certificate saying whatever they liked.

`TestACertificateWeDidNotIssueIsRefused` is that gap written as a test, and
`--break-certtrust` puts the hole back and proves the test notices.

### How a device gets in

```
POST /api/enrolments          an administrator invites a device   (device.enrol)
     -> a one-time token, shown exactly once
POST /api/enrol               the device redeems it with a CSR    (public)
     -> its certificate, and the authority that signed it
```

The token is a bearer credential, so it is treated like one: 32 random bytes,
single use, expiring (7 days by default, 30 at the most), revocable, and
**stored only as a SHA-256 hash**. Someone who reads the `enrolments` table
cannot enrol anything with what they find. It is not an identity and nothing
downstream treats it as one: the identity of the resulting device is the
certificate.

`POST /api/enrol` is the fourth and last route outside the authenticated
middleware, alongside the three sign-in routes. A device redeeming a token
has no session and no certificate yet, so the token is its whole credential.

### One certificate authority per tenant

Not one for the platform. With a shared root, a Kalesi certificate and an
Arbor certificate would be cryptographically indistinguishable, and the only
thing keeping a device out of the wrong tenant would be a string comparison
on the organisational unit — a string comparison standing in for a trust
boundary. Separate roots mean a Kalesi certificate does not verify against
Arbor's authority at all.

The authority is made lazily, on a tenant's first enrolment, because a key
that exists is a key that has to be protected. Its private key is sealed with
the same `secrets.Sealer` that holds identity provider secrets.

### A request is a request, not a fact

The most important rule in `internal/pki`: everything in a certificate
signing request's subject is **discarded**, and the subject is written here
from what the server already knows.

A CSR asking to be a different device, in a different tenant, with an
organisation of its choosing and `mdm.kalesi.example` as a subject
alternative name, gets back a certificate that says none of those things.
`TestTheRequestedSubjectIsDiscarded` asks for all four at once.
`--break-csrsubject` makes the authority honour what it was asked for, which
is the classic mistake, and proves the test catches it.

Also enforced: proof of possession (the CSR must be signed by the key it
carries), a minimum key strength, client authentication only — never
`ServerAuth`, which would let a device impersonate this platform to another
device on the same network — and `IsCA: false` with the root pinned at path
length zero.

### How a certificate is checked afterwards

By fingerprint, not by chain. Verifying a chain proves a certificate was
signed by a key we hold. Matching the SHA-256 of its DER against
`device_certificates` proves it is byte for byte one we issued, recorded, and
have not revoked, which is strictly more — and it answers revocation from the
same row rather than from a list that has to be published and refreshed.

That is one indexed query per device request. It is a real cost and the
alternative is a cache, but a cache in front of a revocation check is a
window during which a revoked device still works, and the window is the whole
point of revoking.

### Re-enrolment

A machine wiped and rebuilt comes back on the same hardware serial. It keeps
its device row, its history and its audit trail, and **every certificate it
used to hold is revoked**. Two live certificates for one machine would mean a
stolen laptop's credential still worked after its replacement was enrolled.
`--break-reenrol` leaves the old one valid and proves the test catches it.

### Renewal

A device certificate lasts a year. Without renewal the first device enrolled
stops being able to authenticate exactly a year later, and so does every
device after it, one at a time, for the rest of the product's life.

```
POST /api/my/certificate     the device, on the certificate it already holds
```

**What authenticates a renewal is the certificate the device already holds.**
That has three consequences, and the first is the reason the route is shaped
this way:

- **A revoked certificate cannot renew.** Not because renewal checks for
  revocation, but because a revoked certificate cannot reach this code at
  all: `deviceCertTrusted` refuses it during resolution, before any route is
  chosen. A renewal path that authenticated some other way would be a way
  around revocation, and revocation would then be decorative.
  `--break-renewrevoked` makes it one.
- **An expired certificate cannot renew either**, for the same reason. Past
  that point the device must enrol again, which is a person's decision and
  the correct one: a machine nobody has heard from in a year is not a machine
  to quietly re-admit.
- **No enrolment token is involved**, so renewal can never put a device into
  a tenant.

The fingerprint is read from the TLS connection, never from the request body.
A fingerprint in a body is a claim.

#### The window is also the rate limit

Renewal is permitted only in a certificate's **last 30 days**, and that one
rule does two jobs. It gives a device a month of chances, and it stops a
device holding a valid certificate from minting an unbounded number of them —
because a certificate issued today is not inside its own window, so a device
that has just renewed cannot renew again. `--break-renewwindow` removes it.

A device asking early gets `409` with the number of days to wait, not an
error. Asking early is what a clock that is slightly fast produces, and the
agent starts at **25 days** rather than 30 so a device whose clock is a day
out is not refused on its first try every year.

#### The old certificate is not revoked

Revoking it the moment the new one is signed would brick any device that
fails to write the answer to disk: it would be holding a certificate the
server has just refused, with no way to ask for another. Letting it expire
naturally means a device has two valid certificates for at most the renewal
window, once a year — bounded, and recoverable from a failed write.

Revoking a device outright still revokes every certificate it holds, so this
does not weaken that.

The agent matches: it generates a new key, asks, and writes the new key and
certificate **only after the server has answered**. A failure anywhere leaves
the old pair working.

#### Somebody is told when it is not happening

A device that is switched off, or whose agent has stopped, quietly stops
authenticating on the day its certificate expires. Until this existed the
first anyone knew was a device going silent — which looks exactly like a
stolen laptop and gets investigated as one.

A daily sweep raises `certificate.expiring` 45 days out, wider than the
renewal window on purpose: by the time a certificate is inside its window and
has **not** renewed, something is already wrong, and the warning should
arrive while there is still time.

It asks for **devices whose newest valid certificate is running out**, not
for certificates that are running out. A device that renewed last week still
holds an old certificate expiring soon, and warning about that would be a
false alarm every single time — which is how a warning stops being read.

### A new action in the matrix

`device.enrol`, held by Super Admin and IT Admin only. The standing rule is
to reuse an existing path before adding a new one and to write down why when
you do not, so: no existing action covers admitting a device. `devices.view`
is read-only, `policy.change` is about policy, and the wipe actions are about
devices already here. Helpdesk in particular should keep seeing devices while
not being able to admit them, and reusing `policy.change` to get today's
roles would have put a lie in the one table that has to be literally true.

### What enrolment still cannot do

The pieces above are the whole of enrolment that does not need Apple. What
needs it: the signed `.mobileconfig` profile (an MDM payload has to be signed
by a certificate Apple trusts), Automated Device Enrolment through Apple
Business Manager, SCEP, and the check-in protocol itself. Those arrive with
the vendor certificate; none of them changes anything above.

Certificate **renewal** is also not built. Device certificates last a year,
so this is a limit with a date on it rather than a setting.

## Policy

Three positions shape this package, each argued rather than assumed.

### Rules are a fixed catalogue, not an expression language

Every rule a tenant can write is one of seven kinds with a typed value:

```
passcode_required          disk_encryption_required   firewall_required
passcode_min_length        screen_lock_timeout_max    jailbreak_blocked
os_version_min
```

Letting policies carry expressions looks more powerful and costs three
things: a sandbox to defend, an unanswerable question (*what does this policy
actually require?* — resolvable only by running it), and the merge below
becomes undecidable.

**An unknown rule name is refused, not skipped.** A policy saying
`passcode_minimum_length` because someone typed it from memory would
otherwise save, display as a policy, and require nothing at all. Silently
ignoring a key in a security policy means the policy lies, and the lie only
surfaces during an incident. The refusal quotes what was typed and lists what
exists. `--break-unknownrule` makes it skip instead and proves the tests
notice.

### The strictest value wins

When several policies apply to one device, their requirements merge by taking
the most demanding of each. Not the newest, not the highest priority, not the
last one assigned.

This is the classic place MDM products go wrong: an administrator assigns a
loose policy to a group and silently relaxes a strict one already there.
Merging strictly makes that impossible, and makes the result **independent of
the order policies are read in** — the property that stops this being a
source of "it was compliant yesterday" tickets. The order-independence is
tested by shuffling the inputs 200 times and asserting the same answer.

| Rule shape | Stricter means |
|---|---|
| `*_required` | true beats false |
| `passcode_min_length`, `os_version_min` | the higher value |
| `screen_lock_timeout_max` | the lower value |

Each requirement carries the policy and version that asked for it, through
the merge, so a finding can say *Finance v2 requires a passcode of at least
14 characters* rather than *policy*. `--break-merge` makes it last-write-wins.

### Not knowing is not passing

A device that does not report on a rule has failed to demonstrate it. It is
not compliant; it is `state_unknown`, which is its own state and is never
counted as a pass. Every field in the report is a **pointer**, so "did not
say" is a different value from "said false" — without that, an agent with a
bug would either mark a fleet non-compliant or quietly pass it, and both are
worse than saying we do not know.

A stale report is the same thing with a different cause. `MaxReportAge` is
seven days, it is a constant rather than a tenant setting (a tenant who can
raise it can make a silent device look compliant), and it is re-checked **at
read time** — so a console never shows a green row for a laptop last seen in
March. `--break-silence` counts a missing field as a pass.

A failure outranks a missing field: a device with one broken requirement and
one unanswered question is not compliant, not unknown, because we already
know enough to act.

### Enforcement: quarantine, with a brake

Evaluation produces a state and a list of findings. Since this sprint it may
also do one thing: **quarantine** the device, and only that.

Lock and wipe still never happen automatically. They go through the command
pipeline, which requires a named reason, a role permitted to ask, and for
anything irreversible a second person from a different role. Wiring a
compliance signal straight to those would route around the one control a
human cannot be talked past, and the first false positive would wipe a
fleet. Quarantine is different in the one way that matters: a person undoes
it in one click and nothing on the device is erased.

So F9's auto-quarantine is built, under three conditions, each with a test:

1. **A policy asked.** `"on_failure": "quarantine"` in the policy body. The
   default is `"none"`; nothing is enforced unless a tenant says so.
   `--break-optin` quarantines without asking.
2. **The device failed.** `not_compliant` triggers it. `state_unknown` never
   does: not knowing is a reason to look, not a reason to act.
3. **The brake has not tripped.** If more than 5% of the fleet (and always at
   least four devices) is failing, nothing is quarantined. The brake is
   measured twice: over the whole fleet, and over the devices each asking
   policy actually covers, because five of five iPads failing is 2.4% of two
   hundred laptops and 100% of what the policy is about. Either measure
   tripping halts, and the halt names the population it measured.
   `--break-scopedbrake` measures the fleet only. An
   `enforcement.halted` notification goes out once per hour and an audit
   record is written, because a failure that wide is far more likely a
   policy change or an agent fault than a fleet gone bad at once. This is
   standing directive 1 ("halt rather than continue silently") applied to
   enforcement, and `--break-brake` removes it: sixty devices failing at
   once become sixty devices quarantined at once, and the test sees it.

There is no grace period, by standing directive 6. The rule fires on the
report that fails, or it does not exist.

**Release is a person's act.** The device page shows who quarantined it (a
person, or `policy:Baseline v3`) and why, and offers "Release from
quarantine" to the roles that may lock a device in an emergency: the people
who may act on a device in a hurry are the people who may say the hurry is
over. A released device is `state_unknown`, not `compliant`, because nothing
has been checked since; its next report decides. The database trigger from
the policy sprint still refuses to move a quarantined device by evaluation;
it lets the move through only when the transaction has set `app.release`,
which `data.ReleaseQuarantine` does and nothing else does.
`--break-releasepath` forgets the setting and the trigger refuses the
release.

**Network-access revocation**, the other half of F9, is built on both
sides. On the device: the agent learns its own state on every report
(`device_state` in the verdict) and a quarantined agent asks its enforcer to
act on `quarantine`; the bundled enforcers do nothing with it, and an
operator's `ScriptEnforcer` drops the VPN or the corporate Wi-Fi profile.
On the network: the access feed below, which is how a Wi-Fi controller,
VPN concentrator, ZTNA gateway or NAC actually revokes access, by asking the
device-management platform before admitting a device.

### The network access feed

```
GET /api/network/access/<serial>     {"serial": …, "access": "allow"|"deny", "state": …, "reason": …, "since": …}
GET /api/network/access/mac/<mac>    the same, by the address the device authenticated with
GET /api/network/denied              {"denied": [...], "as_of": …}
GET /ciscoise/mdminfo                Cisco ISE's MDM API v2, see below
GET /ciscoise/mdmapi?querycriteria=macaddress&value=<mac>
Authorization: Bearer mdm_net_…      or HTTP Basic with the token as the password
```

**By MAC address** (0039), because that is what a network access control
has: the address the device authenticated with, not its serial. The agent
reports its network cards' hardware addresses with every report (physical
interfaces only, as far as a name can tell; a container runtime's or a
VPN's virtual adapters carry addresses no switch will see), the platform
keeps them per device, and the door answers by any of them, written any of
the ways equipment writes a MAC (`3c:22:fb:aa:bb:01`, `3C-22-FB-AA-BB-01`,
`3c22.fbaa.bb01`, bare digits). One address belongs to one device per
tenant, and a report does not simply take one another device holds: a
report is the device's own word, and a word that could move a clean
laptop's address onto a quarantined one would let the quarantined one
borrow the clean one's answer at the door. The address moves only when its
holder has let go of it, which is retired, or compliant and quiet for
longer than the engine tolerates. Never from a device in quarantine, and
never from one whose last word was a failure or nothing: the door denies
such a device, and letting its address move to a clean claimant would turn
that deny into an allow for whoever still carries the address. A holder
that keeps it has the claim written down (`device.mac_contested`).
The honest case, a dock moved between laptops, needs no contest: the first
laptop's next report no longer lists the dock, the row goes, and the second
laptop's claim lands on nothing. `--break-macmove` leaves an address with a
holder that has let go, and the test sees the second laptop answered for by
the first. `--break-macnormalise` matches the address only as written and
the Cisco form stops answering. The compliance report (CSV and PDF) names
who holds each device and its addresses.

**Cisco ISE** is answered in the shape of its MDM API version 2
(`internal/gateway/ise.go`): ISE is given this platform's hostname and an
integration token as the password of an HTTP Basic credential, calls
`mdminfo` once, then `mdmapi` with each authenticating device's MAC, and
reads compliance out of the XML. Compliant is the door's allow; the
failure reason is the door's reason, then the first finding. The booleans
the device did not report are absent from the XML rather than false, so
ISE reads them as unknown. An address no device reported comes back
registered false, which ISE reads as "not enrolled here". The product
named in `mdminfo` is the tenant's own brand, never the operator's. Built
to Cisco's published shape and held to it by the tests; it has not yet
been run against an ISE. `--break-isecompliance` tells ISE every
registered device is compliant and the test notices.

**Deny** means one of two things. The platform has put the device
somewhere a person must get it out of: `quarantined` (by a person, or by a
policy under F9) or `retired`. Or the device has not shown it is clean: it
has never reported, its last clean report is older than the engine's seven
days, or it was just released from quarantine and has not reported since
(ruling 2026-11-04: deny unknown until it reports clean). The rule the
engine applies everywhere, that not knowing is never a pass, applies at the
door as well, and `--break-feedunknown` makes the door forget it. Two things
deliberately do not deny. A `not_compliant` verdict
alone does not, because if a tenant wants failing devices kept off the
network that is exactly what `"on_failure": "quarantine"` means, and then
they are. A lost report does not, because the lost report executes nothing
by design and a lost device still on the network is one that can still be
located and locked. A serial the tenant does not manage is `404` with
`"access": "unknown"`: the network's own policy decides what an unmanaged
device gets, and we do not say allow for a device we have never seen.
`--break-feeddeny` makes the feed allow a quarantined device.

**The credential** is an integration token, minted by a Super Admin on the
Sign-in page (it is access control, so it sits with the role map), named
for the equipment that holds it, shown once on the page itself rather than
through a redirect, and stored as its SHA-256. It resolves to the `network`
role, which holds `network.read` and nothing else: a token that tries
`/api/devices` is refused, and `--break-networkrole` gives it the device
list and both the matrix transcription test and the feed test notice. A
token minted by tenant A is looked up in tenant B's rows when presented at
tenant B's hostname, and is not there. Revocation is a timestamp on the
row, checked on every request; `--break-tokenrevoked` ignores it. The page
shows when each token last asked, so a dead integration is visible.

Why a new table and a new role (SD 10, written in `0017_network.sql`): no
existing credential fits a machine that is not a device. A device
certificate names one device; a session is a person; the development
bearer identities are development only. A network controller is a tenant's
machine that needs one bit per device, for years, with nobody at a
keyboard.

**The push** rides on the channels the tenant already has: `device.quarantined`
and the new `device.released` go to the tenant's webhook or email like any
other topic, so a controller that accepts webhooks hears within seconds. The
feed is the source of truth between pushes.

### An administrative hold is not undone by a good report

A device that is `quarantined` or `retired` was put there by a person. A
cheerful report from a laptop that has just been wiped must not release it.
Evaluation may only move a device between the three states it owns —
`compliant`, `not_compliant`, `state_unknown` — and the verdict is still
recorded honestly on the compliance row either way.

Enforced twice: in Go, which skips the update, and in a database trigger,
which refuses it. `--break-quarantine` removes the Go half and the trigger
catches it, which is the defence in depth working rather than a redundancy.

### Staged rollout

F7. A policy name may have two active versions: the live one, for every
device its scope covers, and a rolling one, for a stage: the devices
carrying a tag, a percentage of the rest chosen by a stable hash of the
device id, or both. "Promote to everyone" makes the stage live; "Withdraw
the stage" halts it and the live version stands. A device's share is
decided from its id, so a stage widens rather than shuffles: a device in
the 25% is still in the 50%, and the same device gets the same answer on
every report (`--break-rolloutshuffle` makes it flip; `--break-rolloutall`
puts every device in every stage). Tags are the groups: plain words on the
device row, set from the device page by whoever may change policy. A policy
delivered enterprise-wide to Google is the live merge; a stage reaches
Android devices when it is promoted.

### Policies are versioned, never edited, and rolled back forward

Rollback (F6) restores an earlier version as a NEW version with that
version's body and scope: "v4, restored from v2", with v2 untouched. A
verdict reached against v2 still names v2 and can still be explained.
`--break-rollbackinplace` switches the old row back on instead, and the test
that counts versions sees history fold. Templates (F5) are starting points
in `policy.Templates`: four of them, each held by a test to parse under the
same `Parse` as a typed body, each filling the form and creating nothing
until it is saved under the person's own name.


Saving writes a new version and switches the previous one off; a partial
unique index allows only one live version per name. A verdict reached last
month was reached against a particular set of requirements, and if those can
be rewritten underneath it then the verdict cannot be explained afterwards.
Superseded versions stay in the table and on the page, because "what did we
require in March" should be answerable from the row rather than from a backup.

### The loop

```
POST /api/devices/{id}/report     the device, on its own certificate
GET  /api/devices/{id}/compliance the verdict, with the reasons
GET  /api/devices/{id}/policy     what this device is being held to
GET  /api/policies                live and superseded          (devices.view)
POST /api/policies                a new version                (policy.change)
POST /api/policies/{name}/retire                               (policy.change)
```

A device reports on itself and nothing else: the route is reachable only on
the device certificate path, and only for the device that certificate names.
An administrator posting a report on a device's behalf would make every
verdict deniable, and a fleet is only evidence if the evidence comes from the
machines.

The verdict becomes the device's own `state`, so the dashboard and device
list reflect compliance without a second count that could disagree with the
first.

### What policy still cannot do

**Nothing is delivered to a device by the server.** The engine decides what
is required and whether it is met; pushing a configuration payload needs
Apple's profile payloads and Declarative Device Management, Android's
managed configurations, or Windows CSPs, none of which this half does. What
it does do, when a policy carries `"remediate": true`, is mark each failed
finding for the device to put right itself, with the number the rule asks
for; the agent's native enforcer acts on the marks (below, under the agent).
Without that key a policy judges and nothing on any device changes.

**Scope is two fields**, operating system and ownership. Device groups and
tags are the obvious next want and are deliberately absent: the moment
scoping becomes expressive, "what does this laptop actually have to do"
stops being answerable without running the engine.

**History is by change, not by report** (0041). `device_compliance` still
holds one row per device, the latest report and verdict; beside it
`device_compliance_history` gets a row each time the verdict CHANGES (the
state, or which rules fail or cannot be read), written in the same
transaction from the same evaluation, so a device saying the same thing
every quarter of an hour adds nothing and the report that changed the
answer adds one row. The device page shows the changes and
`/api/devices/{id}/compliance/history` returns them, newest first;
`--break-historychange` writes a row per report and the test counts them.
The fleet's trend is a daily snapshot of the dashboard's own counts
(`compliance_snapshots`, taken by the gateway under a tenant claim at start
and once a day, replaced within the day by the later reading), drawn on
the dashboard as one line of the compliant share over thirty days with the
days as a table beneath it, and served by `/api/compliance/trend`. It is
its own job rather than a line in the usage snapshot because that job runs
on the operator's pool, whose role may not read devices and is not given
the right to for a count. `--break-trendcount` counts something else and
the test sees the board and the trend disagree.

**Templates** (F5) are starting points, not policies: nothing exists until
one is saved under the person's own name and scope. Eight ship, and
together they address every operating system and ownership the engine
scopes (`policy.TemplateCoverage`, held to by a test): a baseline for
everything, company laptops, phones quarantined on failure, personal
devices with a work profile, executive and finance Macs, company Windows
PCs, Android work devices, and shared field devices. Each parses with the
same code as a typed policy and says in a sentence why it exists.
`--break-templates` drops the Android one and the coverage test notices.

## The device agent

`internal/agent` is the half of this platform that runs on the managed
machine, and `cmd/agent` is the binary.

```
agent -server https://mdm.kalesi.example -dir /var/lib/mdm enrol -token XXXX
agent -server https://mdm.kalesi.example -dir /var/lib/mdm run
agent -server ... -dir ... once      # one cycle, for a launchd or systemd timer
```

### The escalation this sprint found

Before writing a line of the agent I checked what a device certificate was
actually allowed to do. Since the gateway sprint, `resolve` had been handing
every device certificate `authz.ITAdmin`. Reproduced, with the old code:

```
a device certificate could enumerate the fleet:        200
a device certificate could lock another device:        202
a device certificate could wipe another device:        202
a device certificate could rewrite the policy:         201
a device certificate could invite a device:            201
a device certificate could read the audit log:         200
a device certificate could read the whole queue:       200
```

**One stolen laptop could have wiped the fleet.** A device certificate lives
on a machine that can be stolen, handed to a repair shop, or rooted by the
person carrying it, so what it may do has to be the shortest list in the
product.

There is now an `authz.Device` role holding `devices.view_own` and nothing
else, and three routes a device can reach: report on itself, read its own
queue, acknowledge its own work. Each handler narrows that further to the one
device its certificate names. `--break-devicerole` puts `it_admin` back, and
it is the most important control in the build.

`GET /api/my/commands` is a route of its own rather than a filter on the
administrator's listing. That listing is unscoped by design — an IT admin
looks at the tenant's whole queue — and bolting a conditional scope onto it
would mean one missed branch is a fleet-wide leak of who is being wiped and
why. Here there is no branch to miss.

### A push notification is a wake-up, not a delivery

Worth stating plainly, because it decides how much of this waits on Apple:
**APNs carries no payload worth acting on.** Neither do Google's or
Microsoft's. The notification tells a device to check in; the instruction
travels over the device's own authenticated connection.

So the loop closes today. The one-time code is minted when a command is
requested, and it reaches the device over mutual TLS, in a response type the
administrator's listing does not share. The push provider, when the vendor
certificate arrives, makes the loop **timely** rather than possible — without
it a device learns of an instruction at its next scheduled check-in instead
of within seconds.

### The key never leaves the device

Generated on the machine, written `0600`, and only a certificate signing
request is ever transmitted. `TestThePrivateKeyNeverLeavesTheDevice` records
every request body the agent sends and asserts no private key material
appears in any of them, then checks the file mode on disk.

Enrolment holds everything in memory until the server has answered, and only
then writes. A failed enrolment leaves no key on disk, so a retry with a good
token works cleanly rather than looking half enrolled.

### The agent reports facts; the server judges

No policy is evaluated on the device and none is stored there. A machine that
has been tampered with cannot be made compliant by editing a local rule file,
because there is no local rule file.

What it **can** do is lie about what it sees. That is inherent to
agent-based compliance rather than a defect of this design, and the answer is
hardware attestation — Apple's managed device attestation, Android's Play
Integrity — which is listed as not built.

### Anything it cannot determine is left unsaid

Every field in the report is a pointer, and a probe that cannot read a
setting returns nil. `HostProbe` establishes the operating system family and
version, the hostname and the hardware serial, and then asks the platform's
own tools about the rest (`internal/agent/native.go`): on a Mac, `fdesetup`
for FileVault, `socketfilterfw` for the firewall, `csrutil` for System
Integrity Protection (off is reported as jailbroken), `pwpolicy` for the
enforced minimum password length, the console user's directory record for
whether a password is set, and that user's screensaver idle time plus lock
delay for the screen lock; on Windows, `manage-bde` for BitLocker, `net
accounts` for the password length, the machine inactivity-timeout policy
for the lock, and `netsh advfirewall` for the firewall, which counts as on
only when every profile is on; on Linux, `lsblk` for an encrypted volume,
`ufw` or `firewall-cmd`, and `pwquality.conf`. The passcode length is the
enforced minimum: no person's actual password is ever read. A lock that is
switched off reports zero, which the engine reads as "never locks" and
fails. A tool that is missing, refuses to run, or prints something this
build does not recognise leaves its field nil.

This lands exactly where the policy engine already was: silence is
`state_unknown` and never a pass. An agent on a half-supported platform
therefore produces an honest "we do not know" rather than a fleet of green
rows. `HostProbe.Overrides` lets a deployment fill in what it can read from
elsewhere, and whatever it does not fill in stays unsaid. Every reader is a
pure function over the tool's text, and the tests hold them to the text
real machines print, through a runner that answers from a table: a Mac is
read, on Linux, from what a Mac says.

### Work that failed is not acknowledged

Acknowledgement is the only state the console reports as done, so an
instruction the agent could not carry out stays outstanding. The shipped
enforcer is `Native`, the platform's own tools in front of a fallback: a
lock suspends the console session on a Mac (`CGSession -suspend` as the
person at the keyboard), disconnects the active session on Windows
(`tsdiscon`), and locks every session on Linux (`loginctl`). A wipe is
never native, because there is no undoing a wrong one: it goes to the
fallback, which is `ScriptEnforcer` when the operator has installed a
helper and otherwise `NotConfigured`, which names what is missing — the
same shape as the server's `AppleNotConfigured` — and returns an error, so
nothing is silently marked complete. Nothing the server sends ever reaches
a shell: the helper map is keyed by instruction kind and an unknown kind is
refused, and the native tools are run by path with fixed arguments.

### The agent puts things right when a policy asks

A policy that says `"remediate": true` asks the devices it covers to put
their own failures right. The server marks each failed finding (`fix`) and
carries the number the rule asks for (`num`); the agent acts on the marks
and on nothing else, and then reports again in the same cycle so the
console shows the fix within the minute. Three things are never acted on: a
finding the policy did not mark, because a tenant that only wants to
observe must never find its fleet's settings changed; a finding that could
not be read, because a setting the agent cannot see is not one it should
change; and, when two policies ask for the same rule, the number from a
policy that did not ask for remediation, because the mark travels with the
requirement that wins the merge rather than being inherited from the loser.

What is put right, by platform: the firewall on (`socketfilterfw`, `netsh
advfirewall`, `ufw`); disk encryption started (`fdesetup enable -defer`,
which enables FileVault at the next login and writes the recovery key to
the escrow file then, and `manage-bde -on` with a recovery password, which
is written to the escrow file now and encrypts in the background); the
minimum password length (`pwpolicy -setaccountpolicies` from a plist this
process writes, `net accounts /minpwlen`); and the screen lock (the
screensaver idle time as the person at the keyboard on a Mac, the machine
inactivity-timeout policy on Windows). The deferred ones come back as
`ErrDeferred`, which is neither done nor failed, so they are not counted
and not asked twice: a FileVault deferral already active, or a BitLocker
conversion in progress, is recognised and left to finish. What is not put
right is said by name: a passcode is chosen by a person, an operating
system is updated by its own updater, a Mac with its protections off is
reinstalled, and on a Mac the delay between screensaver and password prompt
is the person's own setting and needs their password to change, so only the
idle time is set and the next report says what the two add up to.

Only a number ever reaches a command line, and it is checked first: a
password length is 1 to 64, a lock timeout is 1 to 86400 seconds, and
anything else is refused before any tool runs. The sentences in a finding
(the rule, what the device said, which policy asked) are never arguments.
`--break-remediate` marks every failure regardless of what the policy said
and two tests notice, one in the engine and one end to end;
`--break-nativebounds` lets any number through and the refusal test
notices. The binary runs this by default; `-native=false` makes it report
only.

### The first end-to-end test

`internal/agent/agent_test.go` is the only place in the build where the
**whole stack** runs: a real agent, over real TLS, presenting a real client
certificate, against the real gateway and a real PostgreSQL.

Everything before this sprint tested the device path by setting `r.TLS` on a
synthetic request. That proved the handler logic and proved nothing about
whether a certificate this platform issues is one a Go TLS client can present
and a Go TLS server can read. It is, and this is where that is established —
along with the privilege boundary above, because a boundary that only holds
for synthetic requests is not one.

### Installing it

```bash
./build_agent.sh                                   # five platforms into ./dist
echo "$TOKEN" | sudo ./packaging/install.sh --server https://mdm.kalesi.example
```

Five binaries: macOS on Intel and Apple silicon, Linux on both, Windows on
amd64. `CGO_ENABLED=0` throughout, which is why one machine can build all of
them — a cgo dependency would mean a build machine per platform, and that is
the reason the agent has no cgo in it.

The cross-compile earns its place immediately: the first run failed on
`syscall.Stat_t`, which does not exist on Windows. Building only for the
machine this was written on would have shipped that.

#### The token must not reach the command line

**There is no `-token` flag.** There was one until this sprint, and it was
wrong.

An enrolment token is a bearer credential: whoever holds it can enrol a
device into the tenant. On Linux and macOS the full argument list of every
process is readable by **every local user** through `ps`. So
`agent enrol -token XXXX` hands it to anybody with a shell on the machine
for as long as the command runs — and enrolment is the one command somebody
types by hand, as root, from an install script.

It is read from standard input, or from a file that nobody else can read:

```bash
echo "$TOKEN" | agent ... enrol
agent ... -token-file /root/token enrol     # refused unless mode 600
```

`--break-tokenfile` accepts a readable file again. There is also a test that
fails if `flag.String("token"` reappears in `cmd/agent`, because a security
fix with nothing stopping its reversal is a security fix with a half-life.

#### The agent runs as root, so what it runs from matters

It has to run as root: locking and wiping are privileged. That makes the
binary, the helper scripts and **the directories on the way to them** a path
to root for anybody who can write to them. A file that is group-writable is
not a configuration preference at that point — it is a local privilege
escalation with a service unit pointing at it.

Nothing the agent does at runtime would notice, so `agent doctor` checks it:

```
PROBLEM  /var/lib/mdm-agent
         the state directory is mode 0755, so other users can reach this
         device's private key
         fix: chmod 700 /var/lib/mdm-agent
```

It checks the state directory, the private key, the binary, each helper, the
service definition, and the directories holding them — and exits non-zero on
anything serious, so the install script fails loudly. The sticky bit is
understood, because reporting `/tmp` as writable is a false alarm an
administrator learns to ignore. `--break-doctor` stops it noticing a
replaceable binary.

#### The service definitions

**launchd**, a LaunchDaemon rather than a LaunchAgent: a LaunchAgent runs as
the logged-in person and stops at logout, which would make compliance
reporting depend on somebody being at the machine. `KeepAlive` with
`SuccessfulExit false`, so a crash restarts and a clean exit is left alone —
an agent that stopped because its certificate was revoked should not be
restarted into a loop. launchd itself **refuses** a plist that is group or
world writable, which the install script sets correctly and which is worth
knowing before an install silently does nothing.

**systemd**, with the hardening that actually narrows what root means here:
`ProtectSystem=strict` with `ReadWritePaths` naming only the state directory
and the log, `NoNewPrivileges`, `MemoryDenyWriteExecute`, a syscall filter.
Those apply to the helper scripts too, and a helper that needs something back
should get a narrowed exception rather than the hardening deleted.

#### The uninstaller says what it did not do

An uninstaller that quietly leaves a device enrolled is how a fleet ends up
with records of machines nobody can reach. So it prints, in words:

- the device is **still enrolled** and its certificate is still valid.
  Revoking is a console action, deliberately — a machine that can uninstall
  its own agent must not be able to delete its own record
- **nothing was un-enforced**. Removing the agent removes the reporting, not
  the configuration

#### Windows is honestly labelled

`packaging/windows/install.ps1` registers a **scheduled task running as
SYSTEM, not a Windows service**. A service needs the service control manager
plumbing, which is not built, and the difference matters: a task does not
restart the way a service does and does not appear where an administrator
looks. `agent doctor` reports that its permission checks are not implemented
on Windows rather than returning a clean bill of health that means nothing.

Enough to run a pilot, not enough to ship, and the script says so at the top.

#### Nothing is signed

`SHA256SUMS` sits beside the binaries, which proves a copy was not corrupted
and nothing else. macOS will quarantine an unsigned, un-notarised binary
downloaded through a browser; copying it with `scp` or delivering it from an
MDM payload avoids that, which is what the install script assumes. Proper
signing needs an Apple Developer ID and, on Windows, an Authenticode
certificate — **neither of which is the same application as the MDM vendor
certificate that is already outstanding.**

### What the agent still cannot do

**It cannot wipe, or clear a passcode, by itself.** A lock is native and so
are the four settings a policy can ask to have put right, but a wipe is a
privileged, irreversible platform call: on Apple hardware it arrives as an
MDM payload and needs the vendor certificate; elsewhere it needs the helper
an operator installs. `ScriptEnforcer` is the honest seam for it.

**It is not code signed.** See above; it needs a Developer ID and an
Authenticode certificate.

**Windows gets a scheduled task, not a service.**

**It cannot prove it is telling the truth.** See attestation, above.

## The employee page

`/me` is what the person carrying the device sees. It has been a hole since
the console sprint: the `employee` role has held `devices.view_own` since the
first migration and there was nothing to view, because **nothing linked a
person to a device.** A tenant's devices were a flat list.

### The link is made at enrolment

That is the only moment anyone knows. An administrator invites a device *for
someone*, and the device inherits the assignment when it redeems the
invitation. By the time a machine is reporting, nothing on it says whose desk
it is on.

`assigned_to` is what was typed, and beside it since 0040 is `person_id`:
the key to a person the platform has met (`internal/data/people.go`). This
is still not a directory. A tenant's people live at its identity provider,
and a row here appears only when the platform actually meets someone: they
sign in (their subject, the identifier a provider never reuses, with the
address and name the provider sent), an administrator assigns a device to
an address (a row with the address and no subject yet, which becomes theirs
at their first sign-in), or HR says someone has left. The row stays when
they leave, marked left, with who said so; their subject and address are
then free, so the next hire with the same address is a new row and inherits
nothing. That is the limit 0009 wrote down, closed: `--break-emailreuse`
lets a leaver's row answer for the address again and the test sees the new
hire shown the leaver's laptop. The People page lists everyone met with
their devices and whether they have left; a person's page offboards
everything they hold. Offboarding marks the person left (`--break-leftmark`
forgets to), and HR naming a stranger is kept once as a leaver, so a device
assigned to that address afterwards is a new person's.

This is also why `tenantclaim.Claim` gained an `Email` field — the one
attribute of a person the data layer needs, and the line the claim's
"deliberately small" rule is drawn at.

### Two controls, since 0042

Tenant isolation has **two** independent controls: the repository
functions, and row-level security that would refuse a cross-tenant read
even if the Go were wrong.

Person isolation inside a tenant had **one**, because row-level security
could not tell an employee from an administrator: both are the same
database role, and a policy strong enough to stop the one would stop the
other. Since 0042 the claim's role, subject and email reach the
transaction beside the tenant (`set_config` in `data.WithTenant`), and a
restrictive policy on `devices` and on `device_compliance` holds an
employee's transaction to the devices of the person it belongs to
(`app.current_person()`, the same clause `data.activePerson` uses) and is
true for every other role. The predicate in `data.MyDevices` remains the
first control, and the only one for an administrator reading their own
page. One consequence surfaced at once: the gateway's own transactions
(resolving a device certificate, redeeming an enrolment, reading a brand
or a role map before anyone is signed in) had been minted as employee,
the role that "can do almost nothing", and the moment the database gave
employee a meaning, a transaction that was nobody's could see no device
and no enrolment completed. They are now `authz.Bootstrap`, a role with no
permissions in the matrix and no person behind it, which is what they
always were.

So it is built the way the tenant scoping is built — the person comes from
the verified claim, never from an argument:

```go
func MyDevices(ctx context.Context, tx *Tx) ([]Device, error)
func MyDevice(ctx context.Context, tx *Tx, id uuid.UUID) (Device, error)
func ReportMyDeviceLost(ctx context.Context, tx *Tx, id uuid.UUID, note string) (Device, error)
```

There is no signature there a caller could pass someone else's identity to,
and no identifier on `/me` or `/api/me/devices` that could be changed to a
colleague's. `--break-mine` removes the predicate and proves the tests catch
it.

`person_id IS NOT NULL` is load-bearing: without it a caller with no person
behind it — a device certificate — would match every device nobody has been
given. The person is resolved by the same clause everywhere (`activePerson`):
the active row with this subject, or, for someone who has not signed in
yet, the active row with this address.

### Reporting a device lost executes nothing

The one write an employee can make. It raises a flag an administrator sees,
and that is all: no lock, no wipe, no wake-up.

The reason is the policy engine's reason. Locking and wiping go through the
command pipeline, which needs a named reason, a role permitted to ask, and
for anything irreversible a second person from a different role. A button on
the most junior page in the product must not reach past all of that.

What it buys is the eleven-o'clock-at-night case: someone's laptop is gone
and the person who knows cannot reach the help desk until morning. The flag
is on the device the moment they press it; the decision is still a person's
in the morning.

Standing the report down is an administrator's, not the holder's: someone
phished into reporting a laptop lost should not also be the one who can
quietly clear it. Pressing the button twice does not move the timestamp,
because when it was first reported is the fact anyone investigating wants.

### An employee lands somewhere they can actually go

`GET /` used to hand an employee a 403 on the front page, which is a product
that looks broken rather than one working correctly. It now redirects to
`/me` when the role cannot read the fleet. The dashboard is still guarded;
only the choice between two guarded pages moved.

The page itself is written for someone who does not work in IT: *what to do*
beside *how it is set now*, no jargon, and an explicit sentence saying that
reporting a device lost erases nothing.

### A control that failed, and what it found

`--break-lostowner` **failed** on its first run: the tests passed with the
ownership check removed. The cause was not the test — it was the code. The
re-read at the end of `ReportMyDeviceLost` also goes through `MyDevice`, so
the write landed and was then rolled back by the error from that second
read.

The protection was holding by accident rather than by design. The control now
patches both call sites, which is the only version of it that proves
anything. This is the whole argument for negative controls in one incident:
the suite was green, the behaviour was correct, and the reason it was correct
was not the reason anyone would have given.

## Notifications

### Two claims the product was making and not keeping

This sprint started by checking one line. Since the pipeline sprint the
console has answered a tripped bulk-wipe limiter with:

> your queue is paused and the Security Manager has been told

Nothing in the platform told anyone. **A product that says a control fired
when it did not is worse than one without the control**, because the person
reading that line stops looking.

Checking that turned up a second one in the same family. R1 requires the
limiter to record the refused attempt, and `internal/command` does write the
refusal row and audit it. Over HTTP it did not survive: `Request` returns
`ErrLimiterTripped`, the handler returned that error out of `WithTenant`, and
**the transaction rolled back, taking the refusal record with it.** The unit
test passed throughout, because it held its own transaction open. The
end-to-end test is `TestTheLimitersRefusalSurvivesTheRequestThatCausedIt` and
`--break-refusal` puts the defect back.

Both are fixed, and the refusal, its audit entry and its notification now
commit together or not at all.

### The outbox

A notification is written **in the same transaction as the event**, and
delivered afterwards by a worker. `Enqueue` takes the caller's transaction
for exactly that reason, and nothing in the package sends anything inline.

| | |
|---|---|
| Nothing is lost | the row commits with the event or neither does |
| Nothing is blocked | a wipe request does not fail because chat is down |
| Nothing is invented | there is no message without its event |

Calling a webhook inline fails all three: a slow endpoint holds the request
open, a failing one either loses the message or rolls back a legitimate wipe,
and a retry after commit can tell somebody about an event that was then
rolled back.

Retries double from 30 seconds and give up after five attempts. A fleet of
gateways hammering a recovering endpoint every 30 seconds is a second outage
caused by the first.

### It does not resolve people

Sending to "everyone who may approve a wipe" would mean holding a directory
of a tenant's staff and their roles, and this platform holds neither. A
tenant points a topic at a channel their team already watches, which is also
how operations teams work.

```
device.lost          someone reports a device they hold as lost
approval.waiting     a command is waiting for a second person
limiter.tripped      the bulk-wipe limiter pauses a queue
device.wiped         a wipe is acknowledged by the device
enrolment.completed  a new device finishes enrolling
```

A reversible command raises nothing: it needed no second person, so there is
nothing waiting and a message would be noise. **A channel that fills with
noise is a channel people mute, and a muted channel is worse than none
because it looks covered.**

### An event that reached nobody is visible

`Enqueue` deliberately does not check whether a target exists. A tenant who
has configured nothing still produces the record, and the worker marks it
`undeliverable` with the reason. Failures are audited too, so *were we told?*
is answerable from the tenant's own record. Believing you were told when you
were not is the worst outcome this package has.

### The webhook endpoint is a risk handed to us on a form

A tenant administrator supplies the address, and this platform then makes a
request to it **from inside its own network**. Pointing it at the cloud
metadata service, or at a database on the internal network, is a tenant
asking our server to fetch something they cannot reach themselves.

So the address is checked at **dial time, after DNS**, not by looking at the
URL. Checking the hostname is not enough: a name that resolves to a public
address when it is saved and to `169.254.169.254` when it is called is a
thirty-second attack, and the URL still looks fine. Redirects go through the
same dialler, so a redirect inside is refused by the same check.

The stored address is sealed and never shown back. Anyone holding a chat
webhook URL can post into that channel as the integration, so a settings page
that prints it hands it to anyone who can read the page.

### Two controls that failed, and the weak tests they found

`--break-ssrf` and `--break-dedupe` both **passed with their protection
removed** on the first run. Neither was a flaw in the control.

The SSRF test pointed at `169.254.169.254` and asserted nothing arrived. That
proves those addresses are *unreachable from a test container*, not that the
guard works — it would pass either way. It now points at the test's own chat
server on `127.0.0.1`, which is private **and reachable**, and asserts zero
messages arrive. Plus a direct table of the ranges, because a missed range
only matters on the day somebody points a webhook at it.

The dedupe control patched away `ON CONFLICT DO NOTHING`, which makes the
unique index raise instead — the count stayed at one for entirely the wrong
reason. It now gives every message its own key, which is the failure a
careless edit would actually produce.

That is twice in two sprints that a control has caught a test proving
something other than what it claimed.

### Email

```
MDM_SMTP_SERVER    mail.example.com:587
MDM_SMTP_FROM      notifications@example.com
MDM_SMTP_SECURITY  starttls | tls | none     (default starttls)
MDM_SMTP_USERNAME  optional
MDM_SMTP_PASSWORD  optional
```

A deployment with no `MDM_SMTP_SERVER` has **no email channel at all**, and
an email target is refused by name rather than accepted and silently
delivered nowhere.

**The split that matters.** A tenant configures WHO is written to. The
operator configures HOW mail leaves. That is not tidiness: a tenant-supplied
*webhook* address is a request this platform makes from inside its own
network, which is why that one is checked at dial time; a tenant-supplied
*email* address is not, because nothing here connects to it. The two look
identical on the settings form and are not the same risk.

#### Header injection is the risk email brings

An address field containing a newline is not a malformed address, it is extra
headers:

```
security@kalesi.example\r\nBcc: attacker@elsewhere.example
```

Written into a message, that is a silent copy of every notification to
somebody else, configured through a form field by anyone who can reach the
settings page. Every value that reaches a header goes through
`checkHeaderValue` first — the whole input, before anything tries to parse it,
because a check that runs after a parse is one a parser can be talked around.
It is refused **at save time**, so somebody who mistypes is told on the form
rather than by a delivery that failed an hour later.

`--break-headers` removes it.

#### The transport

STARTTLS by default, and a server that has been configured for it and does
not offer it is **refused rather than downgraded** — whether that is a
misconfiguration or somebody in the middle stripping the capability.

A password is never handed to an unencrypted connection, even if the mail
would arrive. That failure is silent precisely because the mail arrives.
`--break-cleartext` removes it.

Worth noting what has no negative control: the STARTTLS downgrade refusal.
Removing the check does not produce an unencrypted send, it produces a failed
`StartTLS` call, because the protection is structural rather than a guard
that can be deleted. A control there would prove nothing, so there is not one.

#### Testing against a real SMTP server

`internal/notify/smtptest` speaks the protocol: greeting, EHLO, STARTTLS,
AUTH, MAIL FROM, RCPT TO, DATA terminated by a lone full stop, QUIT.

A fake channel that records what it was handed would prove the calling code
ran and nothing about the thing that matters. For email that thing is the
**envelope** — the addresses the server was told to deliver to — which is a
different list from the `To` header. Header injection is exactly the case
where the two diverge, and only a server that speaks the protocol can tell
them apart.

#### Details that are easy to get wrong

- **The sender wears the tenant's name.** T12 reaches the inbox: a message
  landing in a tenant's staff inbox is as tenant-facing as a page.
- **Non-ASCII subjects are RFC 2047 encoded.** A device name with an accent
  would otherwise go out as raw bytes in a header, which some servers reject
  and others mangle.
- **Dot-stuffing.** A line in the body that is a single full stop ends the
  DATA command, so a message containing one would be truncated there and the
  rest fed to the server as commands.
- **`Auto-Submitted: auto-generated`,** so a holiday auto-reply does not
  bounce back at the platform forever.
- **At most ten recipients.** A target is a mailbox or a small list; a form
  that accepts two hundred addresses is one somebody will paste a leaked list
  into.
- **An email address is shown in full**, unlike a webhook URL. It is not a
  credential, and hiding it would stop an administrator noticing that
  notifications have been going to somebody who left — the thing most worth
  noticing on that page.

#### Sending as the tenant's own domain

Mail used to leave with a From the tenant chose and no signature, so a
message claiming to be from `security@kalesi.example` failed SPF and carried
no DKIM at all. At a customer running DMARC with `p=reject` that mail does
not arrive; at one running `p=none` it lands in a spam folder and nobody
reads the notification about their stolen laptop.

**The control: nothing signs mail as a domain until the tenant has proven
they control it, and the proof is the DKIM record itself.** This platform
generates the key, the tenant publishes the public half in their own DNS, and
we look it up. Publishing at `mdm._domainkey.theirdomain` requires control of
that zone.

Without that check, a form field would let any tenant have this platform sign
mail as any domain in the world. That is a phishing service with an enrolment
flow. `--break-dnsproof` removes it.

The check compares the **key**, not the presence of a record. A record that
exists but carries somebody else's key is not proof of anything — it is what
a tenant would have if they pointed us at a domain already running DKIM for a
different service.

```
POST /api/sending-domains                    claim it, get a key
POST /api/sending-domains/{domain}/verify    prove it
```

Re-registering generates a new key and **clears the proof**, because whatever
was verified before was verified against a key that no longer signs anything.

#### Alignment is the point, not the signature

A valid signature as one domain on a message sent from another aligns with
nothing and fails DMARC anyway. So the From header becomes the tenant's
address whenever a verified domain exists, and `d=` matches it.
`--break-alignment` signs as the tenant and sends as the operator, which is
the failure nobody notices until a customer says the mail is not arriving.

The signing is go-msgauth's, not mine — the same call made for OpenID
Connect. Relaxed canonicalisation, body hashing and tag ordering are fiddly
in ways that fail quietly, and **a DKIM signature that does not verify is
worse than none**, because a receiver running DMARC reads it as a failure
rather than an absence.

That makes the signer and the test verifier the same library, which is not
independent. The honest mitigation is the tampering tests: change the body,
the subject or the sender and the signature must stop verifying. A signature
that survives a changed body is decorative, and those tests prove this one is
not.

#### Why there is no SPF record to add

The obvious question on that page, answered there:

> No SPF change is needed. Replies and bounces come back to this platform, so
> the envelope stays ours and SPF checks our domain, not yours. What makes
> your mail pass DMARC is the DKIM signature below, which is signed as your
> domain and matches the address it is sent from.

DMARC passes when **either** SPF or DKIM authenticates and aligns. The
envelope sender stays the operator's so bounces come back to us, which means
SPF authenticates the operator's domain and does not align. DKIM does. Telling
a tenant to add an `include:` would be advice that changes nothing, because
nothing is ever sent with their domain in the envelope.

#### The 255-character thing

A TXT string cannot exceed 255 characters and a 2048-bit key is about four
hundred, so the record has to be published as several quoted strings the
resolver joins back. Every administrator meets this once, usually by the
record silently not working, so the console shows the split form rather than
leaving them to find out.

#### What email still cannot do

**No key rotation.** One selector per domain, forever. Rotating means
publishing a second record and retiring the first, and neither is built.

**No DMARC reporting.** A tenant who turns on `p=reject` gets no visibility
from here into what is failing.

**No bounce handling.** A message accepted by the server and bounced
afterwards reads as delivered here.

### What is not built

**No coalescing.** Five hundred devices going non-compliant at once would
produce five hundred messages. Deduplication stops the *same* event queuing
twice; it does nothing about many different events at once.

**Nobody is told about compliance.** `device.lost`, `approval.waiting` and
`limiter.tripped` are wired. A device drifting out of compliance tells only
the person holding it, on their own page.

### The Apple seam

`command.PushProvider` is the whole of the Apple, Google and Microsoft
dependency in this package. Everything above it is built and tested.

The platform ships `command.AppleNotConfigured()`, which refuses with the
reason: it names the Apple MDM vendor CSR signing certificate and the
per-tenant APNs certificate that follows it. A command that cannot be pushed
**stays queued rather than being refused** — the command is fine and the
tenant did nothing wrong; the gap is ours, and a queue that holds its work
until the gap closes is the correct behaviour.

## Setup

T1: a tenant can be set up, and can see what is left to set up, without
anyone typing SQL.

### The operator's half: `tenantctl`

```bash
MDM_OPERATOR_DSN=postgres://mdm_operator:...@db/mdm MDM_SEALING_KEY=... \
  go run ./cmd/tenantctl create --name "Kalesi Foods" --slug kalesi \
    --host console.kalesi.example \
    --issuer https://login.microsoftonline.com/kalesi/v2.0 --client-id kalesi-console \
    --admin-group MDM-Owners < client_secret.txt
go run ./cmd/tenantctl list
go run ./cmd/tenantctl suspend kalesi      # visitors are told; the host still resolves
go run ./cmd/tenantctl add-host kalesi mdm.kalesifoods.example   # both answer during a changeover
go run ./cmd/tenantctl signups          # open self-service sign-ups: waiting or opened
go run ./cmd/tenantctl signups --all    # plus finished, expired and replaced
go run ./cmd/tenantctl cancel-signup ada@arbor.example   # the open link stops working; the row stays
```

`signups` is the answer to "where is the one from this morning": one state
word per request (waiting, opened, finished, expired, replaced), the company,
the draft slug, the caller's address and, for a finished one, the tenant it
became. It carries no token and no hash, so a pasted listing is not a list of
working links. `cancel-signup` is the operator's one move against a sign-up
they do not like the look of: the link dies, the row stays, so it still
counts against the caps.

The client secret arrives on stdin or from a `0600` file, never on the
command line. `create` writes four rows in one transaction, so a tenant with
no hostname, or a hostname with no tenant, cannot be left behind.

**The boundary this keeps.** Migration `0014_onboarding.sql` lets the
operator's database role WRITE exactly those four tables: `tenants`,
`tenant_domains`, `tenant_identity`, and ONE `tenant_role_map` row so the
first administrator can get in. It still cannot read a device, a command, an
audit entry or a policy, and cannot read, change or remove the role mapping
it seeded. `TestTheDirectoryRoleCannotReachTenantData` probes every one of
those, and `--break-operatorreach` adds one more grant to the migration and
requires the probe to notice.

Why the first mapping is the operator's: to configure sign-in you have to be
signed in. Somebody breaks that circle once per tenant.

### The tenant's half: the console

**Setup** (`/setup`, anyone who runs the console) is a checklist: brand,
hostname, sign-in, notifications, sending domain, network, Apple, Android,
first device. The network step is done only when the network has actually
asked the access feed, not when a token has been minted: a token nobody has
used is an integration somebody meant to finish, and the feed being asked is
the only sign of the network's side the platform can see. Each step says whether it is done and where to do it. A step that
cannot be done yet says why (Apple and Android are blocked on the vendor
certificates, by name) rather than sitting there as a ticket waiting to be
opened. The page also shows the PRD's first success metric, **time from
sign-up to first enrolled device**, in words, because a metric that is not
shown is a metric nobody is held to. It is shown only when it can honestly be
stated: a tenant created before this sprint has no sign-up time and the line
is absent, not zero.

**Branding** (`/branding`, policy.change) is the form behind the placeholder
banner. `branding.Save` runs the contrast guard at the write, so a colour
white text cannot be read on is refused with the number, and the form shows
the number before you press save.

**Sign-in** (`/identity`, access.manage) is the identity provider and the
role map. `access.manage` is a new action held by Super Admin alone: anyone
who can edit the role map can map their own group to `super_admin`, so
editing it has to be gated to people who already are. The nav entry is
absent for everyone else rather than present and refused. The redirect URL is
derived from the request's own host rather than typed, a blank secret keeps
the old one, and the last `super_admin` mapping cannot be removed: that
leaves a tenant nobody can administer, and the people who could fix it are
the people it just locked out.

## Sign-up

A stranger with a work email becomes a tenant. This is the only surface in
the platform that a stranger can reach and cause a write from, so the whole
design is about bounding what a stranger can cause.

It lives on its own hostname (`MDM_SIGNUP_HOST`), decided before anything
else looks at the request: a tenant's hostname never serves `/signup` and the
sign-up hostname serves nothing else. It carries the operator's own brand
(`MDM_SIGNUP_PRODUCT_NAME`, `MDM_SIGNUP_COLOUR`), which the operator-brand
rule allows exactly here, because there is no tenant yet whose brand it
could carry instead.

```
1. POST /signup              company and work email. One row, one email.
2. GET  /signup/{token}      the link from the email. Opening it proves the address.
3. POST /signup/{token}/slug the console's address: <slug>.<MDM_SIGNUP_TENANT_DOMAIN>
4. POST /signup/{token}/finish the identity provider and the admin group.
                             The tenant is created and the link is spent, in one transaction.
```

**What a stranger can cause before the proof:** a row in `signups` and one
email to an address they typed. Bounded three ways: a per-address burst
bucket in memory, caps of 5 per email domain and 10 per caller address per
day in the database, and a refusal of free-mail providers, because a tenant
is a company and the address that creates it has to be one the company
controls. Asking again replaces the first link rather than adding to it, so
an address holds at most one open link.

**The free-mail list** (`internal/directory/freemail.go`) is thirty-two
thousand domains shipped in the binary: the free-mail providers and the
disposable-address services, built from two maintained public lists
(`freemail_domains.txt` says which), validated to be lower-case domains
and to hold no public suffix, because refusing co.uk would refuse a
country. A subdomain of any entry is refused too, so a provider's regional
host or a disposable service's per-user hostname is caught by its parent;
`--break-freemailsuffix` checks the exact domain only and the test
notices. A deployment adds its own refusals from
`MDM_SIGNUP_BLOCKED_DOMAINS_FILE`, one per line, for the provider big in
one country and missing from both lists. What it does not do is look up
the domain's mail exchanger: a company on Google Workspace has Google's
servers as its exchanger and is a company all the same.

**The token** is 256 random bits, carried in the link and stored as its
SHA-256: a copy of the table is not a set of working links. It is the
credential for every step after the email, which is why there is no session
and no CSRF token here. It lasts a day and works once. The single-use guard
is the `UPDATE ... WHERE finished_at IS NULL` inside the same transaction as
the tenant's creation, so two people racing on one link get one tenant and
one refusal, never two tenants. A used or expired link says so, because the
person holding it did get it from us; a token we never issued is simply not
found.

**The welcome.** After the tenant is created, one more email goes to the
proven address: the console's address, the sign-in link, the administrators'
group and what the Setup page still asks for. It is sent after the commit and
is not allowed to fail the sign-up: the tenant exists either way, and the done
page says the same thing. It never carries the token, which has just been
spent.

**Why a new table** (SD 10, written in `0015_signup.sql`): a pending sign-up
has nothing to attach to. The existing path, a `tenants` row with status
`provisioning`, was rejected because it would reserve a slug and a hostname
for a stranger who has not yet proven an email address.

**Links are https** unless the gateway is in insecure-cookie mode AND the
request is to localhost. The directory separately refuses a plain-http
console URL anywhere but localhost, and a test found that the first rule
alone was not enough.

In the demonstration, sign-up is at `http://signup.localhost:8090/signup`.
There is no mail server, so the verification link is printed to the console
log (`docker logs mdm-demo-app`). A tenant that signs up as `arbor` answers
at `http://arbor.localhost:8090`; browsers resolve `*.localhost` to this
machine without an `/etc/hosts` entry.

## Android Enterprise

The Google half of the vendor dependency, built up to the line where a
credential is needed and honest about the line.

**The shape of it.** Android devices are managed through Google's Android
Management API. The operator holds ONE service account for the platform
(`MDM_ANDROID_CREDENTIALS_FILE`); each tenant binds its OWN enterprise by a
Super Admin signing in with a Google account, so what a tenant's devices do
is decided under that tenant's enterprise and nobody else's. Policies,
enrolment tokens and commands are all addressed under the enterprise name,
which came from the tenant's own row. The adapter never sees a tenant id.

**Binding** (`/android`, Super Admin) is a round trip: we ask Google for a
sign-up URL with our callback on it, send the person there, Google sends
them back with an enterprise token, and the sign-up URL's name is presented
with that token to finish. The name travels in a cookie signed to the
person who pressed the button, and the callback refuses without it: a
token arriving on a callback nobody here began is a token somebody else
began, and binding on it would bind their enterprise to this tenant.
`--break-androidstate` makes the callback bind without it.

**Policy** is delivered at binding and on every policy save, inside the same
transaction, so a policy Google refuses is a policy that was not saved.
`android.Translate` turns the effective rules for Android devices into
Google's policy JSON: passcode rules become `passwordRequirements`, encryption
becomes `encryptionPolicy`, the screen-lock timeout becomes
`maximumTimeToLock`. The three rules Google cannot enforce (`os_version_min`,
`firewall_required`, `jailbreak_blocked`) are named back to the person
saving the policy as "judged on sync rather than enforced on the device",
and `--break-androidjudged` makes them vanish silently instead.

**Enrolment** is a one-time token from Google, tied to the policy and to the
person it is for, shown once on the page and recorded by name so the device
that enrols with it lands on that person's page with the label and the
ownership that were typed. A token for a personal device asks Google for a
work profile (`allowPersonalUsage`), which is F2's BYOD enrolment and F10's
separation on Android: the profile is managed, the person's own space is
not, and a selective wipe removes the profile alone.

**Sync** runs every fifteen minutes (F8) and on demand. It lists the
enterprise's devices, gives a new one a row, and judges every one with the
same engine as every other report, from what Google reports: screen lock,
encryption, verified boot (Google's root check), Android version, with the
report time Google gives rather than now, so staleness is honest. Two
inferences, written down in `android.ReportFrom`: Google never reports a
passcode's length or the screen-lock timeout, but it reports whether the
device is compliant with the policy we delivered, and that policy carries
the minimum length and the maximum timeout. A device Google calls compliant
has a passcode at least that long and locks at least that soon. From there
the engine does what it always does, including F9. The sync ends with an in-vs-out block: listed, created,
judged, skipped-with-reason.

**Commands** route by operating system (`command.ByOS`): Android goes to
Google, everything else still waits on the Apple certificate. Google carries
the command out, so the Android channel is a `command.Executor` and the
pipeline marks such a command acknowledged with the one-time code spent,
rather than pushed and waiting for an agent that does not exist. The
pipeline's own rules have all run first: the reason, the role, the second
approval for a full wipe. A selective wipe removes the work profile and
leaves the person's own data; a full wipe carries `WIPE_EXTERNAL_STORAGE`;
`--break-androidwipe` sends the selective one as full.

**Lost mode** (F14) is two commands, `lost_mode` and `lost_mode_end`, each
with a reason and each its own audit row, under the same role as the
emergency lock, from the device page or the API. On Android they are
Google's `START_LOST_MODE` and `STOP_LOST_MODE`. What the lock screen says
is the tenant's name and who to call, built from the tenant's brand: the
Branding page holds a lost-device phone number and email, checked for
being dialable and plain, shown on that lock screen and nowhere else. The
operator-brand rule applies to a found phone exactly as it does to a page;
`--break-lostbrand` puts the operator's name there, and
`--break-lostcontact` keeps the name and drops the way to reach the owner.

**Inviting a phone.** A token is a thing to send, so the page shows it as
Google's enrolment link (`android.EnrolLink`:
`https://enterprise.google.com/android/enroll?et=<token>`), copyable, and
offers to email it to the person through the tenant's own mail
(`gateway.Config.Mail`: the email channel in production, the log in the
demonstration). The invitation is written for the person holding the
phone, stamped with the tenant's name and sending identity like every
other email (`notify.Service.Stamp`), and audited as `android.invite_sent`.
The address is checked before Google is asked for a token, so a bad one
costs nothing there and a line break in it never reaches a mail header.
The link is Google's, not the console's, because the phone talks to Google
and never to us; `--break-invitelink` points it at the console and
`--break-inviteaddress` skips the address check, and both are caught. The
laptop-agent enrolment link on the Enrolments page is a different thing:
it points at the console because the agent talks to the console.

**Tested against a fake of Google** (`android.FakeGoogle`): the same seven
calls over HTTP, recording what it was asked, so the tests read request
shapes back rather than trusting a client library. The real client
(`android.AMAPI`) is the same code pointed at Google, authenticated with the
service account's JWT. The demonstration runs the fake in-process with a
pretend phone at `http://localhost:8093/phone`, so the whole flow can be walked with no Google
account in the room.

**What waits on Google.** A service account with the Android Management API
enabled, which the operator creates in a Google Cloud project. Without it
the Android page and the setup step say so by name, and nothing else
changes.

**Running the demonstration against the real Google.** The demonstration
uses its fake of Google unless `MDM_ANDROID_CREDENTIALS_FILE` names a
service account key when `./demo.sh` starts; then the key is mounted
read-only into the container and the same client `cmd/gateway` builds is
used, so the first real bind can be walked on a laptop:

```
MDM_ANDROID_CREDENTIALS_FILE=/etc/mdm/android-service-account.json ./demo.sh
```

With the real Google in play the demonstration keeps its database across
restarts and its seed leaves the Android rows alone, so an enterprise
bound at Google is still bound after `./demo.sh` is run again; an
enterprise forgotten here would be an orphan there. The demonstration keeps
a ledger of applied migrations (`demo_migrations`) so a kept database takes
only the new ones. `./demo.sh reset` starts from nothing.

Google's refusals (an API not enabled, a role missing) are shown on the
Android page as a sentence with Google's own instruction in it, not as the
JSON envelope they arrive in; `--break-googlewords` dumps the envelope and
the test notices.

Four things the first real bind taught the fake, each now a test and a
control. A token's expiry is in Google's `expirationTimestamp`, not the
`expirationTime` the client used to read and the fake used to send
(`--break-expiryfield`): the first real invitation said it expired in the
year 1. Google wants the project named on the two calls that create a
sign-up URL and an enterprise (`--break-projectid`). Google sends the
administrator back only to an https address, so the demonstration runs a
second listener with a certificate made at startup, on the console port
plus two, and names it as the callback (`gateway.Config.AndroidCallbackBase`;
`--break-callbackbase`); the browser warns once about that certificate on
the way back. And the fake refuses a plain-http callback exactly as Google
does (`--break-fakehttps`), so a console tested only against the fake cannot
pass with a callback Google would refuse.

## Reports

F18: the compliance report, as CSV and PDF, on demand and weekly.

A report is an export of tenant data, and is treated as one: built under
the tenant's claim like every other read, audited when it is made
(`report.generated`, with the format and the device count), and available
to the roles that may see devices, which includes the auditor because a
report is what an auditor is for. `--break-reportaudit` makes the export
leave no record.

**CSV** is one row per device: name, serial, OS, ownership, who it is
assigned to, the verdict as the engine would give it right now (stale
re-checked, so a device that went quiet since it was judged reads as
unknown), when it last reported, and the findings with the policy that
asked, joined into one cell. A spreadsheet filter on the verdict column and
a read of the findings column is the whole triage.

**PDF** is written by hand in `internal/report/pdf.go`: one font, A4, a band
in the tenant's colour with the product name, the summary, the device
table, then a section of what is wrong and which policy asked for every
device that is not compliant. Every page carries the footer the house rule
asks for, the title then "Page N of M", and the tenant's legal footer under
it. No library, because a library puts its own producer string on a
tenant's document; `--break-reportbrand` puts the operator's name in the
band and the test reads it back out of the content stream.

**Weekly** is the existing notification path rather than a new scheduler
table (SD 10): point the `report.compliance` topic at an inbox or a
channel under Notifications, and a sweep sends the summary and a link to
the download once per ISO week per tenant, keyed so a daily sweep sends on
its first run of the week and not again. The Reports page says who is
scheduled to receive it, or that nobody is.

## Plans, quotas and metering

T8 and T9: what a tenant may use, and what it has used.

**Administrator seats are enforced at sign-in** (0032). A seat is a
person with an administrative role, anything but employee, who has signed
in within the last 30 days; the plan says how many there are (starter 3,
growth 10, scale 50). The check runs inside the same transaction as the
role lookup, so an administrator with a session is an administrator with
a seat. A newcomer to a full plan is told, on the sign-in page, how many
seats there are and the two ways out (a Super Admin releases a seat on the
Sign-in page, or the plan grows); the refusal is audited and the tenant is
told once a day on `quota.reached`. A seat not used for 30 days lapses by
itself. Employees never take a seat: the self-service role is part of every
plan, and counting it would turn "three administrator seats" into "three
people". `tenantctl usage` shows seats used over seats held, and the daily
snapshot keeps both. `--break-seats` never checks the count and
`--break-seatlapse` holds a seat for ever; both are caught.

**A plan is a named set of defaults** (`directory.Plans`: starter, growth,
scale), and the tenant row holds the numbers the plan gave it when it was
set, so a plan can change later without quietly changing every invoice.
`tenantctl set-plan` moves a tenant and takes the plan's numbers;
`set-quota` overrides one number; `feature <slug> <name> on|off` switches
one flag over the plan's default. The flags this platform understands are
`android`, `network_feed` and `weekly_report`; starter has none of the first
two, growth and scale have all three.

**The device cap is enforced twice.** The invitation is refused first, in
words: "47 of 50 devices are in use. Retire a device, or ask for a larger
plan." Then the database trigger `device_cap` refuses the row for any writer
that forgets to ask, including the Android sync, which skips the phone with
the reason and says so once a day through `quota.reached`.
`--break-devicecap` removes both halves. The API rate limit has been on the
tenant row since the first sprint. Admin seats are recorded and shown, not
enforced: there is no table of people, only of groups, and counting seats
honestly needs one (see the limits).

**A feature that is not in the plan is absent or refused by name.** The
Android page says "not part of this plan"; the setup step says the same;
the network token form refuses. `--break-featureflag` makes every flag
answer yes.

**Metering** is the one place the operator needs numbers from inside
tenants and the one place it must not get rows. `app.tenant_usage(tenant)`
returns active devices, devices enrolled and commands and notifications in
the last thirty days, and bytes stored, and nothing with a name in it. It is
`SECURITY DEFINER`, owned by `mdm_meter`, a role nobody can log in as whose
one property is that row-level security does not apply to it, so the bypass
is contained to the body of one function. The operator may execute it and
still cannot `SELECT` from devices; the probe test and the metering test
both say so. `tenantctl usage` prints it; a sweep takes one snapshot per
tenant per day into `usage_snapshots` for billing history, which the
application role cannot read (a tenant's console has no business seeing the
operator's billing table, including its own); `tenantctl usage <slug>
--history 30` shows it, and `tenantctl billing --month 2026-10 [--format
json]` hands a billing system the month: one row per tenant with the days
that had a snapshot, device-days (the sum of the daily active counts, what
a per-device-per-day price applies to), the peak device count and peak
storage, and the plan the month ended on. A month with no snapshots is an
empty export, not an error.

## SIEM export

F19: every audit event, streamed to the tenant's SIEM.

The audit log is append-only and hash-chained; a SIEM wants a copy of every
row as it lands, in a form it already parses. The destination is an ordinary
notification target, topic `siem.audit`, kind `syslog`
(`syslog://host:514`, `syslogs://` for TLS, `?format=leef` for LEEF instead
of CEF) or `webhook` for JSON. The position is a cursor per tenant in
`siem_cursors`, the one new table (SD 10: nothing else records "this tenant
has received audit events up to id N").

**A stream, not a notification.** The outbox deduplicates and retries single
messages; a stream has to know exactly where it got to. So the exporter in
`internal/siem` delivers directly, one event at a time, and moves the cursor
past each event only after the collector has taken it. A send that fails
stops the run with the cursor where it was and the error on the page; the
next run, a minute later, starts from there. No gaps, no repeats, and the
test that takes the collector down and brings a new one up counts every
line. `--break-siemcursor` moves the cursor first.

**The vendor field is the tenant's.** `CEF:0|Kalesi Device Care|Device
Management|1|device.quarantined|device quarantined|6|rt=… suser=… act=…
cs1=object cs2=tenant cn1=auditId cs3=hash`: what a tenant's analysts see
is the tenant's own product, never ours, on a log line as on a page.
`--break-siembrand` puts the operator there. The hash travels with every
line, so a SIEM can verify the chain it holds against the one here.

The syslog channel refuses destinations inside this platform's own network
unless the operator sets `MDM_SIEM_ALLOW_PRIVATE=yes`, for the same reason
the webhook channel does: a tenant administrator choosing a destination must
not be able to make this platform open connections to its own internals.

## Offboarding

F4: a device, and everything a leaver holds.

**A device** is offboarded by a selective wipe through the command
pipeline, with its reason and its role, and then retired the moment the
wipe is done: state `retired`, certificate revoked, slot freed under the
plan's cap. The two are ordered on purpose: a certificate revoked before
the wipe lands is a wipe that never lands, so the device page shows "being
offboarded" until the device, or Google, confirms. `command.Pipeline.OnWiped`
is the hook; `--break-offboardretire` removes it and a confirmed wipe
retires nothing. A device that never enrolled anywhere has nothing to wipe
and is retired at once.

**A leaver** is every device assigned to their address. "Offboard
everything they hold" on any of their device pages, `POST
/api/people/offboard`, or the HR system through `POST /api/hr/leavers`
with an integration token minted with the `hr` scope. That token resolves
to the `hr_feed` role, which holds `offboard.employee` and nothing else:
it may say a person has left, and may not read the access feed, wipe a
named device, or offboard a named device. `--break-tokenscope` gives every
token the network role. The offboarding wipe is permitted to that role for
`wipe_selective` only; `--break-offboardscope` lets it reach a full wipe.

What "automatic offboarding from HR lifecycle events" needs on the HR side
is one call per leaver with their address. The platform keeps no table of
people, so the address is the key: a device assigned to nobody is not
offboarded by anyone leaving, which the limits section says.

## Leaving: suspension, export, offboarding

T10, in three deliberate steps, each the operator's.

**Suspend** (`tenantctl suspend`): visitors are told, nothing runs, the
hostname still resolves so "not active" is a billing conversation rather
than a vanished product.

**Export** (`tenantctl export-mode`, then the Super Admin downloads from the
Sign-in page or `GET /api/export`): one zip of JSON lines per table, every
table the tenant has, read under the tenant's own claim and audited. While
the status is `exporting` the console answers the export and sign-in and
nothing else. Sealed secrets, token hashes and one-time codes are replaced
with `[not exported]`: an export is a file that will be emailed, and a file
that will be emailed is not a vault. `--break-exportsecret` lets them
travel.

**Or sent to the tenant's own bucket**, from the same page: any
S3-compatible store (AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi)
takes a PutObject signed with Signature Version 4, which is HMAC and no
SDK (`internal/gateway/bucket.go`). The keys are typed for that one upload
and are never kept, logged or audited; the audit line names the endpoint,
the bucket and the object. The endpoint is held to the webhook's rule and
then some: https, and every address its name resolves to must be on the
public internet, checked at dial time rather than at save time, so a name
that resolves to one public and one private address is refused whole.
Otherwise "my bucket" could be the metadata service and a Super Admin
could have the export posted inside this platform's own network;
`--break-bucketssrf` dials whatever the name resolves to and the test
notices. A bucket that refuses is said plainly and nothing is recorded as
sent.

The address rule the webhook and the bucket share is a refusal list for
IPv4 and an allow-list for IPv6, because the shapes differ: IPv4 has a
handful of named private ranges, while IPv6's global unicast is one block
(2000::/3) and everything outside it is link-local, unique-local, discard,
documentation, or a transition format carrying an IPv4 address inside an
IPv6 one. NAT64 is the sharp one: with a translator on the path,
`64:ff9b::169.254.169.254` is the metadata service wearing an IPv6
address. It falls outside 2000::/3 and is refused; 6to4 (`2002::/16`) is
inside it, so the four bytes it carries are judged by the IPv4 rules,
which is how `2002:a9fe:a9fe::` is refused and `2002:0808:0808::` is not.

**Offboard** (`tenantctl offboard <slug> --confirm <slug>`): every row of
the tenant's in every tenant table, in foreign-key order, deleted by
`app.offboard_tenant`, a `SECURITY DEFINER` function owned by `mdm_reaper`,
a role nobody can log in as that holds DELETE and nothing else. It refuses
an active tenant: suspension first, on purpose (`--break-offboardactive`).
Key destruction is literal, because the keys are rows: `tenant_ca` (the
sealed device-signing key), `tenant_identity` (the sealed client secret),
`sending_domains` (the sealed DKIM key) and `notification_targets` (the
sealed endpoints) are emptied with everything else. Then, inside the same
transaction, `app.tenant_residue` counts what is left in every table; if
anything remains nothing is committed and the operator is told which table
(`--break-offboardresidue` skips the audit log and silences the check).
The tenants row stays, status `offboarded`, with no hostname, as the
record that a tenant existed; `offboarding_log` on the operator's side
holds the counts and the verified zero.

## Sign-in without an identity provider

A customer with no Entra, Google Workspace or Okta cannot be a customer of a
product that only signs people in through one. The third mode (0044,
`internal/localauth`, `internal/gateway/local_signin.go`) is accounts held
here: an email address, a password and, for the roles that can act on a
fleet, an authenticator app. It is a mode of the TENANT, chosen when the
tenant is made, not a second door on every tenant: a tenant with an identity
provider takes its people from there and a local account it happens to hold
does not sign in, because a password account would be a way round the
provider's own controls, offboarding above all (`--break-localprotocol`).

**Making one.** Self-service sign-up offers two forms on its last page: an
identity provider, or "I do not have one", where the person who proved the
address becomes the first administrator with the password they choose there.
`tenantctl create --protocol local --owner-email kemi@x.example` makes the
owner an invited account and prints a link that works once, for seven days;
the operator's role may insert exactly that row, a Super Admin, invited or
active, and may read nothing back (a test holds that line, and refuses an
employee or a disabled account by row-level security, not by a missing
privilege).

**Adding people.** A Super Admin invites from the Users page, which only a
Super Admin sees: an address, a name and one of the six roles. The person
gets a link, emailed in the tenant's own brand when mail is set up and shown
once on the page either way, to choose a password. The link is 256 random
bits kept as their hash, good once, for a limited time, and asking for
another replaces the first. A link opened at another tenant's hostname is
nothing. Disabling signs the person out everywhere and frees their
administrator seat; an account is never deleted, so the audit log and any
device assigned to them still have a person to point at. The last active
Super Admin cannot be disabled or demoted, with the active ones locked first
so two demoting each other at once cannot both succeed (`--break-lastadmin`).
Changing a role, disabling, resetting a password or resetting the second
step ends that person's sessions, because the role travels in the session.

**The password.** Argon2id at 46 MiB, two passes, parameters written into
every hash so raising them later leaves the old ones verifiable, and read
back bounded so a hash row edited to ask for 4 GiB is refused. At least
twelve characters, not one of the long passwords everybody tries, not a run
of keys, and not built from the person's own name, address or organisation.
Hashing runs four at a time, because each holds the memory. A wrong password
and an address with no account cost the same time (the unknown one verifies
against a hash nobody knows), and every way a sign-in can fail before the
second step gets the same words: an unknown address, a wrong password, a
disabled account, an account never activated, a locked one
(`--break-enumeration`). Five wrong answers lock the account for fifteen
minutes, the count restarts after a lock runs out, and a locked account
refuses even the right password so the lock cannot be used as an oracle
(`--break-lockout`). A per-address limit stands in front of that for the
guesser who rotates accounts. The forgot-password form says the same thing
whether or not the address exists, sends at most one link a minute per
address, and does its lookup and its mail after the answer, so the answer's
time says nothing either. A reset link also ends every session the person
had and leaves the second step alone: a link in an inbox is not a way round
it (`--break-sessionsend`).

**The second step.** TOTP, RFC 6238, six digits, thirty seconds, the codes
the RFC publishes held in a test. Super admins, IT admins and security
managers must have one; a Super Admin can widen that to everybody. The
password step ends in a signed, ten-minute cookie that is good for the
second-step page and nothing else: no session exists until both are done,
and the failure count does not reset until both are. First sign-in shows the
QR code and the key as text, keeps the secret sealed under the tenant's own
key (opening the page twice does not replace what the first look put in a
phone), and on the first good code shows ten recovery codes once and keeps
only their hashes. A code is good once: the step it was accepted for is
recorded and that step or an earlier one is refused, so a code somebody
watched being typed is no use (`--break-totpreplay`). A recovery code is
spent in one statement, so two people holding one cannot both use it. A
Super Admin resets someone's second step if they lose the phone and the
codes. `--break-mfarequired` lets an administrator in on a password alone.

**The front door.** The operator's own hostname used to redirect straight to
the sign-up form, which sent every returning person to the page for
strangers. It now has a home page with two ways in: "Sign in to your
organisation", where a person types the short name their organisation chose
(or the address they usually open it at) and is sent to that console's
sign-in, and "Set up your company". A short name is turned into the
console's address without looking anything up, so the form cannot be used to
ask which organisations exist; the console answers 404 for one that does
not, as it always did, and the name is public in DNS either way. A hostname
is followed only if it resolves to an active organisation, so the form is not
an open redirect, and anything with a slash, an at sign, a colon or a space
is refused.

**Leaving.** A local tenant that later gets an identity provider connects it
on the Sign-in page; the switch is refused until a group is mapped to Super
Admin and the provider's secret is given, because after it the accounts here
stop signing in and the tenant would otherwise lock itself out of the one
page that could fix it. The reverse, an identity-provider tenant moving to
local accounts, is not built.

## One key per tenant

T3. The platform's master key seals tenant keys and nothing else; a
tenant's key seals that tenant's values and nothing else: the sign-in
client secret, notification endpoints, the DKIM signing key, the
device-signing key. A sealed value carries the version of the tenant key
that sealed it (`internal/secrets/keyring.go`), and the transaction's claim
says whose key, so no caller can seal under another tenant's key by passing
the wrong id. The tenant key is made when the tenant is: by `tenantctl
create`, by sign-up, or on first use for a tenant that predates this.

**Rotation is the tenant's, and touches only the tenant.** "Rotate the
key" on the Sign-in page (or `POST /api/keys/rotate`, Super Admin) makes a
new version, retires the old, and re-seals every value of this tenant's
under it, in one transaction; the audit record says how many values moved.
Nothing of any other tenant's is read or written, which the test proves by
reading tenant B's bytes before and after tenant A rotates.
`--break-rotatereseal` makes a new version and moves nothing;
`--break-keyscope` seals everyone under the master again. Retired versions
stay readable, so a value this list somehow missed still opens. Values
sealed before tenant keys existed are in the old format under the master;
they still open, and the first rotation brings them under the tenant's key.

The operator's role may insert a tenant's first key and may never read one
back: a key it can read is a key it can use, and the probe test holds that
line with the rest.

**Rotating the master** (0033) is three steps, and the middle one is all
or nothing. One: deploy with the new key as `MDM_SEALING_KEY` and the old
one as `MDM_SEALING_KEY_PREVIOUS`; the keyring opens tenant keys under
either and seals under the new one only, so nothing stops working in the
window. Two: `tenantctl reseal-master` moves every tenant key, every
version, retired ones included, under the new master in one transaction,
through two functions owned by `mdm_keymaster` (a role nobody can log in
as; the operator's role still cannot read or write `tenant_keys` itself,
and the probe test says so). Each write is compare-and-swap on the
ciphertext read. A key that opens under neither master halts the run and
rolls it back, with the tenant and version named and "nothing was changed"
said: a half-rotated database is the one state nobody recovers from
without the tool, and the tool would not know where it stopped.
`--dry-run` reports without writing. Three: `tenantctl reseal-master
--verify` has to say every key opens under the current master alone, then
`MDM_SEALING_KEY_PREVIOUS` comes out of the deployment. The plaintext of a
tenant key exists only inside the tool for the length of one call.
`--break-resealhalt` skips the unopenable key and `--break-previousmaster`
forgets the old master; both are caught.

### Where the platform keys come from

The three platform keys (the claim signer, the session signer, the master
sealing key) and the master being rotated out come from the source
`MDM_KEY_SOURCE` names (`internal/platformkeys`):

| `MDM_KEY_SOURCE` | Where the keys are | For |
|---|---|---|
| `env` (default) | `MDM_CLAIM_SIGNING_KEY`, `MDM_SESSION_SIGNING_KEY`, `MDM_SEALING_KEY`, `MDM_SEALING_KEY_PREVIOUS` | a laptop; the gateway warns at start |
| `files` | one file per key in `MDM_KEY_DIR` (default `/run/secrets`): `claim_signing_key`, `session_signing_key`, `sealing_key`, `sealing_key_previous` | a Kubernetes or Docker secret, a systemd credential, a cloud secret mounted by a CSI driver |
| `vault` | the four as fields of one KV v2 secret at `MDM_VAULT_PATH` in `MDM_VAULT_ADDR` | HashiCorp Vault, token (`MDM_VAULT_TOKEN_FILE`) or AppRole (`MDM_VAULT_ROLE_ID` + `MDM_VAULT_SECRET_ID_FILE`); `MDM_VAULT_NAMESPACE` and `MDM_VAULT_CA_FILE` as needed |

Whatever the source, the keys are checked the same way before anything
runs: the signers at least thirty-two bytes, the sealing keys exactly
thirty-two, the three different from each other (one key doing three jobs
is one compromise doing three), and the previous master different from the
current. A value written `base64:...` is decoded, for a key of arbitrary
bytes in a field that holds text; otherwise the bytes are as given, less
the line break an editor leaves. A key file, a vault token file or an
AppRole secret-id file that other users can read is refused by name
(Kubernetes sets `defaultMode: 0400` on the volume). The vault is https,
with plain http allowed to a loopback address and nowhere else; the vault
is spoken to over its HTTP API with no client library, the secret is read
once so the four keys cannot come from two versions of it, and the vault's
refusal is reported in its own words. A source name this build does not
know is refused rather than falling back to the environment. `tenantctl`
and `sealsecret` read the sealing keys from the same source, so an
operator running `reseal-master` against a vault pastes nothing.

The bytes are never written anywhere. The start-up line says where the
keys came from and the first four bytes of each key's SHA-256, enough to
tell which key is in use and far too little to find it.
`--break-vaulthttp` lets a key be fetched in the clear across a network,
`--break-keydescribe` prints the keys on the start-up line, and
`--break-keyfilemode` reads a world-readable key file; each is caught.
**Re-read while running** (0044, `platformkeys.Watch`): every five
minutes, and at once on SIGHUP, the source is read again and a set whose
fingerprints differ is applied: `tenantclaim.Signer.Rotate`,
`session.Signer.Rotate` and the gateway's form-token key keep the key
before the rotation so what it signed still verifies until the next
rotation, which is longer than any session; `secrets.Keyring.RotateMaster`
keeps the old master among the previous ones so every tenant key opens
until `tenantctl reseal-master` has moved them. The environment is not
watched, because it cannot change under a running process.
`--break-rotategrace` forgets the previous key and the open-session test
notices; `--break-keysdiffer` lets one key do three jobs through the
checks that run at start and at every re-read, and the test notices.


## A lock in seconds

F12. The agent keeps one request open on its own queue, `GET
/api/my/commands?wait=25`, and the gateway holds it until there is work, the
wait runs out, or a command is pushed to that device. The instruction still
travels over the device's own authenticated connection, as it always did;
the wake is only timing. A device that is not listening gets its commands at
the next check-in, as before. In the tests a lock reaches a held poll in
under a second (`--break-wake` removes the wake and it takes the five-second
fallback tick instead), and a listening agent acknowledges one in about a
second.

The wake registry is per gateway instance; the wake is not. A push raises
a PostgreSQL notification on the command's own transaction
(`Tx.Notify`, channel `mdm_wake`, payload the device id and nothing
else), the database delivers it at commit to every instance listening
(`Gateway.RunWake`, one held connection per process, retaken after an
error), and each instance wakes the polls it holds. So a lock requested on
one gateway reaches a phone held open on another in the time a
notification takes; in the test a second gateway over the same database
gets it in well under a second. The five-second fallback tick stays for an
instance whose listener is between connections. Raising the notification
on the transaction, not beside it, is what orders the wake after the
commit: nobody is told to look for a command that is not there yet.
`--break-sharedwake` keeps the wake in memory and the cross-instance test
waits for the tick instead.

## Inventory and escrow

F3. The agent reports what is installed beside its compliance facts: on
macOS the bundles in `/Applications` and `/System/Applications` with their
identifiers and versions, on Linux the package list, on Windows the
Uninstall registry, and on Android what Google reports once the policy asks
for application reports. The list replaces the device's previous one on
every report, so `device_apps` is the device's current inventory and
nothing older. The device page lists it; the Apps page and `GET
/api/apps?name=` answer "who has Zoom 5.x" across the fleet, under
row-level security like every other read.

F11. The disk-encryption recovery key is escrowed by the agent (from a file
a platform helper leaves at `RecoveryKeyFile`, handed up over the device's
own certificate and removed once the server has it), sealed under the
tenant's key before the row sees it. Revealing it is a separate act: a
reason, by a role holding `key.retrieve` (Super Admin and Security Manager;
not IT, not the help desk), written to the audit log with the name and the
reason, counted on the row, and shown once on its own page rather than
through a redirect. `--break-revealaudit` reveals without a record;
`--break-revealrole` lets the help desk reveal. Enforcement of encryption
itself is the policy's `disk_encryption_required`, judged from what the
device reports and, on Android, set as the enterprise's `encryptionPolicy`.

## The brand in the inbox

T4 reaches email. Every message a tenant sends is two halves of one
message: plain text, and HTML wearing the tenant's brand (`notify.RenderHTML`):
a band in the brand colour with the product name, the message, and the
legal footer; the stamp that puts the tenant's name on the From line
(`notify.Service.Stamp`) puts the colour and footer on the message too,
and sign-up mail takes them from the sign-up brand. Nothing from the
message is markup: the body is escaped, and an https address in it becomes
a link with the address escaped like everything else. The Branding page
links to a preview (`/branding/email`): the same renderer with the same
stamp and a sample message, which is the only honest preview.
`--break-emailescape` shows the body as markup and `--break-emailbrand`
leaves the brand off; both are caught.

## Logo and favicon

T4's last two items. The logo replaces the letter mark in the header of
every page and in the band of the compliance PDF; the favicon is the
browser tab. Both are bytes on the branding row, uploaded from the Branding
page by whoever may change policy, typed by what the bytes are rather than
what the upload claimed (`branding.ImageType` sniffs PNG, JPEG, GIF, ICO and
SVG; an SVG with a script in it is not an image), and capped at 200 KB and
64 KB. `--break-logosniff` trusts the upload and an HTML file is served as
`image/png` on every page.

They are served per hostname with no session at `/brand/logo` and
`/brand/favicon.ico`, under a claim with no identity, so the sign-in error
page and the tab carry them before anyone has signed in; a logo requested
on another tenant's hostname is that tenant's or nothing. In the PDF a PNG
or JPEG logo is decoded to samples and embedded as a Flate image object, so
the report still needs no image library to read.

## Managed TLS

T5. With `MDM_TLS=managed` the gateway answers on :443 with certificates
from an ACME authority (Let's Encrypt by default; `MDM_TLS_DIRECTORY` for
a staging or private one, `MDM_TLS_EMAIL` for the account) and on :80 only
to answer challenges and redirect. A tenant's custom domain
(`tenantctl add-host`) gets its certificate the first time a browser
arrives, with nothing to install.

**The host policy is the directory.** `Directory.HostAllowed` issues only
for a hostname that a tenant owns, verified, and the tenant is not
offboarded; everything else is refused before any ACME call. The point is
the issuance budget: a stranger pointing a name at this platform must not
be able to spend it, and a tenant that has left must not keep getting
renewals. `--break-hostpolicy` issues for any hostname.

**The cache is the operator's table** (`tls_cache`): certificates and the
account key are platform material, shared by every instance, never
tenant data; the application role has no grant on it.

Not exercised against a real authority in the tests, which hold the policy
and the cache; the first run against Let's Encrypt staging is the first
real test, as with Google.

## Tickets

F20. Two more kinds of notification target, `jira` and `servicenow`, so a
tenant can point `approval.waiting`, `device.wiped`, `device.quarantined`
or any other topic at its own ticket queue: a Jira issue
(`/rest/api/3/issue`, basic auth with an API token, project key and issue
type) or a ServiceNow incident (`/api/now/table/incident`, basic auth,
`correlation_id` set to the object). Everything about how a topic reaches a
destination already existed (the target, the sealed endpoint, the outbox,
the worker, the retries); these only teach it a second shape. The endpoint
is the integration's configuration as JSON and carries a token, so it is
sealed like every endpoint, checked when typed (https only, no query, the
tool's own required fields), and shown on the page as "jira at
https://…" and nothing more.

The ticketing client dials with the same guard as the webhook channel: a
URL that resolves inside this platform's own network is refused, because
the URL is a tenant administrator's and the body is theirs too.
`--break-ticketssrf` lets it through.

## Partners

T7, the reseller tier. A partner is an operator-side account that manages
many tenants under a shared brand, with one token (`tenantctl partner
create`, shown once, `rotate-token` to replace it) sent to the partner API
on the operator's hostname: `GET /partner/tenants`, `POST /partner/tenants`
(within the partner's tenant cap, with the tenant's own key made at
creation), `GET /partner/tenants/{slug}/usage`, and suspend and resume. The
partner's product name, colour and footer are the DEFAULT a new tenant
starts with, written into the tenant's own branding row; the tenant may
change them.

"Strict separation between tenants" is two things here. Inside a tenant,
row-level security, as everywhere: the partner API runs on the operator's
role, which the probe test keeps out of every tenant table, so a partner
meters and suspends and never reads a device. Between partners,
`partner_id` on the shell: every call resolves the tenant within the
partner's own list first, so another partner's tenant is "not yours"
before anything else happens, and `--break-partnerscope` makes the list
everyone's.

## Data residency

T11. A tenant's region is on its row, chosen once at sign-up from the
regions the operator offers (`MDM_SIGNUP_REGIONS`) or set by whoever creates
it, and shown on the Setup page. A deployment serves one region
(`MDM_REGION`) and refuses, at the door, a tenant whose row names another:
"this tenant's data is kept in another region", whatever DNS says
(`--break-region` turns that off).

**Moving a tenant between regions** (0035) is three steps across two
deployments. On the destination, `tenantctl move-key` prints a transport
key, handed to the tenant's Super Admin out of band. On the source, the
Super Admin makes a move bundle on the Sign-in page (or `POST
/api/export/move`) with that key: every table, sealed values intact (they
are under the tenant's own key and nothing without it), the tenant's keys
re-sealed under the transport key, the tenant's plan and quotas in the
manifest; audited as `tenant.move_exported`. The master key never
travels. On the destination, `tenantctl import <bundle> --transport-key`
lands it in one transaction: the tenant row, suspended; every row through
`app.import_tenant_row`, owned by `mdm_importer` (a role nobody can log in
as, insert and nothing else), which refuses a row that names another
tenant or a table that is not a tenant's; the tenant's keys re-wrapped
under this region's master; the audit chain rebuilt in order by the
trigger; serial sequences moved past what arrived; then the count: every
table has to hold exactly what the manifest sent, or nothing is committed
and the operator is told which table and by how much. Then the hostnames
move, `tenantctl resume`, and the source is offboarded. In the test a
tenant leaves one database and arrives in the same one as a second region
with its devices, a device certificate that authenticates, and a sealed
client secret that opens under the new master through the re-wrapped key.
`--break-importcounts` commits a short bundle and `--break-importtenant`
lets a row cross tenants; both are caught.

## Known limits, stated rather than discovered

**The rate limiter is shared** (0034). The bucket is a row per key in
`api_rate`, taken from in one atomic statement by every instance, so a
plan's limit is the plan's limit behind a balancer; in the test a second
gateway over the same database is refused the fourth request of a
three-a-minute plan. The in-memory bucket stays as the fallback for a
store that cannot be reached, per instance and said in the log, so a
database blip slows a tenant a little rather than shutting the door on
everyone. The table holds a key and a count and nothing of any tenant's,
which is why it is the one thing the application role reaches without a
tenant claim. `--break-sharedrate` counts in memory and the test notices.

**Command signing keys are rows** (0036). `command.StoredKeys` keeps a key
per tenant and version in `command_signing_keys`, the private half sealed
under the tenant's own key and opened under the tenant's claim, the public
half in the clear; the first command a tenant signs makes its key, every
instance signs with the same one, and `POST /api/signing-keys/rotate`
(Super Admin, audited) makes the next version while the old stays
readable, so a command signed yesterday still verifies on a laptop that
was off. Devices read the public halves at `GET /api/my/signing-keys` and
the agent verifies every instruction against them, with the same
`command.Verify` the server's tests use, before carrying anything out: an
instruction whose signature fits no key is refused and left outstanding,
so the console shows it was never done. `--break-agentverify` skips the
check in the agent and `--break-sealedsigning` stores the key in the
clear; both are caught. The development provider remains for tests that
need no database.

**The platform keys are re-read while running** (0044). They come from a
key directory or HashiCorp Vault (see Where the platform keys come from),
with the environment kept for a laptop and warned about. The source is
read again every five minutes and on SIGHUP; a changed set that passes
the start-up checks is handed to the signers and the keyring, each of
which keeps the key before it, so a session or a form opened before the
rotation still works and a tenant key sealed under the old master still
opens until `reseal-master` has run. A set that fails the checks is logged
and the running keys stay. Other vaults reach the gateway as mounted
files, not over their own APIs.

**One person can be signed out** (0037). Sessions are still signed
tokens, not rows; what a Super Admin sets from the Sign-in page is a stamp
on the person's row in `tenant_admins` (made, lapsed, if they have none),
and every request compares the session's start, which renewal never
moves, against it, exactly as the tenant-wide stamp works. The stamp is
read under a bootstrap claim and remembered for thirty seconds per
instance, so the person is gone from the instance that signed them out at
once and from the others within half a minute; releasing a seat stamps
them too. Audited as `session.revoked`. `--break-persignout` ignores the
stamp and the test notices.

**Sign-out ends the provider's session too.** Sign-out clears our cookie
and then sends the browser to the provider's end-session page when its
discovery document offers one (RP-initiated logout:
`identity.OIDC.EndSessionURL`), naming our sign-in page as the place to
come back to and the application that asked. A provider without one gets
the plain sign-in page. On a shared machine that is the session that
matters. `--break-rplogout` stops at our cookie and the test notices.

**SAML 2.0 beside OpenID Connect.** A tenant whose provider is not OpenID
Connect (an older ADFS, a Shibboleth, or an Entra or Okta application the
security team has already approved as SAML) sets `protocol = saml` on the
same identity row (`0038_saml.sql`): the issuer becomes the provider's
entity id, our entity id (`https://<host>/saml/metadata`) is the audience
the assertion must name, the reply URL (`https://<host>/signin/saml`) is
our assertion consumer service, and the groups come from an attribute named
by the same role claim field. There is no client secret; trust runs through
the provider's signing certificate, pasted on the Sign-in page (PEM or bare
base64, parsed before it is stored) or given to `tenantctl create --protocol
saml --saml-sso-url … --saml-certificate-file …`. Our metadata is served at
`/saml/metadata` for the provider to import.

The adapter is `identity.SAML` (`internal/identity/saml.go`), the second
behind the same shape as `identity.OIDC`: `AuthURL` makes the request and
hands back its id, which the signed flow cookie remembers where OIDC keeps
its state; `Consume` opens the posted response and refuses one that is not
signed by the pinned certificate, does not name our entity id, answers
another request or none (identity-provider-initiated sign-in is refused
outright), is addressed elsewhere, or is outside its validity window. The
library is github.com/crewjam/saml v0.5.1, which carries the fixes for the
signature-bypass and multiple-assertion CVEs and runs the document through
an XML round-trip validator before parsing. `internal/identity/idptest`
grows a working SAML provider that signs real assertions, so the tests walk
the same path an Entra sign-in walks: `--break-saml` lets an assertion
answer any request and three tests notice; `--break-samlhost` lets a
sign-in begun on one tenant's hostname finish on another's.

**Single logout** (0043) closes the one thing SAML sign-out left open.
Each SAML tenant gets a signing key and certificate of its own, made the
first time one is needed, the key sealed under the tenant's key beside the
provider's certificate, the certificate published in our metadata with the
logout endpoint so the provider can verify what we sign. With the
provider's logout URL set on the Sign-in page (or `tenantctl create
--saml-slo-url`), sign-out sends the browser to the provider with a signed
LogoutRequest naming the person's NameID; the provider ends its session and
returns a signed LogoutResponse to `/signout/saml`, which has to be signed
by the pinned certificate, come from the provider's entity id, be addressed
to us, and answer the request the flow cookie remembers. The other way
round, a provider ending a session it started elsewhere sends a signed
LogoutRequest to the same endpoint; it is verified the same way, our
cookies go, and the provider gets a signed answer. The test provider
(`idptest`) pins our certificate from our metadata as a real one does and
refuses a request not signed by it. `--break-slosig` takes the provider's
request unsigned and the test notices; a request from another provider is
refused by the same check. Without a logout URL, sign-out ends our session
and goes to the sign-in page, as before.

One difference from OIDC decides the flow cookie: the provider returns on a
cross-site POST, and a SameSite=Lax cookie is withheld from exactly that
request, so the SAML flow cookie is SameSite=None and Secure, which is one
more reason the console runs on https. Sign-out for a SAML tenant without
a logout URL ends our session and stops at the sign-in page; with one, it
is the single logout above.

**Behind a load balancer, set `MDM_TRUSTED_PROXIES`.** Comma-separated CIDRs
or addresses. `X-Forwarded-For` is believed only when the socket peer is in
that set, and then the caller is the rightmost entry that is not itself a
trusted proxy. Unset, the header is ignored from everyone, which is right
with no proxy in front and collapses every per-address limit to one bucket
behind one. `--break-proxytrust` believes the header from anyone and the
sign-up cap test must see a stranger escape it. The rule is in
`internal/gateway/proxy.go`.

**The free-mail list is a list.** Thirty-two thousand domains, kept by
hand from two public lists at build time rather than fetched at run time;
a provider that appears tomorrow is refused when the list is next rebuilt,
or at once through the deployment's own file. The caps bound what gets
past it.

**A device certificate check costs a query.** One indexed lookup per device
request, deliberately not cached, because a cache in front of a revocation
check is a window during which a revoked device still works.

**Notifications coalesce.** Many devices failing at once is one event to
the person reading the channel: when several messages of one topic are
waiting together (three or more, `notify.DefaultCoalesceAbove`), the
outbox sends one digest that names them all, marks each row sent "as one
of N", and audits each; below the line they go one by one, as before. A
digest that fails to deliver puts every row back on the retry clock.
`--break-coalesce` sets the line out of reach and the test notices.

**The agent cannot wipe by itself.** It locks natively and puts the
firewall, disk encryption, password length and screen lock right when a
policy asks, but a wipe needs the helper an operator installs, and on a Mac
the lock delay after the screensaver needs the person's own password.
`agent.ScriptEnforcer` runs operator-supplied helpers.

**An agent can lie about what it sees.** Inherent to agent-based compliance.
The answer is hardware attestation, which is not built.

**Policy is judged, not delivered.** Nothing here configures a device. The
agent enforces locally and reports; pushing configuration needs the vendor
channels and the Apple half of that waits on the vendor certificate.

**Lost mode is delivered on Android only.** On an Apple device it stays
queued until the vendor certificate arrives. Google's own non-compliance
details are not surfaced: the engine judges from the facts Google reports,
and a `firewall_required` rule scoped to Android reads as unknown because
Android has no firewall to report.

**Quarantine stops nothing by itself.** On the platform it is a state a
person must release, a notification, and a `deny` on the access feed. What
the deny does depends on the tenant's network consulting the feed; the
platform cannot see whether it does. On the device it is a request to the
agent's enforcer, which does nothing unless an operator script is installed.
A Wi-Fi profile removal pushed to the device still waits on the vendor
channel.

**Person isolation has two controls** (0042). Row-level security separates
tenants; inside a tenant, the predicate in `data.MyDevices` is one control
and the database is the other: the claim's role, subject and email travel
into the transaction beside the tenant, and a restrictive policy on
`devices` and `device_compliance` holds an employee's transaction to the
devices of the person it belongs to, whatever the SQL asks for. For any
other role the policy is true, which is why an administrator asking for
their own page is narrowed by the Go predicate alone and `--break-mine`
still shows there. `--break-personsql` passes everything through the
policy and a raw query from an employee's transaction reads the tenant;
`./db/run.sh --break-personrls` drops the policy and the SQL suite's
section 6 notices.

**People are who the platform has met, not a directory.** Nothing is read
from the identity provider's user list; a person appears on sign-in, on
assignment or when HR names them. Name changes arrive at the next sign-in.

**Integration tests share one database**, so `run_go.sh` passes `-p 1` to run
packages sequentially. Without it they seed over each other, which is how the
first run of this sprint failed.

## Not here yet, deliberately

No SCEP, no NanoMDM spike, no signed Apple enrolment profile, and no
delivery of policy or lost mode to an Apple device.

The operator-scoped repository is also absent on purpose. Reads that
legitimately cross tenants, such as billing aggregates and the tenant list,
belong in their own package with their own role and no access to device,
policy or key tables. A comment in `internal/data/data.go` says so, because
adding a "just this once" escape hatch to `WithTenant` is how the isolation
model dies.

## Phase 0 is still open

Nothing in this folder needs Apple or Microsoft, and the Google half needs
only a service account the operator can create today. Everything Apple
still waits. The Apple MDM vendor CSR signing certificate is granted by hand on an
unpublished timeline and gates every Apple requirement in the PRD, so the
application should be in before this foundation is finished rather than after.
