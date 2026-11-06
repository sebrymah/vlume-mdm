# Deploying: Supabase (database), Fly.io (gateway), Vercel (public site)

```
 visitors ──▶ Vercel   www.<domain>        public page, "Sign in" finder
                │  form posts to
                ▼
 browsers ──▶ Fly.io   app.<domain>        home, sign-up, /find
 devices  ──▶ Fly.io   <name>.<domain>     each organisation's console and device API
                │  database logins (mdm_app, mdm_operator)
                ▼
              Supabase Postgres             row-level security keeps tenants apart
```

Everything below has been rehearsed locally: all 44 migrations applied as a
role limited the way Supabase's `postgres` is, the cross-tenant isolation suite
(18 checks) run on that database with its negative control, and the real image
started against it. What has NOT been done is anything on your three accounts, so `fly.toml`
and `vercel.json` are untested against the real services (neither CLI is installed here).

**Why the gateway is on Fly and not Vercel.** The gateway is one long-running
process with its own timers (notifications, Android sync, weekly reports), a
database `LISTEN` connection and per-organisation hostnames. Vercel runs short
functions. The public page is exactly what Vercel is good at.

## What you need first

| Need | Why | Note |
|---|---|---|
| A domain you control | Each organisation gets `<name>.<domain>`; Fly's own `*.fly.dev` cannot do that | One purchase, then two DNS records |
| Supabase account | The database | Choose a region near your customers; Europe (London) is the closest Supabase offers to West Africa (assumption, check their current list) |
| Fly.io account with a card | Runs the gateway | Roughly 5 to 6 US dollars a month for the size in `fly.toml` (assumption, check Fly's pricing page) |
| Vercel account | The public page | Free tier is enough |
| A mail server (SMTP) | Sign-up, invitations and reset links are emails | Your Zoho Mail works: `smtp.zoho.com:587`, STARTTLS |
| The Android service-account JSON | Android management | The file you already use in the demo |

## 1. Supabase: the database

You: create a project (name `vlume`, strong database password saved in your password manager).
Then open **Connect** and copy two strings:

- **Session pooler** (host `aws-0-<region>.pooler.supabase.com`, port **5432**, user `postgres.<ref>`). Works from a Mac without IPv6.
- Use the same session-pooler form for the gateway. **Never port 6543** (transaction mode): the gateway keeps a `LISTEN` connection and uses prepared statements, and neither works there.

Run the setup (it needs Docker, and nothing else is installed):

```bash
export SUPABASE_DB_URL='postgresql://postgres.<ref>:<database-password>@aws-0-<region>.pooler.supabase.com:5432/postgres'
```

```bash
"/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform/deploy/supabase/apply.sh"
```

It creates the seven roles, applies the 44 migrations once each, and prints two
generated passwords, **once**: `mdm_app` and `mdm_operator`. Put them in your password
manager now. Running it again is safe and changes nothing.

Build the two connection strings the gateway needs (note the user is `<role>.<ref>`):

```
MDM_APP_DSN       postgres://mdm_app.<ref>:<app-password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require
MDM_OPERATOR_DSN  postgres://mdm_operator.<ref>:<operator-password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require
```

Two settings to switch on in the Supabase dashboard: **Database, Backups** (daily is on by
default; point-in-time recovery is a paid add-on and worth it before real customers) and
**Settings, Data API: turn the REST API off**. The platform talks to Postgres directly, so
nothing should be reachable through Supabase's own API.

## 2. Fly.io: the gateway

```bash
brew install flyctl
```

```bash
fly auth login
```

Edit the three `EDIT` lines in `fly.toml` (app name, region, your domain). Then:

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly apps create vlume-mdm
```

**The sealing key protects every organisation's stored secrets. If it is lost they
cannot be read again, and Fly never shows a secret back.** So make it first, save it, then set it:

```bash
openssl rand -base64 32
```

Save that line in your password manager as `MDM_SEALING_KEY` (prefix it with `base64:` when you set it, below). Then:

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly secrets set \
  MDM_SEALING_KEY="base64:<the line you saved>" \
  MDM_CLAIM_SIGNING_KEY="base64:$(openssl rand -base64 32)" \
  MDM_SESSION_SIGNING_KEY="base64:$(openssl rand -base64 32)" \
  MDM_APP_DSN="<the app string above>" \
  MDM_OPERATOR_DSN="<the operator string above>" \
  MDM_SMTP_SERVER="smtp.zoho.com:587" MDM_SMTP_FROM="<your sending address>" \
  MDM_SMTP_USERNAME="<your sending address>" MDM_SMTP_PASSWORD="<its app password>"
```

The other two keys can be regenerated at any time (it signs everyone out), so only the sealing key needs keeping.

Android (optional until you bind a real Google enterprise):

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly secrets set MDM_ANDROID_CREDENTIALS_B64="$(base64 < "/full/path/to/android-service-account.json" | tr -d '\n')"
```

Deploy:

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly deploy
```

## 3. DNS and certificates

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly ips list
```

At your domain's DNS provider add (the `fly certs` command below prints the exact challenge records):

| Name | Type | Value |
|---|---|---|
| `app` | A and AAAA | the two addresses from `fly ips list` |
| `*` | A and AAAA | the same two addresses (every organisation's console) |
| `_acme-challenge` | CNAME | the value `fly certs add` prints (needed for the wildcard) |
| `www` | CNAME | Vercel's value (step 4) |

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly certs add app.<domain>
```

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly certs add "*.<domain>"
```

## 4. Vercel: the public page

Edit `deploy/site/config.js`: set `app` to `https://app.<domain>`. Then:

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform/deploy/site" && npx vercel login
```

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform/deploy/site" && npx vercel --prod
```

In the Vercel project, **Settings, Domains**: add `www.<domain>` and follow the DNS value it shows.

## 5. Check it

1. `https://www.<domain>` shows the page; "Set up your company" opens `https://app.<domain>/signup`.
2. Sign up with "I do not have an identity provider". The welcome email arrives; the link sets a password.
3. Sign in at `https://<name>.<domain>/signin`, set up the authenticator app, and you are in as Super Admin.
4. Look at the audit trail: the sign-in line should show your real address, not one starting `172.16`. If it shows `172.16`, tell me and I will change `MDM_TRUSTED_PROXIES`.

## Running a one-off command (list organisations, add a host)

```bash
cd "/Users/tobi.adeyemo/BG_Cowork/Claude Cowork/Projects/MDM_Platform/platform" && fly ssh console -C "tenantctl list"
```

## Later migrations

Each new `db/migrations/NNNN_*.sql` goes up with the same `apply.sh`. A migration that
adds a `SECURITY DEFINER` function owned by one of the four definer roles needs nothing
extra, because `00_roles.sql` already lets the migrating user act as them.

## Not decided yet

- **Windows devices** are not enrolled yet; the page says "Windows next" on purpose.
- **Payment at sign-up** is not built; organisations are created free.
- **Apple** stays parked until the vendor certificate exists.
