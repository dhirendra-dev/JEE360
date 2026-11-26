# JEE360 on Cloudflare Workers

JEE360 is deployed as an independent Cloudflare Worker with a dedicated D1 database. It does not share the JEE Prep Hub Worker, D1 database, or domain.

## Included

- Email/password account registration and sign-in
- Authenticated password changes with current-password verification and session rotation
- PBKDF2-SHA-256 password hashing with per-account random salts
- Opaque, hashed, HttpOnly, Secure, SameSite=Lax session cookies (30-day expiry)
- Per-account task and subject records
- Study-session logging and daily study goal
- 25-minute focus and 5-minute break timer; completed focus blocks are saved automatically
- Seven-day study activity chart, all-time study total, and consecutive study-day streak
- Task search plus All, Open, Completed, and High-priority filters
- Subtle entrance, progress, and interaction animations with reduced-motion support
- Responsive cream-and-blue light theme and balanced dark theme
- System theme detection, manual theme toggle, and saved theme preference
- Server-side ownership checks for every private record
- Same-origin mutation checks and input validation
- Per-IP authentication attempt throttling and constant-time password-hash comparison

## Database

The production D1 database is named `jee360-production` (binding: `DB`). The canonical bootstrap schema is `schema.sql`; versioned, idempotent D1 migrations live in `migrations/` and are configured by `wrangler.toml`.

From this directory, inspect and apply migrations with:

```sh
npx wrangler d1 migrations list jee360-production --remote
npx wrangler d1 migrations apply jee360-production --remote
```

Do not apply schema changes during Worker startup or as a side effect of a deployment. Future schema changes must be new, sequential files (for example, `0002_add_feature.sql`); do not edit an already-applied migration. The initial migration uses `IF NOT EXISTS` so it can safely baseline a database that was previously created from `schema.sql`.

The schema adds database-enforced ownership checks for subject references, case-insensitive per-user subject uniqueness, range constraints, and indexes for the dashboard's user-scoped query paths. The health endpoint probes each required table directly rather than querying SQLite's internal schema catalog.

## Worker

Entry point: `worker.js`

Public app: https://jee360.jeeprephubofficial.workers.dev

Health endpoint: https://jee360.jeeprephubofficial.workers.dev/api/health

Required binding:

| Binding | Type | Resource |
|---|---|---|
| `DB` | D1 | `jee360-production` |

The Worker is intentionally deployed under its own name and workers.dev hostname. No existing JEE Prep Hub Worker or custom domain is modified.

## Security notes

- Passwords are never stored in plaintext.
- Session tokens are stored as SHA-256 hashes and only delivered in Secure, HttpOnly cookies.
- Every task, subject, setting, and study-session query is scoped to the authenticated user.
- OAuth/social login and email verification are not enabled because no provider credentials or transactional email service have been provisioned. Email/password accounts are fully supported.
- Configure account recovery and verified-email flows before opening public registration at large scale.
