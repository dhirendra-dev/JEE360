# JEE360 on Cloudflare Workers

JEE360 is deployed as an independent Cloudflare Worker with a dedicated D1 database. It does not share the JEE Prep Hub Worker, D1 database, or domain.

## Included

- Email/password account registration and sign-in
- PBKDF2-SHA-256 password hashing with per-account random salts
- Opaque, hashed, HttpOnly, Secure, SameSite=Lax session cookies (30-day expiry)
- Per-account task and subject records
- Study-session logging and daily study goal
- Server-side ownership checks for every private record
- Same-origin mutation checks and input validation

## Database

The production D1 database is named `jee360-production`. Its schema is versioned in `schema.sql`. Apply schema changes using the Cloudflare D1 migration workflow, not during application startup.

## Worker

Entry point: `worker.js`

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
