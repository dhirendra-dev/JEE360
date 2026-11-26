# Cloudflare Workers migration

This branch makes Cloudflare Workers the default Nitro build target while retaining an explicit Vercel build target.

## Build commands

- `npm run build:cloudflare` builds Nitro with the `cloudflare_module` preset.
- `npm run build:vercel` builds with the Vercel preset.
- `npm run db:migrate` applies the SQL migrations to the configured database. Database migrations are deliberately not run as a side effect of a frontend/server bundle build.

## Production migration requirements

A successful build is not sufficient to make this application production-ready on Workers. The existing application has server-side database and authentication assumptions that must be migrated and verified before routing real users to it.

1. **Database connection:** `src/lib/db.ts` creates a `pg.Pool` from `process.env.DATABASE_URL`. On Workers, production PostgreSQL access should use a Cloudflare Hyperdrive binding. Refactor the SQL client to resolve the binding from the request/runtime environment and keep the existing parameterized query interface.
2. **Better Auth:** `src/lib/auth/server.ts` constructs a PostgreSQL pool at module scope and currently falls back to an embedded PGLite/Kysely dialect when `DATABASE_URL` is absent. The Worker deployment must use the persistent Hyperdrive-backed database; the PGLite fallback is for local preview only and must never be used for production sessions.
3. **Runtime compatibility:** audit all Node built-ins and dependencies under the Workers `nodejs_compat` runtime. Exercise auth callbacks, cookie handling, file APIs, and every server function against the built Worker runtime.
4. **Schema:** provision the production database and apply `migrations/*.sql` plus the opt-in Better Auth schema using the repository's migration process. Do not run migrations automatically during a deployment build.
5. **Secrets:** configure `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL`, OAuth broker credentials, and the database/Hyperdrive binding through Cloudflare secrets and bindings. Never commit these values.
6. **Release:** deploy to a new Worker name first, run smoke tests for public routes, sign-in/sign-out, session persistence, and core planner CRUD, then attach a custom domain only after the checks pass.

## Safety

Do not replace the existing `jeeprephubofficial` Worker or change the `jeeprep.in` zone as part of this migration. Use a distinct JEE360 Worker and preview URL until the migration is verified.
