# JEE360

JEE360 is a personal JEE preparation planner with Cloudflare Workers and D1 as its production platform.

The Cloudflare implementation lives in `cloudflare/`. See [Cloudflare deployment and architecture](cloudflare/README.md).

## Current production components

- Cloudflare Worker: `jee360`
- Cloudflare D1: `jee360-production`
- Account system: email/password with secure sessions
- Planner: tasks, subjects, study-session logging, and daily goals

The older TanStack workspace scaffold is retained for future integration; it is not the deployed production entry point yet.
