# Build & deploy target

Cloudflare Workers is the sole production deployment target. The default `npm run build` and explicit `npm run build:cloudflare` commands use Nitro's `cloudflare_module` preset. Do not add Vercel adapters, build scripts, deployment workflows, or configuration.

Production builds must emit valid Worker output. Watch for dev-only dependencies, server-only Node APIs at import time, runtime filesystem writes, and hard-coded hosts, ports, or secrets.

## A passing build does not mean the deployed app renders

The most common blank-deploy failure is a built HTML document requesting JS assets that return 404 or the HTML fallback with the wrong MIME type. Verify that generated assets resolve correctly and that the Worker serves the app shell and static assets correctly.

If you edited source after kicking off the build, re-run `npm run build:cloudflare` before testing the new output.

## What `vite.config.ts` already does

The workspace ships a ready `vite.config.ts` and `tsconfig.json` — don't recreate them or import a vendored preset. The config:

- binds the dev port `0.0.0.0:8080`;
- pins `vite preview` to loopback `127.0.0.1:8081`, so built output is not picked up as the live preview;
- gates Nitro on `command === "build" || isPreview`, so it never runs in dev and does not open a second dev-server port;
- defaults Nitro to the Cloudflare `cloudflare_module` preset;
- mounts `grokPwaPlugin()`.

If you edit it, preserve both port contracts, the build/preview-gated Nitro plugin including its `serverDir: "./server"` option, and `grokPwaPlugin()`.
