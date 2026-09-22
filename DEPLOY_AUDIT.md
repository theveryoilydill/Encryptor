# Deploy Audit: why `develop` pushes land in Cloudflare production

<!-- Mr. AI Acting on s183173's Behalf -->

Status: **root cause identified — fix is a Cloudflare dashboard setting, not a repo change.**

## TL;DR

The repo contains **no** Cloudflare deploy workflow (checked all of `.github/workflows/`).
Deploys are performed by Cloudflare's Git integration — the **Workers Builds** GitHub App
(`cloudflare-workers-and-pages`), project `encryptor`, account `222a870054499e3a409b0387fd013fc2` —
and that integration's **production branch is set to `develop`**. Workers Builds deploys the
production branch straight to the worker's production environment on every push, so every merge
into `develop` goes live immediately, exactly the behavior `main` used to have.

## Evidence

1. GitHub check-runs posted by app `cloudflare-workers-and-pages`, name `Workers Builds: encryptor`,
   all pointing at `.../workers/services/view/encryptor/**production**/builds/...`:

   | Commit | Branch | PR | Merge time (UTC) | WB build started (UTC) | Target |
   |---|---|---|---|---|---|
   | `c1a0f27` | develop | #54 | 2026-09-22 02:02:23 | 2026-09-22 02:03:19 | production |
   | `e80ecbe` | develop | #53 | 2026-09-22 01:48:41 | 2026-09-22 02:02:18 | production |
   | `ddd6a61` | develop | #52 | 2026-09-22 01:33:42 | 2026-09-22 02:01:17 | production |
   | `6ecc155` | develop | #48 | 2026-09-22 00:51:55 | 2026-09-22 00:52:55 | production |
   | `9ee690d` | main | — | direct push | 2026-09-12 22:07:46 | production |

   Every merge to `develop` produced a production build ~1 minute later. Preview builds would
   show `/preview/builds/` in the dashboard URL; these all say `/production/builds/`.

2. Repo-side elimination:
   - `nextjs.yml` → GitHub Pages only, `main` only, and its builds fail (legacy leftover).
   - `ci.yml` → typecheck/lint/format only.
   - `AutoFormat.yml` → formatting only.
   - `codeql.yml` → security scanning only.
   - No `wrangler deploy` / `opennextjs-cloudflare deploy` call exists in any workflow,
     so nothing on the GitHub side can deploy to Cloudflare.

3. `wrangler.json` defines a single top-level worker (`name: "encryptor"`) with **no `env`
   blocks**. There is exactly one production deployment target and nothing else — whatever
   deploys, deploys to production.

## Why this happened

Workers Builds decides which branch is "production" in the **Cloudflare dashboard**, not in the
repo. At some point the `encryptor` Worker's Git integration was (re)connected with
`develop` chosen as the production branch (the early-August commit history —
"This is supposed to make deploy work", "I should probably stop using the cloudflare ai agent" —
shows the deploy setup went through a rough patch where a reconnect was likely).

## Fix (dashboard, ~1 minute)

1. Cloudflare Dashboard → **Workers & Pages** → `encryptor` → **Settings** → **Build** →
   Git integration.
2. Change **Production branch** from `develop` back to `main`.
3. Optional but recommended: enable **non-production branch builds** so pushes to `develop`
   and PR branches build to preview versions/URLs instead of being ignored.

No repo change is required for the fix itself; this document is the record.

## Recommended hardening (follow-ups)

- `wrangler.json`: add an `env.preview` (separate worker name + preview bindings) and use
  `opennextjs-cloudflare deploy` with explicit environments, so manual `bun run deploy` can
  never silently hit production from an arbitrary branch.
- Retire or repair `.github/workflows/nextjs.yml` — it deploys to GitHub Pages from `main`,
  which this project abandoned, and it currently fails on every main push.
- Consider branch protection on `main` and `develop` so only PR merges land there (Dependabot
  PR #41 currently targets `main` while everything else targets `develop` — worth aligning).
- Note the irony for merge order: merging *this* PR into `develop` will itself trigger a
  production deploy of the audit doc — flip the dashboard setting first, or merge last.
