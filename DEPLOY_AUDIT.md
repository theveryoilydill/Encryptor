# Deploy Audit: why non-main branches land in Cloudflare production

<!-- Mr. AI Acting on s183173's Behalf -->

Status: **root cause corrected after dashboard screenshot (second pass); repo-side hardening applied in this PR.**

## Correction vs first pass

The first version of this audit claimed the Workers Builds **production branch was set to
`develop`**. The owner's dashboard screenshot disproved that: **Branch control = `main`**
on the Production builds tab. The revised diagnosis below is based on the screenshot,
additional check-run data from PR branches, and the Workers Builds documentation.

## TL;DR (corrected)

The Workers Builds Git integration runs **`bunx wrangler deploy`** for builds. Because
`wrangler.json` defines **no environments**, `wrangler deploy` has exactly one target:
the production worker `encryptor`. The command does not depend on the branch, so every
branch build — `develop` merges, PR branches, even dependabot branches — promotes itself
to the worker's **Active (production) Deployment** instead of saving as a preview version.
Per Cloudflare's docs, builds only save as versions (without promotion) when the build
runs `wrangler versions upload`.

## Evidence

1. Dashboard screenshot (Production → Settings → Builds):
   - Git repository: `theveryoilydill/Encryptor`
   - Build command: `bun run build`, Deploy command: **`bunx wrangler deploy`**, Root: `/`
   - Branch control: **`main`** ("Pushes to this branch will automatically trigger builds")
   - Builds sub-tabs: **Production** / **Previews Base**
2. GitHub check-runs (app `cloudflare-workers-and-pages`, name `Workers Builds: encryptor`)
   — the dashboard URLs always land under `/production/builds/`, including for branches
   that should never touch production:

   | Commit    | Branch                           | Context      | WB build started (UTC) |
   | --------- | -------------------------------- | ------------ | ---------------------- |
   | `c1a0f27` | develop                          | PR #54 merge | 2026-09-22 02:03:19    |
   | `e80ecbe` | develop                          | PR #53 merge | 2026-09-22 02:02:18    |
   | `ddd6a61` | develop                          | PR #52 merge | 2026-09-22 02:01:17    |
   | `6ecc155` | develop                          | PR #48 merge | 2026-09-22 00:52:55    |
   | `0ff3e13` | ai/postquantum-algos             | open PR #47  | 2026-09-16 04:04:49    |
   | `d3fa4e5` | ai/qol-features                  | open PR #46  | 2026-09-16 04:38:31    |
   | `04502ca` | dependabot/npm_and_yarn/recharts | open PR #41  | 2026-09-18 22:08:17    |
   | `9ed5d88` | dependabot/npm_and_yarn/oxfmt    | open PR #38  | 2026-09-18 22:06:42    |
   | `9ee690d` | main                             | direct push  | 2026-09-12 22:07:46    |

   Every merge into `develop` produced a build ~1 minute after the merge.

3. Repo-side elimination:
   - `.github/workflows/`: `nextjs.yml` (legacy GitHub Pages, `main` only, build fails),
     `ci.yml` (typecheck/lint/format), `AutoFormat.yml` (formatting), `codeql.yml`
     (scanning) — **no Cloudflare deploy step exists on the GitHub side**.
   - `wrangler.json` (before this PR): a single top-level worker (`name: "encryptor"`)
     with **no `env` blocks**, so `wrangler deploy` from any context mutates production.

## Mechanism (per Cloudflare docs)

- Workers Builds docs (Workers → CI-CD → Builds): "Production branch builds create a new
  version under Version History. If the build is configured to deploy, that version is
  promoted to the Active Deployment." and "To disable automatic deployments while still
  allowing builds to run automatically and save as versions (without promoting them to an
  active deployment), update your deploy command to: `npx wrangler versions upload`."
- With deploy command `bunx wrangler deploy` and no environments in `wrangler.json`,
  every build that runs that command deploys the production worker — branch is irrelevant.

## Fix

### Dashboard (owner, ~1 minute — the actual kill switch)

1. Workers & Pages → `encryptor` → Settings → Builds → **Previews Base** tab.
2. Make sure the command non-production builds run is **`bunx wrangler versions upload`**
   (not `wrangler deploy`). Then only `main` builds promote to Active Deployment; all
   other branches produce versions/previews that never receive production traffic.
3. Leave the Production tab's deploy command as `bunx wrangler deploy`.

### Repo-side hardening (applied in this PR)

- `wrangler.json`: new `env.preview` targeting a separate worker `encryptor-preview`
  (explicit `main` + `assets` + `compatibility_*`; `name` overridden so it can never
  collide with the production worker). Bindings are not inherited by wrangler
  environments, so `env.preview` intentionally has **no `REGISTRY_DB` binding** — a
  preview deploy cannot read or write the production registry D1. Verified with
  `wrangler deploy --dry-run --env preview` (preview resolves to ASSETS only) and
  `wrangler deploy --dry-run` (top-level still resolves to REGISTRY_DB + ASSETS).
  Note: registry endpoints will error on preview until a dedicated preview D1 is
  deliberately wired into `env.preview`.
- `package.json`: new `deploy:preview` script —
  `next build && opennextjs-cloudflare build --skipNextBuild && bunx wrangler deploy --env preview` —
  so manual preview deploys have an explicit, safe target instead of reusing
  `bun run deploy` (which stays production-only).
- `.github/dependabot.yml`: `target-branch: "develop"` — Dependabot PRs were the odd ones
  out (e.g. PR #41 targeted `main` while the team flow merges everything into `develop`).

## Recommended follow-ups

- Retire or repair `.github/workflows/nextjs.yml` — dead GitHub Pages pipeline that fails
  on every `main` push.
- Optionally create `encryptor-registry-preview` (D1) and bind it in `env.preview` when
  registry features are needed on preview deploys.
- Consider branch protection on `main` and `develop` so only PR merges land there.
- Merge-order note: merging this PR into `develop` will itself trigger a build — with the
  dashboard fix from above applied first, that build will no longer promote to production.
