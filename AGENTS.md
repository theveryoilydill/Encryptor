# For agents

## Use the Anthropic skills

When working on this repo, actually use the installed Anthropic skills — do not freelance:

1. **frontend-design** — for any UI work (new screens, restyling, components). Follow its guidance on intentional, non-templated visual choices; keep the theme above as the constraint.
2. **webapp-testing** — to verify your work in a real browser (Playwright). Drive the actual user flows (sign-in gate, encrypt, decrypt, sign, verify) and check the console for errors before you claim anything works.

## Before you flip a PR to "ready for review", check EVERYTHING

A PR is not done because it compiles. All of these must be green before "ready for review":

1. `bun run typecheck`, `bun run lint`, `bun run format:check`
2. `bun run build` (includes the OpenNext/Cloudflare bundle)
3. A real browser pass over the affected flows (see webapp-testing above) with zero console errors
4. The branch merges cleanly into its target — merge/rebase the target branch in, resolve conflicts, and make sure CI is green
5. No stray files (see "Keep the repo clean")

## Keep the repo clean

Do not put random files in the repo. Not allowed: agent worklogs/notes, scratch dirs, zip/patch dumps, editor leftovers, lockfiles from a different package manager (this repo uses **bun.lock** only), generated artifacts. If a file is not part of the product or required config, keep it out of the commit. Upload deliverables outside the repo (see "Uploading the finished product").

## If you need something, ping — don't guess

Missing credentials, unclear requirements, a decision you are not sure about? Stop and ask in the PR (comment and tag the owner) instead of inventing values, endpoints or scope. Never hardcode secrets or fake data to make something "work".

## Security and clean, mergeable code come first

1. Every change must preserve the security posture: no new uploads, no telemetry, no plaintext secrets on disk, no weakened crypto.
2. Keep diffs focused: one PR = one concern. No drive-by refactors mixed into feature PRs.
3. Prefer the smallest change that solves the problem, and resolve conflicts in favor of combining both sides' intent — never silently drop the target branch's newer work.

## Report comment at the end

When you finish work on a PR, leave ONE final comment on it: clean, concise, and structured — what changed, how it was verified (checks + browser flows), and any known limitations or follow-ups. The AI disclosure tag goes first (see attribution above).

## Theme

Keep it keybase colors for now, blue accent color, white background color, and black text. Try to keep things minimal and clean.

## Security

This is a high security project where it is critical that everything stays secure. Please make sure that there is no way anything can go wrong. Use these rules to help.

1. Minimize uploads: This will make it easier to see if anything is being exfiltrated.
2. Keep everything up to date: More on that below

## Always make sure it works

Do as much as you can with the info you are given to make sure that the product looks the best it can, works the best it can, etc.

## Up to date rule

Make sure that everything in the repo is the latest version. This is to get new features and remove vulnerabilities. Here are some examples of things to check for:

- Dependencies in package.json: Use bun update --latest to update.
- NodeJS: Make sure to use the latest
- Github workflows: Use the latest versions for steps like actions/checkout
- Package manager: Use the latest versions of package managers

## Code style

1. No more than 3 levels of recursion
2. Optimize for readability
3. Use DRY: Don't repeat code
4. Direct messages to the user, don't put an explaination for features that I asked you to add, like: Sign in with keybase, but don't store the unencrypted private key in memory.
5. No more than 3 levels of indentation in brackets — if you need a fourth, use another function (or return early from checks).
