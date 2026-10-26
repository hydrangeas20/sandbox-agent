# Live smoke test on GitHub Actions (Claude Haiku 5.5)

`.github/workflows/live-smoke.yml` runs **one** paid real-model task: the
`paginator` fixture on `claude-haiku-5-5`, capped at **$0.50** for the task and
**$0.50** for the run's ledger. It never runs automatically.

## One-time setup (repository owner, in the GitHub web UI)

These settings are the actual security boundary. The `if:` guards inside the
workflow only protect *this* copy of the file. Someone with write access could
dispatch a modified copy from another branch, so the environment must refuse
every branch except `main`.

1. **Check your plan, since the repository is private.** GitHub's
   [environment documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
   says:
   - **GitHub Free:** environment secrets are *not available* in private repositories,
     so the workflow's secret check will always refuse to run.
   - **GitHub Pro or Team:** environment secrets and **deployment branch** restrictions
     work in private repositories, but **required reviewers do not** (on Free, Pro and
     Team they are public-repository only).
2. **Protect `main`.** Settings → Branches (or Rules), applied to `main`:
   - require a pull request before merging;
   - block force pushes and deletion;
   - preferably include administrators.

   Without this, anyone with write access, including an AI coding session with push
   access, could push a workflow change straight to `main`.
3. **Create the environment.** Settings → Environments → **New environment** →
   `sandbox-agent-eval`:
   - **Deployment branches and tags:** *Selected branches and tags* → add `main` only.
     Do **not** add `refs/pull/*`.
   - **Required reviewers** (if your plan offers it): add yourself and enable
     *Prevent self-review* only if someone else will approve.
   - **Environment secret:** `ANTHROPIC_API_KEY`. Use a dedicated key in a dedicated
     Console workspace with a monthly spend limit (see "Budget" below). Do not add
     it as a *repository* secret: repository secrets reach every workflow on every
     branch.
4. **Merge to `main`.** GitHub only offers `workflow_dispatch` for workflows on the
   default branch. `main` currently has only the initial empty commit, so PR #1 (or a
   reviewed subset containing this workflow and the code it runs) must be merged first.

## Running it (only after explicit approval)

Actions → **live-smoke (manual, paid)** → *Run workflow* on `main`, with:

- `expected_sha`: the full SHA of the reviewed commit at the tip of `main`. The job
  refuses to run if `main` has moved, so you run exactly what you reviewed.
- `confirm`: `RUN-PAID-HAIKU-SMOKE`

The job, in order:

1. Checks the guard, then that the secret is present. It fails closed if missing,
   and never shows the value.
2. Checks out that exact SHA with `persist-credentials: false`.
3. Without the secret: installs dependencies, runs the offline tests, builds the
   sandbox image from `python:3.12-slim`, runs preflight and 9 Docker isolation tests
   (network, privileges, exact env, pinned seccomp, runtime attestation, PID 1).
4. Runs the paid task. The secret is in the **controller** process environment only.
5. With the secret: scans `runs/` for the key and its encodings, and for any
   Anthropic-key-shaped string. Artifacts are uploaded **only** if the scan is clean.
6. Writes a job summary: status, API calls, tokens, estimated cost, failed requests,
   ledger state.

## How the secret is kept from the sandbox

The controller passes the Docker CLI a filtered environment (`PATH`, `HOME`,
`DOCKER_*` only). Each container is created with `--env` values for exactly the six
configured variables, plus a per-run nonce that the entrypoint removes. The
container's environment is then:

1. verified with `docker inspect` (it must match exactly) before start;
2. scrubbed again by the PID 1 entrypoint before the test command runs.

`test_env_is_minimal` and `test_sr02_*`, which run in this job before the paid
step, plant credential-like variables in the host environment and assert that
they are absent inside the container.

## Spend ledger on GitHub Actions: what it does and does not protect

- **Within one run:** every model request is reserved in `runs/spend-ledger.json`
  before it is sent and settled afterwards. Retries reserve against the same $0.50.
  A request that would exceed it is refused.
- **Across runs: no protection.** The runner is destroyed after the job, and the
  ledger goes with it. Each run starts with an empty ledger and its own $0.50
  limit. The ledger is uploaded as an artifact (14-day retention) **for audit only**;
  it is not read back by later runs. Two dispatches are two independent $0.50
  budgets. The `concurrency` group only prevents them from running at the same time.
- **Cross-run limits must come from outside the runner:**
  - a monthly **spend limit** on a dedicated Console workspace, with the key scoped
    to that workspace (not available on the Default Workspace). Its exact enforcement
    behaviour and minimum amount are not documented;
  - a prepaid balance with auto-reload **off**;
  - deleting or rotating the key after the experiment.
- Ledger figures are estimates from published prices. The Anthropic Console usage
  page is authoritative.

## Remaining risks

- **Write access is enough to redirect a run** unless `main` is protected and the
  environment is restricted to `main`. This includes AI coding sessions with push
  access. On Pro and Team, private repositories cannot require a reviewer.
- **The key exists on the runner** while the controller runs. A compromise of the
  runner image or a pinned third-party action could read it. Actions are pinned to
  full commit SHAs to limit this.
- **Repository tests run in the sandbox** (shared kernel, see `SECURITY_REVIEW.md`
  A-1). The secret is not in the container, but a kernel escape would reach the
  runner, and with it the controller's environment.
- **Spend between runs** is bounded only by Console-side limits (see above).
