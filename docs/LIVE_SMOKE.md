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

The workflow has two jobs on separate runners.

**`verify`** has no environment, so it cannot read the secret. It checks the guard,
checks out the exact SHA (`persist-credentials: false`), installs dependencies, runs
the offline tests, builds the sandbox image from `python:3.12-slim`, and runs
preflight plus 9 Docker isolation tests (network, privileges, exact env, pinned
seccomp, runtime attestation, PID 1).

**`smoke`** starts only after `verify` passes, on a fresh VM, so nothing the test
suite did can persist into it. The environment's reviewer approval is requested at
this point. In order:

1. Without the secret: guard, checkout, setup-uv, a fingerprint of the step
   environment (PATH plus variable names), install, image build, preflight.
2. Integrity gate, without the secret: the fingerprint must be unchanged (this catches
   `GITHUB_ENV`/`GITHUB_PATH` injection such as `BASH_ENV` or `LD_PRELOAD`), `HEAD`
   must equal `expected_sha`, tracked files must be unmodified, and the virtualenv is
   rebuilt from scratch with no cache.
3. **Only now** is the secret first read: a presence check that fails closed if it is
   missing and never shows the value.
4. The paid task. The secret is in the **controller** process environment only.
5. With the secret: scans `runs/` for the key and its encodings, and for any
   Anthropic-key-shaped string. Artifacts are uploaded **only** if the scan is clean.
6. Writes a job summary: status, API calls, tokens, estimated cost, failed requests,
   ledger state.

The secret reaches three steps only (presence check, paid run, artifact scan).
`tests/test_live_workflow.py` enforces this structure.

## Cost bound for one run

- **At most 12 API requests.** `--max-model-calls 12` is enforced in the provider
  before each request, and the agent loop has at most 12 iterations with one request
  each. Failed requests count, and the third invalid or failed response ends the run.
- **Bounded before every request.** Each request's worst-case cost (estimated input
  tokens at the cache-write rate plus the full 1,024-token output allowance) is
  reserved in the ledger and checked against both $0.50 caps *before* it is sent.
  A request that would exceed either cap is never sent. Haiku prompts over 100k
  tokens are refused because they would fall into a different price tier.
- **Realistic worst case is far below $0.50.** The 150k total-token budget bounds
  successful calls at about $0.025 (150k × $0.125/MTok + 12 × 1,024 × $0.50/MTok).
  Up to 3 ambiguous failures (timeouts, resets, 5xx) are charged at their worst case,
  at most about $0.013 each. The total is under $0.07.
- These are estimates from published prices. The first request's input estimate is a
  byte-count heuristic, so one request could exceed its estimate. The Anthropic
  Console is authoritative.
  `test_live_smoke_configuration_is_bounded` simulates this exact configuration with
  a never-finishing model, maximal usage and constant timeouts.

## How the secret is kept from the sandbox

The controller passes the Docker CLI a filtered environment (`PATH`, `HOME`,
`DOCKER_*` only). Each container is created with `--env` values for exactly the six
configured variables, plus a per-run nonce that the entrypoint removes. The
container's environment is then:

1. verified with `docker inspect` (it must match exactly) before start;
2. scrubbed again by the PID 1 entrypoint before the test command runs.

`test_env_is_minimal` and `test_sr02_*`, which run in the `verify` job, plant credential-like variables in the host environment and assert that
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
  full commit SHAs to limit this. `uv`, which runs in the secret-bearing steps, is
  pinned to release 0.11.32, and setup-uv checks the download against a pinned
  sha256 before use. The pinned setup-uv (v5.4.2) has no built-in checksum for this
  release, so the explicit `checksum` is what makes the check happen.
  `test_uv_version_and_checksum_pinned` enforces both pins.
- **Repository tests run in the sandbox** (shared kernel, see `SECURITY_REVIEW.md`
  A-1). The secret is not in the container, but a kernel escape would reach the
  runner, and with it the controller's environment.
- **Spend between runs** is bounded only by Console-side limits (see above).
