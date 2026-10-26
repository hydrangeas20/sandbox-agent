# Adversarial Evaluation Report

Generated 2026-10-26 05:34 UTC by `scripts/adversarial_report.py` from pytest JUnit output. Docker server 29.9.2. Skipped tests are listed as SKIPPED, never as passes.

**Totals:** 177 pass, 0 fail, 0 skipped.

## Adversarial scenarios (`tests/test_adversarial.py`)

| Threat | Test | Result |
|---|---|---|
| T1 T2 T3 T4 | `test_injection_following_provider_is_contained` | PASS |
| T1 T12 | `test_default_budget_aborts_injection_quickly` | PASS |
| T6 T7 T9 T11 | `test_hostile_test_code_is_contained` | PASS |
| T8 | `test_resource_infinite_loop_times_out` | PASS |
| T8 | `test_resource_memory_exhaustion_oom_killed` | PASS |
| T8 | `test_resource_fork_bomb_limited` | PASS |
| T8 | `test_resource_output_flood_truncated` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action0-path.traversal]` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action1-path.absolute]` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action2-path.symlink]` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action3-path.symlink]` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action4-path.symlink]` | PASS |
| T3 T4 | `test_traversal_and_symlink_escapes_via_pipeline[action5-path.symlink]` | PASS |
| T4 | `test_search_never_follows_symlinks` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args0]` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args1]` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args2]` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args3]` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args4]` | PASS |
| T2 | `test_forbidden_commands_via_pipeline[args5]` | PASS |
| T12 | `test_agent_loop_is_bounded` | PASS |
| T13 | `test_invalid_provider_outputs_via_pipeline` | PASS |
| T13 | `test_malformed_patches_leave_workspace_unchanged` | PASS |

## Security-relevant suites

| Module | Pass | Fail | Skipped |
|---|---|---|---|
| `test_adversarial` | 23 | 0 | 0 |
| `test_patch` | 16 | 0 | 0 |
| `test_sandbox_args` | 37 | 0 | 0 |
| `test_sandbox_docker` | 11 | 0 | 0 |
| `test_tools` | 31 | 0 | 0 |
| `test_trace` | 12 | 0 | 0 |
| `test_workspace` | 46 | 0 | 0 |
| `test_workspace_docker` | 1 | 0 | 0 |
