# Adversarial Evaluation Report

Generated 2026-10-26 20:49 UTC by `scripts/adversarial_report.py` from pytest JUnit output. Docker server 29.9.2. Skipped tests are listed as SKIPPED, never as passes.

**Totals:** 289 pass, 0 fail, 0 skipped.

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

## Security-review regressions (`tests/test_security_review*.py`)

Finding IDs refer to `docs/SECURITY_REVIEW.md`. Before/after evidence for each is in
`docs/security-review/REGRESSION_EVIDENCE.md`.

| Finding | Test | Result |
|---|---|---|
| SR-01 | `test_sr01_create_args_pin_profile_and_wrap_command` | PASS |
| SR-01 | `test_sr01_pinned_profile_is_enforced` | PASS |
| SR-01 | `test_sr01_runtime_attestation_catches_weak_seccomp[allow_all]` | PASS |
| SR-01 | `test_sr01_runtime_attestation_catches_weak_seccomp[unconfined]` | PASS |
| SR-01 | `test_sr01_verify_rejects_apparmor_unconfined_and_entrypoint` | PASS |
| SR-01 | `test_sr01_verify_rejects_tampered_pinned_profile` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[allow_all_profile]` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[apparmor]` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[no_profile]` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[paths]` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[selinux_disabled]` | PASS |
| SR-01 | `test_sr01_verify_rejects_weak_security_options[unconfined]` | PASS |
| SR-02 | `test_sr02_container_env_is_exactly_configured` | PASS |
| SR-02 | `test_sr02_image_with_extra_env_fails_closed` | PASS |
| SR-02 | `test_sr02_verify_rejects_image_provided_env` | PASS |
| SR-03 | `test_sr03_editing_tests_cannot_produce_success` | PASS |
| SR-03 | `test_sr03_final_diff_gate_catches_out_of_band_changes` | PASS |
| SR-03 | `test_sr03_protected_path_variants[./tests/test_core.py]` | PASS |
| SR-03 | `test_sr03_protected_path_variants[tests//test_core.py]` | PASS |
| SR-03 | `test_sr03_protected_path_variants[tests/test_core.py]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[.sandbox-agent/policy.toml]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[conftest.py]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[evals/tasks.json]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[pkg/conftest.py]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[pkg/evil.pth]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[pyproject.toml]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[pytest.ini]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[setup.cfg]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[sitecustomize.py]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[tox.ini]` | PASS |
| SR-03 | `test_sr03_test_config_policy_and_eval_files_protected[usercustomize.py]` | PASS |
| SR-04 | `test_sr04_container_stops_when_host_process_dies` | PASS |
| SR-04 | `test_sr04_pid1_watchdog_cannot_be_killed_or_traced` | PASS |
| SR-04 | `test_sr04_reaper_spares_live_runs_and_removes_orphans` | PASS |
| SR-04 | `test_sr04_sigkill_to_controller_is_recovered` | PASS |
| SR-04 | `test_sr04_sigterm_to_controller_cleans_up_promptly` | PASS |
| SR-04 | `test_sr04_workspace_reaper` | PASS |
| SR-05 | `test_sr05_host_backstop_without_entrypoint_enforcement` | PASS |
| SR-05 | `test_sr05_output_budget_boundary_is_exact[0-False]` | PASS |
| SR-05 | `test_sr05_output_budget_boundary_is_exact[1-True]` | PASS |
| SR-05 | `test_sr05_output_flood_is_stopped_early[stderr]` | PASS |
| SR-05 | `test_sr05_output_flood_is_stopped_early[stdout]` | PASS |
| SR-05 | `test_sr05_workload_cannot_bypass_the_output_relay` | PASS |
| SR-06 | `test_sr06_fifo_fixture_task_fails_fast` | PASS |
| SR-06 | `test_sr06_fifo_in_fixture_does_not_hang` | PASS |
| SR-07 | `test_sr07_hard_link_in_fixture_rejected` | PASS |
| SR-08 | `test_sr08_directory_swapped_during_copy_is_not_followed` | PASS |
| SR-08 | `test_sr08_file_growth_during_copy_respects_limit` | PASS |
| SR-09 | `test_sr09_all_workspace_opens_are_descriptor_relative` | PASS |
| SR-09 | `test_sr09_intermediate_directory_swap_is_not_followed` | PASS |
| SR-10 | `test_sr10_unexpected_provider_exception_is_contained` | PASS |
| SR-10 | `test_sr10_unexpected_tool_exception_is_execution_error` | PASS |
| SR-10 | `test_sr10_unreadable_fixture_file_is_workspace_error` | PASS |
| SR-11 | `test_sr11_api_rejects_foreign_host_header` | PASS |
| SR-11 | `test_sr11_text_plain_post_is_rejected` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[ANTHROPIC_API_KEY]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[AWS_SECRET_ACCESS_KEY]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[Proxy-Authorization]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[access_token]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[client_secret]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[credentials]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[db_password]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[private_key]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[refresh_token]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[sessionToken]` | PASS |
| SR-12 | `test_sr12_credential_named_keys_redacted_when_nested[x-goog-api-key]` | PASS |
| SR-12 | `test_sr12_custom_credential_env_var_values_redacted` | PASS |
| SR-12 | `test_sr12_encoded_registered_secret_redacted` | PASS |
| SR-12 | `test_sr12_redaction_is_not_quadratic[bearer_run]` | PASS |
| SR-12 | `test_sr12_redaction_is_not_quadratic[embedded_name]` | PASS |
| SR-12 | `test_sr12_redaction_is_not_quadratic[pem_without_end]` | PASS |
| SR-12 | `test_sr12_redaction_is_not_quadratic[scheme_like]` | PASS |
| SR-12 | `test_sr12_redaction_is_not_quadratic[word_run]` | PASS |
| SR-12 | `test_sr12_test_output_never_enters_trace` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[aws_assignment]` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[basic_auth]` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[json_key]` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[jwt]` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[token_header]` | PASS |
| SR-12 | `test_sr12_unusual_credential_formats[url_userinfo]` | PASS |
| SR-13 | `test_sr13_oom_kill_is_attributed_with_cgroup_evidence` | PASS |
| SR-13 | `test_sr13_unrelated_sigkill_is_not_called_oom` | PASS |
| SR-14 | `test_sr14_reader_keeps_head_and_tail` | PASS |

## Security-relevant suites

| Module | Pass | Fail | Skipped |
|---|---|---|---|
| `test_adversarial` | 23 | 0 | 0 |
| `test_patch` | 16 | 0 | 0 |
| `test_real_model_path` | 24 | 0 | 0 |
| `test_reliability` | 5 | 0 | 0 |
| `test_sandbox_args` | 37 | 0 | 0 |
| `test_sandbox_docker` | 11 | 0 | 0 |
| `test_security_review` | 66 | 0 | 0 |
| `test_security_review_docker` | 17 | 0 | 0 |
| `test_tools` | 31 | 0 | 0 |
| `test_trace` | 12 | 0 | 0 |
| `test_workspace` | 46 | 0 | 0 |
| `test_workspace_docker` | 1 | 0 | 0 |
