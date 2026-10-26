# Regression evidence (generated)

Final regression tests (`tests/test_security_review*.py`) run twice on the build host:
- **before**: source at `242b36c` (pre-review) with its own runner image (`sandbox/Dockerfile` at that commit);
- **after**: source at the security commits, rebuilt runner image.

`test_sr12_redaction_is_not_quadratic` is excluded from *before*: it guards a regression introduced (and fixed) during the review;
against `242b36c` it passes (5/5), and against the intermediate redaction change it did not finish within 300 s.

| Test | Before (242b36c) | After |
|---|---|---|
| `test_sr01_create_args_pin_profile_and_wrap_command` | FAILED | PASSED |
| `test_sr01_verify_rejects_apparmor_unconfined_and_entrypoint` | FAILED | PASSED |
| `test_sr01_verify_rejects_tampered_pinned_profile` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[allow_all_profile]` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[apparmor]` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[no_profile]` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[paths]` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[selinux_disabled]` | FAILED | PASSED |
| `test_sr01_verify_rejects_weak_security_options[unconfined]` | FAILED | PASSED |
| `test_sr02_verify_rejects_image_provided_env` | FAILED | PASSED |
| `test_sr03_editing_tests_cannot_produce_success` | FAILED | PASSED |
| `test_sr03_final_diff_gate_catches_out_of_band_changes` | FAILED | PASSED |
| `test_sr03_protected_path_variants[./tests/test_core.py]` | FAILED | PASSED |
| `test_sr03_protected_path_variants[tests//test_core.py]` | FAILED | PASSED |
| `test_sr03_protected_path_variants[tests/test_core.py]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[.sandbox-agent/policy.toml]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[conftest.py]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[evals/tasks.json]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[pkg/conftest.py]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[pkg/evil.pth]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[pyproject.toml]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[pytest.ini]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[setup.cfg]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[sitecustomize.py]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[tox.ini]` | FAILED | PASSED |
| `test_sr03_test_config_policy_and_eval_files_protected[usercustomize.py]` | FAILED | PASSED |
| `test_sr04_reaper_spares_live_runs_and_removes_orphans` | FAILED | PASSED |
| `test_sr04_workspace_reaper` | FAILED | PASSED |
| `test_sr06_fifo_fixture_task_fails_fast` | FAILED | PASSED |
| `test_sr06_fifo_in_fixture_does_not_hang` | FAILED | PASSED |
| `test_sr07_hard_link_in_fixture_rejected` | FAILED | PASSED |
| `test_sr08_directory_swapped_during_copy_is_not_followed` | FAILED | PASSED |
| `test_sr08_file_growth_during_copy_respects_limit` | FAILED | PASSED |
| `test_sr09_all_workspace_opens_are_descriptor_relative` | FAILED | PASSED |
| `test_sr09_intermediate_directory_swap_is_not_followed` | FAILED | PASSED |
| `test_sr10_unexpected_provider_exception_is_contained` | FAILED | PASSED |
| `test_sr10_unexpected_tool_exception_is_execution_error` | FAILED | PASSED |
| `test_sr10_unreadable_fixture_file_is_workspace_error` | FAILED | PASSED |
| `test_sr11_api_rejects_foreign_host_header` | FAILED | PASSED |
| `test_sr11_text_plain_post_is_rejected` | PASSED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[ANTHROPIC_API_KEY]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[AWS_SECRET_ACCESS_KEY]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[Proxy-Authorization]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[access_token]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[client_secret]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[credentials]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[db_password]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[private_key]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[refresh_token]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[sessionToken]` | FAILED | PASSED |
| `test_sr12_credential_named_keys_redacted_when_nested[x-goog-api-key]` | FAILED | PASSED |
| `test_sr12_custom_credential_env_var_values_redacted` | FAILED | PASSED |
| `test_sr12_encoded_registered_secret_redacted` | FAILED | PASSED |
| `test_sr12_redaction_is_not_quadratic[bearer_run]` | not run | PASSED |
| `test_sr12_redaction_is_not_quadratic[embedded_name]` | not run | PASSED |
| `test_sr12_redaction_is_not_quadratic[pem_without_end]` | not run | PASSED |
| `test_sr12_redaction_is_not_quadratic[scheme_like]` | not run | PASSED |
| `test_sr12_redaction_is_not_quadratic[word_run]` | not run | PASSED |
| `test_sr12_test_output_never_enters_trace` | PASSED | PASSED |
| `test_sr12_unusual_credential_formats[aws_assignment]` | FAILED | PASSED |
| `test_sr12_unusual_credential_formats[basic_auth]` | FAILED | PASSED |
| `test_sr12_unusual_credential_formats[json_key]` | FAILED | PASSED |
| `test_sr12_unusual_credential_formats[jwt]` | FAILED | PASSED |
| `test_sr12_unusual_credential_formats[token_header]` | FAILED | PASSED |
| `test_sr12_unusual_credential_formats[url_userinfo]` | FAILED | PASSED |
| `test_sr14_reader_keeps_head_and_tail` | FAILED | PASSED |
| `test_sr01_pinned_profile_is_enforced` | FAILED | PASSED |
| `test_sr01_runtime_attestation_catches_weak_seccomp[allow_all]` | FAILED | PASSED |
| `test_sr01_runtime_attestation_catches_weak_seccomp[unconfined]` | FAILED | PASSED |
| `test_sr02_container_env_is_exactly_configured` | FAILED | PASSED |
| `test_sr02_image_with_extra_env_fails_closed` | FAILED | PASSED |
| `test_sr04_container_stops_when_host_process_dies` | FAILED | PASSED |
| `test_sr04_pid1_watchdog_cannot_be_killed_or_traced` | FAILED | PASSED |
| `test_sr04_sigkill_to_controller_is_recovered` | FAILED | PASSED |
| `test_sr04_sigterm_to_controller_cleans_up_promptly` | FAILED | PASSED |
| `test_sr05_output_flood_is_stopped_early[stderr]` | FAILED | PASSED |
| `test_sr05_output_flood_is_stopped_early[stdout]` | FAILED | PASSED |
| `test_sr13_oom_kill_is_attributed_with_cgroup_evidence` | FAILED | PASSED |
| `test_sr13_unrelated_sigkill_is_not_called_oom` | FAILED | PASSED |

Totals before: 2 passed, 72 failed. After: 79 passed, 0 failed.
