# Guarantees and their evidence

Every claim the project makes about isolation, policy and lifecycle, with the code that
enforces it and the regression tests that check it. `tests/test_guarantees_doc.py`
verifies that every function and test named here exists.

**Scope.** These are *container hardening* guarantees on a shared Linux kernel. They are
not VM-grade isolation. A kernel or container-runtime vulnerability is outside what they
can stop, and the sandbox is not escape-proof (see `THREAT_MODEL.md` and
`SECURITY_REVIEW.md` A-1). Tests show the controls behave as described on the hosts
measured (cgroup v1 build host, cgroup v2 GitHub Actions). They are not formal proofs.

## Model output to tool call

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| Only six structured tools exist; there is no shell tool | `src/sandbox_agent/tools.py::ToolExecutor._gate` | `test_no_shell_tool_exists`, `test_unknown_tool_denied` |
| A per-task tool allowlist is enforced in trusted code, before arguments are parsed | `src/sandbox_agent/tools.py::ToolExecutor._gate` | `test_tool_outside_the_task_allowlist_is_denied_by_the_controller`, `test_inspect_only_task_denies_patch_and_tests_through_the_controller` |
| Tool arguments are validated by strict schemas; malformed model output never reaches a tool | `src/sandbox_agent/tools.py::ToolExecutor.execute`, `src/sandbox_agent/agent.py::AgentController.run` | `test_invalid_arguments`, `test_malformed_or_hostile_model_output_fails_closed`, `test_invalid_provider_outputs_via_pipeline` |
| Commands are names mapped to fixed argv; selectors match a strict pattern | `src/sandbox_agent/policy.py::build_command` | `test_run_tests_uses_fixed_argv`, `test_forbidden_commands_via_pipeline`, `test_build_command_rejects_unknown` |
| Task status is computed by the controller, never taken from the model | `src/sandbox_agent/agent.py::AgentController.run` | `test_model_claiming_success_without_passing_tests_fails`, `test_selector_only_pass_is_not_success` |
| Iteration, tool-call, wall-clock, denial and invalid-output budgets end the run | `src/sandbox_agent/agent.py::AgentController.run` | `test_iteration_budget`, `test_tool_call_budget`, `test_wall_clock_budget`, `test_policy_denials_abort` |

## Workspace and files

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| Paths are workspace-relative; traversal is refused | `src/sandbox_agent/workspace.py::validate_relpath` | `test_traversal_rejected`, `test_traversal_and_symlink_escapes_via_pipeline` |
| Every open is descriptor-relative with `O_NOFOLLOW`; symlinks, hard links and special files are refused | `src/sandbox_agent/workspace.py::_open_child_dir`, `src/sandbox_agent/workspace.py::_open_regular` | `test_sr09_all_workspace_opens_are_descriptor_relative`, `test_sr09_intermediate_directory_swap_is_not_followed`, `test_symlink_swapped_in_after_copy_is_refused`, `test_sr07_hard_link_in_fixture_rejected`, `test_special_files_rejected` |
| Tests, test configuration, policy and eval files cannot be changed, by a patch or out of band | `src/sandbox_agent/policy.py::protected_reason`, `src/sandbox_agent/patch.py::apply_patch` | `test_sr03_protected_path_variants`, `test_sr03_test_config_policy_and_eval_files_protected`, `test_sr03_final_diff_gate_catches_out_of_band_changes` |
| The original fixture is never modified (manifest hash checked) | `src/sandbox_agent/workspace.py::tree_manifest` | `test_manifest_detects_changes`, `test_agent_fixes_real_bug_and_fixture_is_untouched` |

## Container configuration (verified before start)

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| No network, uid 10001, all capabilities dropped, `no-new-privileges`, read-only rootfs and workspace, noexec `/tmp`, private cgroup/IPC | `src/sandbox_agent/sandbox.py::DockerSandbox.build_create_args`, `src/sandbox_agent/sandbox.py::DockerSandbox.verify` | `test_create_args_contain_every_control`, `test_verify_rejects_deviation`, `test_network_disabled`, `test_privilege_restrictions`, `test_filesystem_restrictions` |
| The exact pinned seccomp profile is applied; a weaker one is refused | `src/sandbox_agent/sandbox.py::load_seccomp_profile`, `src/sandbox_agent/sandbox.py::DockerSandbox.verify` | `test_sr01_verify_rejects_tampered_pinned_profile`, `test_sr01_verify_rejects_weak_security_options`, `test_sr01_pinned_profile_is_enforced` |
| The container environment is exactly the configured variables (no host secrets) | `src/sandbox_agent/sandbox.py::DockerSandbox.verify`, `src/sandbox_agent/sandbox.py::_docker_cli_env` | `test_sr02_container_env_is_exactly_configured`, `test_sr02_image_with_extra_env_fails_closed`, `test_env_is_minimal` |
| Only the workspace is mounted, from inside the private workspace root | `src/sandbox_agent/sandbox.py::DockerSandbox.validate_mount_source`, `src/sandbox_agent/sandbox.py::DockerSandbox.verify` | `test_mount_source_outside_root_rejected`, `test_mount_source_symlink_rejected`, `test_verify_rejects_extra_mount` |
| Memory (= swap), CPU, PIDs, file size and output limits | `src/sandbox_agent/sandbox.py::DockerSandbox.build_create_args` | `test_resource_memory_exhaustion_oom_killed`, `test_resource_fork_bomb_limited`, `test_pids_limit_blocks_fork_bomb` |
| Any mismatch refuses the run and removes the container | `src/sandbox_agent/sandbox.py::DockerSandbox.run` | `test_isolation_mismatch_fails_closed_and_removes_container` |

## Trusted PID 1 (`sandbox/entry.py`)

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| Isolation is attested from inside before any untrusted code runs | `sandbox/entry.py::attest` | `test_sr01_runtime_attestation_catches_weak_seccomp`, `test_pid1_assumption_enforced_when_docker_injects_an_init` |
| Markers carry a per-run nonce; forged markers are ignored | `sandbox/entry.py::emit`, `src/sandbox_agent/sandbox.py::_take_marker` | `test_forged_markers_do_not_change_classification`, `test_forged_exit_marker_is_ignored_when_host_kills` |
| The workload cannot signal, trace or kill PID 1 | `sandbox/entry.py::drop_signal_handlers` | `test_sr16_workload_cannot_signal_pid1`, `test_sr04_pid1_watchdog_cannot_be_killed_or_traced` |
| A deadline inside the container, independent of the host | `sandbox/entry.py::supervise` | `test_sr16_deadline_still_enforced_without_sigalrm`, `test_sr04_container_stops_when_host_process_dies` |
| Total output is cut at exactly the budget, inside the container | `sandbox/entry.py::Relay.pump` | `test_sr05_output_budget_boundary_is_exact`, `test_sr05_output_flood_is_stopped_early`, `test_sr05_workload_cannot_bypass_the_output_relay` |
| OOM kills are attributed from cgroup evidence | `sandbox/entry.py::oom_kills`, `src/sandbox_agent/sandbox.py::classify_outcome` | `test_sr13_oom_kill_is_attributed_with_cgroup_evidence`, `test_sr13_unrelated_sigkill_is_not_called_oom` |

## Host-side lifecycle

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| A run whose cancellation or deadline is already due never starts the container | `src/sandbox_agent/sandbox.py::RunControl.due`, `src/sandbox_agent/sandbox.py::DockerSandbox.run` | `test_sa01_precancelled_run_executes_nothing`, `test_sa01_cancel_during_creation_never_starts`, `test_sa01_deadline_already_passed_starts_nothing` |
| Cancellation and the caller's deadline stop a running container | `src/sandbox_agent/sandbox.py::DockerSandbox._wait` | `test_cancel_stops_a_running_container_promptly`, `test_caller_deadline_earlier_than_timeout_stops_the_run`, `test_task_cancelled_during_a_hanging_test_run` |
| An exit already observed is never re-labelled; documented precedence | `src/sandbox_agent/sandbox.py::DockerSandbox._wait`, `src/sandbox_agent/sandbox.py::classify_outcome` | `test_exit_already_observed_beats_a_pending_cancel`, `test_exit_already_observed_beats_an_expired_deadline`, `test_documented_precedence`, `test_sa02_near_simultaneous_exit_and_cancel` |
| `completed` requires a valid attestation and an exit report consistent with Docker | `src/sandbox_agent/sandbox.py::classify_outcome`, `src/sandbox_agent/sandbox.py::_report_exit_status` | `test_success_requires_the_supervisor_report`, `test_sr16_missing_exit_report_fails_closed`, `test_external_kill_of_pid1_fails_closed_with_diagnostics` |
| Unverifiable runs are refused with bounded diagnostics, never counted as success | `src/sandbox_agent/errors.py::SandboxIsolationError` | `test_docker_start_failure_fails_closed_with_diagnostics`, `test_isolation_error_diagnostics_are_bounded` |
| The attach CLI is reaped and the container removed on any exception | `src/sandbox_agent/sandbox.py::_reap`, `src/sandbox_agent/sandbox.py::DockerSandbox.run` | `test_daemon_failure_during_stop_reaps_the_cli_and_removes_the_container`, `test_unexpected_exception_while_parsing_still_removes_the_container`, `test_interrupt_during_run_still_removes_container` |
| A failed `docker rm` is reported, never masks the original error, and is not counted as reaped | `src/sandbox_agent/sandbox.py::DockerSandbox._remove`, `src/sandbox_agent/sandbox.py::DockerSandbox.reap_stale` | `test_rm_failure_after_success_is_reported_not_ignored`, `test_rm_error_never_masks_the_original_failure`, `test_reaper_counts_only_containers_it_actually_removed` |
| Containers and workspaces of crashed controllers are reaped on the next start | `src/sandbox_agent/sandbox.py::DockerSandbox.reap_stale`, `src/sandbox_agent/workspace.py::Workspace.reap_stale` | `test_sr04_reaper_spares_live_runs_and_removes_orphans`, `test_sr04_sigkill_to_controller_is_recovered`, `test_sr04_workspace_reaper` |
| Binary and unterminated output is bounded (head and tail kept) | `src/sandbox_agent/sandbox.py::_BoundedReader` | `test_binary_and_unterminated_output`, `test_sr14_reader_keeps_head_and_tail`, `test_output_is_capped` |

## Secrets and traces

| Guarantee | Enforced by | Regression tests |
|---|---|---|
| Traces are redacted at emit time (credential names, registered secrets and their encodings, linear-time patterns) | `src/sandbox_agent/trace.py::Tracer.emit`, `src/sandbox_agent/trace.py::Tracer.scrub` | `test_sr12_encoded_registered_secret_redacted`, `test_sr12_redaction_is_not_quadratic`, `test_registered_secret_and_env_secret_redacted` |
| Test output never enters the trace | `src/sandbox_agent/tools.py::ToolExecutor.execute` | `test_sr12_test_output_never_enters_trace` |
| Model spend is reserved before each request and survives a killed process | `src/sandbox_agent/spend.py::SpendLedger.reserve` | `test_reservation_is_persisted_before_the_request_is_sent`, `test_sigkill_mid_request_preserves_reservation_and_blocks_overspend` |
