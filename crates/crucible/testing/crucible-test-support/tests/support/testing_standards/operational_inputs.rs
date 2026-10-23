//! Binds operational waits to exact local and original-caller obligations.
//!
//! These harness contracts remove only reviewed tokens from flaky-test scanning.
//! They do not grant a runtime deadline or permit another test attempt.

use super::{compact_code, mask_expression};

#[path = "operational_catalog_gc.rs"]
mod operational_catalog_gc;

#[path = "operational_gc_marks.rs"]
mod operational_gc_marks;

#[path = "operational_measurement.rs"]
mod operational_measurement;

#[path = "operational_packed.rs"]
mod operational_packed;

#[path = "operational_sqlite.rs"]
mod operational_sqlite;

#[path = "operational_ram_read.rs"]
mod operational_ram_read;

#[path = "operational_source_observations.rs"]
mod operational_source_observations;

#[path = "operational_retry_cadence.rs"]
mod operational_retry_cadence;

struct Companion {
    path: &'static str,
    required: &'static [&'static str],
    counts: &'static [(&'static str, usize)],
}

struct Contract {
    package: &'static str,
    target: &'static str,
    required: &'static [&'static str],
    expressions: &'static [(&'static str, usize)],
    companions: &'static [Companion],
}

const CONTRACTS: &[Contract] = &[
    // Deliberate 120 ms blocked native export against one 80 ms original ControlSetup; refuse late
    // success while preserving earlier real native failure.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/controller/tests/admission",
        required: &[
            ".budgets[0].total_ns=Some(80_000_000);",
            "fnblocked_native_export_retains_one_original_setup_and_refuses_late_success(",
            "fnnative_export_failure_keeps_original_status_after_setup_expiry(",
            "super::super::admission::export_owner_inventory(&retained,|inventory|{",
            "assert!(!worker.is_finished());",
            "released.recv_timeout(Duration::from_secs(2))",
            "entering.recv_timeout(Duration::from_secs(2))",
            ".inventory.is_none()",
            "assert_eq!(controller.operations.capacity.load(Ordering::Acquire),1);",
            "assert!(matches!(result,Err(RamError::Io(error))iferror.kind()==io::ErrorKind::TimedOut));",
            "-libc::ENOTSUP",
            "ifstatus==-libc::ENOTSUP",
            "fn pending_record_cannot_publish_census_or_renew_expired_setup()",
            "assert_eq!(attempts, 1);",
            "assert_eq!(controller.operations.capacity.load(Ordering::Acquire),0);",
        ],
        expressions: &[("std::thread::sleep(Duration::from_millis(120));", 3)],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/controller/admission.rs",
            required: &[
                "let operation: Arc<dyn SourceOperation> = Arc::from(controller.begin(SourceOperationClass::ControlSetup)?);",
                "operation.wait_slice()?;",
                "loop { operation.wait_slice()?; let status = export(&mut inventory); if status == 0 { break; }",
                "if status != NATIVE_INVENTORY_PENDING_RECORD { return Err(RamError::Native",
                "} operation.wait_slice()?; if inventory.existing_tasks == 0",
                "Ok((inventory, operation))",
                "letstatus=(controller.native_grant)(generation,metadata_bytes,&mutallowance);",
                "if status != 0 || allowance == 0 { controller.mark_failed(); return Err(RamError::Native",
                "ifallowance<rust_metadata_required_bytes{controller.mark_failed();",
                "}operation.wait_slice()?;Ok(allowance)",
            ],
            // Pending-record sleep adds one boundary on the same setup start;
            // export, completed census and native grant preserve their cuts.
            counts: &[
                ("operation.wait_slice()?;", 7),
                ("controller.begin(SourceOperationClass::ControlSetup)?", 1),
            ],
        }],
    },
    // Native record polling and host grant polling retain the same exported
    // setup operation. Only explicit pending records repeat native observation;
    // both waits leave their locks before sleeping and preserve the original cap.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/controller/admission",
        required: &[
            "const NATIVE_INVENTORY_PENDING_RECORD: c_int = 1;",
            "pub(super) fn export_owner_inventory(",
            "mut export: impl FnMut(&mut RamControlOwnerInventory) -> c_int",
            "let operation: Arc<dyn SourceOperation> = Arc::from(controller.begin(SourceOperationClass::ControlSetup)?);",
            "loop { operation.wait_slice()?; let status = export(&mut inventory); if status == 0 { break; }",
            "if status != NATIVE_INVENTORY_PENDING_RECORD { return Err(RamError::Native",
            r#"if inventory.existing_tasks != 0
                || inventory.existing_file_descriptors != 0
                || inventory.registered_service_tasks != 0
            { return Err(RamError::Invariant("pending native inventory contains census output",)); }"#,
            "let slice = operation.wait_slice()?;",
            "} operation.wait_slice()?; if inventory.existing_tasks == 0 || inventory.existing_file_descriptors == 0 || inventory.registered_service_tasks > inventory.existing_tasks",
            "Ok((inventory, operation))",
            "let (owner_resources, operation) = export_owner_inventory(&controller, |inventory|",
            r#"let (grant, spill_quota) = loop {
                let slice = operation.wait_slice()?;
                let grant = controller.state.lock()
                    .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
                    .inventory.as_ref().and_then(|inventory| inventory.grant);
                if let Some(grant) = grant { break grant; }
                std::thread::sleep(slice.min(Duration::from_millis(10)));
            };"#,
            r#"let allowance = grant_native_rust_allowance(
                &controller, operation.as_ref(), generation, grant.metadata_bytes,
                rust_metadata_required_bytes,
            )?;
            let owner = PausedPagingOwner::new(grant, controller.clone())?;"#,
            r#"operation.wait_slice()?;
                let mut allowance = 0;
                let status = (controller.native_grant)(generation, metadata_bytes, &mut allowance);"#,
            "if status != 0 || allowance == 0 { controller.mark_failed(); return Err(RamError::Native",
            "if allowance < rust_metadata_required_bytes { controller.mark_failed();",
            "} operation.wait_slice()?; Ok(allowance)",
        ],
        expressions: &[
            (
                "let slice = operation.wait_slice()?; std::thread::sleep(slice.min(Duration::from_millis(10)));",
                1,
            ),
            (
                "if let Some(grant) = grant { break grant; } std::thread::sleep(slice.min(Duration::from_millis(10)));",
                1,
            ),
        ],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/controller/tests/admission.rs",
            required: &[
                "fn pending_record_cannot_publish_census_or_renew_expired_setup()",
                r#"let result = super::super::admission::export_owner_inventory(&controller, |_| {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(120));
                    1
                });"#,
                "assert_eq!(attempts, 1);",
                "assert!(matches!(result, Err(RamError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));",
                "fn negative_or_unknown_inventory_status_never_retries_as_record_pending()",
                "for status in [-libc::EAGAIN, -libc::EBUSY, -libc::EIO, 2]",
                "fn pending_inventory_with_output_or_success_without_census_refuses_publication()",
                "assert!(controller.state.lock().unwrap().inventory.is_none());",
                "fn pending_record_retries_without_reissuing_setup_or_publishing_partial_census()",
                "assert_eq!(attempts, 3);",
                "fn successful_export_returns_same_setup_custody_without_completion_or_renewal()",
                "assert!(Arc::ptr_eq(&operation, &retained));",
                "fn actual_native_residual_must_cover_the_complete_report_before_owner_birth()",
                "assert!(matches!(result, Err(RamError::MetadataAdmission { required: actual, admitted, }) if actual == required && admitted == required - 1));",
                "assert!(state.owner.is_none());",
                "assert!(operation.wait_slice().is_err());",
            ],
            counts: &[(
                "fn pending_record_cannot_publish_census_or_renew_expired_setup(",
                1,
            )],
        }],
    },
    // Production startup observation polls one supplied original Setup receipt before every
    // identity readiness inspection; capped 10 ms sleep after unlocking state.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/worker_quiescence/identity",
        required: &[
            "fnwait_initial_ready(",
            "mutwait_slice:implFnMut()->Result<std::time::Duration,RamError>",
            "letslice=wait_slice()?;",
            "ifletSome(error)=&state.failure{returnErr(error.clone());}",
            "self.identities_complete(&snapshot)",
            "snapshot.parked_mask==snapshot.worker_mask",
            "snapshot.pending_mask==0",
            "snapshot.operations_in_flight==0",
            "drop(state);",
            "ifready{returnOk(());}",
        ],
        expressions: &[(
            "std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
            1,
        )],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime.rs",
                required: &[
                    r#"state.setup.check_original_startup()
.map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
let result = state.required_workers.handoff(stream);
let post = state.setup.check_original_startup();
state.required_workers.record_handoff_post(&post);
result.map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })?;
post.map_err(|source| PluginRuntimeInstallError::StartupSource { source })"#,
                    r#"let mut stream = Some(control_stream);
if let Err(error) = callbacks_registered.handoff_run_control(&mut stream) {
fatal_policy.terminate(error); } let workers = callbacks_registered.worker_quiescence();
if let Err(source) = workers.wait_initial_ready(|| callbacks_registered.original_startup_slice())
.and_then(|()| callbacks_registered.complete_original_startup_registration())"#,
                    ".wait_initial_ready(||callbacks_registered.original_startup_slice())",
                    ".and_then(|()|callbacks_registered.complete_original_startup_registration())",
                    ".setup.original_startup_slice().map_err(crate::startup_source::InstallerStartupSource::retained_ram_error)",
                ],
                counts: &[
                    ("callbacks_registered.handoff_run_control(&mut stream)", 1),
                    (
                        "workers.wait_initial_ready(||callbacks_registered.original_startup_slice())",
                        1,
                    ),
                    (
                        "workers.wait_initial_ready(||callbacks_registered.original_startup_slice()).and_then(|()|callbacks_registered.complete_original_startup_registration())",
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/setup.rs",
                required: &[
                    "self.original_startup()?.wait_slice()",
                    r#"self.startup_source.as_mut().ok_or(crate::StartupSourceError::Ownership{reason:"initial installer Source is absent",})?.registration_complete()"#,
                ],
                counts: &[],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/startup_source.rs",
                required: &[
                    "self.accept_status((api.query_slice)(self.plugin_id,&mutbounded_ns))?;",
                    "ifbounded_ns==0{",
                    "self.invalid_slice.store(true,Ordering::Release);",
                    "Ok(Duration::from_nanos(bounded_ns))",
                    "self.registration_completed=true;",
                    "self.accept_status((api.registration_complete)(self.plugin_id,0))",
                ],
                counts: &[],
            },
        ],
    },
    // Fingerprint readiness observes the same retained installer Source before
    // each inspection and once more before returning registration success.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/fingerprint_worker",
        required: &[
            "fnwait_registered(",
            "mutwait_slice:implFnMut()->Result<std::time::Duration,crate::StartupSourceError>",
            "letslice=control.check_original(&mutwait_slice)?;",
            "wait_slice().map_err(|source|{",
            "ifstate.supervision_failure.is_none(){state.supervision_failure=Some(source);}",
            "ifstate.failure.is_some(){drop(state);returnErr(Self::failed(control));}",
            "letregistered=state.registered;drop(state);",
            "ifregistered{control.check_original(&mutwait_slice)?;returnOk(());}",
            "ifself.join.as_ref().is_none_or(JoinHandle::is_finished){",
            "control.refuse(FingerprintWorkerCause::Panic);",
        ],
        expressions: &[(
            "thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
            1,
        )],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime.rs",
                required: &[
                    ".wait_fingerprint_registered(||state.setup.original_startup_slice())",
                    ".setup.check_original_startup()",
                ],
                counts: &[],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/setup.rs",
                required: &["self.original_startup()?.wait_slice()"],
                counts: &[],
            },
        ],
    },
    // The real fork fixture polls its one finite transport end, kills and joins
    // the actual child on expiry, and asserts physical inherited-owner cleanup.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_callbacks/fingerprint_worker/tests",
        required: &[
            "fnactual_fork_child_disarms_without_inherited_mutex_or_stale_unmap()",
            "letdeadline=TransportDeadline::new(Duration::from_secs(5)).unwrap();",
            "letchild=unsafe{libc::fork()};",
            "letobserved=unsafe{libc::waitpid(child,&mutstatus,libc::WNOHANG)};",
            "ifobserved==child{break;}",
            "ifdeadline.remaining().is_err(){",
            "unsafe{libc::kill(child,libc::SIGKILL)};",
            "assert_eq!(unsafe{libc::waitpid(child,&mutstatus,0)},child);",
            "assert!(libc::WIFEXITED(status));",
            "assert_eq!(libc::WEXITSTATUS(status),0);",
            "unsafe{worker.restore_workspace_after_fork()}.unwrap();",
        ],
        expressions: &[("thread::sleep(Duration::from_millis(1));", 1)],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/supervision.rs",
            required: &[
                "pub(crate)structTransportDeadline{started:OperationalStart,total:Duration,}",
                "letstarted=OperationalStart::begin();",
                "if total.is_zero()||started.0.checked_add(total).is_none(){",
                "Ok(Self{started,total})",
                "self.total.checked_sub(self.started.elapsed()).filter(|duration|!duration.is_zero())",
                "monotonic_now().saturating_duration_since(self.0)",
            ],
            counts: &[],
        }],
    },
];

pub(super) fn mask(package: &str, target: &str, code: &str) -> String {
    if let Some(masked) = operational_catalog_gc::mask(package, target, code) {
        return masked;
    }
    let Some(contract) = CONTRACTS
        .iter()
        .chain(operational_sqlite::CONTRACTS)
        .chain(operational_ram_read::CONTRACTS)
        .chain(operational_source_observations::CONTRACTS)
        .chain(operational_retry_cadence::CONTRACTS)
        .chain(operational_packed::CONTRACTS)
        .chain(operational_measurement::CONTRACTS)
        .find(|contract| contract.package == package && contract.target == target)
    else {
        return code.to_owned();
    };
    let companions = match read_companions(contract) {
        Ok(companions) => companions,
        Err(_) => return code.to_owned(),
    };
    mask_with_companions(contract, code, &companions)
}

fn read_companions(contract: &Contract) -> std::io::Result<Vec<String>> {
    let root = super::super::super::workspace_root();
    contract
        .companions
        .iter()
        .map(|companion| std::fs::read_to_string(root.join(companion.path)))
        .collect()
}

fn mask_with_companions(contract: &Contract, code: &str, companions: &[String]) -> String {
    let compact = compact_code(code);
    let local_matches = contract
        .required
        .iter()
        .all(|part| compact.contains(&pattern(part)))
        && contract.expressions.iter().all(|(expression, count)| {
            super::expression_offsets(code, &pattern(expression)).len() == *count
        });
    let companion_matches = companions.len() == contract.companions.len()
        && contract
            .companions
            .iter()
            .zip(companions)
            .all(|(binding, source)| {
                let code = super::super::scrub_comments_and_strings(source);
                let compact = compact_code(&code);
                binding
                    .required
                    .iter()
                    .all(|part| compact.contains(&pattern(part)))
                    && binding.counts.iter().all(|(expression, count)| {
                        super::expression_offsets(&code, &pattern(expression)).len() == *count
                    })
            });
    if !local_matches || !companion_matches {
        return code.to_owned();
    }

    let mut masked = code.to_owned();
    for (expression, count) in contract.expressions {
        mask_expression(&mut masked, &pattern(expression), *count);
    }
    masked
}

// Contracts use readable Rust snippets; comments and string payloads cannot
// supply executable obligations, just as they cannot supply lint findings.
fn pattern(source: &str) -> String {
    compact_code(&super::super::scrub_comments_and_strings(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_escape(code: &str) -> bool {
        super::super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`") || finding.contains("`thread::sleep`"))
    }

    // Recovery custody has its own exact contract and mutation controls. Apply
    // it to the original source before this suite changes wait obligations or
    // appends forbidden attempts, so those additions cannot be pre-masked.
    fn input_contract_source(contract: &Contract, source: &str) -> String {
        let code = super::super::super::scrub_comments_and_strings(source);
        super::super::operational_recovery::mask(contract.package, contract.target, &code)
    }

    #[test]
    fn exact_operational_inputs_reject_drift_extra_waits_and_test_reruns()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                crate::workspace::package_path(&root.join("crates"), contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = input_contract_source(contract, &source);
            let compact = compact_code(&code);
            let companions = read_companions(contract)?;
            assert!(
                super::super::super::flaky_escape_failures(
                    contract.package,
                    contract.target,
                    &source,
                )
                .is_empty(),
                "composed operational contracts rejected reviewed source: {}",
                contract.target
            );
            for requirement in contract.required {
                assert!(
                    compact.contains(&pattern(requirement)),
                    "missing local obligation: {} {requirement}",
                    contract.target
                );
                let changed = compact.replace(&pattern(requirement), "removed_obligation()");
                assert!(!changed.contains(&pattern(requirement)));
                assert!(
                    has_escape(&mask_with_companions(contract, &changed, &companions)),
                    "removed local obligation was masked: {} {requirement}",
                    contract.target
                );
            }
            assert!(
                !has_escape(&mask_with_companions(contract, &code, &companions)),
                "reviewed source did not match: {}",
                contract.target
            );
            assert!(
                has_escape(&code),
                "unreviewed source unexpectedly clear: {}",
                contract.target
            );

            for (expression, count) in contract.expressions {
                // Count the same canonical tokens used by the live matcher.
                let expression = pattern(expression);
                assert_eq!(compact.match_indices(expression.as_str()).count(), *count);
                let additional = format!("{compact}{expression}");
                assert!(
                    has_escape(&mask_with_companions(contract, &additional, &companions)),
                    "additional exact expression was masked: {} {expression}",
                    contract.target
                );
                let changed_expression = expression
                    .replace("90", "91")
                    .replace("120", "121")
                    .replace("from_millis(10)", "from_millis(11)")
                    .replace("from_millis(1)", "from_millis(2)")
                    .replace("read_retry", "read_retry_changed");
                assert_ne!(changed_expression, expression);
                let changed = compact.replacen(expression.as_str(), &changed_expression, 1);
                assert!(
                    has_escape(&mask_with_companions(contract, &changed, &companions)),
                    "changed expression was masked: {} {expression}",
                    contract.target
                );
            }
            for addition in [
                "fnconceal_failure(){std::thread::sleep(unbounded);}",
                "fnconceal_failure(){retry();}",
                "fnconceal_failure(){retry!();}",
                "fnconceal_failure(){retry_failed_test();}",
                "fnconceal_failure(){loop{retry_failed_test();}}",
            ] {
                let changed = format!("{code}\n{addition}");
                assert!(
                    has_escape(&mask_with_companions(contract, &changed, &companions)),
                    "additional escape was masked: {} {addition}",
                    contract.target
                );
                let changed_source = format!("{source}\n{addition}");
                assert!(
                    !super::super::super::flaky_escape_failures(
                        contract.package,
                        contract.target,
                        &changed_source,
                    )
                    .is_empty(),
                    "composed operational contracts masked an additional escape: {} {addition}",
                    contract.target
                );
            }
            assert!(
                has_escape(&mask_with_companions(contract, &code, &[])),
                "missing caller/helper source was admitted: {}",
                contract.target
            );
        }
        Ok(())
    }

    #[test]
    fn operational_inputs_require_exact_original_helpers_and_callers()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                crate::workspace::package_path(&root.join("crates"), contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = input_contract_source(contract, &source);
            let companions = read_companions(contract)?;
            for (index, binding) in contract.companions.iter().enumerate() {
                let compact = compact_code(&super::super::super::scrub_comments_and_strings(
                    &companions[index],
                ));
                for obligation in binding.required {
                    assert!(
                        compact.contains(&pattern(obligation)),
                        "missing companion obligation: {} {obligation}",
                        binding.path
                    );
                    let mut changed = companions.clone();
                    changed[index] =
                        compact.replace(&pattern(obligation), "removed_original_boundary()");
                    assert!(!changed[index].contains(&pattern(obligation)));
                    assert!(
                        has_escape(&mask_with_companions(contract, &code, &changed)),
                        "removed original source obligation admitted: {} {obligation}",
                        binding.path
                    );
                }
                let (before, after) = match binding.path {
                    "crates/crucible/storage/crucible-store/src/content_store.rs" => {
                        ("io::ErrorKind::Interrupted", "io::ErrorKind::TimedOut")
                    }
                    "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/control.rs" => (
                        "install(Duration::from_millis(25))?",
                        "install(Duration::from_millis(250))?",
                    ),
                    "crates/crucible/qemu/crucible-qemu-plugin/src/runtime.rs" => {
                        (".original_startup_slice()", ".unbounded_startup_slice()")
                    }
                    "crates/crucible/qemu/crucible-qemu-plugin/src/setup.rs" => (
                        "self.original_startup()?.wait_slice()",
                        "Ok(std::time::Duration::from_secs(60))",
                    ),
                    "crates/crucible/qemu/crucible-qemu-plugin/src/startup_source.rs" => (
                        "(api.query_slice)(self.plugin_id,&mutbounded_ns)",
                        "(api.unbounded_slice)(self.plugin_id,&mutbounded_ns)",
                    ),
                    "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/supervision.rs" => (
                        "self.total.checked_sub(self.started.elapsed())",
                        "Some(std::time::Duration::from_secs(60))",
                    ),
                    _ => (
                        "operation.wait_slice()",
                        "Ok(std::time::Duration::from_secs(60))",
                    ),
                };
                assert!(
                    compact.contains(before),
                    "mutation was not applicable: {}",
                    binding.path
                );
                let mut changed = companions.clone();
                changed[index] = compact.replace(before, after);
                assert!(!changed[index].contains(before));
                assert!(
                    has_escape(&mask_with_companions(contract, &code, &changed)),
                    "changed retry/deadline semantics admitted: {}",
                    binding.path
                );

                for (expression, count) in binding.counts {
                    let expression = pattern(expression);
                    assert_eq!(compact.match_indices(expression.as_str()).count(), *count);
                    let mut changed = companions.clone();
                    changed[index] = format!("{compact}{expression}");
                    assert!(
                        has_escape(&mask_with_companions(contract, &code, &changed)),
                        "renewed operation boundary admitted: {} {expression}",
                        binding.path
                    );
                }
            }
        }
        Ok(())
    }
}
