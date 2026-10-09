//! Binds operational waits to exact local and original-caller obligations.
//!
//! These harness contracts remove only reviewed tokens from flaky-test scanning.
//! They do not grant a runtime deadline or permit another test attempt.

use super::{compact_code, mask_expression};

#[path = "operational_catalog_gc.rs"]
mod operational_catalog_gc;

#[path = "operational_packed.rs"]
mod operational_packed;

#[path = "operational_sqlite.rs"]
mod operational_sqlite;

#[path = "operational_ram_read.rs"]
mod operational_ram_read;

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
    // Two deliberate idle intervals longer than unchanged 25 ms admission polling; one Hello
    // record, physical stop/join/resume, same sequence continued by Status.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/control/idle_timeout_tests",
        required: &[
            "fnactual_request_after_idle_retries_restores_polling_and_parent_sequence(",
            "host.set_read_timeout(Some(Duration::from_secs(1))).unwrap();",
            "PagerControlWorker::start(socket,[4;32],target,Arc::clone(&controller)).unwrap();",
            "exchange(&muthost,1,target,RamControlRequest::Hello);",
            "letpaused=worker.stop().unwrap().join().unwrap().unwrap();",
            "assert_eq!(paused.sequence,1);",
            "paused.stream.read_timeout().unwrap(),Some(Duration::from_millis(25))",
            "letworker=PagerControlWorker::resume(paused,controller).unwrap();",
            "exchange(&muthost,2,target,RamControlRequest::Status);",
            "assert_eq!(paused.sequence,2);",
        ],
        expressions: &[("thread::sleep(Duration::from_millis(90));", 2)],
        companions: &[Companion {
            path: "crates/crucible-qemu-plugin/src/paged_ram/control.rs",
            required: &[
                "install(Duration::from_millis(25))?;",
                "if!*installed{",
                "record.operation.complete()?;",
                "operation:controller.begin(SourceOperationClass::Cleanup)?,",
            ],
            counts: &[],
        }],
    },
    // Deliberate 120 ms blocked native export against one 80 ms original ControlSetup; refuse late
    // success while preserving earlier real native failure.
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/controller/tests/admission",
        required: &[
            ".budgets[0].total_ms=Some(80);",
            "fnblocked_native_export_retains_one_original_setup_and_refuses_late_success(",
            "fnnative_export_failure_keeps_original_status_after_setup_expiry(",
            "super::super::admission::export_owner_inventory(&retained,|inventory|{",
            "assert!(!worker.is_finished());",
            "released.recv_timeout(Duration::from_secs(2))",
            "entering.recv_timeout(Duration::from_secs(2))",
            ".inventory.is_none()",
            "assert_eq!(controller.operations.load(Ordering::Acquire),1);",
            "assert!(matches!(result,Err(RamError::Io(error))iferror.kind()==io::ErrorKind::TimedOut));",
            "-libc::ENOTSUP",
            "ifstatus==-libc::ENOTSUP",
            "assert_eq!(controller.operations.load(Ordering::Acquire),0);",
        ],
        expressions: &[("std::thread::sleep(Duration::from_millis(120));", 2)],
        companions: &[Companion {
            path: "crates/crucible-qemu-plugin/src/paged_ram/controller/admission.rs",
            required: &[
                "Arc::from(controller.begin(SourceOperationClass::ControlSetup)?);operation.wait_slice()?;",
                "operation.wait_slice()?;",
                "letstatus=export(&mutinventory);",
                "ifstatus!=0{",
                "}operation.wait_slice()?;Ok((inventory,operation))",
            ],
            counts: &[("operation.wait_slice()?;", 3)],
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
        companions: &[Companion {
            path: "crates/crucible-qemu-plugin/src/runtime.rs",
            required: &[
                "ifletSome(operation)=startup{",
                ".wait_initial_ready(||{operation.wait_slice().map_err(crate::ram_error::RamError::from)})",
                ".and_then(|()|{operation.complete().map_err(crate::ram_error::RamError::from)})",
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
        .chain(operational_packed::CONTRACTS)
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

    #[test]
    fn exact_operational_inputs_reject_drift_extra_waits_and_test_reruns()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = super::super::super::scrub_comments_and_strings(&source);
            let compact = compact_code(&code);
            let companions = read_companions(contract)?;
            for requirement in contract.required {
                assert!(
                    compact.contains(requirement),
                    "missing local obligation: {} {requirement}",
                    contract.target
                );
                let changed = compact.replace(requirement, "removed_obligation()");
                assert!(!changed.contains(requirement));
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
                assert_eq!(compact.match_indices(expression).count(), *count);
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
                    .replace("read_retry", "read_retry_changed");
                assert_ne!(changed_expression, *expression);
                let changed = compact.replacen(expression, &changed_expression, 1);
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
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = super::super::super::scrub_comments_and_strings(&source);
            let companions = read_companions(contract)?;
            for (index, binding) in contract.companions.iter().enumerate() {
                let compact = compact_code(&super::super::super::scrub_comments_and_strings(
                    &companions[index],
                ));
                for obligation in binding.required {
                    assert!(
                        compact.contains(obligation),
                        "missing companion obligation: {} {obligation}",
                        binding.path
                    );
                    let mut changed = companions.clone();
                    changed[index] = compact.replace(obligation, "removed_original_boundary()");
                    assert!(!changed[index].contains(obligation));
                    assert!(
                        has_escape(&mask_with_companions(contract, &code, &changed)),
                        "removed original source obligation admitted: {} {obligation}",
                        binding.path
                    );
                }
                let (before, after) = match binding.path {
                    "crates/crucible-cas/src/content_store.rs" => {
                        ("io::ErrorKind::Interrupted", "io::ErrorKind::TimedOut")
                    }
                    "crates/crucible-qemu-plugin/src/paged_ram/control.rs" => (
                        "install(Duration::from_millis(25))?",
                        "install(Duration::from_millis(250))?",
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
                    assert_eq!(compact.match_indices(expression).count(), *count);
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
