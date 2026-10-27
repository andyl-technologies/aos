//! Exact original-operation custody for physical native retirement waits.

use super::super::operational_target_cleanup;
use super::super::operational_operations::{FAILED_BODIES, RECONCILE_BODY};
use super::{Companion, Contract};

const TARGET_RETIREMENT_OBLIGATIONS: &[&str] = &operational_target_cleanup::OBLIGATIONS;
const TARGET_RETIREMENT_COUNTS: &[(&str, usize)] = &operational_target_cleanup::COUNTS;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_attempt_host/original_roster",
        required: &[
            RECONCILE_BODY,
            "assert!(roster.retry_unsettled().is_err());",
            "assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());",
        ],
        expressions: &[
            ("retry_unsettled", 3),
            ("self.retry_failed_launch_bodies()", 1),
            (
                "assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());",
                2,
            ),
            (
                "terminal_cleanup_refuses_retry_and_keeps_actual_storage_and_generation",
                1,
            ),
        ],
        companions: &[Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: TARGET_RETIREMENT_OBLIGATIONS,
            counts: TARGET_RETIREMENT_COUNTS,
        }, Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/retirement.rs",
            required: &[FAILED_BODIES],
            counts: &[],
        }],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_attempt_host/original_roster/fork_target",
        required: TARGET_RETIREMENT_OBLIGATIONS,
        expressions: TARGET_RETIREMENT_COUNTS,
        companions: &[Companion {
            path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
            required: &[
                "for slot in &mut state.slots { fork_target::retry_unsettled_target(slot)?; if slot.fork_target.is_owned() || slot.unsettled.is_none() { continue; }",
            ],
            counts: &[("pub fn retry_unsettled(", 1)],
        }],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_cgroup/original_finish",
        required: &[
            "fn finish_under_original(",
            "original: &HostOperationGuard",
            "let slice = match original.wait_slice()",
            "if join.is_finished() { break; }",
            "let now = Instant::now();",
            "if now >= deadline",
            "if let Err(source) = original.wait_slice()",
            "let Some(join) = self.join.take()",
            "join.join()",
        ],
        expressions: &[
            ("original: &HostOperationGuard", 3),
            ("original.wait_slice()", 9),
            (
                "std::thread::sleep(slice.min(WATCHER_WAIT_POLL_INTERVAL).min(deadline.duration_since(now)),);",
                1,
            ),
        ],
        companions: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::super::super::super::scrub_comments_and_strings;
    use super::super::super::expression_offsets;
    use super::super::{mask_with_companions, pattern, read_companions};
    use super::*;

    // Scanner offsets address compact bytes; mutations retain the original
    // whitespace so identifier-boundary checks exercise the real input.
    fn replace_occurrence(code: &str, expression: &str, occurrence: usize) -> String {
        let offsets = code
            .char_indices()
            .filter(|(_, character)| !character.is_whitespace())
            .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
            .collect::<Vec<_>>();
        let start = offsets[occurrence];
        let end = offsets[occurrence + expression.len() - 1] + 1;
        let mut changed = code.to_owned();
        changed.replace_range(start..end, "removed_original_obligation();");
        changed
    }

    #[test]
    fn original_retirement_tokens_reject_missing_guards_and_extra_waits()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                crate::workspace::package_path(&root.join("crates"), contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = scrub_comments_and_strings(&source);
            let companions = read_companions(contract)?;
            let masked = mask_with_companions(contract, &code, &companions);
            assert_ne!(masked, code, "{}", contract.target);

            for requirement in contract.required {
                let requirement = pattern(requirement);
                let occurrences = expression_offsets(&code, &requirement);
                assert!(!occurrences.is_empty(), "{requirement}");
                for occurrence in occurrences {
                    let changed = replace_occurrence(&code, &requirement, occurrence);
                    assert_eq!(
                        mask_with_companions(contract, &changed, &companions),
                        changed
                    );
                }
            }
            for (expression, count) in contract.expressions {
                let expression = pattern(expression);
                let occurrences = expression_offsets(&code, &expression);
                assert_eq!(occurrences.len(), *count, "{expression}");
                for occurrence in occurrences {
                    let changed = replace_occurrence(&code, &expression, occurrence);
                    assert_eq!(
                        mask_with_companions(contract, &changed, &companions),
                        changed
                    );
                }
                let changed = format!("{code}\n{expression}");
                assert_eq!(
                    mask_with_companions(contract, &changed, &companions),
                    changed
                );
            }
            if !companions.is_empty() {
                assert_eq!(mask_with_companions(contract, &code, &[]), code);
            }
            for (index, binding) in contract.companions.iter().enumerate() {
                let helper = scrub_comments_and_strings(&companions[index]);
                for requirement in binding.required {
                    let requirement = pattern(requirement);
                    let occurrences = expression_offsets(&helper, &requirement);
                    assert!(!occurrences.is_empty(), "{requirement}");
                    for occurrence in occurrences {
                        let mut changed = companions.clone();
                        changed[index] = replace_occurrence(&helper, &requirement, occurrence);
                        assert_eq!(mask_with_companions(contract, &code, &changed), code);
                    }
                }
                for (expression, count) in binding.counts {
                    let expression = pattern(expression);
                    let occurrences = expression_offsets(&helper, &expression);
                    assert_eq!(occurrences.len(), *count, "{expression}");
                    for occurrence in occurrences {
                        let mut changed = companions.clone();
                        changed[index] = replace_occurrence(&helper, &expression, occurrence);
                        assert_eq!(mask_with_companions(contract, &code, &changed), code);
                    }
                    let mut changed = companions.clone();
                    changed[index] = format!("{}\n{expression}", companions[index]);
                    assert_eq!(mask_with_companions(contract, &code, &changed), code);
                }
            }
            for extra in [
                "fn conceal() { retry(); }",
                "fn conceal() { std::thread::sleep(unbounded); }",
            ] {
                let changed = format!("{code}{extra}");
                let masked = mask_with_companions(contract, &changed, &companions);
                assert!(
                    !super::super::super::super::flaky_escape_failures(
                        contract.package,
                        contract.target,
                        &masked,
                    )
                    .is_empty()
                );
            }
        }
        Ok(())
    }
}
