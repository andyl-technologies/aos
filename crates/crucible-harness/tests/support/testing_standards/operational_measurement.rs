//! Exact original-operation custody for physical native retirement waits.

use super::Contract;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu",
        target: "src/linux_attempt_host/original_roster",
        required: &[
            "pub fn retry_unsettled(&mut self) -> Result<(), QemuVmRealizationError>",
            "for slot in &mut state.slots",
            "if slot.unsettled.is_none() { continue; }",
            "let cleanup = retain_cleanup(slot).map_err(original_error)?;",
            ".finish(&cleanup)?;",
            "close_slot(slot).map_err(original_error)?;",
            "slot.unsettled = None;",
            "assert!(roster.retry_unsettled().is_err());",
            "assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());",
        ],
        expressions: &[
            ("retry_unsettled", 3),
            (
                "assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());",
                2,
            ),
            (
                "terminal_cleanup_refuses_retry_and_keeps_actual_storage_and_generation",
                1,
            ),
        ],
        companions: &[],
    },
    Contract {
        package: "crucible-qemu",
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
    use super::super::{mask_with_companions, pattern};
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
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = scrub_comments_and_strings(&source);
            let masked = mask_with_companions(contract, &code, &[]);
            assert_ne!(masked, code, "{}", contract.target);

            for requirement in contract.required {
                let requirement = pattern(requirement);
                let occurrences = expression_offsets(&code, &requirement);
                assert!(!occurrences.is_empty(), "{requirement}");
                for occurrence in occurrences {
                    let changed = replace_occurrence(&code, &requirement, occurrence);
                    assert_eq!(mask_with_companions(contract, &changed, &[]), changed);
                }
            }
            for (expression, count) in contract.expressions {
                let expression = pattern(expression);
                let occurrences = expression_offsets(&code, &expression);
                assert_eq!(occurrences.len(), *count, "{expression}");
                for occurrence in occurrences {
                    let changed = replace_occurrence(&code, &expression, occurrence);
                    assert_eq!(mask_with_companions(contract, &changed, &[]), changed);
                }
                let changed = format!("{code}\n{expression}");
                assert_eq!(mask_with_companions(contract, &changed, &[]), changed);
            }
            for extra in [
                "fn conceal() { retry(); }",
                "fn conceal() { std::thread::sleep(unbounded); }",
            ] {
                let changed = format!("{code}{extra}");
                let masked = mask_with_companions(contract, &changed, &[]);
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
