//! Exercises exact SQLite source contracts and rejects operational drift.

use super::super::{mask_with_companions, pattern, read_companions};
use super::*;

fn has_escape(code: &str) -> bool {
    super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
        .iter()
        .any(|finding| finding.contains("`retry`") || finding.contains("`thread::sleep`"))
}

fn local_source(contract: &Contract) -> std::io::Result<String> {
    let root = super::super::super::super::workspace_root();
    let source = std::fs::read_to_string(
        root.join("crates")
            .join(contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    Ok(super::super::super::super::scrub_comments_and_strings(
        &source,
    ))
}

// Preserve lexical spacing around mutations, especially `fn retry` and
// `match connection`, so a negative check cannot pass for the wrong reason.
fn replace_pattern(source: &str, before: &str, after: &str) -> String {
    let code = super::super::super::super::scrub_comments_and_strings(source);
    let compact = pattern(&code);
    let start = compact.find(before).expect("applicable contract mutation");
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let mut changed = code;
    changed.replace_range(offsets[start]..offsets[start + before.len() - 1] + 1, after);
    super::super::super::super::scrub_comments_and_strings(&changed)
}

fn replace_all_patterns(source: &str, before: &str, after: &str) -> String {
    let mut changed = source.to_owned();
    while pattern(&changed).contains(before) {
        changed = replace_pattern(&changed, before, after);
    }
    changed
}

#[test]
fn exact_sqlite_operations_reject_changed_extra_and_unrelated_retries()
-> Result<(), Box<dyn std::error::Error>> {
    for contract in CONTRACTS {
        let source = local_source(contract)?;
        let compact = pattern(&source);
        let companions = read_companions(contract)?;
        assert!(
            has_escape(&source),
            "unreviewed target: {}",
            contract.target
        );
        assert!(
            !has_escape(&mask_with_companions(contract, &source, &companions)),
            "reviewed target: {}",
            contract.target
        );

        for (expression, count) in contract.expressions {
            let reviewed = expression;
            let expression = pattern(expression);
            assert_eq!(compact.match_indices(&expression).count(), *count);
            let unchanged = replace_pattern(&source, &expression, reviewed);
            assert!(
                !has_escape(&mask_with_companions(contract, &unchanged, &companions)),
                "unchanged operation reinsertion: {} {expression}",
                contract.target
            );
            let additional = format!("{source}\n{expression}");
            assert!(
                has_escape(&mask_with_companions(contract, &additional, &companions)),
                "additional exact operation: {} {expression}",
                contract.target
            );

            let changed_expression = reviewed.replace("retry", "retry_changed");
            assert_ne!(pattern(&changed_expression), expression);
            let changed = replace_pattern(&source, &expression, &changed_expression);
            assert!(
                has_escape(&mask_with_companions(contract, &changed, &companions)),
                "changed operation: {} {expression}",
                contract.target
            );

            for prefix in ["other_", "other::", "other :: ", "λ", "a\u{0301}"] {
                let changed = replace_pattern(&source, &expression, &format!("{prefix}{reviewed}"));
                assert!(
                    has_escape(&mask_with_companions(contract, &changed, &companions)),
                    "changed helper identity: {} {prefix}{expression}",
                    contract.target
                );
            }

            for argument in ["connection", "transaction", "boundary", "check", "original"] {
                if !expression.contains(argument) {
                    continue;
                }
                let altered = reviewed.replacen(argument, "different_operation", 1);
                let changed = replace_pattern(&source, &expression, &altered);
                assert!(
                    has_escape(&mask_with_companions(contract, &changed, &companions)),
                    "changed original argument: {} {argument}",
                    contract.target
                );
            }
        }

        for addition in [
            "retry();",
            "retry!();",
            "retry_failed_test();",
            "other_busy::retry(connection, true, quarantined, boundary, statement);",
            "busy::retry(connection, true, quarantined, &mut || Ok(()), statement);",
            "std::thread::sleep(unbounded);",
        ] {
            let changed = format!("{source}\n{addition}");
            assert!(
                has_escape(&mask_with_companions(contract, &changed, &companions)),
                "unreviewed extra retry: {} {addition}",
                contract.target
            );
        }
    }
    Ok(())
}

#[test]
fn sqlite_operations_require_original_guards_and_busy_cleanup_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    for contract in CONTRACTS {
        let source = local_source(contract)?;
        let compact = pattern(&source);
        let companions = read_companions(contract)?;
        for obligation in contract.required {
            let reviewed = obligation;
            let obligation = pattern(reviewed);
            assert!(compact.contains(&obligation));
            let unchanged = replace_pattern(&source, &obligation, reviewed);
            assert!(
                !has_escape(&mask_with_companions(contract, &unchanged, &companions)),
                "unchanged local guard reinsertion: {} {obligation}",
                contract.target
            );
            let altered = reviewed.replacen('(', "_changed_guard(", 1);
            assert_ne!(pattern(&altered), obligation);
            let changed = replace_all_patterns(&source, &obligation, &altered);
            // A comment containing the former guard cannot repair a missing check.
            let changed = format!("{changed}\n/* {obligation} */");
            let changed = super::super::super::super::scrub_comments_and_strings(&changed);
            assert!(
                has_escape(&mask_with_companions(contract, &changed, &companions)),
                "missing local guard: {} {obligation}",
                contract.target
            );
        }

        for guard in [
            "check_original(boundary,&account,operation.as_deref())",
            "letmutoriginal=||check(backend,account,boundary);",
            "account.verify_live().map_err(admission)?;",
            "operation.check()?;",
            "boundary()?;",
            "guard.verify()?;",
            "&mut||guard.verify()",
            "busy::with_zero(",
            "with_zero(",
        ] {
            let bound_guard = contract
                .required
                .iter()
                .copied()
                .chain(
                    contract
                        .expressions
                        .iter()
                        .map(|(expression, _)| *expression),
                )
                .any(|obligation| pattern(obligation).contains(guard));
            if !bound_guard {
                continue;
            }
            assert!(compact.contains(guard));
            let changed = replace_all_patterns(&source, guard, "missing_original_guard();");
            assert!(
                has_escape(&mask_with_companions(contract, &changed, &companions)),
                "removed original callback or scope: {} {guard}",
                contract.target
            );
        }

        assert!(has_escape(&mask_with_companions(contract, &source, &[])));
        for (index, binding) in contract.companions.iter().enumerate() {
            let helper = pattern(&companions[index]);
            for obligation in binding.required {
                let reviewed = obligation;
                let obligation = pattern(reviewed);
                assert!(helper.contains(&obligation));
                let mut unchanged = companions.clone();
                unchanged[index] = replace_pattern(&companions[index], &obligation, reviewed);
                assert!(
                    !has_escape(&mask_with_companions(contract, &source, &unchanged)),
                    "unchanged helper guard reinsertion: {} {obligation}",
                    contract.target
                );
                let mut changed = companions.clone();
                let altered = reviewed.replacen('(', "_changed_guard(", 1);
                assert_ne!(pattern(&altered), obligation);
                changed[index] = replace_pattern(&companions[index], &obligation, &altered);
                assert!(
                    has_escape(&mask_with_companions(contract, &source, &changed)),
                    "missing helper guard: {} {obligation}",
                    contract.target
                );
            }

            for (before, after) in [
                ("code.extended_code==5", "code.extended_code==6"),
                ("transactional&&connection.is_autocommit()", "false"),
                ("boundary()?;", "Ok::<(),StoreError>(())?;"),
                ("Duration::ZERO", "Duration::from_secs(60)"),
                (
                    "restore(connection,Duration::from_millis(saved))",
                    "Ok::<(),rusqlite::Error>(())",
                ),
            ] {
                assert!(helper.contains(before), "inapplicable mutation: {before}");
                let mut changed = companions.clone();
                changed[index] = replace_pattern(&companions[index], before, after);
                assert!(
                    has_escape(&mask_with_companions(contract, &source, &changed)),
                    "changed BUSY cleanup semantics: {} {before}",
                    contract.target
                );
            }

            for (expression, count) in binding.counts {
                let expression = pattern(expression);
                assert_eq!(helper.match_indices(&expression).count(), *count);
                let mut changed = companions.clone();
                changed[index] = format!("{}\n{expression}", companions[index]);
                assert!(has_escape(&mask_with_companions(
                    contract, &source, &changed
                )));
            }
        }
    }
    Ok(())
}
