//! Exercises every registered continuation contract with causal source mutations.
//!
//! Each fixture first binds its real production source and companions, then
//! proves that missing obligations or altered recovery operations remain visible
//! to both the local mask and the composed scanner.

use super::{
    compact_code, constructor_continuations, contracts, expression_offsets, hot_fork_retirement,
    host_physical_custody, identifier_count, lifecycle_retirement, mask_contract, read_companions,
    replace_one_obligation, retained_continuations, service_continuations, source_pattern,
    pager_placement,
};

#[test]
fn continuation_waits_require_original_posts_and_physical_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::super::super::workspace_root();
    let has_escape = |code: &str| {
        super::super::super::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`") || finding.contains("`thread::sleep`"))
    };
    for contract in contracts() {
        let source = std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = super::super::super::scrub_comments_and_strings(&source);
        let companions = read_companions(contract)?;
        let rejects = |candidate: &str, evidence: &[String]| {
            let masked = mask_contract(contract, candidate, evidence);
            has_escape(&masked)
                && has_escape(&super::super::mask_after_operations(
                    contract.package,
                    contract.target,
                    &masked,
                ))
        };
        assert!(
            has_escape(&code),
            "unreviewed source has no escape: {}",
            contract.target
        );
        assert!(
            !has_escape(&mask_contract(contract, &code, &companions)),
            "reviewed continuation changed: {}: {:#?}",
            contract.target,
            lifecycle_retirement::contract_diagnostics(contract, &code, &companions)
        );
        assert!(
            rejects(&code, &[]),
            "missing Original/custody companion passed: {}",
            contract.target
        );

        assert!(
            super::super::super::flaky_escape_failures(contract.package, contract.target, &source)
                .is_empty(),
            "composed operation contracts changed: {}",
            contract.target
        );

        if contract.package == "crucible-qemu-host"
            && contract.target == "src/linux_attempt_host/original_roster"
        {
            let obligation = source_pattern(
                "slot.installed_process = None; slot.source_control_payer = None; slot.active = None;",
            );
            for replacement in [
                "slot.installed_process = None; slot.active = None;",
                "slot.source_control_payer = None; slot.installed_process = None; slot.active = None;",
                "slot.installed_process = None; slot.active = None; slot.source_control_payer = None;",
            ] {
                let changed = replace_one_obligation(&code, &obligation, replacement);
                assert!(
                    rejects(&changed, &companions),
                    "omitted or reordered Source payer return was masked: {replacement}"
                );
            }
        }

        for (requirement, count) in contract.required {
            let obligation = source_pattern(requirement);
            assert_eq!(
                compact_code(&code).match_indices(&obligation).count(),
                *count
            );
            if *count == 0 {
                let added = format!("{code}\n{obligation}");
                assert!(
                    rejects(&added, &companions),
                    "new clock or phase constructor was masked: {} {requirement}",
                    contract.target
                );
                continue;
            }
            // Omitting an entire signature must leave its same retry name
            // visible; deleting the sole escape cannot test classification.
            // The import-only clause similarly retains its actual imported name.
            let declaration_marker = contract.identifiers.iter().find_map(|(name, _)| {
                obligation
                    .contains(&format!("fn{name}("))
                    .then(|| format!("fn {name}() {{"))
            });
            let replacement = declaration_marker
                .as_deref()
                .or_else(|| lifecycle_retirement::omission_replacement(contract, requirement))
                .unwrap_or(" removed_original_obligation() ");
            let changed = replace_one_obligation(&code, &obligation, replacement);
            assert_ne!(changed, code, "local omission did not change {requirement}");
            assert_eq!(
                mask_contract(contract, &changed, &companions),
                changed,
                "missing local obligation still satisfied its contract: {} {requirement}",
                contract.target
            );
            assert!(
                rejects(&changed, &companions),
                "removed local obligation was masked: {} {requirement}",
                contract.target
            );
        }
        for (index, binding) in contract.companions.iter().enumerate() {
            let source = super::super::super::scrub_comments_and_strings(&companions[index]);
            for (requirement, count) in binding.required {
                let obligation = source_pattern(requirement);
                assert_eq!(
                    compact_code(&source).match_indices(&obligation).count(),
                    *count
                );
                if *count == 0 {
                    let mut changed = companions.clone();
                    changed[index] = format!("{source}\n{obligation}");
                    assert!(
                        rejects(&code, &changed),
                        "new companion clock was masked: {} {requirement}",
                        binding.path
                    );
                    continue;
                }
                let mut changed = companions.clone();
                changed[index] =
                    replace_one_obligation(&source, &obligation, " removed_original_obligation() ");
                assert!(
                    rejects(&code, &changed),
                    "removed companion obligation was masked: {} {requirement}",
                    binding.path
                );
            }
        }
        for (expression, count) in contract.expressions {
            let expression = *expression;
            let expression_pattern = source_pattern(expression);
            assert_eq!(expression_offsets(&code, &expression_pattern).len(), *count);
            let additional = format!("{code}\n{expression}");
            assert!(
                rejects(&additional, &companions),
                "additional continuation was masked: {} {expression}",
                contract.target
            );
            let changed_expression = expression
                .replace("from_millis(1)", "from_millis(2)")
                .replace("from_millis(10)", "from_millis(11)")
                .replace("(&error)", "(&other_error)")
                .replace("retry_unsettled()", "retry_unsettled(altered)")
                .replace("retry_pending()", "retry_pending(altered)")
                .replace("retry_abandoned_jobs()", "retry_abandoned_jobs(altered)")
                .replace("(&state, slot)", "(&other_state, slot)")
                .replace(
                    "(self.epoch, self.process_generation)",
                    "(altered_epoch, self.process_generation)",
                )
                .replace(
                    "slice.min(WATCHER_WAIT_POLL_INTERVAL)",
                    "WATCHER_WAIT_POLL_INTERVAL",
                )
                .replace(
                    "retry_reserved_publication()",
                    "retry_reserved_publication(altered)",
                )
                .replace("(slot)", "(other_slot)")
                .replace("(provider)", "(other_provider)")
                .replace("(&mut self)", "(&mut other)");
            let changed_expression = if changed_expression == expression {
                lifecycle_retirement::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                hot_fork_retirement::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                retained_continuations::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                constructor_continuations::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                service_continuations::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                host_physical_custody::altered_expression(expression)
            } else {
                changed_expression
            };
            let changed_expression = if changed_expression == expression {
                pager_placement::altered_expression(expression)
            } else {
                changed_expression
            };
            assert_ne!(changed_expression, expression);
            let changed = replace_one_obligation(&code, &expression_pattern, &changed_expression);
            assert!(
                rejects(&changed, &companions),
                "changed continuation was masked: {} {expression}",
                contract.target
            );
        }
        for (name, count) in contract.identifiers {
            assert_eq!(identifier_count(&code, name), *count);
            let additional = format!("{code}\nfn conceal_failure() {{ {name}(); }}");
            assert!(
                rejects(&additional, &companions),
                "additional recovery call was masked: {} {name}",
                contract.target
            );
        }
        for addition in [
            "fn conceal_failure() { thread::sleep(unbounded); }",
            "fn conceal_failure() { retry(); }",
            "fn conceal_failure() { retry!(); }",
            "fn retry() {}",
            "fn conceal_failure() { retry_failed_test(); }",
            "fn conceal_failure() { loop { retry_failed_test(); } }",
        ] {
            let additional = format!("{code}\n{addition}");
            assert!(
                rejects(&additional, &companions),
                "additional test escape was masked: {} {addition}",
                contract.target
            );
        }
    }
    Ok(())
}
