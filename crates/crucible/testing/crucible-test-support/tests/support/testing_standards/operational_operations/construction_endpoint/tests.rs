//! Rejects changed handback authority, premature closure and lost actual leaves.

use super::*;
use super::super::{
    expression_offsets, mask_contract, read_companions, replace_one_obligation, source_pattern,
};

const MUTATIONS: &[(&str, &str, &str, &str)] = &[
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"self.publish()?;"#,
        r#"self.publish()?; self.publish()?;"#,
        "duplicate initial publication",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"let history = returned.retry()?;"#,
        r#"let history = other.retry()?;"#,
        "foreign receipt retry",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"*self = Self::History(Some(history));"#,
        r#"*self = Self::History(None);"#,
        "lost completed history",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"if failure.additional.is_some()"#,
        r#"if failure.additional.is_none()"#,
        "lost additional cause",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"matches!(failure.storage, FailureStorage::Rejected { .. })"#,
        r#"matches!(failure.storage, FailureStorage::Missing(_))"#,
        "wrong publication dispatch",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#".retry_reserved_publication()"#,
        r#".retain_in_reserved_cleanup()"#,
        "republish returned pair via initial route",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"shell: slot.take(),
                first: None,
                receipt: Some(receipt),"#,
        r#"shell: slot.take(), first: None, receipt: None,"#,
        "receipt lost before shell conversion",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"*slot = Some(failure);"#,
        r#"*slot = None;"#,
        "lost refused original failure",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"self.shell = Some(shell);"#,
        r#"self.shell = None;"#,
        "lost refused original shell",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"if self.shell.is_some()"#,
        r#"if self.shell.is_none()"#,
        "ignored unpublished independent custody",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"let _attempt = receipt.retry();"#,
        r#"let _attempt = receipt.retry(); let _again = receipt.retry();"#,
        "extra native cleanup attempt",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"SourceCleanupHistory::take_returned_constructor(&mut self.first, &mut self.receipt)"#,
        r#"SourceCleanupHistory::take_returned_constructor(&mut foreign.first, &mut self.receipt)"#,
        "foreign first slot",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"*slot = Some(history);"#,
        r#"*slot = None;"#,
        "lost occupied-destination input",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug.rs"#,
        r#"body.retain_source_history(history)"#,
        r#"body.retain_source_history(other_history)"#,
        "foreign history payload",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#"Ok(crucible_control_api::ProductionVmCleanupStage::Complete)"#,
        r#"Ok(crucible_control_api::ProductionVmCleanupStage::BodyDestroyed)"#,
        "body-only completion",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#"if !handoff.retain_post_body()
            || !handoff"#,
        r#"if !handoff.retain_post_body() && !handoff"#,
        "weakened terminal conjunction",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#".is_some_and(crate::ProductionVmConstructionPostBody::has_terminal_custody)"#,
        r#".is_some()"#,
        "absent actual terminal custody",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#"*first = Some(original_first);"#,
        r#"*first = None;"#,
        "lost first on absent receipt",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#"terminal_receipt: Some(SourceCleanupHandoff::new(original_receipt))"#,
        r#"terminal_receipt: None"#,
        "lost original terminal receipt",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/qemu_campaign_lifecycle.rs"#,
        r#"receipt.dispose();"#,
        r#"drop(receipt);"#,
        "discarded canonical token without terminal disposal",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/runtime.rs"#,
        r#"construction.retry()?;"#,
        r#"construction.retry()?; *retained = None;"#,
        "body cleanup clears retained slot",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/runtime.rs"#,
        r#"construction.transfer_history(destination)?;
            *retained = None;"#,
        r#"*retained = None;"#,
        "clear before owning history acceptance",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/runtime.rs"#,
        r#"*retained = Some(construction::RetainedDebugConstruction::new(failure));"#,
        r#"drop(failure);"#,
        "diagnostic before owning save",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs"#,
        r#"if !self.physically_closed.load(Ordering::Acquire)"#,
        r#"if self.physically_closed.load(Ordering::Acquire)"#,
        "history extraction before body closure",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs"#,
        r#"self.post_body = body;"#,
        r#"drop(body);"#,
        "lost saved parent obligations",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs"#,
        r#"lifecycle.transfer_retained_debug_construction(&mut self.post_body)?;"#,
        r#"let _ = lifecycle.transfer_retained_debug_construction(&mut self.post_body);"#,
        "discarded child handback refusal",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs"#,
        r#"self.first = Some(first);"#,
        r#"self.first = None;"#,
        "lost containing original first",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs"#,
        r#"self.terminal.is_some()"#,
        r#"true"#,
        "fabricated terminal evidence",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs"#,
        r#"return Err(history);"#,
        r#"return Ok(());"#,
        "occupied history silently discarded",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs"#,
        r#"self.not_started.is_some()
            || self"#,
        r#"true || self"#,
        "history-only Source return",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs"#,
        r#"super::terminal::return_report_reference(&key, true);"#,
        r#"super::terminal::return_report_reference(&key, false);"#,
        "unreturned actual terminal pin",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs"#,
        r#"epoch: self.epoch,"#,
        r#"epoch: self.epoch + 1,"#,
        "foreign cleanup epoch",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs"#,
        r#"self.report_reference = false;"#,
        r#"self.report_reference = true;"#,
        "duplicate original report pin",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs"#,
        r#"self.terminal_history = Some(body);"#,
        r#"drop(body);"#,
        "lost returned actual terminal",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs"#,
        r#"drop(receipt);
    drop(terminal);"#,
        r#"drop(terminal); drop(receipt);"#,
        "terminal released before original token destructor",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs"#,
        r#"slot.external_receivers.load(Ordering::Acquire) != 0"#,
        r#"false"#,
        "outstanding receiver ignored",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs"#,
        r#"if !body.native_returns_observed() || body.terminal.is_some()"#,
        r#"if body.terminal.is_some()"#,
        "native return bypass",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs"#,
        r#"slot.report_references.load(Ordering::Acquire) != 1"#,
        r#"slot.report_references.load(Ordering::Acquire) != 0"#,
        "wrong sole actual report pin",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/terminal.rs"#,
        r#"prepared: prepared.owner.take(),"#,
        r#"prepared: None,"#,
        "lost original terminal prepared payload",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"assert_eq!(std::ptr::from_ref(custody.as_ref()), address);"#,
        r#"assert_ne!(std::ptr::from_ref(custody.as_ref()), address);"#,
        "changed actual carrier identity assertion",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);"#,
        r#"assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);"#,
        "accepted native callback during refusal",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"assert_eq!((current.dev(), current.ino()), identity);"#,
        r#"assert_ne!((current.dev(), current.ino()), identity);"#,
        "lost missing carrier inode check",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"additional_probe.assert_first(failure.additional.as_ref().unwrap());"#,
        r#"additional_probe.assert_open();"#,
        "lost additional typed original assertion",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"assert!(receipt.as_ref().unwrap().retained_post_body().is_none());"#,
        r#"assert!(receipt.as_ref().unwrap().retained_post_body().is_some());"#,
        "accepted unavailable canonical receipt",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs"#,
        r#"assert_eq!(std::ptr::from_ref(actual), incoming_probe.cause);"#,
        r#"assert_ne!(std::ptr::from_ref(actual), incoming_probe.cause);"#,
        "lost occupied history identity",
    ),
    (
        r#"crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody/post_body/tests.rs"#,
        r#"assert_eq!(message.as_ptr(), original_message);"#,
        r#"assert_ne!(message.as_ptr(), original_message);"#,
        "lost containing first allocation identity",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop.rs",
        "let lease_binding = self.prepare_whole_node_shutdown();",
        "let lease_binding = Ok(foreign_binding);",
        "omitted same-owner whole-shutdown preparation",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop.rs",
        "Ok(binding) => self.finish_whole_node_leases(binding)",
        "Ok(binding) => self.finish_whole_node_leases(foreign_binding)",
        "foreign whole-shutdown lease binding",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop/whole_shutdown.rs",
        "lease.identity().node() != node || lease.identity().generation() != *generation",
        "false",
        "foreign lease identity accepted before arming",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop/whole_shutdown.rs",
        ".prepare_whole_shutdown(binding, self.node_leases.keys())",
        ".prepare_whole_shutdown(binding, std::iter::empty())",
        "omitted actual leased-node membership",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop/whole_shutdown.rs",
        "if binding != self.whole_shutdown_binding()",
        "if false",
        "changed generation binding accepted for lease return",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop/whole_shutdown.rs",
        "self.inner.backend().verify_whole_shutdown_return(binding)?;",
        "verify_unproved_return();",
        "lease return without same-backend physical disposition",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        "WholeShutdown::Returned(saved) if *saved == binding => Ok(())",
        "WholeShutdown::Returned(_) => Ok(())",
        "foreign returned whole-set binding",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        "if !self.nodes.is_empty()",
        "if true",
        "empty uninstalled set mints an armed disposition",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        ".any(|node| !node.cleanup_physically_returned())",
        ".any(|_| false)",
        "actual node leaf return bypassed",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        "matches!(self.whole_shutdown, WholeShutdown::Destructing)",
        "false",
        "destruction-unwind entry refusal missing",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        "let prior = std::mem::replace(&mut self.whole_shutdown, WholeShutdown::Destructing);",
        "let prior = std::mem::replace(&mut self.whole_shutdown, WholeShutdown::Unarmed);",
        "missing actual Destructing journal before value destruction",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/whole_shutdown.rs",
        "self.nodes.clear(); self.whole_shutdown = match prior { WholeShutdown::Armed(binding) => WholeShutdown::Returned(binding), prior => prior, };",
        "self.whole_shutdown = match prior { WholeShutdown::Armed(binding) => WholeShutdown::Returned(binding), prior => prior, }; self.nodes.clear();",
        "return published before actual map value destruction",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set.rs",
        "pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> { self.invalidate_whole_shutdown();",
        "pub fn insert(&mut self, node: NodeId, backend: QemuNode) -> Option<QemuNode> {",
        "map insertion inherits a prior return phase",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set.rs",
        "pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> { self.invalidate_whole_shutdown();",
        "pub fn take(&mut self, node: &NodeId) -> Option<QemuNode> {",
        "map extraction inherits a prior return phase",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set.rs",
        "let mut owned = Vec::with_capacity(operations.len()); self.invalidate_whole_shutdown();",
        "let mut owned = Vec::with_capacity(operations.len());",
        "concurrent hot-fork extraction retains stale whole-set phase",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/lifecycle.rs",
        "self.invalidate_whole_shutdown(); for (node, replacement) in plan.nodes.into_iter().zip(replacements.drain(..))",
        "for (node, replacement) in plan.nodes.into_iter().zip(replacements.drain(..))",
        "replacement map expansion before invalidating the same phase",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node_set/concurrent.rs",
        "self.invalidate_whole_shutdown(); self.arm_concurrent_fault_event_staging(&runs)?;",
        "self.arm_concurrent_fault_event_staging(&runs)?;",
        "concurrent run extraction retains stale phase",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle/quantum_loop.rs",
        "let retired = self.inner.backend_mut().commit_terminal_replacements(plan, replacement_values)?;",
        "let retired = Vec::new();",
        "lease expansion without actual backend commit invalidation",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle.rs",
        "if let Err(error) = lease.finish()",
        "if let Err(error) = foreign_lease.finish()",
        "foreign lease retirement before releasing the actual slot",
    ),
    (
        "crates/crucible/control/crucible-daemon/src/vm_lifecycle.rs",
        "continue; } node_leases.remove(node);",
        "} node_leases.remove(node);",
        "lease body removed after its own retirement refusal",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node/host_policy.rs",
        "self.child.reaped() && self.child_shutdown.physically_returned()",
        "self.child.reaped()",
        "process reap substituted for whole-leaf return",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_continuation.rs",
        "if returned { self.complete(); }",
        "self.complete();",
        "Original completion before actual RAM return",
    ),
    (
        "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_continuation.rs",
        "guard.complete_observed()",
        "foreign_guard.complete_observed()",
        "foreign Original completion substituted for the saved guard",
    ),
];

// These exact finite cuts reuse the scoped facts instead of copying each loop
// into before/after snapshots. Every mutation changes one actual occurrence.
fn scoped_behavior_mutations() -> Vec<(&'static str, String, String, String)> {
    let path = "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/retained_debug/tests.rs";
    let mut cases = Vec::with_capacity(9);
    for (name, original) in [
        ("body", controls::BODY_OBSERVATIONS),
        ("pair", controls::PAIR_OBSERVATIONS),
        ("receipt", controls::RECEIPT_OBSERVATIONS),
    ] {
        for (before, after) in [("0..2", "0..0"), (".is_err()", ".is_ok()")] {
            assert_eq!(original.matches(before).count(), 1);
            cases.push((
                path,
                original.to_owned(),
                original.replacen(before, after, 1),
                format!("{name}: {before} -> {after}"),
            ));
        }
    }
    let original = controls::OCCUPIED_SUCCESS;
    let effect = "retained.transfer_history(&mut destination).unwrap();";
    assert_eq!(original.matches(effect).count(), 1);
    for (replacement, reason) in [
        ("", "omitted transfer"),
        (
            "retained.transfer_history(&mut other_destination).unwrap();",
            "foreign destination",
        ),
        (
            "retained.transfer_history(&mut destination).unwrap(); retained.transfer_history(&mut destination).unwrap();",
            "duplicate transfer",
        ),
    ] {
        cases.push((
            path,
            original.to_owned(),
            original.replacen(effect, replacement, 1),
            reason.to_owned(),
        ));
    }
    assert_eq!(cases.len(), 9);
    cases
}

#[test]
fn candidate_handback_requires_original_terminal_custody_and_all_seven_controls()
-> Result<(), Box<dyn std::error::Error>> {
    // Shared arrays retain their existing order; verify the selected facts so
    // a later reordering cannot silently weaken this endpoint's provenance.
    for (binding, expected) in [
        (
            super::super::hot_fork_retirement::CONSTRUCTOR_BODY,
            "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
        ),
        (
            super::super::hot_fork_retirement::CONSTRUCTOR_WORLD_RETURN,
            "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/post_body.rs",
        ),
        (
            super::super::hot_fork_retirement::CONSTRUCTOR_WORLD_POOL,
            "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool.rs",
        ),
        (
            super::super::hot_fork_retirement::CONSTRUCTOR_WORLD_LEDGER,
            "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/ledger.rs",
        ),
    ] {
        assert_eq!(binding.path, expected);
    }
    assert!(
        super::super::hot_fork_retirement::CONSTRUCTOR_BODY
            .required
            .iter()
            .any(|(clause, _)| source_pattern(clause)
                .starts_with(&source_pattern("fn retire_complete(")))
    );
    let root = crate::workspace_root();
    let escapes = |code: &str| {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`") || finding.contains("`thread::sleep`"))
    };
    let behavior_mutations = scoped_behavior_mutations();
    for contract in CONTRACTS {
        let source = std::fs::read_to_string(
            root.join("crates/crucible/control/crucible-daemon")
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = crate::scrub_comments_and_strings(&source);
        let companions = read_companions(contract)?;
        assert!(escapes(&code));
        assert!(!escapes(&mask_contract(contract, &code, &companions)));
        let generated = behavior_mutations
            .iter()
            .map(|(path, before, after, reason)| {
                (*path, before.as_str(), after.as_str(), reason.as_str())
            });
        for (path, before, after, reason) in MUTATIONS.iter().copied().chain(generated) {
            let mut evidence = companions.clone();
            let mut candidate = code.clone();
            let mut bound = false;
            for (binding, actual) in contract.companions.iter().zip(&mut evidence) {
                if binding.path != path {
                    continue;
                }
                let Some((clause, _)) = binding
                    .required
                    .iter()
                    .find(|(clause, _)| source_pattern(clause).contains(&source_pattern(before)))
                else {
                    continue;
                };
                let original_clause = crate::scrub_comments_and_strings(clause);
                let replacement =
                    replace_one_obligation(&original_clause, &source_pattern(before), after);
                assert_ne!(
                    replacement, original_clause,
                    "mutation did not reach {path}: {reason}"
                );
                let original = crate::scrub_comments_and_strings(actual);
                *actual = replace_one_obligation(&original, &source_pattern(clause), &replacement);
                if path
                    == format!(
                        "crates/crucible/control/crucible-daemon/{}.rs",
                        contract.target
                    )
                {
                    candidate =
                        replace_one_obligation(&candidate, &source_pattern(clause), &replacement);
                }
                bound = true;
            }
            assert!(bound, "unbound mutation {path}: {reason}");
            assert!(
                escapes(&mask_contract(contract, &candidate, &evidence)),
                "changed terminal/ownership evidence was masked: {reason} ({})",
                contract.target,
            );
        }
    }
    Ok(())
}

/// Changes each real refusal assertion independently, including missing/poison.
#[test]
fn every_actual_candidate_refusal_keeps_its_negative_result()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &CONTRACTS[1];
    assert_eq!(
        contract.target,
        "src/vm_lifecycle/construction/retained_debug/tests"
    );
    let source = std::fs::read_to_string(
        crate::workspace_root()
            .join("crates/crucible/control/crucible-daemon")
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = read_companions(contract)?;
    let obligation = source_pattern(controls::REFUSAL_ASSERTION);
    let occurrences = expression_offsets(&code, &obligation);
    assert_eq!(occurrences.len(), 5);
    let offsets = code
        .char_indices()
        .filter_map(|(offset, character)| (!character.is_whitespace()).then_some(offset))
        .collect::<Vec<_>>();
    for start in occurrences {
        let end = start + obligation.len() - 1;
        let mut changed = code.clone();
        changed.replace_range(
            offsets[start]..offsets[end] + 1,
            "assert!(lifecycle.retry_retained_debug_construction().is_ok());",
        );
        assert_ne!(changed, code);
        assert_eq!(mask_contract(contract, &changed, &companions), changed);
        assert!(
            crate::flaky_escape_failures("unreviewed", "unreviewed", &changed)
                .iter()
                .any(|finding| finding.contains("`retry`"))
        );
    }
    Ok(())
}
