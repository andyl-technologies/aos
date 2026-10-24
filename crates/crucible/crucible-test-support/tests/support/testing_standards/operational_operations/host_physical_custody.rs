//! Binds physical node/Target continuations to their actual retained owners.
//!
//! Saved-operation checks and physical return order distinguish these paths
//! from rerunning failed tests. Source checks grant no native authority and
//! do not qualify real-QEMU lifecycle integration.

use super::{Companion, Contract};

#[path = "host_physical_custody/node_construction.rs"]
mod node_construction;
#[path = "host_physical_custody/fork_target.rs"]
mod fork_target;
#[path = "host_physical_custody/normal_world.rs"]
mod normal_world;
#[path = "host_physical_custody/roster_storage.rs"]
mod roster_storage;
#[path = "host_physical_custody/roster_retirement.rs"]
mod roster_retirement;
#[path = "host_physical_custody/target_dispatcher.rs"]
mod target_dispatcher;

pub(in super::super) use roster_retirement::{FAILED_BODIES, RECONCILE_BODY};
pub(super) use roster_retirement::{SOURCE_CLEANUP, SOURCE_ORIGINAL};

pub(super) use node_construction::{
    NODE_OWNER, NODE_BIRTH, NODE_ISSUE, NODE_CONVERSION, NODE_SUBDIVISION, NODE_LEDGER,
    NODE_RETURN_HISTORY, NODE_CREDIT_BIRTH, NODE_PUBLISHER, NODE_LAYOUT, NODE_ROSTER_RETURN,
    NODE_CREDIT_RETURN,
};

// Reuse the exact lower World facts for same-owner daemon forwarders.
pub(super) const NORMAL_WORLD: &Contract = &normal_world::CONTRACT;
pub(super) const TARGET_WORLD: &Contract = &fork_target::CONTRACT;
pub(super) const NATIVE_JOIN: Companion = Companion {
    path: target_dispatcher::CONTRACT.companions[1].path,
    required: target_dispatcher::CONTRACT.companions[1].required,
};

pub(super) const CONTRACTS: &[Contract] = &[
    normal_world::CONTRACT,
    fork_target::CONTRACT,
    target_dispatcher::CONTRACT,
    roster_retirement::CONTRACT,
    node_construction::CONTRACT,
];

#[test]
fn host_continuations_reject_foreign_owners_and_premature_return()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    let mutations: &[&[(&str, &str)]] = &[
        &[
            (
                "entry.as_ref().is_some_and(|node| node.world == world)",
                "true",
            ),
            ("loan.retained_cleanup()", "pool.begin_preparation()"),
            ("original_roster::after_cleanup(result, &cleanup)", "result"),
        ],
        &[
            ("self.returned |= returned;", "self.returned = true;"),
            ("slot.fork_target.occupied != Some(epoch)", "false"),
            (
                "slot.fork_target.reserved_process_generation != Some(process_generation)",
                "false",
            ),
        ],
        &[
            (
                "let after = phase(&mut slot.original);",
                "let after = Ok(());",
            ),
            (
                "slot.phase = JobPhase::Retiring;",
                "slot.phase = JobPhase::Idle;",
            ),
            (
                ".observe_worker_return(worker, cleanup)",
                ".observe_worker_return(other_worker, cleanup)",
            ),
            ("if self.cleanup.is_none()", "if true"),
        ],
    ];
    for (contract, mutations) in CONTRACTS.iter().zip(mutations) {
        let source = std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target)),
        )?;
        let code = crate::scrub_comments_and_strings(&source);
        let evidence = super::read_companions(contract)?;
        for (needle, replacement) in *mutations {
            let changed =
                super::replace_one_obligation(&code, &super::source_pattern(needle), replacement);
            assert_ne!(changed, code, "mutation did not change {needle}");
            let masked = super::mask_contract(contract, &changed, &evidence);
            assert_eq!(masked, changed, "changed custody still matched {needle}");
            assert!(
                !crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty(),
                "changed custody was concealed: {}: {needle}",
                contract.target,
            );
        }
    }
    Ok(())
}

// The generic mutation assertion remains unchanged; this supplies only its new
// concrete no-argument call's foreign-argument recipe.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    match expression {
        "node.retry_cleanup()" => "node.retry_cleanup(foreign_owner)".to_owned(),
        "self.retry_failed_launch_bodies()?" =>
            "self.retry_failed_launch_bodies(foreign_source)?".to_owned(),
        "self.retry_failed_launch_bodies()" =>
            "self.retry_failed_launch_bodies(foreign_source)".to_owned(),
        "retained.retry_physical_cleanup()" =>
            "retained.retry_physical_cleanup(foreign_source)".to_owned(),
        _ => expression.to_owned(),
    }
}

#[test]
fn target_native_join_requires_unique_handle_process_and_irreversible_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &target_dispatcher::CONTRACT;
    let root = crate::workspace_root();
    let source = std::fs::read_to_string(
        crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let evidence = super::read_companions(contract)?;
    let details = super::lifecycle_retirement::contract_diagnostics(contract, &code, &evidence);
    assert!(details.is_empty(), "{}: {details:#?}", contract.target);
    assert_ne!(super::mask_contract(contract, &code, &evidence), code);
    for (needle, replacement) in [
        (
            "job.next_attempt.poll(CGROUP_KILL_INTERVAL)",
            "Ok(Duration::ZERO)",
        ),
        (
            "slot.next_retry.poll(CGROUP_KILL_INTERVAL)",
            "Ok(Duration::ZERO)",
        ),
        (
            "retained_worker: OnceLock::new(),",
            "retained_worker: None,",
        ),
        (
            "self.state = Some(Arc::new(DispatcherState",
            "self.state = None; let _ = Some(Arc::new(DispatcherState",
        ),
        ("*saved = Some(outcome);", "drop(outcome);"),
        ("self.worker = Some(worker);", "drop(worker);"),
    ] {
        let changed =
            super::replace_one_obligation(&code, &super::source_pattern(needle), replacement);
        assert_ne!(
            changed, code,
            "mutation missed actual startup owner cut: {needle}"
        );
        assert_eq!(
            super::mask_contract(contract, &changed, &evidence),
            changed,
            "changed startup ownership was concealed: {needle}"
        );
    }
    for (needle, replacement) in [
        ("worker.into_pthread_t()", "worker.as_pthread_t()"),
        (
            "libc::EBUSY => Ok(NativeJoinObservation::Pending)",
            "libc::EBUSY => Ok(NativeJoinObservation::Returned)",
        ),
        ("*self = Self::Uncertain(status);", "*self = Self::Active;"),
        ("if !self.belongs_to_current_process()", "if false"),
        ("self.native = None;", "self.native = Some(native);"),
        (
            "self.cleanup.verify_identity(cleanup)?;",
            "let _ = cleanup;",
        ),
        ("self.worker != Some(worker.thread_id())", "false"),
    ] {
        let mut changed = evidence
            .iter()
            .map(|source| crate::scrub_comments_and_strings(source))
            .collect::<Vec<_>>();
        let mut matched = false;
        for companion in &mut changed {
            let altered = super::replace_one_obligation(
                companion,
                &super::source_pattern(needle),
                replacement,
            );
            if altered != *companion {
                *companion = altered;
                matched = true;
                break;
            }
        }
        assert!(matched, "mutation missed actual native join: {needle}");
        assert_eq!(
            super::mask_contract(contract, &code, &changed),
            code,
            "changed native join was concealed: {needle}"
        );
    }
    Ok(())
}
