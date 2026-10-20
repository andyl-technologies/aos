//! Binds physical node/Target continuations to their actual retained owners.
//!
//! Saved-operation checks and physical return order distinguish these paths
//! from rerunning failed tests. Source checks grant no native authority and
//! do not qualify real-QEMU lifecycle integration.

use super::{Companion, Contract};

#[path = "host_physical_custody/fork_target.rs"]
mod fork_target;
#[path = "host_physical_custody/normal_world.rs"]
mod normal_world;
#[path = "host_physical_custody/roster_retirement.rs"]
mod roster_retirement;
#[path = "host_physical_custody/target_dispatcher.rs"]
mod target_dispatcher;

// Reuse the exact lower World facts for same-owner daemon forwarders.
pub(super) const NORMAL_WORLD: &Contract = &normal_world::CONTRACT;

pub(super) const CONTRACTS: &[Contract] = &[
    normal_world::CONTRACT,
    fork_target::CONTRACT,
    target_dispatcher::CONTRACT,
    roster_retirement::CONTRACT,
];

#[test]
fn host_continuations_reject_foreign_owners_and_premature_return()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    let mutations: &[&[(&str, &str)]] = &[
        &[
            (".filter(|node| node.world == world)", ".filter(|_| true)"),
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
                ".try_join_worker(worker, cleanup)",
                ".try_join_worker(other_worker, cleanup)",
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
