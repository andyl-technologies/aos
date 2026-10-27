//! Binds Source cleanup continuations to the same carrier and native last use.
//!
//! These source contracts preserve physical custody and raw error histories.
//! They issue no Source, Park or rearm authority and do not qualify the missing
//! native rearm producer. Genuine entered-native validation remains required.

use super::{Companion, Contract};

#[path = "hot_fork_retirement/owners.rs"]
mod owners;
#[path = "hot_fork_retirement/park.rs"]
mod park;
#[path = "hot_fork_retirement/shared.rs"]
mod shared;
#[path = "hot_fork_retirement/source.rs"]
mod source;
#[path = "hot_fork_retirement/pre_vm.rs"]
mod pre_vm;

pub(super) const PRE_VM_CONTRACTS: &[Contract] = pre_vm::CONTRACTS;

/// Shares the actual phase producers with the containing construction carrier.
pub(super) const SHARED_BODY: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/vm_lifecycle/hot_fork/shared_source.rs",
    required: shared::CONTRACT.required,
};
/// Shares the saved rearm refusal and actual Source body return.
pub(super) const REARM_BODY: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/vm_lifecycle/hot_fork/rearm_return.rs",
    required: owners::REARM.required,
};
/// Shares preparation rollback and the same Source retirement delegate.
pub(super) const PREPARATION_BODY: Companion = Companion {
    path: "crates/crucible/crucible-daemon/src/vm_lifecycle/hot_fork/preparation.rs",
    required: owners::PREPARATION.required,
};

/// Reuses the unchanged actual complete-body shutdown ordering.
pub(super) const CONSTRUCTOR_BODY: Companion = Companion {
    path: source::CONTRACT.companions[3].path,
    required: source::CONTRACT.companions[3].required,
};
/// Reuses actual loan observation and its unchanged canonical ledger provenance.
pub(super) const CONSTRUCTOR_WORLD_RETURN: Companion = Companion {
    path: source::CONTRACT.companions[0].path,
    required: source::CONTRACT.companions[0].required,
};
pub(super) const CONSTRUCTOR_WORLD_POOL: Companion = Companion {
    path: source::CONTRACT.companions[1].path,
    required: source::CONTRACT.companions[1].required,
};
pub(super) const CONSTRUCTOR_WORLD_LEDGER: Companion = Companion {
    path: source::CONTRACT.companions[2].path,
    required: source::CONTRACT.companions[2].required,
};

pub(super) const CONTRACTS: &[Contract] = &[
    owners::PREPARATION,
    owners::REARM,
    shared::CONTRACT,
    source::CONTRACT,
    park::CONTRACT,
];

/// Changes only a reviewed expression's actual owner or argument in mutants.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    if !CONTRACTS.iter().chain(PRE_VM_CONTRACTS).any(|contract| {
        contract
            .expressions
            .iter()
            .any(|(actual, _)| *actual == expression)
    }) {
        return expression.to_owned();
    }
    expression
        .replace("self.world", "foreign.world")
        .replace("retry_source_retirement_body()", "retry_source_retirement_body(foreign_source)")
        .replace("self.parent_park", "foreign.parent_park")
        .replace("(&self, source:", "(&self, foreign_source:")
        .replace("retry_retirement(source)", "retry_retirement(foreign_source)")
        .replace("self.handoff", "foreign.handoff")
        .replace("(&mut self)", "(&mut foreign)")
        .replace(
            "receiver.retry_retained_helper()",
            "foreign_receiver.retry_retained_helper()",
        )
        .replace(
            "receiver.retry_physical_cleanup()",
            "foreign_receiver.retry_physical_cleanup()",
        )
        .replace(
            "retry.abort_without_process()",
            "foreign_lease.abort_without_process()",
        )
}

#[cfg(test)]
#[path = "hot_fork_retirement/tests.rs"]
mod tests;
