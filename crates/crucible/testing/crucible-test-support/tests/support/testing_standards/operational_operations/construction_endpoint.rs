//! Reviews one failed debugger candidate through its original terminal handback.
//!
//! These contracts classify the same-owner continuation and negative components.
//! Runtime callers remain evidence only; no replay, Main or Source is issued.

use super::{Companion, Contract};

#[path = "construction_endpoint/facts.rs"]
mod facts;
#[path = "construction_endpoint/controls.rs"]
mod controls;

/// Shares the actual unavailable reservation body without copying its proof.
pub(super) const UNAVAILABLE_RESERVATION: &str = facts::NEGATIVE_TOKENS.required[0].0;
/// Shares the independent handoff helper for scoped mutation controls.
pub(super) const UNAVAILABLE_HANDOFF: &str = facts::NEGATIVE_TOKENS.required[1].0;

const COMPANIONS: &[Companion] = &[
    facts::ENDPOINT,
    facts::NEGATIVE_TOKENS,
    facts::COMPONENT_LAUNCHER,
    facts::COMPONENT_LOOP,
    facts::RUNTIME,
    facts::CONTAINING_JOIN,
    facts::HISTORY,
    facts::PAID_BODY,
    facts::NATIVE_OBSERVATION,
    facts::ROLE_DRIVER,
    facts::ORIGINAL_RECEIPT,
    facts::TERMINAL,
    facts::SHUTDOWN,
    facts::PAYER_0,
    facts::PAYER_1,
    facts::PAYER_2,
    facts::PAYER_3,
    controls::CASE_EVIDENCE,
    controls::JOIN_EVIDENCE,
    super::constructor_continuations::PUBLICATION_ENDPOINT,
    super::production_publication::CONSTRUCTOR_RESERVATION,
    super::production_publication::CONSTRUCTOR_QUEUE,
    super::production_publication::CONSTRUCTOR_DRIVER,
    super::production_publication::CONSTRUCTOR_QUEUED_OWNER,
    super::production_publication::ROLE_REPORTS,
    super::hot_fork_retirement::CONSTRUCTOR_BODY,
    super::hot_fork_retirement::CONSTRUCTOR_WORLD_RETURN,
    super::hot_fork_retirement::CONSTRUCTOR_WORLD_POOL,
    super::hot_fork_retirement::CONSTRUCTOR_WORLD_LEDGER,
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/construction/retained_debug",
        required: &[
            (
                r#"Unpublished(Option<ProductionVmConstructionFailure>),"#,
                1,
            ),
            (r#"Published(ConstructorReturn),"#, 1),
            (r#"History(Option<SourceCleanupHistory>),"#, 1),
            (
                r#"shell: Option<ProductionVmConstructionFailure>,
    first: Option<LifecycleApiError>,
    receipt: Option<CleanupReceipt>,"#,
                1,
            ),
            (r#"Self::Unpublished(Some(failure))"#, 2),
            (r#"Box::new("#, 0),
            (r#"Arc::new("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#"Instant::now("#, 0),
            (r#"thread::"#, 0),
            (r#"mem::forget("#, 0),
            (r#"Box::leak("#, 0),
        ],
        expressions: facts::EFFECTS,
        identifiers: &[("retry", 4), ("retry_reserved_publication", 1)],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/construction/retained_debug/tests",
        required: controls::CASES,
        expressions: &[
            ("custody.retry_cleanup().unwrap()", 1),
            ("lifecycle.retry_retained_debug_construction()", 5),
            (controls::REFUSING_OWNER, 1),
        ],
        identifiers: &[
            ("retry_cleanup", 2),
            ("retry_retained_debug_construction", 5),
        ],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/construction/custody/post_body/tests",
        required: controls::JOIN_CASES,
        expressions: &[("custody.retry_cleanup().unwrap()", 1)],
        identifiers: &[("retry_cleanup", 1)],
        companions: COMPANIONS,
    },
];

/// Mutates only exact reviewed receiver expressions for the generic controls.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    if !CONTRACTS.iter().any(|contract| {
        contract
            .expressions
            .iter()
            .any(|(actual, _)| *actual == expression)
    }) {
        return expression.to_owned();
    }
    expression
        .replace("&mut self,", "&mut other,")
        .replace("custody.retry_cleanup()", "other_custody.retry_cleanup()")
        .replace(
            "lifecycle.retry_retained_debug_construction()",
            "other_lifecycle.retry_retained_debug_construction()",
        )
}

#[cfg(test)]
#[path = "construction_endpoint/tests.rs"]
mod tests;
