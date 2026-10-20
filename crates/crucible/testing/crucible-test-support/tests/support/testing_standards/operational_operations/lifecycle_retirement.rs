//! Qualifies same-owner retirement without admitting another execution attempt.
//!
//! Queue contracts bind each actual epoch, allocation and physical-progress cut.
//! Main contracts bind the same saved Cleanup, including failed admission, and
//! keep first and independent post errors distinct from factual body return.
//! Callback implementations and issuers remain required companion evidence.
//! Neither scheduler requeue nor test reruns are covered by this module.

use super::Contract;

#[path = "lifecycle_retirement/companions.rs"]
mod companions;
#[cfg(test)]
#[path = "lifecycle_retirement/diagnostics.rs"]
mod diagnostics;
#[path = "lifecycle_retirement/main.rs"]
mod main;
#[path = "lifecycle_retirement/owners.rs"]
mod owners;
#[path = "lifecycle_retirement/queue.rs"]
mod queue;
#[path = "lifecycle_retirement/receipts.rs"]
mod receipts;

use companions::{BACKEND, ORIGINAL, RECEIVER, SERVICE, SOURCE};
use owners::{
    AFTER_BODY, ATTACHED_BODY, CONSTRUCTION_FINISH, DISPATCHER, DRIVER_OWNER, FILE_ONLY,
    MAIN_ATTACHMENT, PACKAGED_BODY, TARGET,
};

pub(super) const CONTRACTS: &[Contract] = &[
    queue::DRIVER,
    queue::QUEUED,
    queue::PREPARED_DRIVER,
    queue::PREPARED_SERVICE,
    queue::POST_BODY,
    queue::TARGET_RETURN,
    queue::TRANSPORT,
    queue::QUEUE,
    receipts::RETIREMENT,
    receipts::RESERVATION,
    receipts::FILE_CELL,
    receipts::SHARED_FILE,
    receipts::FILE_TESTS,
    main::MAIN_ATTACHED,
    main::MAIN_CONSTRUCTION,
    main::MAIN_EXPORT,
    main::ATTACHED,
    main::PACKAGED,
];

#[cfg(test)]
/// Explains the actual matcher obligations without changing admission.
pub(super) fn contract_diagnostics(
    contract: &Contract,
    code: &str,
    companions: &[String],
) -> Vec<String> {
    diagnostics::explain(contract, code, companions)
}

/// Removes the reviewed import sibling while retaining its original escape token.
#[cfg(test)]
pub(super) fn omission_replacement(contract: &Contract, requirement: &str) -> Option<&'static str> {
    // Removing this entire clause also removes the only lexical witness. Keep
    // that actual imported name in place while removing its required sibling,
    // so the unchanged scanner can observe rejection of the incomplete import.
    if contract.package == "crucible-daemon"
        && contract.target == "src/campaign_process"
        && requirement == "retry_attached_retirement, verify_attached_start,"
    {
        Some("retry_attached_retirement, removed_original_obligation,")
    } else {
        None
    }
}

/// Produces a foreign-argument mutant only for this module's exact call spans.
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
    let Some(offset) = expression.find('(') else {
        return expression.to_owned();
    };
    let mut altered = expression.to_owned();
    altered.insert_str(offset + 1, "foreign_owner, ");
    altered
}

#[cfg(test)]
#[path = "lifecycle_retirement/tests.rs"]
mod tests;
