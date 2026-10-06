//! Complete deployed host operation budgets, separate from modeled limits.
//!
//! Every class is explicitly present; omitting an allowance means unlimited
//! waiting only where the host supervisor permits it. For example:
//!
//! ```toml
//! [host_operation_budgets.setup]
//! poll_interval_ms = 10
//! total_timeout_ms = 60000
//! [host_operation_budgets.quantum]
//! poll_interval_ms = 10
//! ```
//!
//! A complete deployment supplies the remaining twelve infrastructure classes
//! with finite progress or total allowances as well.

use std::collections::BTreeMap;
use std::time::Duration;

use crucible_api::host_operational::{HostOperationBudget, HostOperationBudgets};
use serde::Deserialize;

use super::{CliError, serve_error};

pub(super) const CLASS_NAMES: [&str; 14] = [
    "setup",
    "quantum",
    "page_in",
    "writeback",
    "fingerprint_initialization",
    "fingerprint_update",
    "quiescence",
    "checkpoint_capture",
    "checkpoint_publication",
    "restore",
    "fork_rearm",
    "transfer",
    "preparation",
    "cleanup",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationBudgetDeployment {
    poll_interval_ms: u64,
    progress_timeout_ms: Option<u64>,
    total_timeout_ms: Option<u64>,
}

pub(super) fn deployed_budgets(
    deployment: &BTreeMap<String, OperationBudgetDeployment>,
) -> Result<HostOperationBudgets, CliError> {
    if deployment.len() != CLASS_NAMES.len() {
        return Err(serve_error(
            "host operation budgets require all fourteen classes",
        ));
    }
    let mut classes = [HostOperationBudget {
        poll_interval: Duration::ZERO,
        progress_timeout: None,
        total_timeout: None,
    }; CLASS_NAMES.len()];
    for (index, name) in CLASS_NAMES.into_iter().enumerate() {
        let budget = deployment
            .get(name)
            .ok_or_else(|| serve_error(format!("missing host operation budget for {name}")))?;
        classes[index] = HostOperationBudget {
            poll_interval: Duration::from_millis(budget.poll_interval_ms),
            progress_timeout: budget.progress_timeout_ms.map(Duration::from_millis),
            total_timeout: budget.total_timeout_ms.map(Duration::from_millis),
        };
    }
    let budgets = HostOperationBudgets { classes };
    budgets
        .validate(false)
        .map_err(|error| serve_error(format!("invalid host operation budgets: {error}")))?;
    Ok(budgets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finite_roster() -> BTreeMap<String, OperationBudgetDeployment> {
        CLASS_NAMES
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    OperationBudgetDeployment {
                        poll_interval_ms: 10,
                        progress_timeout_ms: None,
                        total_timeout_ms: Some(1000),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn authored_roster_refuses_missing_unknown_and_unbounded_infrastructure() {
        let mut roster = finite_roster();
        assert!(deployed_budgets(&roster).is_ok());

        let preparation = roster.remove("preparation");
        assert!(deployed_budgets(&roster).is_err());
        if let Some(preparation) = preparation {
            roster.insert("unknown".to_owned(), preparation);
        }
        assert!(deployed_budgets(&roster).is_err());

        let mut roster = finite_roster();
        if let Some(setup) = roster.get_mut("setup") {
            setup.total_timeout_ms = None;
        }
        assert!(deployed_budgets(&roster).is_err());
    }

    #[test]
    fn quantum_can_wait_without_renewing_an_infrastructure_deadline() {
        let mut roster = finite_roster();
        if let Some(quantum) = roster.get_mut("quantum") {
            quantum.total_timeout_ms = None;
        }
        let budgets = deployed_budgets(&roster)
            .unwrap_or_else(|error| panic!("explicit quantum roster: {error}"));

        assert!(budgets.classes[1].total_timeout.is_none());
        assert_eq!(
            budgets.classes[0].total_timeout,
            Some(Duration::from_secs(1))
        );
    }
}
