//! Checks the actual complete two-child liability before the first PREBIRTH.
//!
//! This is a denial comparison on the existing ledger and permanent parent
//! FD coverage. It issues no child, resets no debt and reserves no new bank.
//! Each real reservation still performs its own debit immediately before IO.

use super::*;

pub(super) struct PairOriginalV2 {
    entered: bool,
    source: Option<Result<(), FixedServiceOperationClosedV4>>,
    fit: Option<Result<ResourceVector, AccountingError>>,
}

impl PairOriginalV2 {
    pub(super) const fn new() -> Self {
        Self {
            entered: false,
            source: None,
            fit: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.fit.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn parent_failure_selected(&self) -> bool {
        matches!(self.source, Some(Err(_)))
    }
}

impl FixedServiceOperationLoanV4<'_> {
    /// Checks both real children and all still-owed parent work before P birth.
    ///
    /// `parent_future` is the closed protected caller's complete transport and
    /// domain-IO programme. The actual reservation suppliers, including FL03,
    /// are joined here. Existing permanent parent FD debt remains charged;
    /// only genuinely additional child FDs enter the future ledger sum.
    ///
    /// # Errors
    /// Retains reentry, poisoned current Source, arithmetic overflow, exhausted
    /// permanent parent FD coverage or insufficient original Source endowment.
    pub fn preflight_network_worker_pair_once_v2(
        &mut self,
        preparation: &mut NetworkWorkerBirthOriginalV2,
        children: [ResourceVector; 2],
        parent_future: ResourceVector,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if preparation.pair.entered
            || preparation.entered
            || preparation.first.is_some()
            || self.operation.worker_birth_mask != 0
        {
            preparation.first.get_or_insert(First::Pair);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        }
        preparation.pair.entered = true;
        preparation.pair.source = Some(self.require_network_worker_current_v4());
        if !matches!(preparation.pair.source, Some(Ok(()))) {
            preparation.first = Some(First::Pair);
            return Err(self.refuse_network_worker_birth_v2(Failure::Order));
        }
        preparation.pair.fit = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::OpenFiles,
            };
            let parents = parent_future
                .checked_add(NetworkWorkerBirthOriginalV2::parent_receiving_demand_v2(
                    NetworkWorkerBirthPurposeV2::Preparation,
                )?)?
                .checked_add(NetworkWorkerBirthOriginalV2::parent_receiving_demand_v2(
                    NetworkWorkerBirthPurposeV2::Observation,
                )?)?;
            let files = self
                .common
                .fixed_startup_demand()?
                .get(D::OpenFiles)
                .checked_add(
                    self.common
                        .service_startup
                        .as_ref()
                        .map_or(0, |startup| startup.committed_files()),
                )
                .and_then(|files| files.checked_add(self.common.operation_files))
                .and_then(|files| files.checked_add(parents.get(D::OpenFiles)))
                .ok_or(overflow)?;
            let permanent = self.common.permanent_open_files().map_err(|_| overflow)?;
            if files > permanent {
                return Err(AccountingError::LimitExceeded {
                    dimension: D::OpenFiles,
                    limit: permanent,
                    attempted: files,
                });
            }
            let ledger = self.common.representation.as_ref().ok_or(overflow)?;
            let ceiling = self
                .common
                .parent
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .map(|(ceiling, _, _)| *ceiling)
                .ok_or(overflow)?;
            let additional = children[0]
                .checked_add(children[1])?
                .checked_add(parents.with(D::OpenFiles, 0))?;
            remaining_parent_after_child_v2(ceiling, ledger.charged(), additional)
        })());
        if !matches!(preparation.pair.fit, Some(Ok(_))) {
            preparation.first = Some(First::Pair);
            return Err(self.refuse_network_worker_birth_v2(Failure::Geometry));
        }
        Ok(())
    }
}
