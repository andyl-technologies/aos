//! Borrows the genuine Launch purpose for its actual catalog acquisition.
//!
//! This private-construction context restricts the same already-consumed Host
//! financial flight. It supplies no independent ledger, budget, writer, native
//! descriptor, caller-selected purpose or positive completion authority.

use aos_sandbox_core::ResourceVector;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use super::HostExecutionReceivingLoanV2;
use crate::{HostError, Result};

/// Borrows the same authenticated Launch while its catalog originals grow.
///
/// Only the actual Host launch engine constructs this context. The catalog
/// derives each passive demand from its reached native/input owners and must
/// admit it before constructing the corresponding destination or performing IO.
pub struct HostLaunchCatalogReceivingV2<'catalog, 'original> {
    receiving: &'catalog mut HostExecutionReceivingLoanV2<'original>,
    complete: &'catalog mut ResourceVector,
    request: &'catalog AuthenticatedBrokerMethodRequestV1,
    deadline: u64,
}

impl<'catalog, 'original> HostLaunchCatalogReceivingV2<'catalog, 'original> {
    pub(crate) fn new(
        receiving: &'catalog mut HostExecutionReceivingLoanV2<'original>,
        complete: &'catalog mut ResourceVector,
        request: &'catalog AuthenticatedBrokerMethodRequestV1,
        deadline: u64,
    ) -> Result<Self> {
        receiving.require_launch_request_v2(request)?;
        Ok(Self { receiving, complete, request, deadline })
    }

    pub(crate) fn authenticated_request_v2(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        self.request
    }

    pub(crate) fn original_deadline_v2(&self) -> u64 {
        self.deadline
    }

    /// Checks that the same consumed Launch still admits native catalog work.
    ///
    /// # Errors
    /// Rejects another purpose, an ended interval, or a closed intrinsic owner.
    pub fn require_current_v2(&self) -> Result<()> {
        self.receiving.require_launch_request_v2(self.request)
    }

    // Passive DATA from only the matching, active, already-consumed Launch.
    // It changes no admission, ledger, reservation, traffic or disposition.
    pub(crate) fn remaining_capacity_v2(&self) -> Result<ResourceVector> {
        self.require_current_v2()?;
        self.receiving.remaining_launch_capacity_v2(*self.complete)
    }

    /// Restricts the same flight against one additional actual catalog demand.
    ///
    /// The actual supplier must include constructor/returned-owner overlap and
    /// the complete lifetime of each native prefix. This comparison neither
    /// creates resources nor refunds earlier retained or consumed liabilities.
    ///
    /// # Errors
    /// Rejects checked overflow, a closed original, or demand exceeding any
    /// dimension of the same authenticated Launch partition.
    pub fn admit_additional_demand_v2(&mut self, additional: ResourceVector) -> Result<()> {
        self.require_current_v2()?;
        *self.complete = self.complete.checked_add(additional)
            .map_err(|_| HostError::ResourceExhausted)?;
        self.receiving.require_complete_v2(*self.complete)
    }
}
