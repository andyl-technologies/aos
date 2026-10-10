//! Publishes the genuine campaign repository under the actor's existing budget.
//!
//! Blob, ref and administration capabilities come from the same retained graph
//! and reference owners. The repository receives that existing decode authority;
//! construction creates neither a bank nor an ordinary store-budget wrapper.
//! Its original control loan remains outside the final repository allocation.

use std::alloc::Layout;

use crucible::owned_decode::{DecodeBudget, DecodeCustody, DecodeScratch};
use crucible_cas::content_store::{OriginalDirectoryRefOwner, OriginalSqliteGraphOwner};

use super::*;

#[cfg(test)]
mod tests;

type OriginalPreparedRepositoryParts = (
    Arc<CampaignRepository>,
    Option<CampaignLocalRepositoryMaintenance>,
    Option<PlannerAuthorityKey>,
);

pub(crate) struct OriginalCampaignRepositoryBootstrap {
    repository: Option<Arc<CampaignRepository>>,
    maintenance: Option<CampaignLocalRepositoryMaintenance>,
    planner: Option<PlannerAuthorityKey>,
    control: Option<DecodeScratch>,
    budget: DecodeBudget,
    custody: DecodeCustody,
    closed: bool,
}

impl OriginalCampaignRepositoryBootstrap {
    #[cfg(test)]
    pub(crate) fn prepare(
        graph: &mut OriginalSqliteGraphOwner,
        refs: &OriginalDirectoryRefOwner,
        budget: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        Self::prepare_inner(graph, refs, budget, None)
    }

    pub(crate) fn prepare_with_components(
        graph: &mut OriginalSqliteGraphOwner,
        refs: &OriginalDirectoryRefOwner,
        budget: &DecodeBudget,
        components: (PlannerAuthorityKey, DebuggerAuthorityKey),
    ) -> Result<Self, StoreError> {
        Self::prepare_inner(graph, refs, budget, Some(components))
    }

    fn prepare_inner(
        graph: &mut OriginalSqliteGraphOwner,
        refs: &OriginalDirectoryRefOwner,
        budget: &DecodeBudget,
        components: CampaignComponentAuthorities,
    ) -> Result<Self, StoreError> {
        budget
            .verify_live()
            .map_err(|source| original_error(budget, source))?;
        let (layout, _) = Layout::new::<(usize, usize)>()
            .extend(Layout::new::<CampaignRepository>())
            .map_err(|_| StoreError::Quota)?;
        let control = budget
            .reserve_scratch_bytes(layout.pad_to_align().size() as u64)
            .map_err(|source| original_error(budget, source))?;
        let mut owner = Self {
            repository: None,
            maintenance: None,
            planner: None,
            control: Some(control),
            budget: budget.clone(),
            custody: budget.custody(),
            closed: false,
        };

        let store = graph.graph()?;
        let admin = graph.take_admin()?;
        let (refs, inventory) = refs.authorities()?;
        if store.configuration_id() != admin.configuration_id()
            || !store.capabilities().durable
            || !store.capabilities().conditional_create
            || !refs.capabilities().durable
        {
            return Err(StoreError::InvalidComposition {
                reason: "original repository authorities do not match",
            });
        }
        owner.maintenance = Some(CampaignLocalRepositoryMaintenance {
            store: Arc::clone(&store),
            graph: admin,
            refs: inventory,
        });
        // CampaignRepository::new only moves its authorities, clones the blob
        // handle into its inline MerkleMap and initializes empty cache maps.
        // The only allocation here is this already admitted repository Arc.
        let admission = CampaignRamAdmission::Available(budget.clone());
        let repository = if let Some((planner, debugger)) = components {
            owner.planner = Some(planner.clone());
            CampaignRepository::with_component_authorities(
                store, refs, admission, planner, debugger,
            )
            .map_err(|_| StoreError::InvalidComposition {
                reason: "original component authorities are invalid",
            })?
        } else {
            CampaignRepository::new(store, refs, admission)
        };
        owner.repository = Some(Arc::new(repository));
        budget
            .verify_live()
            .map_err(|source| original_error(budget, source))?;
        Ok(owner)
    }

    pub(super) fn share_for_service(
        &mut self,
    ) -> Result<OriginalPreparedRepositoryParts, StoreError> {
        self.budget
            .verify_live()
            .map_err(|source| original_error(&self.budget, source))?;
        let repository = self.repository.as_ref().ok_or(StoreError::Unavailable)?;
        Ok((
            Arc::clone(repository),
            self.maintenance.take(),
            self.planner.take(),
        ))
    }

    pub(crate) fn try_close(&mut self) -> Result<(), StoreError> {
        if self.closed {
            return Ok(());
        }
        self.budget
            .check()
            .map_err(|source| original_error(&self.budget, source))?;
        self.budget
            .verify_live()
            .map_err(|source| original_error(&self.budget, source))?;
        if let Some(repository) = self.repository.as_mut() {
            Arc::get_mut(repository).ok_or(StoreError::Unavailable)?;
        }
        drop(self.repository.take());
        drop(self.maintenance.take());
        self.budget
            .verify_live()
            .map_err(|source| original_error(&self.budget, source))?;
        drop(self.control.take());
        self.closed = true;
        Ok(())
    }
}

impl Drop for OriginalCampaignRepositoryBootstrap {
    fn drop(&mut self) {
        if !self.closed {
            // Surviving repository users, an error or unwind are containment,
            // not control retirement. Keep all real authority and credit.
            std::mem::forget(self.repository.take());
            std::mem::forget(self.maintenance.take());
            std::mem::forget(self.control.take());
            std::mem::forget(self.budget.clone());
            std::mem::forget(self.custody.clone());
        }
    }
}

fn original_error(
    budget: &DecodeBudget,
    source: crucible::owned_decode::DecodeAdmissionError,
) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: Some(budget.custody()),
    }
}
