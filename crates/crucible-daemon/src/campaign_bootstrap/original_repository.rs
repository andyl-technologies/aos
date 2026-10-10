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

pub(crate) struct OriginalCampaignRepositoryBootstrap {
    repository: Option<Arc<CampaignRepository>>,
    maintenance: Option<CampaignLocalRepositoryMaintenance>,
    control: Option<DecodeScratch>,
    budget: DecodeBudget,
    custody: DecodeCustody,
    closed: bool,
}

impl OriginalCampaignRepositoryBootstrap {
    pub(crate) fn prepare(
        graph: &mut OriginalSqliteGraphOwner,
        refs: &OriginalDirectoryRefOwner,
        budget: &DecodeBudget,
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
        owner.repository = Some(Arc::new(CampaignRepository::new(
            store,
            refs,
            CampaignRamAdmission::Available(budget.clone()),
        )));
        budget
            .verify_live()
            .map_err(|source| original_error(budget, source))?;
        Ok(owner)
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
