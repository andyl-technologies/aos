//! Borrows actual canonical assemblies for the maintenance append boundary.
//!
//! These recipes contain no funding, account, phase setter or supplied native
//! success. Each arm wraps a private recipe minted by its canonical source
//! assembly; this module exposes no transaction-to-recipe constructor.

use crate::host_catalog_reconciliation::publication_recipe::{
    HostCatalogCommitPhaseV2, HostCatalogCommitRecipeV2,
};
use crate::{Journal, JournalError, JournalTransaction};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogMaintenanceAppendKindV2 {
    CatalogPending,
    CatalogConfirmation,
    StorageInventory,
    NetworkInventory,
    DestinationSlotInventory,
    GuestRootReservation,
}

pub(crate) enum CatalogMaintenanceAppendRecipeV2<'recipe, 'transaction> {
    GuestRootReservation(&'recipe crate::guest_root_publication::GuestRootPublicationAssemblyDataV3),
    HostCatalog(&'recipe HostCatalogCommitRecipeV2<'transaction>),
    ResourceInventory(
        &'recipe crate::resource_inventory::ResourceInventoryCommitRecipeV2<'transaction>,
    ),
    DestinationSlotInventory(
        &'recipe crate::mount_inventory_snapshot::MountInventoryCommitRecipeV2<'transaction>,
    ),
}

impl CatalogMaintenanceAppendRecipeV2<'_, '_> {
    pub(crate) fn require_transaction_v2(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        match self {
            Self::GuestRootReservation(assembly) => {
                assembly.require_transaction_v3(controller, transaction)
            }
            Self::ResourceInventory(recipe) => {
                recipe.require_transaction_v2(controller, transaction)
            }
            Self::DestinationSlotInventory(recipe) => {
                recipe.require_destination_transaction_v2(controller, transaction)
            }
            Self::HostCatalog(recipe) => {
                recipe.require_transaction_v2(transaction)?;
                recipe.require_history_v2(controller)
            }
        }
    }

    pub(crate) fn kind_v2(&self) -> CatalogMaintenanceAppendKindV2 {
        match self {
            Self::GuestRootReservation(_) => CatalogMaintenanceAppendKindV2::GuestRootReservation,
            Self::ResourceInventory(recipe) => {
                if recipe.is_storage_v2() {
                    CatalogMaintenanceAppendKindV2::StorageInventory
                } else {
                    CatalogMaintenanceAppendKindV2::NetworkInventory
                }
            }
            Self::DestinationSlotInventory(_) => {
                CatalogMaintenanceAppendKindV2::DestinationSlotInventory
            }
            Self::HostCatalog(recipe) => match recipe.phase_v2() {
                HostCatalogCommitPhaseV2::Pending => CatalogMaintenanceAppendKindV2::CatalogPending,
                HostCatalogCommitPhaseV2::Confirmation => {
                    CatalogMaintenanceAppendKindV2::CatalogConfirmation
                }
            },
        }
    }
}
