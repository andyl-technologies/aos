//! Observes actual Source18 recipe slots without selecting their retention path.
//!
//! The retained header, history and metadata getters support the real Source
//! census and strict empty-state guards. Production recipe retention and its
//! dedicated constructor rows remain unimported until their genuine current
//! prebirth loan closure exists. This module issues no recipe or Initial result.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialFundingData, PacketNativeImport18LaunchIdentityData,
    PacketNativeImport18PrebirthRecipeData,
};
use std::mem::size_of;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Import18RecipeOwner {
    started: bool,
    completed: bool,
    failed: bool,
    recipe: Option<PacketNativeImport18PrebirthRecipeData>,
    initial: Option<PacketNativeImport18InitialFundingData>,
    launch: Option<PacketNativeImport18LaunchIdentityData>,
}

/// Borrows logical recipe state without lending live launch or Plan identities.
///
/// The enclosing SourceOnce18 codec stores an inert RecipeWire18 projection.
/// It must never deserialize that projection into this live producer owner.
pub(crate) struct Import18RecipeHistoryData<'a> {
    pub(crate) started: bool,
    pub(crate) completed: bool,
    pub(crate) failed: bool,
    pub(crate) recipe: Option<&'a PacketNativeImport18PrebirthRecipeData>,
    pub(crate) initial: Option<&'a PacketNativeImport18InitialFundingData>,
}

impl Import18RecipeOwner {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn empty() -> Self {
        Self {
            started: false,
            completed: false,
            failed: false,
            recipe: None,
            initial: None,
            launch: None,
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Lends all logical recipe and failure state to the explicit Once18 writer.
    ///
    /// This immutable loan performs no formatter, hashing or allocation. The
    /// caller admits its fixed counter first and separately funds its writer.
    /// Actual retained launch-identity cache is disposable only as independently
    /// revalidated DATA; the complete recipe, lease, partitions and once flags
    /// remain present through this historical projection.
    ///
    /// # Errors
    /// Refuses foreign creation, busy recipe custody or callback refusal.
    pub(crate) fn with_native_import18_recipe_history_data<R>(
        &self,
        inspect: impl FnOnce(&Import18RecipeHistoryData<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let result = {
            let owner = self
                .native_import18_recipe
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let view = Import18RecipeHistoryData {
                started: owner.started,
                completed: owner.completed,
                failed: owner.failed,
                recipe: owner.recipe.as_ref(),
                initial: owner.initial.as_ref(),
            };
            inspect(&view)
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Names exact shared-recipe historical views before borrowing the owner.
    pub(crate) fn native_import18_recipe_history_counter_scratch_data<R>() -> usize {
        size_of::<&Self>()
            + size_of::<Import18RecipeHistoryData<'static>>()
            + size_of::<std::cell::Ref<'static, Import18RecipeOwner>>()
            + size_of::<Result<std::cell::Ref<'static, Import18RecipeOwner>, std::cell::BorrowError>>(
            )
            + size_of::<Option<&PacketNativeImport18PrebirthRecipeData>>()
            + size_of::<Option<&PacketNativeImport18InitialFundingData>>()
            + size_of::<Result<R, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }

    /// Returns only the same fully matched Source-owned immutable recipe DATA.
    ///
    /// This cached loan allocates or validates no body and grants no memory,
    /// assigned phase, private transport, native model or World permission.
    ///
    /// # Errors
    /// Refuses foreign origin, absent declaration, busy or failed partials.
    pub(crate) fn original_native_import18_recipe_data(
        &self,
    ) -> Result<PacketNativeImport18PrebirthRecipeData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_native_import18_declaration_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let owner = self
            .native_import18_recipe
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owner.started
            || !owner.completed
            || owner.failed
            || owner.launch.is_none()
            || owner.initial.is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        owner.recipe.ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Returns the exact separately produced initial funding DATA retained at birth.
    ///
    /// No caller row, parsed announcement or complete-recipe ceiling can replace
    /// this opaque result. It grants no native constructor or phase permission.
    ///
    /// # Errors
    /// Refuses foreign origin, an unselected Source or any incomplete/failed slot.
    pub(crate) fn original_native_import18_initial_funding_data(
        &self,
    ) -> Result<PacketNativeImport18InitialFundingData, RuntimeError> {
        self.original_native_import18_recipe_data()?;
        self.native_import18_recipe
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .initial
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Names the origin and shared-owner controls of the cached DATA getters.
    pub(crate) fn native_import18_recipe_metadata_counter_scratch_data() -> usize {
        Self::native_import18_declaration_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<std::cell::Ref<'static, Import18RecipeOwner>>()
            + size_of::<Result<std::cell::Ref<'static, Import18RecipeOwner>, std::cell::BorrowError>>(
            )
            + size_of::<Option<PacketNativeImport18PrebirthRecipeData>>()
            + size_of::<Option<PacketNativeImport18InitialFundingData>>()
            + size_of::<Result<PacketNativeImport18PrebirthRecipeData, RuntimeError>>()
            + size_of::<Result<PacketNativeImport18InitialFundingData, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}
