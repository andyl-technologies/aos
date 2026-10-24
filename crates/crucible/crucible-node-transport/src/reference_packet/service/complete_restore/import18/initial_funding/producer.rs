//! Derives Initial DATA from physical bootstrap demand and the same recipe.
//!
//! Parent construction work is priced separately from future native demand.
//! Neither an announced row nor an escrow ceiling supplies that demand.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;

/// Borrows the actual immutable inputs of one initial funding derivation.
///
/// The original Source lender authenticates these operands and its current
/// Birth before and after construction. This view supplies no Source permission.
/// Custom serializer side effects remain independently funded by the caller.
pub struct PacketNativeImport18InitialFundingInputs<'a, H> {
    /// Borrows the independently derived complete five-phase recipe.
    pub recipe: &'a PacketNativeImport18PrebirthRecipeData,
    /// Borrows the original typed base5 launch.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows the exact original Source declaration bank.
    pub declaration: PacketNativeImport18SourceDeclarationView<'a>,
    /// Borrows the same actual expected host registration.
    pub expected_host_registration: &'a H,
    /// Borrows the private launch identity of the unstarted Birth.
    pub private_launch: &'a Id,
    /// Borrows the controller executable committed by the launch.
    pub host_executable: &'a ContentRef,
    /// Borrows the nonce of that same immutable occurrence.
    pub nonce: &'a [u8; 32],
    /// Names that occurrence's nonzero generation.
    pub generation: U64,
}

/// Prices the formatter window before the producer's serialization walk.
///
/// Admit the fixed producer counter before this metadata-only prewalk, then
/// admit this complete row before quoting construction. Original owners and
/// custom host serializer side effects remain independently funded.
///
/// # Errors
/// Refuses unsupported launch metadata or checked construction overflow.
pub fn native_import18_initial_funding_producer_projection_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let initial = native_import18_initial_quote_formatter_data(launch)?;
    let identity = native_import18_launch_identity_projection_data(launch)?;
    let scratch = native_import18_initial_funding_producer_counter_scratch_data()
        .checked_add(initial[2])
        .and_then(|value| value.checked_add(identity.1))
        .ok_or_else(invalid)?;
    Ok([0, initial[1].max(identity.0), scratch])
}

/// Prices the parent's Initial producer without allocating native owners.
///
/// The Copy result has no backing; callers separately price its eventual owning
/// slot. Transient work includes actual launch identity construction, the
/// initial projection formatter window and result headers. Scratch includes
/// the independent initial projection with all local borrowed controls.
/// The original worker bank stays opaque; native separately funds its parser.
/// Original Source/Birth guards and their work remain independently admitted.
/// Admit `native_import18_initial_funding_producer_projection_data` before this
/// serialization walk; its own fixed counter is admitted before that prewalk.
///
/// # Errors
/// Refuses launch projection overflow, unsupported serialization or parent
/// construction work above its independent supplied restriction.
pub fn native_import18_initial_funding_producer_construction_data<H: Serialize>(
    inputs: &PacketNativeImport18InitialFundingInputs<'_, H>,
    maximum_parent_requested: usize,
) -> Result<[usize; 3], ProviderError> {
    let projection = native_import18_initial_funding_producer_projection_data(inputs.launch)?;
    let launch =
        native_import18_launch_identity_construction_data(inputs.launch, maximum_parent_requested)?;
    let transient = launch
        .0
        .max(projection[1])
        .checked_add(native_import18_initial_funding_construction_transient_data())
        .ok_or_else(invalid)?;
    let scratch = projection[2];
    if transient
        .checked_add(scratch)
        .is_none_or(|total| total > maximum_parent_requested)
    {
        return Err(invalid());
    }
    Ok([0, transient, scratch])
}

/// Derives the initial row from actual bootstrap, decoder, bank and Hello work.
///
/// The parent's construction restriction is independent of future native
/// funding. Native demand is recomputed from real operands using the existing
/// shared constructor formula, then checked against this recipe's own Prepare
/// partition and escrow. The escrow is only a restriction on that computation.
/// No supplied row, announcement decimal or later phase funds the initial row.
///
/// The caller first admits the producer construction row and retains original
/// Source/Birth/collection guards around every outcome. The result is Copy DATA;
/// it creates no recipe, live startup, model, Hold, phase claim or renewed lease.
/// Native independently reconstructs the row before any privileged effect.
///
/// # Errors
/// Refuses foreign birth/launch operands, changed executable identity, invalid
/// recipe structure, unsupported physical projection, checked overflow or demand
/// above the parent's restriction, original Prepare partition or escrow.
pub fn derive_native_import18_initial_funding_data<H: Serialize>(
    inputs: &PacketNativeImport18InitialFundingInputs<'_, H>,
    maximum_parent_requested: usize,
) -> Result<PacketNativeImport18InitialFundingData, ProviderError> {
    native_import18_initial_funding_producer_construction_data(inputs, maximum_parent_requested)?;
    let announcement = inputs.recipe.announcement_data();
    announcement.validate_data()?;
    if inputs.recipe.lease_data() != (*inputs.nonce, inputs.generation)
        || inputs.host_executable != &inputs.launch.controller_executable
    {
        return Err(invalid());
    }
    inputs.private_launch.validate()?;

    let escrow = inputs.recipe.escrow_storage_data();
    let native_maximum = escrow.into_iter().try_fold(0usize, |total, axis| {
        let axis = usize::try_from(axis.get()).map_err(|_| invalid())?;
        total.checked_add(axis).ok_or_else(invalid)
    })?;
    let construction = native_import18_initial_construction_data(
        inputs.launch,
        inputs.declaration,
        inputs.expected_host_registration,
        inputs.private_launch,
        inputs.host_executable,
        native_maximum,
    )?;
    let [retained, transient, scratch] = construction.requested_storage_data().map(to_wire);
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: retained?,
        maximum_simultaneous_transient_bytes: transient?,
        declared_counter_scratch_bytes: scratch?,
    };
    row.requested_peak_data()?;
    announcement.authenticate_initial_limits_data(&row)?;

    let launch = derive_native_import18_launch_identity_data(
        inputs.launch,
        inputs.private_launch,
        construction.maximum_encoded_bytes_data()[1],
    )?;
    inputs.recipe.authenticate_birth_operands_data(
        inputs.nonce,
        inputs.generation,
        &launch.selected_launch_identity_data(),
        &launch.private_launch_identity_data(),
    )?;
    let [recipe, selected, boot] = construction.maximum_encoded_bytes_data().map(to_wire);
    Ok(PacketNativeImport18InitialFundingData {
        row,
        recipe_identity: inputs.recipe.identity_data(),
        lease_identity: inputs.recipe.lease_identity_data(),
        selected_launch_identity: launch.selected_launch_identity_data(),
        private_launch_identity: launch.private_launch_identity_data(),
        nonce: *inputs.nonce,
        generation: inputs.generation,
        body_maximums: [recipe?, selected?, boot?],
    })
}

/// Names fixed producer and metadata-quote controls before Source checking.
///
/// The returned construction row additionally prices Source-check execution.
pub fn native_import18_initial_funding_producer_counter_scratch_data() -> usize {
    native_import18_initial_construction_counter_scratch_data()
        + native_import18_launch_identity_counter_scratch_data()
        + native_import18_prebirth_recipe_counter_scratch_data()
        + native_import18_initial_funding_counter_scratch_data()
        + size_of::<PacketNativeImport18InitialFundingInputs<'static, ()>>()
        + size_of::<&PacketNativeImport18InitialFundingInputs<'static, ()>>()
        + size_of::<PacketNativeImport18InitialConstructionData>()
        + size_of::<Result<PacketNativeImport18InitialConstructionData, ProviderError>>()
        + size_of::<PacketNativeImport18LaunchIdentityData>()
        + size_of::<Result<PacketNativeImport18LaunchIdentityData, ProviderError>>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[U64; 3]>() * 2
        + size_of::<[Result<U64, ProviderError>; 3]>()
        + size_of::<std::array::IntoIter<U64, 3>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<[usize; 8]>()
}

fn to_wire(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| invalid())
}

fn invalid() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial funding derivation")
}
