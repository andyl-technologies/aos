//! Combines physical receiver, prospective decoders and Source checks as DATA.
//!
//! The same future-decimal-width formula is evaluated from actual parent or
//! received operands before recipe rows and commitment exist. An announced row
//! or recipe is never an input. These calculations
//! cannot construct the opaque Initial result, Recipe, native model or escrow.

use super::prospective::{PrivateOperands, ProspectiveBodyConstructionData};
use super::*;
use crate::reference_packet::service::ack_emitter::native_boot::original_import18_raw_bootstrap_storage_data;

/// Retains a numeric construction observation without creating opaque funding.
pub struct PacketNativeImport18InitialConstructionData {
    /// Prices simultaneous retained owners and sequential transient/counter work.
    pub(in crate::reference_packet) row: [usize; 3],
    /// Bounds all three future bodies independently of unknown Initial decimals.
    pub(in crate::reference_packet) maximum_encoded_bytes: [usize; 3],
}

pub(in crate::reference_packet) type InitialConstructionData =
    PacketNativeImport18InitialConstructionData;

impl PacketNativeImport18InitialConstructionData {
    /// Returns the independently projected retained, transient and scratch axes.
    pub fn requested_storage_data(&self) -> [usize; 3] {
        self.row
    }

    /// Returns the independently projected Recipe, Selected and Boot body maxima.
    pub fn maximum_encoded_bytes_data(&self) -> [usize; 3] {
        self.maximum_encoded_bytes
    }
}

/// Projects initial DATA from borrowed original operands before a recipe exists.
///
/// The Source bank stays opaque and the Host serializer borrows its actual typed
/// plan. Callers admit the fixed counter and actual launch formatter before this
/// walk, and keep original Source/Birth/launch guards around every outcome. This
/// result grants no funding, phase permission, native model or readiness.
///
/// # Errors
/// Refuses invalid launch/declaration geometry, unsupported serialization,
/// checked overflow or demand above the independent restriction.
pub fn native_import18_initial_construction_data<H: Serialize>(
    launch: &PacketNative5SourceLaunch,
    declaration: PacketNativeImport18SourceDeclarationView<'_>,
    expected_host_registration: &H,
    private_launch: &Id,
    host_executable: &ContentRef,
    maximum: usize,
) -> Result<PacketNativeImport18InitialConstructionData, ProviderError> {
    let private = PrivateOperands {
        declaration,
        expected_host_registration,
        private_launch,
        host_executable,
    };
    initial_construction_projection_data(launch, &private, maximum)
}

/// Derives complete initial constructor DATA from the real producer operands.
///
/// The caller admits fixed controls and `initial_quote_formatter_data` before
/// this walk. All enclosing parent custody and serialization remain separate.
///
/// # Errors
/// Refuses actual operand geometry, checked overflow or independent restriction.
pub(in crate::reference_packet) fn initial_construction_projection_data<H: Serialize>(
    launch: &PacketNative5SourceLaunch,
    private: &PrivateOperands<'_, H>,
    maximum: usize,
) -> Result<InitialConstructionData, ProviderError> {
    let bodies = prospective::construction_data(launch, private, maximum)?;
    let source = source_authentication_projection_data(&private.declaration, launch, maximum)?;
    combine(
        bodies,
        source,
        initial_quote_formatter_data(launch)?,
        maximum,
    )
}

/// Repeats the same formula over actual decoded DATA without an opaque recipe.
///
/// Every surrounding Source, prefix, recipe and row join remains mandatory.
/// This deliberately makes no Wire-to-Recipe or numeric-to-Initial conversion.
///
/// # Errors
/// Refuses actual body geometry, overflow or the independent restriction.
pub(in crate::reference_packet) fn initial_construction_from_wire_data(
    selected: &PacketNativeImport18SelectedLaunchWireData,
    boot: &PacketNativeImport18PrivateBootWireData,
    maximum: usize,
) -> Result<InitialConstructionData, ProviderError> {
    if boot.private_key.as_slice().len() != size_of::<[u8; 32]>()
        || boot.birth_id.as_slice().len() != size_of::<[u8; 32]>()
    {
        return Err(invalid());
    }
    let launch = selected.launch_data();
    let declaration = native_import18_source_declaration_bank_view_data(
        boot.source_birth.declaration.source_birth_data().as_slice(),
        launch,
    )?;
    let private = PrivateOperands {
        declaration,
        expected_host_registration: &boot.expected_host_registration,
        private_launch: &boot.private_launch,
        host_executable: &boot.host_executable,
    };
    let bodies = prospective::construction_data(launch, &private, maximum)?;
    let source = source_authentication_projection_data(&private.declaration, launch, maximum)?;
    combine(
        bodies,
        source,
        initial_quote_formatter_data(launch)?,
        maximum,
    )
}

fn combine(
    bodies: ProspectiveBodyConstructionData,
    source: [usize; 3],
    formatter: [usize; 3],
    maximum: usize,
) -> Result<InitialConstructionData, ProviderError> {
    // Future U64 decimal widths are fixed before a row exists. Raw and typed
    // outputs coexist; the three body parsers and Source check run sequentially.
    let raw = original_import18_raw_bootstrap_storage_data(bodies.maximum_encoded_bytes)?;
    let mut row = raw;
    for parser in bodies.parser_rows {
        row[0] = add(row[0], parser[0])?;
        row[1] = row[1].max(parser[1]);
        row[2] = row[2].max(add(raw[2], parser[2])?);
    }
    row[0] = add(row[0], source[0])?;
    row[1] = row[1].max(source[1]).max(formatter[1]);
    row[2] = add(row[2], source[2])?.max(add(raw[2], formatter[2])?);
    if add(add(row[0], row[1])?, row[2])? > maximum {
        return Err(exhausted());
    }
    Ok(InitialConstructionData {
        row,
        maximum_encoded_bytes: bodies.maximum_encoded_bytes,
    })
}

/// Prices actual hidden launch formatters and fixed construction controls.
///
/// The Source declaration and defining fixed private key/Birth extents are
/// projected without invoking their Bytes formatters. The caller separately
/// admits any custom Host formatter before lending its serializer.
///
/// # Errors
/// Refuses actual launch metadata or checked base64-length overflow.
pub fn native_import18_initial_quote_formatter_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let mut row = source_authentication_quote_construction_data(launch)?;
    row[2] = add(row[2], initial_construction_counter_scratch_data())?;
    Ok(row)
}

pub(in crate::reference_packet) use native_import18_initial_quote_formatter_data as initial_quote_formatter_data;

/// Names the real projection, Source checker, combining and returned controls.
pub fn native_import18_initial_construction_counter_scratch_data() -> usize {
    prospective::counter_scratch_data()
        + super::private_identity::counter_scratch_data()
        + source_authentication_counter_scratch_data()
        + native_import18_startup_wire_counter_scratch_data()
        + size_of::<InitialConstructionData>()
        + size_of::<Result<InitialConstructionData, ProviderError>>()
        + size_of::<[usize; 3]>() * 5
        + size_of::<std::array::IntoIter<[usize; 3], 3>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>() * 3
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + Bytes::borrowed_serialization_counter_scratch_data()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<&[u8; 32]>()
        + size_of::<Result<&[u8; 32], std::array::TryFromSliceError>>()
        + size_of::<std::iter::Zip<std::array::IntoIter<U64, 3>, std::array::IntoIter<U64, 3>>>()
        + size_of::<Result<(), ProviderError>>() * 5
        + size_of::<PacketNativeImport18SourceDeclarationView<'static>>()
        + size_of::<PrivateOperands<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&Id>()
        + size_of::<&ContentRef>()
}

pub(in crate::reference_packet) use native_import18_initial_construction_counter_scratch_data as initial_construction_counter_scratch_data;

/// Joins exact decoded headers to a separately reconstructed initial row.
///
/// Original Source correspondence and raw/cut custody are checked by the owner.
/// Complete native recipe recomputation still precedes every model/Hold effect.
///
/// # Errors
/// Refuses malformed recipe structure, private Birth/key/executable correspondence
/// or any prefix/body announcement join.
pub(in crate::reference_packet) fn authenticate_initial_headers_data(
    recipe: &PacketNativeImport18PrebirthRecipeWireData,
    selected: &PacketNativeImport18SelectedLaunchWireData,
    boot: &PacketNativeImport18PrivateBootWireData,
    prefix: &PacketNativeImport18PrivatePrefixData,
    derived: &InitialConstructionData,
) -> Result<(), ProviderError> {
    recipe.validate_data()?;
    let to_wire = |n| u64::try_from(n).map(U64::new).map_err(|_| exhausted());
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: to_wire(derived.row[0])?,
        maximum_simultaneous_transient_bytes: to_wire(derived.row[1])?,
        declared_counter_scratch_bytes: to_wire(derived.row[2])?,
    };
    recipe.authenticate_initial_limits_data(&row)?;
    let key: &[u8; 32] = boot
        .private_key
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    prefix.authenticate_private_boot_key_data(key)?;
    super::private_identity::authenticate_data(boot, selected.launch_data(), key)?;
    prefix.authenticate_announced_recipe_identity_data(recipe.announced_identity_data())?;
    prefix.authenticate_initial_funding_data(&row)?;
    selected.authenticate_initial_data(recipe.announced_identity_data(), &row)?;
    if boot.source_birth.prebirth_recipe != *recipe
        || boot.source_birth.initial_funding != row
        || boot.source_birth.mechanism != PacketNativeImport18Selection::SourceSignedImport18
        || boot.birth_id.as_slice().len() != 32
    {
        return Err(invalid());
    }
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial constructor DATA")
}

#[cfg(test)]
#[path = "initial_construction/tests.rs"]
mod tests;
