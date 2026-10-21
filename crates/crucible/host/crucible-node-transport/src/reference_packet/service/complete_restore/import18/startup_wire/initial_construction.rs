//! Combines physical receiver, prospective decoders and Source checks as DATA.
//!
//! The same future-decimal-width formula is evaluated from actual parent or
//! received operands before recipe rows and commitment exist. An announced row
//! or recipe is never an input. These calculations
//! cannot construct the opaque Initial result, Recipe, native model or escrow.

use super::prospective::{PrivateOperands, ProspectiveBodyConstructionData};
use super::*;
use crate::reference_packet::service::ack_emitter::native_boot::{
    original_import18_controller_measurement_construction_data,
    original_import18_hello_envelope_construction_bound_data,
    original_import18_hello_envelope_counter_scratch_data,
    original_import18_hello_exchange_construction_data,
    original_import18_hello_exchange_counter_scratch_data,
    original_import18_hello_frames_construction_data,
    original_import18_hello_frames_counter_scratch_data,
    original_import18_hello_initial_admission_backing_counter_scratch_data,
    original_import18_hello_initial_admission_retained_backing_data,
    original_import18_hello_literal_construction_data,
    original_import18_hello_literal_counter_scratch_data,
    original_import18_hello_registrar_construction_data,
    original_import18_hello_registrar_counter_scratch_data,
    original_import18_hello_request_construction_bound_data,
    original_import18_hello_request_counter_scratch_data,
    original_import18_hello_response_construction_data,
    original_import18_hello_response_counter_scratch_data,
    original_import18_hello_result_construction_data,
    original_import18_hello_result_counter_scratch_data,
    original_import18_hello_selection_construction_data,
    original_import18_hello_selection_counter_scratch_data,
    original_import18_hello_value_construction_bound_data,
    original_import18_hello_value_counter_scratch_data,
    original_import18_public_channel_construction_data,
    original_import18_public_channel_counter_scratch_data,
    original_import18_raw_bootstrap_storage_data,
    original_import18_sdk_hello_request_construction_bound_data,
    original_import18_sdk_hello_request_counter_scratch_data,
    original_import18_selection_construction_data,
    original_import18_selection_counter_scratch_data,
};

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
        native_import18_launch_identity_construction_data(launch, maximum)?,
        HelloConstructionData {
            roster: original_import18_hello_selection_construction_data(launch)?,
            frames: original_import18_hello_frames_construction_data(launch)?,
            literal: original_import18_hello_literal_construction_data(launch)?,
            value: original_import18_hello_value_construction_bound_data(launch, maximum)?,
            request: original_import18_hello_request_construction_bound_data(launch, maximum)?,
            registrar: original_import18_hello_registrar_construction_data(launch, maximum)?,
            sdk_request: original_import18_sdk_hello_request_construction_bound_data(
                launch, maximum,
            )?,
            result: original_import18_hello_result_construction_data(launch, maximum)?,
            envelope: original_import18_hello_envelope_construction_bound_data(launch, maximum)?,
            response: original_import18_hello_response_construction_data(launch, maximum)?,
            admission_backing: original_import18_hello_initial_admission_retained_backing_data(
                launch, maximum,
            )?,
        },
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
        native_import18_launch_identity_construction_data(launch, maximum)?,
        HelloConstructionData {
            roster: original_import18_hello_selection_construction_data(launch)?,
            frames: original_import18_hello_frames_construction_data(launch)?,
            literal: original_import18_hello_literal_construction_data(launch)?,
            value: original_import18_hello_value_construction_bound_data(launch, maximum)?,
            request: original_import18_hello_request_construction_bound_data(launch, maximum)?,
            registrar: original_import18_hello_registrar_construction_data(launch, maximum)?,
            sdk_request: original_import18_sdk_hello_request_construction_bound_data(
                launch, maximum,
            )?,
            result: original_import18_hello_result_construction_data(launch, maximum)?,
            envelope: original_import18_hello_envelope_construction_bound_data(launch, maximum)?,
            response: original_import18_hello_response_construction_data(launch, maximum)?,
            admission_backing: original_import18_hello_initial_admission_retained_backing_data(
                launch, maximum,
            )?,
        },
        maximum,
    )
}

/// Groups the independent retained Hello constructor populations.
struct HelloConstructionData {
    roster: [usize; 3],
    frames: [usize; 3],
    literal: [usize; 3],
    value: [usize; 3],
    request: [usize; 3],
    registrar: [usize; 3],
    sdk_request: [usize; 3],
    result: [usize; 3],
    envelope: [usize; 3],
    response: [usize; 3],
    admission_backing: usize,
}

fn combine(
    bodies: ProspectiveBodyConstructionData,
    source: [usize; 3],
    formatter: [usize; 3],
    launch_identity: (usize, usize),
    hello: HelloConstructionData,
    maximum: usize,
) -> Result<InitialConstructionData, ProviderError> {
    let HelloConstructionData {
        roster: hello,
        frames: hello_frames,
        literal: hello_literal,
        value: hello_value,
        request: hello_request,
        registrar: hello_registrar,
        sdk_request: sdk_hello_request,
        result: hello_result,
        envelope: hello_envelope,
        response: hello_response,
        admission_backing,
    } = hello;
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
    row[1] = row[1].max(launch_identity.0);
    row[2] = row[2].max(add(raw[2], launch_identity.1)?);
    let recipe_identity = native_import18_recipe_identity_construction_data(maximum)?;
    row[1] = row[1].max(recipe_identity.0);
    row[2] = row[2].max(add(raw[2], recipe_identity.1)?);
    // Executable measurement follows all parser/Source/header work. Its actual
    // temporary reference and fixed read bank overlap the same retained owners.
    let measurement = original_import18_controller_measurement_construction_data();
    row[1] = row[1].max(measurement[1]);
    row[2] = row[2].max(add(raw[2], measurement[2])?);
    // Complete immutable definition checks run sequentially without retaining
    // their temporary compiled schemas. All original raw/typed owners coexist.
    let selection = original_import18_selection_construction_data(maximum)?;
    row[1] = row[1].max(selection[1]);
    row[2] = row[2].max(add(raw[2], selection[2])?);
    // Native Hello selection follows initial correspondence while all original
    // raw/typed owners remain live. Only its actual feature/key backing is new.
    row[0] = add(row[0], hello[0])?;
    row[1] = row[1].max(hello[1]);
    row[2] = row[2].max(add(raw[2], hello[2])?);
    // The physical Hello journal and both literal directions coexist with the
    // selected roster and every original raw/typed owner.
    row[0] = add(row[0], hello_frames[0])?;
    row[1] = row[1].max(hello_frames[1]);
    row[2] = row[2].max(add(raw[2], hello_frames[2])?);
    // Public deadline binding coexists with every retained original owner. It
    // uses the pre-parser cut and performs no protocol read or publication.
    let public_channel = original_import18_public_channel_construction_data()?;
    row[0] = add(row[0], public_channel[0])?;
    row[1] = row[1].max(public_channel[1]);
    row[2] = row[2].max(add(raw[2], public_channel[2])?);
    // Framing moves the existing socket/cut and journal. Only its owning Box
    // refusal adds backing; those moved owners remain charged above.
    let hello_exchange = original_import18_hello_exchange_construction_data();
    row[0] = add(row[0], hello_exchange[0])?;
    row[1] = row[1].max(hello_exchange[1]);
    row[2] = row[2].max(add(raw[2], hello_exchange[2])?);
    // The unparsed incoming body retains its own actual bounded allocation
    // beside the immutable literal journal; strict parsing is a later admission.
    row[0] = add(row[0], hello_literal[0])?;
    row[1] = row[1].max(hello_literal[1]);
    row[2] = row[2].max(add(raw[2], hello_literal[2])?);
    // Strict parsing follows the literal read and retains its actual Value or
    // owned reason beside every original body, journal and typed bootstrap.
    row[0] = add(row[0], hello_value[0])?;
    row[1] = row[1].max(hello_value[1]);
    row[2] = row[2].max(add(raw[2], hello_value[2])?);
    // Request claims borrow the same strict tree. Its real typed offer and any
    // owned validation reason remain live beside all earlier bootstrap outputs.
    row[0] = add(row[0], hello_request[0])?;
    row[1] = row[1].max(hello_request[1]);
    row[2] = row[2].max(add(raw[2], hello_request[2])?);
    // The independently funded fresh registrar retains its actual cloned
    // configuration and new epoch/gate/empty registry beside every prior owner.
    row[0] = add(row[0], hello_registrar[0])?;
    row[1] = row[1].max(hello_registrar[1]);
    row[2] = row[2].max(add(raw[2], hello_registrar[2])?);
    // The real typed SDK request retains its independently decoded fields
    // beside the original strict Value, checked offer and fresh registrar.
    row[0] = add(row[0], sdk_hello_request[0])?;
    row[1] = row[1].max(sdk_hello_request[1]);
    row[2] = row[2].max(add(raw[2], sdk_hello_request[2])?);
    // The actual result owns fresh nonce vectors, selected features and the
    // complete provider manifest beside every original request/registrar owner.
    row[0] = add(row[0], hello_result[0])?;
    row[1] = row[1].max(hello_result[1]);
    row[2] = row[2].max(add(raw[2], hello_result[2])?);
    // The decoded request envelope keeps its actual body and extension owners
    // beside the original strict tree, SDK request, registrar and result.
    row[0] = add(row[0], hello_envelope[0])?;
    row[1] = row[1].max(hello_envelope[1]);
    row[2] = row[2].max(add(raw[2], hello_envelope[2])?);
    // Actual Completed and response owners coexist with every original input.
    row[0] = add(row[0], hello_response[0])?;
    row[1] = row[1].max(hello_response[1]);
    row[2] = row[2].max(add(raw[2], hello_response[2])?);
    // Reserve successful SDK registration's additional retained backing. Its
    // complete transient/callback constructor row remains a separate prerequisite
    // before native admission may invoke the real SDK.
    row[0] = add(row[0], admission_backing)?;
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
        + native_import18_launch_identity_counter_scratch_data()
        + native_import18_recipe_identity_counter_scratch_data()
        + original_import18_hello_selection_counter_scratch_data()
        + original_import18_hello_frames_counter_scratch_data()
        + size_of::<[usize; 3]>() // The retained physical Hello constructor row.
        + original_import18_hello_request_counter_scratch_data()
        // Registrar, request, result and envelope quotes return rows in turn.
        // Their recursive quote controls never coexist; the enclosing result
        // and row headers below remain separately represented.
        + original_import18_hello_registrar_counter_scratch_data()
            .max(original_import18_sdk_hello_request_counter_scratch_data())
            .max(original_import18_hello_result_counter_scratch_data())
            .max(original_import18_hello_envelope_counter_scratch_data())
            .max(original_import18_hello_response_counter_scratch_data())
            .max(original_import18_hello_initial_admission_backing_counter_scratch_data())
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 3]>()
        + original_import18_hello_value_counter_scratch_data()
        + size_of::<[usize; 3]>()
        + original_import18_hello_literal_counter_scratch_data()
        + size_of::<[usize; 3]>() // The retained literal-read constructor row.
        + original_import18_hello_exchange_counter_scratch_data()
        + size_of::<[usize; 3]>() // The retained framing constructor row.
        + original_import18_public_channel_counter_scratch_data()
        + size_of::<[usize; 3]>() // The retained physical public-channel row.
        + original_import18_selection_counter_scratch_data()
        + size_of::<[usize; 3]>() // The sequential compiled-definition row.
        + size_of::<[usize; 3]>() // The separate native Hello constructor row.
        + size_of::<PacketNativeImport18LaunchIdentityData>()
        + size_of::<Result<PacketNativeImport18LaunchIdentityData, ProviderError>>()
        + size_of::<(usize, usize)>() * 3
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<[u8; 32]>() * 4
        + size_of::<InitialConstructionData>()
        + size_of::<Result<InitialConstructionData, ProviderError>>()
        + size_of::<HelloConstructionData>()
        + size_of::<usize>() // Additional initial SDK retained-backing result.
        + size_of::<[usize; 3]>() * 6
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
/// launch/private-launch commitments or any prefix/body announcement join.
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
    let actual = derive_native_import18_launch_identity_data(
        selected.launch_data(),
        &boot.private_launch,
        derived.maximum_encoded_bytes[1],
    )?;
    if recipe.launch_identities_data()
        != (
            actual.selected_launch_identity_data(),
            actual.private_launch_identity_data(),
        )
    {
        return Err(ProviderError::Correlation(
            "original import18 recipe launch DATA",
        ));
    }
    recipe.authenticate_identity_data(derived.maximum_encoded_bytes[0])?;
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
