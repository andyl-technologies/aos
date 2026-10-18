//! Quotes fresh Control-family Capture demand from actual Source operands.
//!
//! ```text
//! registration + checkpoint + result/settlement + confirmation
//! ```
//!
//! Root/output/metadata banks, native wrapper/Scope owners and transport remain
//! separate caller obligations. All three axes sum across the four phases;
//! these DATA values never renew a claim or create native spending permission.

use super::*;
use crate::reference_packet::control::{PacketNative5Record, PacketNative5UnderlyingRecord};
use crate::reference_packet::service::{
    PacketNative5SourceLaunch,
    complete_restore::{PacketNativeRestoredRecord, activation::PacketRestorationActivationScope},
    restored_settled_confirmation::PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
};
use crucible_node_contract::{NodeBinding, OwnerBinding, Position};

mod prebirth;
pub use prebirth::{
    restored_settled_capture_control_model_future_from_initial15_data,
    restored_settled_capture_control_model_future_initial15_prequote_data,
};
mod projection;
use projection::Shapes;

/// Borrows immutable DATA from genuine Source launch and current-cache lenders.
///
/// Equal DTOs do not establish the owning lenders, a Source read or native
/// currentness. The actual Source must separately require its eventual ticket
/// argument roster to equal the sole launch owner roster before SDK assignment.
pub struct PacketRestoredSettledCaptureControlFutureInputs<'a> {
    /// Borrows the actual completed startup's immutable launch.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows its actual same-generation restoration scope.
    pub scope: &'a PacketRestorationActivationScope,
    /// Borrows the genuine first-observation ancestry reference.
    pub first_observation: &'a ContentRef,
    /// Borrows the newest complete restored proof reference.
    pub current_record_reference: &'a ContentRef,
    /// Borrows that frozen complete restored proof DTO.
    pub current_record: &'a PacketNativeRestoredRecord,
    /// Borrows its unchanged complete Producer2 or Reactive4 model DTO.
    pub current_model: &'a PacketNative5UnderlyingRecord,
    /// Borrows the actual requested capture identifier.
    pub capture_id: &'a Id,
    /// Carries the actual stopped cut requested by the caller.
    pub cut: Position,
    /// Carries the requested event ordinal at that cut.
    pub event_ordinal: U64,
}

/// Retains fixed model/receipt/original geometry without exposing mutable rows.
///
/// This is constructor DATA, never an imported or current native owner. The
/// runtime constructor binds actual current operands. A prebirth upper bound
/// requires a separate defining Initial15 constructor over validated import
/// geometry and both supported old12 observation families. A new fresh17 proof
/// wrapper is unsupported. Old runtime shapes cannot supply a prebirth bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredSettledCaptureControlModelFutureData {
    model: [usize; 11],
    restored: [usize; 11],
    prior: [usize; 11],
    formatter: usize,
    class: ModelGeometryClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelGeometryClass {
    ActualCurrent,
    SupportedInitial15 { import: [u8; 32], launch: [u8; 32] },
}

impl PacketRestoredSettledCaptureControlModelFutureData {
    // Only defining closed visitors in this module construct these facts.
    fn from_shapes(model: &Shape, restored: &Shape, prior: &Shape, formatter: usize) -> Self {
        Self {
            model: pack(model),
            restored: pack(restored),
            prior: pack(prior),
            formatter,
            class: ModelGeometryClass::ActualCurrent,
        }
    }

    fn supported_from_shapes(
        model: &Shape,
        restored: &Shape,
        prior: &Shape,
        formatter: usize,
        import: [u8; 32],
        canonical_raw5: &[u8],
    ) -> Self {
        let mut data = Self::from_shapes(model, restored, prior, formatter);
        data.class = ModelGeometryClass::SupportedInitial15 {
            import,
            launch: launch_identity(canonical_raw5),
        };
        data
    }

    /// Names the complete defining prebirth loan and visitor controls.
    ///
    /// A caller admits this S before obtaining formatter demand. Embedding the
    /// fixed DATA itself uses `counter_scratch_data` and does not call this
    /// constructor counter, avoiding recursion through import geometry.
    pub fn prebirth_counter_scratch_data() -> usize {
        prebirth::counter_scratch_data()
    }

    /// Names fixed packing, comparison and identity controls only.
    ///
    /// Prebirth constructor/loan/projection controls remain separately named;
    /// callers embedding this fixed DATA do not recurse into its constructor.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<[usize; 11]>() * 3
            + size_of::<Shape>() * 6
            + size_of::<std::array::IntoIter<usize, 11>>() * 3
            + size_of::<std::iter::Once<usize>>()
            + size_of::<
                std::iter::Chain<
                    std::iter::Chain<
                        std::iter::Chain<
                            std::array::IntoIter<usize, 11>,
                            std::array::IntoIter<usize, 11>,
                        >,
                        std::array::IntoIter<usize, 11>,
                    >,
                    std::iter::Once<usize>,
                >,
            >()
            + size_of::<[u8; 16]>()
            + size_of::<&mut blake3::Hasher>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>() * 2
            + size_of::<&[u8]>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Appends the complete defining geometry in a fixed field order as DATA.
    pub(crate) fn bind_identity_data(&self, hash: &mut blake3::Hasher) {
        hash.update(b"source-private.native-capture17-control-model-geometry/1");
        hash.update(&[match self.class {
            ModelGeometryClass::ActualCurrent => 0,
            ModelGeometryClass::SupportedInitial15 { .. } => 1,
        }]);
        if let ModelGeometryClass::SupportedInitial15 { import, launch } = &self.class {
            hash.update(import);
            hash.update(launch);
        }
        for value in self
            .model
            .into_iter()
            .chain(self.restored)
            .chain(self.prior)
            .chain(std::iter::once(self.formatter))
        {
            hash.update(&(value as u128).to_be_bytes());
        }
    }

    /// Matches the exact imported roles and actual newly authenticated launch bytes.
    ///
    /// The defining native constructor must call this before using a prebirth
    /// family. This correspondence check creates no custody or spending right.
    /// Its launch DTO/raw-byte authentication remains a separate prerequisite.
    ///
    /// # Errors
    /// Refuses runtime-only geometry, another decoder family/archive or changed
    /// launch bytes.
    pub fn authenticate_birth_inputs_data(
        &self,
        geometry: &crate::protocol_snapshot::restored_settled17::RestoredSettledNativeImportGeometryData,
        canonical_raw5: &[u8],
    ) -> Result<(), ProviderError> {
        if geometry.initial15_decoder_geometry_data().is_none() {
            return Err(refused());
        }
        match self.class {
            ModelGeometryClass::SupportedInitial15 { import, launch }
                if import == geometry.import_correspondence_data()
                    && launch == launch_identity(canonical_raw5) =>
            {
                Ok(())
            }
            _ => Err(refused()),
        }
    }

    /// Checks that later actual model geometry fits this independently derived bound.
    ///
    /// No match grants custody, native credit or a phase transition.
    ///
    /// # Errors
    /// Refuses any larger actual semantic, encoding, formatter or fixed-work axis.
    pub fn authenticate_actual_model_data(&self, actual: &Self) -> Result<(), ProviderError> {
        within(&unpack(actual.model), &unpack(self.model))?;
        within(&unpack(actual.restored), &unpack(self.restored))?;
        within(&unpack(actual.prior), &unpack(self.prior))?;
        if actual.formatter > self.formatter {
            return Err(exhausted());
        }
        Ok(())
    }
}

fn launch_identity(canonical_raw5: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("source-private.capture17-future-launch/1");
    hash.update(&(canonical_raw5.len() as u128).to_be_bytes());
    hash.update(canonical_raw5);
    *hash.finalize().as_bytes()
}

fn pack(value: &Shape) -> [usize; 11] {
    let Shape {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = value;
    [
        *dom_and_canonical_scratch_bytes,
        *retained_value_backing_bytes,
        *projected_parser_requested_bytes,
        *canonical_output_requested_bytes,
        *serializer_temporary_requested_bytes,
        *declared_counter_scratch_bytes,
        *maximum_encoded_bytes,
        *sequence_elements,
        *sequence_containers,
        *serialized_value_nodes,
        *serialized_capacity_records,
    ]
}

fn unpack(value: [usize; 11]) -> Shape {
    let [
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    ] = value;
    Shape {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    }
}

/// Retains four fresh Control-family obligations without granting any effect.
///
/// These exclude root/output/metadata banks, native wrapper/Scope owners,
/// Endpoint records and transport. Remaining native credit is not inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredSettledCaptureControlFutureStorageData {
    registration: PacketNativeStartupAllocationRow,
    checkpoint: PacketNativeStartupAllocationRow,
    terminal: PacketNativeStartupAllocationRow,
    confirmation: PacketNativeStartupAllocationRow,
    complete: PacketNativeStartupAllocationRow,
    model_future: PacketRestoredSettledCaptureControlModelFutureData,
}

impl PacketRestoredSettledCaptureControlFutureStorageData {
    /// Returns independently derived registration/hash/cache axes.
    pub const fn registration_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.registration
    }

    /// Returns independently derived current-checkpoint comparison axes.
    pub const fn checkpoint_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.checkpoint
    }

    /// Returns independently derived result/settlement axes.
    pub const fn terminal_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.terminal
    }

    /// Returns independently derived final Poll/cache/receipt axes.
    pub const fn confirmation_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.confirmation
    }

    /// Returns the sum of all three axes across the four phases.
    pub const fn complete_family_axes_data(&self) -> PacketNativeStartupAllocationRow {
        self.complete
    }

    /// Returns fixed geometry of this runtime model comparison for correspondence.
    ///
    /// This actual-current result is not a prebirth future upper bound.
    pub const fn model_future_data(&self) -> PacketRestoredSettledCaptureControlModelFutureData {
        self.model_future
    }

    /// Names defining fixed visitors before the actual metadata walk.
    pub fn counter_scratch_data() -> usize {
        counter_scratch_data()
    }
}

/// Names actual formatter demand before any generic future Serialize traversal.
///
/// The caller admits this T and the defining S before the full quote. The walk
/// reads initialized typed Bytes, excluding raw Vec banks. It creates no grant.
///
/// # Errors
/// Refuses mismatched tuples, grant-bearing models, exhausted finite metadata
/// traversal or checked formatter extent overflow.
pub fn restored_settled_capture_control_future_prequote_data(
    input: &PacketRestoredSettledCaptureControlFutureInputs<'_>,
) -> Result<(usize, usize), ProviderError> {
    fields(input)?;
    let mut observer = MetadataObserver::new();
    observer.observe(input.current_record)?;
    match input.current_model {
        PacketNative5UnderlyingRecord::Producer(model) => observer.observe(model.as_ref())?,
        PacketNative5UnderlyingRecord::Reactive(model) => observer.observe(model.as_ref())?,
    }
    observer.observe(&input.scope.restoration.context_digest)?;
    let work = observer
        .ordinary_bytes_formatter_data()
        .maximum_temporary_requested_bytes_data()?
        .max(43)
        .max(20);
    Ok((work, counter_scratch_data()))
}

/// Quotes fresh Control-family demand from complete actual immutable operands.
///
/// New map insertion bounds follow defining nonrecycling original/Begin limits
/// and full pinned BTree split layouts. Generated IDs128 and decimal20 values
/// are geometry extents, never hypothetical Envelopes or content references.
/// The caller first admits the independent prequote T/S.
///
/// # Errors
/// Refuses unsupported actual tuples or grants, future frames above unchanged
/// transport limits, overflow, exhausted metadata or a short complete maximum.
pub fn restored_settled_capture_control_future_storage_data(
    input: &PacketRestoredSettledCaptureControlFutureInputs<'_>,
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlFutureStorageData, ProviderError> {
    let (binding, owner) = fields(input)?;
    let (formatter, _) = restored_settled_capture_control_future_prequote_data(input)?;
    let shapes = projection::shapes(input, binding, owner, maximum)?;
    let frame = usize::try_from(input.launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    for shape in [
        &shapes.capture,
        &shapes.confirmation,
        &shapes.terminal,
        &shapes.confirmation_terminal,
    ] {
        if shape.maximum_encoded_bytes > frame {
            return Err(exhausted());
        }
    }
    let model_future = runtime_model_data(input, formatter, maximum)?;
    rows_from_shapes(shapes, owner, model_future, maximum)
}

/// Quotes all four fresh Control phases before native storage is sealed.
///
/// Only a defining validated-import constructor produces SupportedInitial15 model
/// geometry. A runtime actual-current projection is explicitly refused here.
/// The result remains inert demand, excluding root/wrapper/transport owners.
///
/// # Errors
/// Refuses runtime-current geometry, changed raw5 bytes, missing sole owner or
/// routing, unsupported transport limits, an over-cap frame or short maximum.
pub fn restored_settled_capture_control_future_from_model_data(
    launch: &PacketNative5SourceLaunch,
    canonical_raw5: &[u8],
    model: &PacketRestoredSettledCaptureControlModelFutureData,
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlFutureStorageData, ProviderError> {
    if !matches!(model.class, ModelGeometryClass::SupportedInitial15 { launch, .. }
        if launch == launch_identity(canonical_raw5))
    {
        return Err(refused());
    }
    launch.limits.validate()?;
    let [owner] = launch.selection.realization.owner_bindings.as_slice() else {
        return Err(refused());
    };
    let shapes = projection::shapes_prebirth(launch, maximum)?;
    let frame = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    for shape in [
        &shapes.capture,
        &shapes.confirmation,
        &shapes.terminal,
        &shapes.confirmation_terminal,
    ] {
        if shape.maximum_encoded_bytes > frame {
            return Err(exhausted());
        }
    }
    rows_from_shapes(shapes, owner, *model, maximum)
}

fn rows_from_shapes(
    shapes: Shapes,
    owner: &OwnerBinding,
    model_future: PacketRestoredSettledCaptureControlModelFutureData,
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlFutureStorageData, ProviderError> {
    let model = unpack(model_future.model);
    let restored = unpack(model_future.restored);
    let prior = unpack(model_future.prior);
    let owner_work = actual_serialization_storage_data(owner, Default::default(), maximum)?;
    let scratch = counter_scratch_data();
    let registration = registration_row(&shapes, owner, &owner_work, &model, scratch, maximum)?;
    let checkpoint = checkpoint_row(&model, &restored, &prior, &owner_work, scratch, maximum)?;
    let terminal = terminal_row(&shapes, scratch, maximum)?;
    let confirmation = confirmation_row(&shapes, scratch, maximum)?;
    let complete = add_rows([registration, checkpoint, terminal, confirmation])?;
    if usize::try_from(complete.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
        return Err(exhausted());
    }
    Ok(PacketRestoredSettledCaptureControlFutureStorageData {
        registration,
        checkpoint,
        terminal,
        confirmation,
        complete,
        model_future,
    })
}

fn runtime_model_data(
    input: &PacketRestoredSettledCaptureControlFutureInputs<'_>,
    formatter: usize,
    maximum: usize,
) -> Result<PacketRestoredSettledCaptureControlModelFutureData, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(input.current_record)?;
    let mut restored =
        actual_serialization_storage_data(input.current_record, observer.finish(), maximum)?;
    restored.serializer_temporary_requested_bytes = formatter;
    let mut model = match input.current_model {
        PacketNative5UnderlyingRecord::Producer(model) => {
            actual_serialization_storage_data(model.as_ref(), Default::default(), maximum)?
        }
        PacketNative5UnderlyingRecord::Reactive(model) => {
            actual_serialization_storage_data(model.as_ref(), Default::default(), maximum)?
        }
    };
    model.serializer_temporary_requested_bytes = formatter;
    let prior = actual_serialization_storage_data(
        &input.current_record.native_receipt.original,
        Default::default(),
        maximum,
    )?;
    Ok(
        PacketRestoredSettledCaptureControlModelFutureData::from_shapes(
            &model, &restored, &prior, formatter,
        ),
    )
}

fn fields<'a>(
    input: &'a PacketRestoredSettledCaptureControlFutureInputs<'_>,
) -> Result<(&'a NodeBinding, &'a OwnerBinding), ProviderError> {
    input.launch.limits.validate()?;
    let [binding] = input.launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let [owner] = input.launch.selection.realization.owner_bindings.as_slice() else {
        return Err(refused());
    };
    let original = &input.current_record.native_receipt.original;
    let (actual, grant) = match input.current_model {
        PacketNative5UnderlyingRecord::Producer(model) => (&model.original, model.grant.is_some()),
        PacketNative5UnderlyingRecord::Reactive(model) => (&model.original, model.grant.is_some()),
    };
    if grant
        || actual != original
        || input
            .current_record
            .native_receipt
            .native_record
            .length
            .get()
            == 0
        || input.current_record_reference.length.get() == 0
        || input.first_observation.length.get() == 0
        || input.scope.restoration.context_digest.as_slice().len() != 32
        || input.scope.target.native_pid != input.current_record.native_receipt.native_pid
        || input.scope.target.session != binding.authority.session_id
        || input.scope.target.incarnation != binding.authority.incarnation_id
        || input.scope.target.node != binding.compatibility.node_id
        || input.scope.target.owner != owner.owner.id
        || input.scope.target.world != input.launch.selection.world
        || input.scope.target.prepared_token != input.launch.selection.prepared_token
        || input.scope.target.gate != input.launch.selection.gate
        || input.scope.target.admission != input.launch.selection.admission
        || input.scope.target.transaction != input.launch.selection.transaction
        || owner.owner.participant_ids.is_empty()
    {
        return Err(refused());
    }
    Ok((binding, owner))
}

fn hash_backing(domain: &str) -> usize {
    "blake3-256".len() + domain.len() + 64
}
fn reference_backing() -> usize {
    hash_backing("cnp.blob.v1") + "application/json".len()
}

fn hash_row(
    shape: &Shape,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    row(
        sum(&[
            size_of::<NativePendingCapture17RequestHashAttempt>(),
            shape.retained_value_backing_bytes,
            shape.maximum_encoded_bytes,
            hash_backing("cnp.request.v1"),
        ])?,
        shape.requested_total()?.max(20),
        scratch,
        maximum,
    )
}

fn registration_row(
    shapes: &Shapes,
    owner: &OwnerBinding,
    owner_work: &Shape,
    model: &Shape,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let hash = hash_row(&shapes.capture_identity, scratch, maximum)?;
    let validation = owner
        .owner
        .participant_ids
        .windows(2)
        .try_fold(0usize, |maximum, pair| {
            Ok::<_, ProviderError>(
                maximum.max(sum(&[pair[0].as_str().len(), pair[1].as_str().len()])?),
            )
        })?;
    row(
        sum(&[
            size_of::<NativeCapture17RegistrationAttempt>(),
            size_of::<NativeCapture17RegistrationStorageData>(),
            size_of::<PacketOriginalCaptureReservation>(),
            shapes.capture.retained_value_backing_bytes,
            multiply(2, shapes.begin.retained_value_backing_bytes)?,
            shapes.arguments.retained_value_backing_bytes,
            insertion::<Id, (HashRef, PacketControlReply)>(ORIGINALS - 1)?,
            insertion::<Id, BeginRequest>(63)?,
            insertion::<Id, Id>(ORIGINALS - 1)?,
            2 * 128,
            3 * 128,
            shapes.unknown.retained_value_backing_bytes,
            hash_backing("cnp.owner-binding.v1"),
            hash_backing("cnp.request.v1"),
            usize::try_from(hash.retained_requested_bytes.get()).map_err(|_| exhausted())?,
        ])?,
        sum(&[
            shapes.capture.requested_total()?,
            shapes.begin.requested_total()?,
            shapes.arguments.requested_total()?,
            shapes.request.requested_total()?,
            shapes.unknown.requested_total()?,
            owner_work.requested_total()?,
            model.requested_total()?,
            validation,
            usize::try_from(hash.maximum_simultaneous_transient_bytes.get())
                .map_err(|_| exhausted())?,
        ])?,
        scratch,
        maximum,
    )
}

fn checkpoint_row(
    model: &Shape,
    restored: &Shape,
    prior: &Shape,
    owner: &Shape,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    // Closed restored DOM backing dominates the separately cloned immutable
    // receipt/restoration heap trees; fresh canonical banks remain independent.
    row(
        sum(&[
            size_of::<NativeObservation17CheckpointAttempt>(),
            size_of::<NativeObservation17CheckpointStorageData<'static>>(),
            model.maximum_encoded_bytes,
            restored.maximum_encoded_bytes,
            multiply(2, restored.retained_value_backing_bytes)?,
            size_of::<PacketNative5Record>(),
            size_of::<PacketNativeRestoredRecord>(),
            multiply(2, reference_backing())?,
        ])?,
        sum(&[
            model.requested_total()?,
            restored.requested_total()?,
            prior.requested_total()?,
            owner.requested_total()?,
            hash_backing("cnp.request.v1"),
        ])?,
        scratch
            .checked_add(super::super::capture17_checkpoint_counter_scratch_data())
            .ok_or_else(exhausted)?,
        maximum,
    )
}

fn terminal_row(
    shapes: &Shapes,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    row(
        sum(&[
            size_of::<NativeCapture17TerminalStorageData>(),
            size_of::<NativeCapture17ReplyAttempt>(),
            multiply(3, shapes.result.retained_value_backing_bytes)?,
            insertion::<Id, Map<String, Value>>(ORIGINALS - 1)?,
            128,
            multiply(3, reference_backing())?,
        ])?,
        sum(&[
            shapes.result.requested_total()?,
            shapes.terminal.requested_total()?,
        ])?,
        scratch,
        maximum,
    )
}

fn confirmation_row(
    shapes: &Shapes,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let hash = hash_row(&shapes.confirmation_identity, scratch, maximum)?;
    row(
        sum(&[
            size_of::<NativeCapture17ConfirmationStorageData>(),
            size_of::<NativeCapture17ConfirmationAttempt>(),
            insertion::<Id, (HashRef, PacketControlReply)>(ORIGINALS - 1)?,
            128,
            multiply(2, shapes.confirmation_result.retained_value_backing_bytes)?,
            shapes.confirmation_receipt.retained_value_backing_bytes,
            shapes.capture.retained_value_backing_bytes,
            shapes.capture.maximum_encoded_bytes,
            shapes.terminal.retained_value_backing_bytes,
            shapes.terminal.maximum_encoded_bytes,
            reference_backing(),
            hash_backing(PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN),
            hash_backing("cnp.request.v1"),
            usize::try_from(hash.retained_requested_bytes.get()).map_err(|_| exhausted())?,
        ])?,
        sum(&[
            shapes.confirmation.requested_total()?,
            shapes.confirmation_result.requested_total()?,
            shapes.confirmation_receipt.requested_total()?,
            shapes.confirmation_terminal.requested_total()?,
            shapes.capture.requested_total()?,
            shapes.terminal.requested_total()?,
            usize::try_from(hash.maximum_simultaneous_transient_bytes.get())
                .map_err(|_| exhausted())?,
        ])?,
        scratch,
        maximum,
    )
}

fn add_rows(
    rows: [PacketNativeStartupAllocationRow; 4],
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    rows.into_iter().try_fold(
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(0),
            maximum_simultaneous_transient_bytes: U64::new(0),
            declared_counter_scratch_bytes: U64::new(0),
        },
        |left, right| {
            Ok(PacketNativeStartupAllocationRow {
                retained_requested_bytes: left
                    .retained_requested_bytes
                    .checked_add(right.retained_requested_bytes)?,
                maximum_simultaneous_transient_bytes: left
                    .maximum_simultaneous_transient_bytes
                    .checked_add(right.maximum_simultaneous_transient_bytes)?,
                declared_counter_scratch_bytes: left
                    .declared_counter_scratch_bytes
                    .checked_add(right.declared_counter_scratch_bytes)?,
            })
        },
    )
}

fn counter_scratch_data() -> usize {
    capture17_producer_counter_scratch_data()
        + projection::counter_scratch_data()
        + prebirth::counter_scratch_data()
        + size_of::<PacketRestoredSettledCaptureControlFutureInputs<'static>>()
        + size_of::<PacketRestoredSettledCaptureControlFutureStorageData>()
        + size_of::<Result<PacketRestoredSettledCaptureControlFutureStorageData, ProviderError>>()
        + PacketRestoredSettledCaptureControlModelFutureData::counter_scratch_data()
        + size_of::<PacketRestoredSettledCaptureControlModelFutureData>()
        + size_of::<Result<PacketRestoredSettledCaptureControlModelFutureData, ProviderError>>()
        + size_of::<[usize; 11]>()
        + size_of::<std::array::IntoIter<usize, 11>>() * 3
        + size_of::<std::iter::Once<usize>>()
        + size_of::<[u8; 16]>()
        + size_of::<&mut blake3::Hasher>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<(&Envelope, bool)>()
        + size_of::<&ContentRef>()
        + size_of::<Shape>() * 5
        + size_of::<&NodeBinding>()
        + size_of::<&OwnerBinding>()
        + size_of::<&PacketNative5UnderlyingRecord>()
        + size_of::<&PacketNativeRestoredRecord>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<[&Shape; 4]>()
        + size_of::<std::array::IntoIter<&'static Shape, 4>>()
        + size_of::<[PacketNativeStartupAllocationRow; 4]>()
        + size_of::<std::array::IntoIter<PacketNativeStartupAllocationRow, 4>>()
        + size_of::<[usize; 15]>()
        + size_of::<[usize; 9]>()
        + size_of::<[usize; 7]>()
        + size_of::<std::slice::Windows<'static, Id>>()
        + size_of::<&[Id]>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Result<(&NodeBinding, &OwnerBinding), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize; 2]>()
        + size_of::<usize>() * 5
}

#[cfg(test)]
mod tests;
