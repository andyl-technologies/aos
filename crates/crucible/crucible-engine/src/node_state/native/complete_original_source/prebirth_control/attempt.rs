//! Retains separately admitted Journal and Control DATA before native birth.
//!
//! The small bank reserves one actual owner only after its row is admitted.
//! Every constructor and visitor is tied to the original Source/ticket; neither
//! completion nor an equal body creates fresh target or native permission.

use super::*;
use crate::node_adapters::cnp::{PacketCompleteSemanticSource, PacketCompleteSettledJournal};
use crate::node_contract::NodeRuntime;
use crucible_node_transport::{
    ProviderError,
    protocol_snapshot::restored_settled17::{
        Initial15NativeImportGeometryAttempt as GeometryAttempt,
        Initial15NativeImportGeometryConstructionData as GeometryConstruction,
        RestoredSettledNative17Limits, RestoredSettledNativeImportGeometryData,
    },
    reference_packet::{
        control::{
            PacketDecodedCaptureFutureControlData,
            decode_packet_control_snapshot_for_capture_future_data,
        },
        service::PacketNative5SourceLaunch,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Work {
    Journal,
    Control,
}

/// Retains the actual separately quoted constructor axes and immutable inputs.
///
/// Private fields prevent a caller from filling a missing constructor row with
/// a cap or prior decoder allowance. This row is DATA, not an admission token.
#[derive(Clone, Copy)]
pub struct CompleteInitial15PrebirthControlConstructionData {
    work: Work,
    retained: usize,
    transient: usize,
    scratch: usize,
    source: *const CompleteOriginalSource,
    owner_index: usize,
    reference: *const ContentRef,
    body: [u8; 32],
    maximum_encoded: usize,
    launch: *const PacketNative5SourceLaunch,
    retained_after: usize,
}

impl CompleteInitial15PrebirthControlConstructionData {
    /// Returns independent new retained, simultaneous transient and fixed axes.
    pub fn requested_storage_data(&self) -> [usize; 3] {
        [self.retained, self.transient, self.scratch]
    }
}

struct Owner {
    source: Rc<CompleteOriginalSource>,
    owner_index: usize,
    journal: Option<PacketCompleteSettledJournal>,
    control: Option<PacketDecodedCaptureFutureControlData>,
    geometry: Option<GeometryAttempt>,
    journal_complete: bool,
    control_started: bool,
    control_complete: bool,
}

/// Keeps the actual one-slot parser custody and any refused construction.
///
/// The inline bank has no decoded owner until its prospective row is admitted.
/// A reserved-but-empty vector remains counted after allocation/refusal.
pub struct CompleteInitial15PrebirthControlAttempt {
    owners: Vec<Owner>,
    started: bool,
    failed: bool,
    process: u32,
    thread: ThreadId,
}

impl CompleteInitial15PrebirthControlAttempt {
    /// Creates an empty allocation-free holder for one independently admitted cut.
    pub fn new() -> Self {
        Self {
            owners: Vec::new(),
            started: false,
            failed: false,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }
    }

    /// Declares the actual quote, decoder, owning-census and provenance controls.
    pub fn counter_scratch_data() -> usize {
        CompleteOriginalNativeTicket::initial15_prebirth_control_input_counter_scratch_data()
            + PacketCompleteSettledJournal::decode_construction_counter_scratch_data()
            + PacketCompleteSettledJournal::decode_validation_counter_scratch_data()
            + PacketCompleteSettledJournal::retained_counter_scratch_data()
            + PacketCompleteSemanticSource::original_control_snapshot_complete_quote_counter_scratch_data()
            + PacketDecodedCaptureFutureControlData::retained_metadata_counter_scratch_data()
            + PacketDecodedCaptureFutureControlData::provenance_counter_scratch_data()
            + PacketDecodedCaptureFutureControlData::decoder_counter_scratch_data()
            + GeometryConstruction::counter_scratch_data()
            + GeometryAttempt::retained_counter_scratch_data()
            + crate::node_state::CompleteOriginalNativeRestorationData::reference_counter_scratch_data()
            + size_of::<GeometryConstruction>()
            + size_of::<Option<GeometryAttempt>>()
            + size_of::<Result<GeometryConstruction, ProviderError>>()
            + size_of::<Result<GeometryConstruction, RuntimeError>>()
            + size_of::<Result<&RestoredSettledNativeImportGeometryData, ProviderError>>()
            + size_of::<Result<&RestoredSettledNativeImportGeometryData, RuntimeError>>()
            + size_of::<&crate::node_state::CompleteOriginalNativeRestorationData>()
            + size_of::<Result<&crate::node_state::CompleteOriginalNativeRestorationData, RuntimeError>>()
            + size_of::<&crate::node_state::NativeArchiveRecord>()
            + size_of::<RestoredSettledNative17Limits>()
            + size_of::<Result<RestoredSettledNative17Limits, ProviderError>>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<(&ContentRef, &[u8]), 5>>()
            + crucible_node_format::canonical::json_parse_counter_scratch_bytes_data()
            + size_of::<std::thread::Thread>()
            + size_of::<Self>() + size_of::<Owner>() + size_of::<Result<Owner, RuntimeError>>()
            + size_of::<CompleteInitial15PrebirthControlConstructionData>()
            + size_of::<Result<CompleteInitial15PrebirthControlConstructionData, RuntimeError>>()
            + size_of::<PacketCompleteSettledJournal>()
            + size_of::<Result<PacketCompleteSettledJournal, crate::node_contract::OperationFailure>>()
            + size_of::<Result<PacketDecodedCaptureFutureControlData, ProviderError>>()
            + size_of::<[usize; 2]>() + size_of::<[usize; 3]>() + size_of::<[usize; 4]>()
            + size_of::<(&ContentRef, &ContentRef)>()
            + size_of::<Result<(&ContentRef, &ContentRef), RuntimeError>>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<&PacketNative5SourceLaunch>() + size_of::<&Owner>()
            + size_of::<crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNative17Input<'static>>()
            + size_of::<Result<crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNative17Input<'static>, RuntimeError>>()
            + size_of::<&VerifiedStateContent>() + size_of::<Option<&[u8]>>()
            + size_of::<Option<&Owner>>() + size_of::<Option<&mut Owner>>()
            + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
    }

    /// Declares the actual hash/ordinary formatter floor before quotation.
    pub fn prewalk_data() -> (usize, usize) {
        (
            20 + "blake3-256".len() + "cnp.blob.v1".len() + 64
                + PacketCompleteSemanticSource::original_control_snapshot_complete_quote_transient_data(),
            Self::counter_scratch_data(),
        )
    }

    /// Quotes the unchanged Journal decoder before reserving an output slot.
    ///
    /// The defining combined decoder term is conservatively paid on both R and
    /// T. It is never presented as measured retained backing. Enclosing Source,
    /// factory, target and prior-cache owners are charged separately.
    ///
    /// # Errors
    /// Refuses changed original input, excessive record bound, overflow or an
    /// independent prior-plus-constructor row above `maximum`.
    pub fn journal_construction_data(
        input: &CompleteInitial15PrebirthControlInput<'_>,
        prior_retained: usize,
        maximum: usize,
    ) -> Result<CompleteInitial15PrebirthControlConstructionData, RuntimeError> {
        input.authenticate_origin_data()?;
        let (reference, bytes) = input.journal_data();
        let maximum_encoded = input
            .ticket
            .source
            .archive
            .limits
            .state
            .maximum_record_bytes;
        if bytes.len() > maximum_encoded {
            return Err(RuntimeError::ResourceLimit);
        }
        let decoder = PacketCompleteSettledJournal::decode_construction_storage_data(bytes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let retained = checked_sum(&[size_of::<Owner>(), decoder])?;
        // IdSet::validate_sorted holds two adjacent owned participant keys.
        // Each decoded UTF-8 key is no longer than this exact JSON input; these
        // are independent clone windows, not a general DOM-size multiplier.
        let participant_key = bytes.len();
        let transient = checked_sum(&[
            decoder,
            participant_key,
            participant_key,
            size_of::<Owner>(),
            size_of::<Owner>(),
        ])?;
        let scratch = Self::counter_scratch_data();
        ensure_row(prior_retained, retained, transient, scratch, maximum)?;
        input.authenticate_origin_data()?;
        Ok(CompleteInitial15PrebirthControlConstructionData {
            work: Work::Journal,
            retained,
            transient,
            scratch,
            source: input.ticket.source.as_ref(),
            owner_index: input.ticket.owner_index,
            reference,
            body: *blake3::hash(bytes).as_bytes(),
            maximum_encoded,
            launch: std::ptr::null(),
            retained_after: retained,
        })
    }

    /// Reserves and retains one original Journal before later constructors run.
    ///
    /// The caller admits the complete row before entry. No observer is called
    /// while this mutable bank loan or the borrowed input is held.
    ///
    /// # Errors
    /// Refuses reused custody, changed input/row, reservation, decode or exact
    /// original owner/runtime/cut disagreement. Every initialized field survives.
    pub fn retain_journal_into(
        &mut self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        row: &CompleteInitial15PrebirthControlConstructionData,
    ) -> Result<(), RuntimeError> {
        self.actor()?;
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        self.failed = true;
        authenticate_row(
            input,
            row,
            Work::Journal,
            input.journal,
            input.journal_bytes,
        )?;
        self.owners
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.owners.push(Owner {
            source: Rc::clone(&input.ticket.source),
            owner_index: input.ticket.owner_index,
            journal: None,
            control: None,
            geometry: None,
            journal_complete: false,
            control_started: false,
            control_complete: false,
        });
        let owner = self
            .owners
            .first_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.journal = Some(
            PacketCompleteSettledJournal::decode_data(input.journal_bytes, row.maximum_encoded)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if journal.owner != input.owner.owner
            || journal.participants != input.owner.participants
            || journal.native_snapshot != input.owner.state
            || journal.cut != input.owner.cut
            || journal.runtime != owner.source.runtime
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        input.authenticate_origin_data()?;
        owner.journal_complete = true;
        self.retained_requested_storage_data(row.retained)?;
        self.failed = false;
        Ok(())
    }

    /// Quotes the same defining original Control constructor from the real launch.
    ///
    /// The genuine caller binds this immutable launch to its actual target code
    /// authority before entry. No fresh Source or live model is reconstructed.
    ///
    /// # Errors
    /// Refuses a missing/failed Journal, changed origin, absent Control body,
    /// original selected bound, checked geometry or independent row excess.
    pub fn control_construction_data(
        &self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        launch: &PacketNative5SourceLaunch,
        prior_retained: usize,
        maximum: usize,
    ) -> Result<CompleteInitial15PrebirthControlConstructionData, RuntimeError> {
        let owner = self.original_owner(input)?;
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let reference = &journal.native_control;
        let bytes = owner
            .source
            .content()
            .get(reference)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (retained, decoder_transient, decoder_scratch, maximum_encoded) =
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                bytes,
                launch.storage.control_snapshot_bytes,
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let transient = checked_sum(&[
            decoder_transient,
            20 + "blake3-256".len() + "cnp.blob.v1".len() + 64,
        ])?;
        let scratch = checked_sum(&[Self::counter_scratch_data(), decoder_scratch])?;
        ensure_row(prior_retained, retained, transient, scratch, maximum)?;
        input.authenticate_origin_data()?;
        Ok(CompleteInitial15PrebirthControlConstructionData {
            work: Work::Control,
            retained,
            transient,
            scratch,
            source: owner.source.as_ref(),
            owner_index: owner.owner_index,
            reference,
            body: *blake3::hash(bytes).as_bytes(),
            maximum_encoded,
            launch,
            retained_after: checked_sum(&[
                self.retained_requested_storage_data(maximum)?,
                retained,
            ])?,
        })
    }

    /// Retains the actual unchanged Control decoder result and its input identity.
    ///
    /// The caller independently admits this row including every prior live cache
    /// before entry. Failure is sticky; no second parse can replace the attempt.
    ///
    /// # Errors
    /// Refuses changed launch/row/body, reused work, decoder/cut/census failure.
    pub fn retain_control_into(
        &mut self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        launch: &PacketNative5SourceLaunch,
        row: &CompleteInitial15PrebirthControlConstructionData,
    ) -> Result<(), RuntimeError> {
        self.original_owner(input)?;
        self.failed = true;
        let owner = self
            .owners
            .first_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if owner.control_started {
            return Err(RuntimeError::OutstandingObligations);
        }
        owner.control_started = true;
        if !std::ptr::eq(row.launch, launch) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let bytes = owner
            .source
            .content()
            .get(&journal.native_control)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        authenticate_row(input, row, Work::Control, &journal.native_control, bytes)?;
        owner.control = Some(
            decode_packet_control_snapshot_for_capture_future_data(
                bytes,
                &journal.native_control,
                row.maximum_encoded,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        if owner
            .control
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .control_data()
            .administrative_cut()
            != journal.cut
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        input.authenticate_origin_data()?;
        owner.control_complete = true;
        self.retained_requested_storage_data(row.retained_after)?;
        self.failed = false;
        Ok(())
    }

    /// Borrows the actual old Controller and native roots for mapping quotation.
    ///
    /// The Journal remains owned by this same completed Source occurrence. These
    /// references do not establish a fresh mapping or any native allowance; the
    /// caller independently binds its real target's planned registration.
    ///
    /// # Errors
    /// Refuses foreign, failed or incomplete original Journal custody.
    pub fn normalization_references_data<'a>(
        &'a self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
    ) -> Result<(&'a ContentRef, &'a ContentRef), RuntimeError> {
        let owner = self.original_owner(input)?;
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        input.authenticate_origin_data()?;
        Ok((&journal.host_protocol, &journal.native_after_protocol))
    }

    /// Borrows the same five genuine immutable roles for a separate validator.
    ///
    /// The returned bytes remain backed by the completed original Source. They
    /// grant no decoder allowance: the native11 prewalk/alias bank/validation and
    /// future normalization bound each need their defining independent row.
    ///
    /// # Errors
    /// Refuses failed/incomplete or foreign original custody or absent role bytes.
    pub fn original_input_data<'a>(
        &'a self,
        input: &'a CompleteInitial15PrebirthControlInput<'_>,
    ) -> Result<
        crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNative17Input<
            'a,
        >,
        RuntimeError,
    >{
        let owner = self.original_owner(input)?;
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let content = owner.source.content();
        let body = |reference| content.get(reference).ok_or(RuntimeError::OwnerUnavailable);
        let result = crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNative17Input {
            snapshot: (&input.owner.state, body(&input.owner.state)?),
            current_protocol: (&journal.native_after_protocol, body(&journal.native_after_protocol)?),
            control: (&journal.native_control, body(&journal.native_control)?),
            anchor: (&journal.native_anchor, body(&journal.native_anchor)?),
            journal: (input.journal, input.journal_bytes),
        };
        input.authenticate_origin_data()?;
        Ok(result)
    }

    /// Quotes the genuine original native11 validator and its retained aliases.
    ///
    /// The actual archive's immutable constraints bound DATA traversal only.
    /// The original decoder limits come from this same ticket's retained cold
    /// validation row; only a newly run real validator can construct geometry.
    /// No copied demand or late Window allowance substitutes for that witness.
    ///
    /// # Errors
    /// Refuses changed original roles, absent original limits, malformed role
    /// framing, an independently derived normalization outside its grammar, or
    /// prior-cache plus constructor demand beyond `maximum`.
    pub fn geometry_construction_data(
        &self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        normalization_maximum: usize,
        maximum: usize,
    ) -> Result<GeometryConstruction, RuntimeError> {
        self.original_owner(input)?;
        let native = self.original_input_data(input)?;
        let original = input.ticket.native_restoration_construction_data()?;
        original.authenticate_original_references_data([
            native.current_protocol.0,
            native.control.0,
            native.anchor.0,
            native.snapshot.0,
            native.journal.0,
        ])?;
        let archive = &input.ticket.source.archive;
        let lengths = native.roles_data().map(|(_, bytes)| bytes.len());
        let nodes = lengths.into_iter().try_fold(0usize, |sum, length| {
            sum.checked_add(length).ok_or(RuntimeError::ResourceLimit)
        })?;
        let limits = RestoredSettledNative17Limits::new(
            lengths,
            archive
                .limits
                .state
                .maximum_total_content_bytes
                .min(archive.limits.native.maximum_total_record_bytes),
            input.ticket.source.content().object_count(),
            archive.limits.state.maximum_dependency_depth.min(64),
            nodes,
            maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let row = GeometryConstruction::quote_data(
            &native,
            original.native_decoder_limits_data(),
            limits,
            normalization_maximum,
            maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let [retained, transient, scratch] = row.requested_axes_data();
        ensure_row(
            self.retained_requested_storage_data(maximum)?,
            retained,
            transient,
            scratch,
            maximum,
        )?;
        input.authenticate_origin_data()?;
        Ok(row)
    }

    /// Retains a separately admitted actual native11 validation attempt.
    ///
    /// The destination becomes occupied before every fallible reservation or
    /// validator step. Partial aliases survive refusal in this original owner;
    /// the completed fixed geometry remains DATA, without native permission.
    ///
    /// # Errors
    /// Refuses reused work, changed original role/body/limits, alias allocation
    /// or actual defining native validation failure. Every partial is retained.
    pub fn retain_geometry_into(
        &mut self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        row: &GeometryConstruction,
    ) -> Result<(), RuntimeError> {
        self.original_owner(input)?;
        self.failed = true;
        let owner = self
            .owners
            .first_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let Owner {
            source,
            journal,
            geometry,
            ..
        } = owner;
        let journal = journal.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let content = source.content();
        let body = |reference| content.get(reference).ok_or(RuntimeError::OwnerUnavailable);
        let native = crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNative17Input {
            snapshot: (&input.owner.state, body(&input.owner.state)?),
            current_protocol: (&journal.native_after_protocol, body(&journal.native_after_protocol)?),
            control: (&journal.native_control, body(&journal.native_control)?),
            anchor: (&journal.native_anchor, body(&journal.native_anchor)?),
            journal: (input.journal, input.journal_bytes),
        };
        let result = row.construct_into_data(&native, geometry);
        let origin = input.authenticate_origin_data();
        result.map_err(|_| RuntimeError::InvalidReceipt)?;
        origin?;
        self.failed = false;
        Ok(())
    }

    /// Borrows only geometry completed by the same actual original validation.
    ///
    /// # Errors
    /// Refuses failed/incomplete or foreign custody, changed roles or absent
    /// genuine defining geometry. The result issues no live native grant.
    pub fn geometry_data(
        &self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
    ) -> Result<&RestoredSettledNativeImportGeometryData, RuntimeError> {
        let owner = self.original_owner(input)?;
        let native = self.original_input_data(input)?;
        let geometry = owner
            .geometry
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = geometry
            .geometry_data(&native)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        input.authenticate_origin_data()?;
        Ok(result)
    }

    /// Names the actual immutable visitor closure and both returned DATA views.
    ///
    /// The caller admits this defining fixed row before invoking its concrete
    /// visitor. Heap or formatting work performed by that visitor is separate.
    pub fn with_control_counter_scratch_data<T, F>() -> usize
    where
        F: FnOnce(&PacketDecodedCaptureFutureControlData) -> Result<T, ProviderError>,
    {
        Self::counter_scratch_data()
            + size_of::<F>()
            + size_of::<T>()
            + size_of::<Result<T, ProviderError>>()
            + size_of::<Result<T, RuntimeError>>()
    }

    /// Lends the real decoded input to a separately funded prospective visitor.
    ///
    /// The callback returns immutable facts only, with no observer, native effect
    /// or escaped Source/owner loan. Origin is fenced on both callback outcomes.
    ///
    /// # Errors
    /// Refuses incomplete/failed custody, changed source/input or visitor failure.
    pub fn with_control_data<T>(
        &mut self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
        visitor: impl FnOnce(&PacketDecodedCaptureFutureControlData) -> Result<T, ProviderError>,
    ) -> Result<T, RuntimeError> {
        let owner = self.original_owner(input)?;
        if !owner.control_complete {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.failed = true;
        let owner = self.owners.first().ok_or(RuntimeError::OwnerUnavailable)?;
        let journal = owner
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let bytes = owner
            .source
            .content()
            .get(&journal.native_control)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let control = owner
            .control
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        control
            .authenticate_body_data(&journal.native_control, bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let result = visitor(control);
        input.authenticate_origin_data()?;
        let result = result.map_err(|_| RuntimeError::ResourceLimit)?;
        self.failed = false;
        Ok(result)
    }

    /// Counts every actual reserved slot and initialized parser child.
    ///
    /// Enclosing Source/archive/factory owners remain separate outer census terms.
    ///
    /// # Errors
    /// Refuses foreign actor, arithmetic/layout failure or actual bound excess.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.actor()?;
        let mut total = self
            .owners
            .capacity()
            .checked_mul(size_of::<Owner>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for owner in &self.owners {
            owner.source.authenticate_birth()?;
            if let Some(journal) = &owner.journal {
                total = checked_sum(&[total, journal.retained_requested_storage_data(maximum)?])?;
            }
            if let Some(geometry) = &owner.geometry {
                let backing = geometry
                    .retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?
                    .checked_sub(GeometryAttempt::header_requested_bytes_data())
                    .ok_or(RuntimeError::ResourceLimit)?;
                total = checked_sum(&[total, backing])?;
            }
            if let Some(control) = &owner.control {
                let backing = control
                    .retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?
                    .checked_sub(
                        PacketDecodedCaptureFutureControlData::header_requested_bytes_data(),
                    )
                    .ok_or(RuntimeError::ResourceLimit)?;
                total = checked_sum(&[total, backing])?;
            }
        }
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    fn original_owner(
        &self,
        input: &CompleteInitial15PrebirthControlInput<'_>,
    ) -> Result<&Owner, RuntimeError> {
        self.actor()?;
        input.authenticate_origin_data()?;
        let owner = self.owners.first().ok_or(RuntimeError::OwnerUnavailable)?;
        if self.failed
            || self.owners.len() != 1
            || !owner.journal_complete
            || !Rc::ptr_eq(&owner.source, &input.ticket.source)
            || owner.owner_index != input.ticket.owner_index
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(owner)
    }

    fn actor(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl Default for CompleteInitial15PrebirthControlAttempt {
    fn default() -> Self {
        Self::new()
    }
}

fn authenticate_row(
    input: &CompleteInitial15PrebirthControlInput<'_>,
    row: &CompleteInitial15PrebirthControlConstructionData,
    work: Work,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    input.authenticate_origin_data()?;
    if row.work != work
        || !std::ptr::eq(row.source, input.ticket.source.as_ref())
        || row.owner_index != input.ticket.owner_index
        || !std::ptr::eq(row.reference, reference)
        || row.body != *blake3::hash(bytes).as_bytes()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn checked_sum(terms: &[usize]) -> Result<usize, RuntimeError> {
    terms.iter().try_fold(0usize, |sum, term| {
        sum.checked_add(*term).ok_or(RuntimeError::ResourceLimit)
    })
}

fn ensure_row(
    prior: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<(), RuntimeError> {
    if checked_sum(&[prior, retained, transient, scratch])? > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}
