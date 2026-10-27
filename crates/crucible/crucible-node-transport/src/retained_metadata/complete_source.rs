//! Observes a closed borrowed set of actual complete Source installation owners.
//!
//! These measurements count requested retained capacities through the exhaustive
//! typed walker. They neither serialize originals nor grant installation rights.
//! Caller-owned Source holder layouts, facet enums, bank/boot owners and physical
//! tree/shared-header geometry remain separate simultaneous admission terms.

use super::*;

mod coordinator_counter;
use crate::reference_packet::connected::{PacketConnectedDefinition, PacketInputConnection};
use crate::reference_packet::{PacketEvent, PacketProgramDefinition};
pub use coordinator_counter::retained_native_coordinator_counter_scratch_data;

/// Borrows the actual one native program family retained by a Source.
pub enum RetainedCompleteSourceDefinition<'a> {
    /// Borrows the original finite producer definition.
    Program(&'a PacketProgramDefinition),
    /// Borrows the original input-reactive definition.
    Connected(&'a PacketConnectedDefinition),
}

impl RetainedCompleteSourceDefinition<'_> {
    /// Reports actual requested backing in this original native definition.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow or the finite traversal/depth limit.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::Program(value) => observer.observe(*value)?,
            Self::Connected(value) => observer.observe(*value)?,
        }
        Ok(observer.finish())
    }
}

/// Reports actual backing retained in one complete native coordinator original.
///
/// Repeated independent clones must be walked independently; shared observations
/// have no authority or alias discount. Serialized lengths are never substituted.
///
/// # Errors
/// Refuses checked arithmetic overflow or the finite traversal/depth limit.
pub fn observe_retained_native_coordinator(
    original: &PacketNative5CoordinatorInstallation,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(original)?;
    Ok(observer.finish())
}

/// Appends the original coordinator's defining capacity rows to an admitted bank.
///
/// Earlier rows and every refused prefix remain retained. This shares the
/// observation roster with [`observe_retained_native_coordinator`]; the caller
/// authenticates the enclosing Source before lending this ordinary DTO.
///
/// # Errors
/// Refuses unavailable backing, exhausted rows, arithmetic overflow or the
/// unchanged ordinary component traversal and depth restrictions.
pub fn record_retained_native_coordinator_data(
    original: &PacketNative5CoordinatorInstallation,
    bank: &mut records::PacketRuntimeMetadataRecordBank,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::appending(bank.recording_bank_data()?);
    observer.observe(original)?;
    Ok(observer.finish())
}

/// Reports actual backing retained by one original typed native launch.
///
/// The enclosing launch header or array is excluded. Independently retained
/// encoded launch bytes, private boot data, Source holders and observation
/// scratch remain separate owning terms. This counts private token and path
/// capacities without serializing or exposing their contents.
///
/// # Errors
/// Refuses checked arithmetic overflow or the finite traversal/depth limit.
pub fn observe_retained_native_launch(
    original: &crate::reference_packet::service::PacketNative5SourceLaunch,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observe_native_launch_into(original, &mut observer)?;
    Ok(observer.finish())
}

/// Appends one original launch's actual child capacities to an admitted bank.
///
/// The defining walk is shared with [`observe_retained_native_launch`]. Existing
/// rows and refused prefixes remain retained. The enclosing tuple allocation and
/// creator authentication belong to the caller; this DATA grants no launch right.
///
/// # Errors
/// Refuses unavailable bank backing, exhausted rows, checked arithmetic overflow
/// or the unchanged ordinary component traversal and depth restrictions.
pub fn record_retained_native_launch_data(
    original: &crate::reference_packet::service::PacketNative5SourceLaunch,
    bank: &mut records::PacketRuntimeMetadataRecordBank,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::appending(bank.recording_bank_data()?);
    observe_native_launch_into(original, &mut observer)?;
    Ok(observer.finish())
}

/// Walks the same exhaustive launch roster in its caller's retained population scope.
pub(super) fn observe_native_launch_into(
    original: &crate::reference_packet::service::PacketNative5SourceLaunch,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::{
        PacketConnectedSourceProgram, PacketNative5SourceLaunch, PacketNative5StorageLimits,
    };

    let PacketNative5SourceLaunch {
        schema_version,
        selection,
        program,
        controller_pid,
        controller_uid,
        controller_executable,
        admission_token,
        initial_coordinator,
        limits,
        storage,
        capture_profile,
        confirmation_selection,
        ack_emitter_selection,
        native_codec_metadata_extent,
        protocol_metadata_limits,
        complete_restore_selection,
        restore_input_emitter_selection,
        capture_allocation_selection,
        fresh_restore_allocation_selection,
        effects,
    } = original;
    observer.observe(schema_version)?;
    observer.observe(selection)?;
    match program {
        PacketConnectedSourceProgram::Producer { program } => observer.observe(program)?,
        PacketConnectedSourceProgram::Reactive { program } => observer.observe(program)?,
    }
    observer.observe(controller_pid)?;
    observer.observe(controller_uid)?;
    observer.observe(controller_executable)?;
    observer.observe(admission_token)?;
    observer.observe(initial_coordinator)?;
    observer.observe(limits)?;

    let PacketNative5StorageLimits {
        snapshot_bytes,
        control_snapshot_bytes,
        protocol_snapshot_bytes,
        frame_bank_bytes,
        frames_per_direction,
        hello_bytes,
        settlement_bytes,
    } = storage;
    observer.observe(snapshot_bytes)?;
    observer.observe(control_snapshot_bytes)?;
    observer.observe(protocol_snapshot_bytes)?;
    observer.observe(frame_bank_bytes)?;
    observer.observe(frames_per_direction)?;
    observer.observe(hello_bytes)?;
    observer.observe(settlement_bytes)?;

    observer.observe(capture_profile)?;
    observer.observe(confirmation_selection)?;
    observer.observe(ack_emitter_selection)?;
    observer.observe(native_codec_metadata_extent)?;
    observer.observe(protocol_metadata_limits)?;
    observer.observe(complete_restore_selection)?;
    observer.observe(restore_input_emitter_selection)?;
    observer.observe(capture_allocation_selection)?;
    observer.observe(fresh_restore_allocation_selection)?;
    // PathBuf exposes the real native OsString backing capacity. A lossy or
    // serialized path length would omit its separately retained spare storage.
    observer.vector::<u8>(effects.capacity())?;
    Ok(())
}

/// Borrows the closed actual contract/provider owners in a complete installation.
///
/// References must point to the caller's retained originals. Facts are data only;
/// the caller authenticates origin/current custody and admits simultaneous banks.
pub struct RetainedCompleteSourceMetadata<'a> {
    /// Borrows the original provider declaration.
    pub provider: &'a ProviderManifest,
    /// Borrows the selected node manifest.
    pub manifest: &'a NodeManifest,
    /// Borrows the original node descriptor.
    pub descriptor: &'a NodeDescriptor,
    /// Borrows the complete original node binding.
    pub binding: &'a NodeBinding,
    /// Borrows the selected capability profile.
    pub capabilities: &'a CapabilityProfile,
    /// Borrows the selected operation facet.
    pub facet: &'a FacetSelection,
    /// Borrows the selected guarantee profile.
    pub guarantees: &'a GuaranteeProfile,
    /// Borrows the complete original owner binding.
    pub owner: &'a OwnerBinding,
    /// Borrows the original realization request.
    pub realize: &'a RealizeRequest,
    /// Borrows the original admission identifier.
    pub admission: &'a Id,
    /// Borrows the original transaction identifier.
    pub transaction: &'a Id,
    /// Borrows the original physical gate identifier.
    pub gate: &'a Id,
    /// Borrows the actual original admission receipt reference.
    pub admission_receipt: &'a ContentRef,
    /// Borrows the complete world binding.
    pub world: &'a HashRef,
    /// Borrows the installed receipt schema.
    pub receipt_schema: &'a SchemaRef,
    /// Borrows the original operating contract.
    pub operating_contract: &'a OperatingContract,
    /// Borrows the complete native coordinator installation.
    pub coordinator: &'a PacketNative5CoordinatorInstallation,
    /// Borrows the original producer or reactive definition, without cloning it.
    pub definition: RetainedCompleteSourceDefinition<'a>,
}

impl RetainedCompleteSourceMetadata<'_> {
    /// Walks actual retained containers and reports their requested layout facts.
    ///
    /// No encoded length, public ceiling, caller callback or shared-owner label
    /// substitutes for the actual String/Vec/tree fields visited by this walk.
    /// Repeated actual fields remain conservatively counted on every view.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow or the finite traversal/depth limit.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Appends this actual borrowed component to a separately admitted bank.
    ///
    /// Existing rows are preserved. The caller authenticates Source custody and
    /// the complete object; this DATA walk grants no action or traversal rights.
    ///
    /// # Errors
    /// Refuses unready backing, exhausted rows, arithmetic overflow or the
    /// unchanged ordinary component traversal/depth restriction. Refusal retains
    /// every initialized prefix and its actual backing.
    pub fn record_retained_metadata_data(
        &self,
        bank: &mut records::PacketRuntimeMetadataRecordBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::appending(bank.recording_bank_data()?);
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names actual component observer, bank loan and result controls.
    ///
    /// Physical frames, encoding and Source custody require separate admission.
    pub fn recording_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<&mut records::PacketRuntimeMetadataRecordBank>()
            + size_of::<Result<&mut records::MetadataRecordBank, ProviderError>>()
    }

    fn observe_into(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            provider,
            manifest,
            descriptor,
            binding,
            capabilities,
            facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world,
            receipt_schema,
            operating_contract,
            coordinator,
            definition,
        } = self;
        observer.observe(*provider)?;
        observer.observe(*manifest)?;
        observer.observe(*descriptor)?;
        observer.observe(*binding)?;
        observer.observe(*capabilities)?;
        observer.observe(*facet)?;
        observer.observe(*guarantees)?;
        observer.observe(*owner)?;
        observer.observe(*realize)?;
        observer.observe(*admission)?;
        observer.observe(*transaction)?;
        observer.observe(*gate)?;
        observer.observe(*admission_receipt)?;
        observer.observe(*world)?;
        observer.observe(*receipt_schema)?;
        observer.observe(*operating_contract)?;
        observer.observe(*coordinator)?;
        match definition {
            RetainedCompleteSourceDefinition::Program(value) => observer.observe(*value)?,
            RetainedCompleteSourceDefinition::Connected(value) => observer.observe(*value)?,
        }
        Ok(())
    }
}

fields!(
    CapabilityProfile,
    schema_version,
    facets,
    devices_ref,
    requirements_ref,
    extensions
);
fields!(
    GuaranteeProfile,
    schema_version,
    repeatability,
    capture_scope,
    continuation,
    durable_restart,
    isolated_fork,
    conditional_replay,
    limitations_ref,
    extensions
);
fields!(PacketProgramDefinition, schema, events);
fields!(PacketEvent, id, evaluation, completion, payload);
fields!(PacketConnectedDefinition, schema, connections, output);
fields!(
    PacketInputConnection,
    id,
    policy,
    producer,
    consumer,
    delay_ps
);
fields!(Position, time_ps, microstep, phase);
fields!(Endpoint, node_id, port_id, lane_id);

impl ObserveMetadata for Phase {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::BoundaryControl | Self::Publication | Self::Delivery | Self::Reaction => Ok(()),
        }
    }
}
impl ObserveMetadata for Repeatability {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Qualified | Self::Nondeterministic | Self::Unqualified => Ok(()),
        }
    }
}
impl ObserveMetadata for CaptureScope {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::CompleteModel | Self::Architectural | Self::None => Ok(()),
        }
    }
}
impl ObserveMetadata for Continuation {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Exact | Self::BestEffort | Self::Unsupported => Ok(()),
        }
    }
}

/// Names the defining typed launch observation headers before its borrowed walk.
///
/// The count excludes the separately admitted launch clone, raw encoded bank,
/// nested requested backing and Source holder. It allocates nothing and grants
/// neither launch, clone nor capture permission.
pub fn retained_native_launch_counter_scratch_data() -> usize {
    use crate::reference_packet::service::{PacketNative5SourceLaunch, PacketNative5StorageLimits};
    use std::mem::size_of;

    size_of::<&PacketNative5SourceLaunch>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<&mut records::PacketRuntimeMetadataRecordBank>()
        + size_of::<Result<&mut records::MetadataRecordBank, ProviderError>>()
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&PacketProgramDefinition>()
        + size_of::<&PacketConnectedDefinition>()
        + native_launch_field_view_bytes(|original: &'static PacketNative5SourceLaunch| {
            let PacketNative5SourceLaunch {
                schema_version,
                selection,
                program,
                controller_pid,
                controller_uid,
                controller_executable,
                admission_token,
                initial_coordinator,
                limits,
                storage,
                capture_profile,
                confirmation_selection,
                ack_emitter_selection,
                native_codec_metadata_extent,
                protocol_metadata_limits,
                complete_restore_selection,
                restore_input_emitter_selection,
                capture_allocation_selection,
                fresh_restore_allocation_selection,
                effects,
            } = original;
            (
                (
                    schema_version,
                    selection,
                    program,
                    controller_pid,
                    controller_uid,
                    controller_executable,
                ),
                (
                    admission_token,
                    initial_coordinator,
                    limits,
                    storage,
                    capture_profile,
                    confirmation_selection,
                ),
                (
                    ack_emitter_selection,
                    native_codec_metadata_extent,
                    protocol_metadata_limits,
                    complete_restore_selection,
                ),
                (
                    restore_input_emitter_selection,
                    capture_allocation_selection,
                    fresh_restore_allocation_selection,
                    effects,
                ),
            )
        })
        + native_launch_field_view_bytes(|original: &'static PacketNative5SourceLaunch| {
            let PacketNative5StorageLimits {
                snapshot_bytes,
                control_snapshot_bytes,
                protocol_snapshot_bytes,
                frame_bank_bytes,
                frames_per_direction,
                hello_bytes,
                settlement_bytes,
            } = &original.storage;
            (
                snapshot_bytes,
                control_snapshot_bytes,
                protocol_snapshot_bytes,
                frame_bank_bytes,
                frames_per_direction,
                hello_bytes,
                settlement_bytes,
            )
        })
}

fn native_launch_field_view_bytes<T>(
    _: impl FnOnce(&'static crate::reference_packet::service::PacketNative5SourceLaunch) -> T,
) -> usize {
    std::mem::size_of::<T>()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "asserts actual retained typed capacities"
)]
mod tests {
    use super::*;

    #[test]
    fn program_metadata_uses_actual_spare_banks_and_inline_event_layout() {
        let mut schema = String::with_capacity(61);
        schema.push_str("source-owned.packet-program.v1");
        let mut payload = Vec::with_capacity(97);
        payload.extend_from_slice(b"original");
        let mut events = Vec::with_capacity(8);
        events.push(PacketEvent {
            id: Id::new("actual-event").unwrap(),
            evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(1), U64::new(1), Phase::Reaction),
            payload: Some(Bytes::new(payload)),
        });
        let definition = PacketProgramDefinition { schema, events };
        let expected_strings =
            definition.schema.capacity() + definition.events[0].id.allocated_capacity();
        let expected_vectors = definition.events.capacity() * size_of::<PacketEvent>()
            + definition.events[0]
                .payload
                .as_ref()
                .unwrap()
                .allocation_capacity();

        let mut observer = MetadataObserver::new();
        observer.observe(&definition).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.string_capacity_bytes, expected_strings);
        assert_eq!(facts.vector_capacity_bytes, expected_vectors);
        assert_eq!(facts.string_banks, 2);
        assert_eq!(facts.vector_banks, 2);
        assert_eq!(facts.tree_containers, 0);
    }
}

#[path = "complete_source/counter.rs"]
mod counter;
