//! Streams the closed projected request without constructing a parent JSON DOM.
//!
//! The private 160-byte header is big-endian: magic8/version4/reserved4,
//! task32/worker32/algorithm32/payloadLength8/payloadHash32/reserved8.
//! Payload order is the exhaustive eighteen launch fields, opaque shapes,
//! independent expected coordinator/disposition, then the actual planned record.

use super::records::record;
use super::*;
use super::{ExpectedIdentity, JobContext, RequestInput, RequestReceipt};
use crate::profile::reference_packet::control::PacketControlSelection;
use crate::profile::reference_packet::{
    coordinator::PacketNative5CoordinatorInstallation,
    service::{
        PacketConnectedSourceProgram, PacketNative5AckEmitterSelection,
        PacketNative5CaptureProfile, PacketNative5ConfirmationSelection,
        PacketNative5LaunchValidationFields, PacketNative5LaunchValidationProjection,
        PacketNative5PathSerializationData, PacketNative5ProtocolMetadataLimits,
        PacketNative5StorageLimits,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    },
};
use crate::profile::{
    client::CanonicalAckCodecMetadataExtent, handshake::Limits, reference_service::InstalledContent,
};
use crate::{
    registration::PacketCompleteAckHostRegistrationPlan,
    source_birth::derive::{ExpectedCoordinator, WorldRefusal},
};
use crucible_node_format::*;

const MAGIC: &[u8; 8] = b"CSBIN001";
pub(crate) const HEADER: usize = 160;

struct LaunchOperands {
    schema_version: u16,
    selection: PacketControlSelection,
    program: PacketConnectedSourceProgram,
    controller_pid: U64,
    controller_uid: U64,
    controller_executable: ContentRef,
    initial_coordinator: InstalledContent,
    limits: Limits,
    storage: PacketNative5StorageLimits,
    capture_profile: PacketNative5CaptureProfile,
    confirmation_selection: Option<PacketNative5ConfirmationSelection>,
    ack_emitter_selection: Option<PacketNative5AckEmitterSelection>,
    native_codec_metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    protocol_metadata_limits: Option<PacketNative5ProtocolMetadataLimits>,
    complete_restore_selection: Option<PacketNative5CompleteRestoreSelection>,
    restore_input_emitter_selection: Option<PacketNative5RestoreInputEmitterSelection>,
    capture_allocation_selection: Option<PacketNative5CaptureAllocationSelection>,
    fresh_restore_allocation_selection: Option<PacketNative5FreshRestoreAllocationSelection>,
}

record!(LaunchOperands {
    schema_version,
    selection,
    program,
    controller_pid,
    controller_uid,
    controller_executable,
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
    fresh_restore_allocation_selection
});

impl LaunchOperands {
    fn projection(
        &self,
        token_length: usize,
        path: PacketNative5PathSerializationData,
    ) -> PacketNative5LaunchValidationProjection<'_> {
        PacketNative5LaunchValidationProjection::from_parts_data(
            PacketNative5LaunchValidationFields {
                schema_version: self.schema_version,
                selection: &self.selection,
                program: &self.program,
                controller_pid: self.controller_pid,
                controller_uid: self.controller_uid,
                controller_executable: &self.controller_executable,
                initial_coordinator: &self.initial_coordinator,
                limits: &self.limits,
                storage: &self.storage,
                capture_profile: &self.capture_profile,
                confirmation_selection: self.confirmation_selection,
                ack_emitter_selection: self.ack_emitter_selection,
                native_codec_metadata_extent: self.native_codec_metadata_extent,
                protocol_metadata_limits: self.protocol_metadata_limits,
                complete_restore_selection: self.complete_restore_selection,
                restore_input_emitter_selection: self.restore_input_emitter_selection,
                capture_allocation_selection: self.capture_allocation_selection,
                fresh_restore_allocation_selection: self.fresh_restore_allocation_selection,
            },
            token_length,
            path,
        )
    }
}

enum Expected {
    Producer(PacketNative5CoordinatorInstallation),
    Reactive(PacketNative5CoordinatorInstallation),
    Deferred(WorldRefusal),
}

impl Retire for Expected {
    fn retire(&mut self) {
        match self {
            Self::Producer(value) | Self::Reactive(value) => value.retire(),
            Self::Deferred(_) => {}
        }
    }
}

impl Expected {
    fn borrowed(&self) -> ExpectedCoordinator<'_> {
        match self {
            Self::Producer(value) => ExpectedCoordinator::Producer(value),
            Self::Reactive(value) => ExpectedCoordinator::Reactive(value),
            Self::Deferred(reason) => ExpectedCoordinator::Deferred(*reason),
        }
    }
}

pub(crate) struct Request {
    pub(crate) context: JobContext,
    pub(crate) input_digest: [u8; 32],
    launch: Owned<LaunchOperands>,
    token_length: usize,
    path: PacketNative5PathSerializationData,
    expected: Owned<Expected>,
    registration: Owned<PacketCompleteAckHostRegistrationPlan>,
}

impl Request {
    pub(crate) fn derive(
        &self,
        limits: OperationalLimits,
    ) -> Result<
        crate::source_birth::derive::DerivedSourceBirth,
        crate::source_birth::derive::DerivationFailure,
    > {
        use crate::source_birth::derive::{DerivationInput, OutputLimits, derive_source_birth};
        let launch = self.launch.get().projection(self.token_length, self.path);
        derive_source_birth(
            DerivationInput {
                launch: &launch,
                expected: self.expected.get().borrowed(),
                registration: self.registration.get(),
            },
            OutputLimits {
                maximum_output_bytes: limits.maximum_output_bytes,
            },
        )
    }
}

fn payload<'a, W: Write>(
    input: &RequestInput<'a>,
    out: &mut Encoder<'a, W>,
) -> Result<(), ExportError> {
    let PacketNative5LaunchValidationFields {
        schema_version,
        selection,
        program,
        controller_pid,
        controller_uid,
        controller_executable,
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
    } = input.launch.fields_data();
    out.item()?;
    out.item()?;
    out.write_all(&schema_version.to_be_bytes())?;
    selection.encode(out)?;
    program.encode(out)?;
    out.item()?;
    out.write_all(&controller_pid.get().to_be_bytes())?;
    out.item()?;
    out.write_all(&controller_uid.get().to_be_bytes())?;
    controller_executable.encode(out)?;
    initial_coordinator.encode(out)?;
    limits.encode(out)?;
    storage.encode(out)?;
    json_copy(&capture_profile, out)?;
    json_optional(confirmation_selection, out)?;
    json_optional(ack_emitter_selection, out)?;
    json_optional(native_codec_metadata_extent, out)?;
    out.item()?;
    match protocol_metadata_limits {
        None => out.write_all(&[0])?,
        Some(value) => {
            out.write_all(&[1])?;
            out.item()?;
            out.item()?;
            out.write_all(&value.native_before_rows.get().to_be_bytes())?;
            out.item()?;
            out.write_all(&value.native_after_rows.get().to_be_bytes())?;
        }
    }
    json_optional(complete_restore_selection, out)?;
    json_optional(restore_input_emitter_selection, out)?;
    json_optional(capture_allocation_selection, out)?;
    json_optional(fresh_restore_allocation_selection, out)?;
    out.length(input.launch.token_length_data())?;
    write_path(input.launch.path_serialization_data(), out)?;
    match input.expected {
        ExpectedCoordinator::Producer(value) => {
            out.write_all(&[0])?;
            value.encode(out)?;
        }
        ExpectedCoordinator::Reactive(value) => {
            out.write_all(&[1])?;
            value.encode(out)?;
        }
        ExpectedCoordinator::Deferred(reason) => {
            out.write_all(&[2, world_tag(reason)])?;
        }
    }
    input.registration.encode(out)
}

fn json_copy<T: serde::Serialize, W: Write>(
    value: &T,
    out: &mut Encoder<'_, W>,
) -> Result<(), ExportError> {
    out.item()?;
    let mut count = super::records::Count(0);
    serde_json::to_writer(&mut count, value)?;
    out.length(count.0)?;
    serde_json::to_writer(out, value)?;
    Ok(())
}

fn json_optional<T: serde::Serialize, W: Write>(
    value: Option<T>,
    out: &mut Encoder<'_, W>,
) -> Result<(), ExportError> {
    out.item()?;
    match value {
        None => out.write_all(&[0])?,
        Some(value) => {
            out.write_all(&[1])?;
            json_copy(&value, out)?;
        }
    }
    Ok(())
}

pub(crate) fn world_tag(value: WorldRefusal) -> u8 {
    match value {
        WorldRefusal::ForeignCreatorProcess => 0,
        WorldRefusal::ForeignCreatorThread => 1,
        WorldRefusal::ProducerWorldAbsent => 2,
        WorldRefusal::ProducerCoordinatorChanged => 3,
        WorldRefusal::ReactiveForeignOwner => 4,
        WorldRefusal::ReactiveCoordinatorChanged => 5,
        WorldRefusal::AmbiguousBinding => 6,
    }
}

fn world_from_tag(value: u8) -> Result<WorldRefusal, CodecError> {
    Ok(match value {
        0 => WorldRefusal::ForeignCreatorProcess,
        1 => WorldRefusal::ForeignCreatorThread,
        2 => WorldRefusal::ProducerWorldAbsent,
        3 => WorldRefusal::ProducerCoordinatorChanged,
        4 => WorldRefusal::ReactiveForeignOwner,
        5 => WorldRefusal::ReactiveCoordinatorChanged,
        6 => WorldRefusal::AmbiguousBinding,
        _ => return Err(ProtocolFault::Edition.into()),
    })
}

fn write_path<W: Write>(
    path: PacketNative5PathSerializationData,
    out: &mut Encoder<'_, W>,
) -> Result<(), ExportError> {
    let (tag, length) = match path {
        PacketNative5PathSerializationData::QuotedUtf8 { bytes } => (0, bytes),
        PacketNative5PathSerializationData::InvalidUtf8 => (1, 0),
        PacketNative5PathSerializationData::Unrepresentable => (2, 0),
    };
    out.write_all(&[tag])?;
    out.length(length)
}

fn read_path<R: Read>(
    input: &mut Decoder<R>,
) -> Result<PacketNative5PathSerializationData, CodecError> {
    let mut tag = [0];
    input.read_exact(&mut tag)?;
    let bytes = input.length()?;
    Ok(match (tag[0], bytes) {
        (0, bytes) => PacketNative5PathSerializationData::QuotedUtf8 { bytes },
        (1, 0) => PacketNative5PathSerializationData::InvalidUtf8,
        (2, 0) => PacketNative5PathSerializationData::Unrepresentable,
        _ => return Err(ProtocolFault::Edition.into()),
    })
}

/// Emits a measured private request by two bounded borrowed passes.
///
/// The parent retains all original operands and spool custody. This writer
/// authenticates no Source/job and constructs no parent DTO or deep clone.
///
/// # Errors
/// Refuses operational wire/work bounds, changed measured output or actual I/O.
pub(crate) fn write<'a, W: Write>(
    input: RequestInput<'a>,
    writer: &mut W,
    limits: OperationalLimits,
    workspace: super::super::literal_value::LiteralWriteWorkspace<'a>,
) -> Result<RequestReceipt, ExportError> {
    let maximum = limits
        .maximum_input_bytes
        .checked_sub(HEADER)
        .ok_or(ProtocolFault::Limit)?;
    let mut measured = Encoder::new(
        io::sink(),
        maximum,
        limits.maximum_elements,
        None,
        workspace,
    );
    payload(&input, &mut measured)?;
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&1u32.to_be_bytes());
    header[16..48].copy_from_slice(&input.context.task_digest);
    header[48..80].copy_from_slice(&input.context.worker_digest);
    header[80..112].copy_from_slice(&input.context.algorithm_digest);
    header[112..120].copy_from_slice(
        &u64::try_from(measured.bytes)
            .map_err(|_| ProtocolFault::Overflow)?
            .to_be_bytes(),
    );
    header[120..152].copy_from_slice(measured.payload.finalize().as_bytes());
    writer.write_all(&header)?;
    let mut actual = Encoder::new(
        writer,
        maximum,
        limits.maximum_elements,
        Some(&header),
        measured.workspace,
    );
    payload(&input, &mut actual)?;
    if actual.bytes != measured.bytes
        || actual.work != measured.work
        || actual.payload.finalize() != measured.payload.finalize()
    {
        return Err(ProtocolFault::Digest.into());
    }
    Ok(RequestReceipt {
        context: input.context,
        input_digest: *actual.complete.finalize().as_bytes(),
        wire_bytes: actual.bytes + HEADER,
        elements: actual.work,
    })
}

pub(crate) fn read<R: Read>(
    reader: &mut R,
    limits: OperationalLimits,
    expected: ExpectedIdentity,
) -> Result<Request, CodecError> {
    if limits.maximum_input_bytes < HEADER {
        return Err(ProtocolFault::Limit.into());
    }
    let mut header = [0; HEADER];
    reader.read_exact(&mut header)?;
    if &header[..8] != MAGIC
        || &header[8..12] != 1u32.to_be_bytes().as_slice()
        || header[12..16] != [0; 4]
        || header[152..] != [0; 8]
    {
        return Err(ProtocolFault::Edition.into());
    }
    let context = JobContext {
        task_digest: array(&header, 16),
        worker_digest: array(&header, 48),
        algorithm_digest: array(&header, 80),
    };
    if context.worker_digest != expected.worker_digest
        || context.algorithm_digest != expected.algorithm_digest
    {
        return Err(ProtocolFault::Identity.into());
    }
    let bytes = usize::try_from(u64::from_be_bytes(array(&header, 112)))
        .map_err(|_| ProtocolFault::Overflow)?;
    if bytes > limits.maximum_input_bytes - HEADER {
        return Err(ProtocolFault::Limit.into());
    }
    let mut input = Decoder::new(reader, bytes, limits, &header);
    let launch = LaunchOperands::decode(&mut input)?;
    let token_length = input.length()?;
    let path = read_path(&mut input)?;
    let mut tag = [0];
    input.read_exact(&mut tag)?;
    let expected = Owned::new(match tag[0] {
        0 => Expected::Producer(
            <PacketNative5CoordinatorInstallation as Wire>::decode(&mut input)?.into_inner(),
        ),
        1 => Expected::Reactive(
            <PacketNative5CoordinatorInstallation as Wire>::decode(&mut input)?.into_inner(),
        ),
        2 => {
            input.read_exact(&mut tag)?;
            Expected::Deferred(world_from_tag(tag[0])?)
        }
        _ => return Err(ProtocolFault::Edition.into()),
    });
    let registration = PacketCompleteAckHostRegistrationPlan::decode(&mut input)?;
    if input.remaining != 0 {
        return Err(ProtocolFault::Trailing.into());
    }
    if input.payload.finalize().as_bytes() != &header[120..152] {
        return Err(ProtocolFault::Digest.into());
    }
    let input_digest = *input.complete.finalize().as_bytes();
    let mut trailing = [0];
    if input.reader.read(&mut trailing)? != 0 {
        return Err(ProtocolFault::Trailing.into());
    }
    Ok(Request {
        context,
        input_digest,
        launch,
        token_length,
        path,
        expected,
        registration,
    })
}

pub(super) fn array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0; N];
    result.copy_from_slice(&bytes[offset..offset + N]);
    result
}
