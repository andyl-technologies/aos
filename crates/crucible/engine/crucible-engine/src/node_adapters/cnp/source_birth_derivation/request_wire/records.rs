//! Fences the private field order against the actual public DTO declarations.
//!
//! Every record destructure and constructor is exhaustive. A DTO field addition
//! fails compilation instead of silently omitting an exported original operand.
//! No alternate Coordinator or portable schema type is declared here.

use super::*;
use crate::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan;
use crucible_node_format::*;
use crucible_node_transport::client::CanonicalAckCodecMetadataExtent;
use crucible_node_transport::reference_packet::control::PacketControlSelection;
use crucible_node_transport::reference_packet::{
    PacketEvent, PacketProgramDefinition,
    connected::{PacketConnectedDefinition, PacketInputConnection},
    coordinator::{PacketConnectedHostSelection, PacketNative5CoordinatorInstallation},
    service::{
        PacketConnectedSourceProgram, PacketNative5AckEmitterSelection,
        PacketNative5CaptureProfile, PacketNative5ConfirmationSelection,
        PacketNative5ProtocolMetadataLimits, PacketNative5StorageLimits,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    },
};
use crucible_node_transport::{
    bodies::RealizeRequest, handshake::Limits, reference_service::InstalledContent,
};

macro_rules! record {
    ($ty:ident { $($field:ident),+ $(,)? }) => {
        impl Retire for $ty {
            fn retire(&mut self) {
                $(self.$field.retire();)+
            }
        }

        impl Wire for $ty {
            fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
                out.item()?;
                let Self { $($field),+ } = self;
                $($field.encode(out)?;)+
                Ok(())
            }

            fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
                input.item()?;
                // Every field is guarded before the next fallible field read.
                $(let $field = read_field(input)?;)+
                Ok(Owned::new(Self { $($field: $field.into_inner()),+ }))
            }
        }
    }
}

pub(super) use record;

record!(ArtifactIdentity {
    id,
    role,
    content,
    extensions
});

record!(BindingCompatibility {
    schema_version,
    node_id,
    descriptor_hash,
    implementation,
    profile_ref,
    configuration_ref,
    operating_contract,
    execution_owner,
    capture_owner,
    capabilities_ref,
    guarantees_ref,
    qualification_refs,
    extensions
});

record!(ContentRef {
    hash,
    length,
    media_type
});

record!(Endpoint {
    node_id,
    port_id,
    lane_id
});

record!(FacetSelection {
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions
});

record!(HashRef {
    algorithm,
    domain,
    digest
});

record!(ImplementationIdentity {
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions
});

record!(LaneDescriptor {
    id,
    direction,
    payload_schema,
    maximum_payload_bytes,
    maximum_pending_events,
    extensions
});

record!(Limits {
    frame_bytes,
    nesting,
    requests,
    journal_entries,
    blob_chunk_bytes
});

record!(LiveAuthority {
    schema_version,
    session_id,
    incarnation_id,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    host_receipt,
    extensions
});

record!(NodeBinding {
    compatibility,
    authority,
    extensions
});

record!(NodeBindingRef {
    node_id,
    binding_hash,
    extensions
});

record!(NodeDescriptor {
    schema_version,
    id,
    roles,
    model_ref,
    configuration_ref,
    initialization_ref,
    ports,
    extensions
});

record!(NodeManifest {
    schema_version,
    profile_id,
    roles,
    configuration_schema,
    allowed_combinations_ref,
    port_templates_ref,
    state_formats,
    operation_facets,
    extensions
});

record!(OperatingContract {
    schema_version,
    mode,
    scheduling_role,
    ordering_profile,
    policy_ref,
    resolution_ps,
    phase_ps,
    facets,
    extensions
});

record!(OwnerBinding {
    schema_version,
    owner,
    owner_roles,
    node_bindings,
    ownership_ref,
    extensions
});

record!(OwnerRef {
    id,
    participant_ids,
    state_domain_ids
});

record!(PacketConnectedDefinition {
    schema,
    connections,
    output
});

record!(PacketConnectedHostSelection {
    descriptor,
    binding,
    owner,
    prepared_token,
    initial_node
});

record!(PacketControlSelection {
    provider,
    realization,
    realize,
    prepared_token,
    admission,
    transaction,
    gate,
    world,
    admission_receipt
});

record!(PacketEvent {
    id,
    evaluation,
    completion,
    payload
});

record!(PacketInputConnection {
    id,
    policy,
    producer,
    consumer,
    delay_ps
});

record!(PacketNative5CoordinatorInstallation {
    schema,
    participants,
    host,
    template
});

record!(PacketNative5StorageLimits {
    snapshot_bytes,
    control_snapshot_bytes,
    protocol_snapshot_bytes,
    frame_bank_bytes,
    frames_per_direction,
    hello_bytes,
    settlement_bytes
});

record!(PacketProgramDefinition { schema, events });

record!(PortDescriptor {
    id,
    lanes,
    interface_id,
    features,
    configuration_ref,
    extensions
});

record!(Position {
    time_ps,
    microstep,
    phase
});

record!(ProviderManifest {
    schema_version,
    provider_id,
    implementation,
    protocol_versions,
    supported_profiles,
    extensions_supported,
    qualification_refs,
    extensions
});

record!(RealizationManifest {
    schema_version,
    realization_id,
    provider_manifest,
    descriptors,
    bindings,
    owners,
    owner_bindings,
    extensions
});

record!(RealizeRequest {
    realization_id,
    configuration,
    requested_node_ids,
    resource_limits,
    extensions
});

record!(ResourceLimits {
    cpu_budget_ns,
    memory_bytes,
    writable_bytes,
    processes,
    descriptors,
    pending_events,
    content_bytes,
    maximum_operations,
    extensions
});

record!(SchemaRef {
    id,
    version,
    definition,
    extensions
});

record!(SemanticVersion {
    major,
    minor,
    patch,
    prerelease,
    build
});

record!(ExtensionSelection {
    declaration,
    identifier,
    semantic_version,
    schema_digest
});

record!(InstalledContent { reference, bytes });

record!(PacketNative5ProtocolMetadataLimits {
    native_before_rows,
    native_after_rows
});

record!(PacketCompleteAckHostRegistrationPlan {
    connection_id,
    features,
    extensions,
    envelope_extensions
});

// Only closed Value-free enum leaves use their original serde representation.
// Literal Value or arbitrary map fields never pass through Deserialize.
macro_rules! json_leaf {
    ($($ty:ty),+ $(,)?) => {$(
        impl Wire for $ty {
            fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
                out.item()?;
                let mut count = Count(0);
                serde_json::to_writer(&mut count, self)?;
                out.length(count.0)?;
                serde_json::to_writer(out, self)?;
                Ok(())
            }

            fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
                input.item()?;
                let bytes = input.raw()?;
                Ok(Owned::new(serde_json::from_slice(&bytes)?))
            }
        }
    )+}
}

pub(super) struct Count(pub(super) usize);

impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Exhaustive unit matches reject schema additions before an enum could acquire
// an arbitrary Value that this JSON-only leaf path cannot encode faithfully.
macro_rules! unit_leaf_retirement {
    ($ty:ty, $($variant:ident),+ $(,)?) => {
        impl Retire for $ty {
            fn retire(&mut self) {
                match self { $(Self::$variant => {}),+ }
            }
        }
    }
}
unit_leaf_retirement!(Direction, Input, Output);
unit_leaf_retirement!(OperatingMode, Exact, Quantized);
unit_leaf_retirement!(SchedulingRole, Active, EventDriven, Autonomous);
unit_leaf_retirement!(Phase, BoundaryControl, Publication, Delivery, Reaction);
unit_leaf_retirement!(PacketNative5ConfirmationSelection, AfterProtocolPoll5);
unit_leaf_retirement!(PacketNative5AckEmitterSelection, CanonicalSdkBlob5);
unit_leaf_retirement!(CanonicalAckCodecMetadataExtent, CanonicalAck512KiB);
unit_leaf_retirement!(
    PacketNative5CompleteRestoreSelection,
    SourceSignedOwned11,
    SourceSignedTransfer12
);
unit_leaf_retirement!(
    PacketNative5RestoreInputEmitterSelection,
    CanonicalSdkRestoreInputs12
);
unit_leaf_retirement!(PacketNative5CaptureAllocationSelection, OriginalObserve12);
unit_leaf_retirement!(
    PacketNative5FreshRestoreAllocationSelection,
    CompletedAdmit13
);

impl Retire for PacketNative5CaptureProfile {
    fn retire(&mut self) {
        match self {
            Self::OriginalArrays6 => {}
            Self::CompactBytes7 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            }
            | Self::OwnedProtocol11 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            } => {
                // These exact scalar types fence payload-type changes as well
                // as new fields/variants. A Value needs the literal path.
                let _: &mut U64 = native_before_protocol_bytes;
                let _: &mut U64 = native_after_protocol_bytes;
                let _: &mut U64 = host_protocol_bytes;
            }
        }
    }
}

json_leaf!(
    Direction,
    OperatingMode,
    SchedulingRole,
    Phase,
    PacketNative5CaptureProfile,
    PacketNative5ConfirmationSelection,
    PacketNative5AckEmitterSelection,
    CanonicalAckCodecMetadataExtent,
    PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection,
    PacketNative5CaptureAllocationSelection,
    PacketNative5FreshRestoreAllocationSelection
);

impl Retire for PacketConnectedSourceProgram {
    fn retire(&mut self) {
        match self {
            Self::Producer { program } => program.retire(),
            Self::Reactive { program } => program.retire(),
        }
    }
}

impl Wire for PacketConnectedSourceProgram {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        match self {
            Self::Producer { program } => {
                out.write_all(&[0])?;
                program.encode(out)?;
            }
            Self::Reactive { program } => {
                out.write_all(&[1])?;
                program.encode(out)?;
            }
        }
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        let mut tag = [0];
        input.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(Owned::new(Self::Producer {
                program: PacketProgramDefinition::decode(input)?.into_inner(),
            })),
            1 => Ok(Owned::new(Self::Reactive {
                program: PacketConnectedDefinition::decode(input)?.into_inner(),
            })),
            _ => Err(ProtocolFault::Edition.into()),
        }
    }
}
