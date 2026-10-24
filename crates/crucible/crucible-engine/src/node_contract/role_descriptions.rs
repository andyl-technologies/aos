//! Immutable role semantics projected from admitted bindings and actual models.
//!
//! These process-local values describe a realized role. They contain no operation
//! admission, live owner authority, readiness token or alternate mutation path.
//! A selected profile reference binds the complete specification; the typed
//! fields expose its concrete architectural, service or timing parameters.

use crucible_node_format::{
    BindingCompatibility, ContentRef, Endpoint, Id, NodeBinding, NodeDescriptor, SchemaRef,
};

use super::{Refusal, RoleDescription};

/// Borrows the admitted role and its complete durable semantic context.
#[derive(Clone, Copy, Debug)]
pub struct RoleDeclaration<'a> {
    /// Names the exact role present in the original descriptor roster.
    pub role: &'a Id,
    /// Borrows the immutable logical model, parameters, initialization and ports.
    pub descriptor: &'a NodeDescriptor,
    /// Borrows the selected profile, operating contract, owners and guarantees.
    ///
    /// This durable projection excludes the live authority portion of a binding.
    pub binding: &'a BindingCompatibility,
}

impl RoleDeclaration<'_> {
    /// Returns the actual complete selected profile's content reference.
    pub fn profile_ref(&self) -> &ContentRef {
        &self.binding.profile_ref
    }
}

/// Describes one architectural processor without prescribing its timing model.
#[derive(Clone, Copy, Debug)]
pub struct ProcessorDescription<'a> {
    /// Names the processor in the selected machine's immutable topology.
    pub id: &'a Id,
    /// Identifies the selected architectural instruction-set contract.
    pub architecture: &'a Id,
    /// Binds complete architectural features and processor clock semantics.
    pub configuration_ref: &'a ContentRef,
}

/// Describes a selected architectural clock domain without a retirement-rate assumption.
#[derive(Clone, Copy, Debug)]
pub struct ClockDomainDescription<'a> {
    /// Names the original domain in the selected machine topology.
    pub id: &'a Id,
    /// Supplies the period numerator in shared picoseconds.
    pub period_ps_numerator: std::num::NonZeroU64,
    /// Supplies the exact period's positive denominator.
    pub period_denominator: std::num::NonZeroU64,
}

/// Describes a compute topology and its admitted observation schemas.
#[derive(Clone, Copy, Debug)]
pub struct ComputeDescription<'a> {
    /// Retains the original compute role and complete selected machine profile.
    pub declaration: RoleDeclaration<'a>,
    /// Lists actual architectural processors from the selected source topology.
    pub processors: &'a [ProcessorDescription<'a>],
    /// Lists actual selected architectural clock domains independently of CPU cost.
    pub clocks: &'a [ClockDomainDescription<'a>],
    /// Lists the explicitly selected architectural observation interfaces.
    pub observation_schemas: &'a [SchemaRef],
}

/// Identifies a command recognized by the block service protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    /// Reads bytes from the selected media view.
    Read,
    /// Writes bytes according to the selected durability contract.
    Write,
    /// Flushes under the selected persistence ordering and completion contract.
    Flush,
    /// Queries the exposed media length.
    GetLength,
    /// Discards a range subject to the selected alignment and readback contract.
    Discard,
}

/// States the persistence stage required for a normal write completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionDurability {
    /// Completion can precede admission to volatile cache or media.
    ControllerAccepted,
    /// Completion can precede persistence of volatile cached bytes.
    VolatileCacheAccepted,
    /// Completion requires persistence according to the selected native contract.
    Durable,
}

/// States the selected readback rule for a successful discard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscardReadback {
    /// Discarded ranges read as zero.
    Zero,
    /// Discarded ranges retain their prior logical bytes.
    PreviousBytes,
    /// Discarded ranges use deterministic device/request-keyed bytes.
    RequestKeyedBytes,
}

/// Describes which object owns mutable media bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStorageOwnership {
    /// Owns a private copy-on-write overlay over a content-pinned read-only base.
    PinnedBasePrivateCopyOnWrite,
}

/// Describes deterministic block response costs without a host timing term.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockLatencyDescription {
    /// Supplies the read floor in modeled nanoseconds.
    pub read_base_ns: u64,
    /// Supplies the write/discard floor in modeled nanoseconds.
    pub write_base_ns: u64,
    /// Supplies the flush cost in modeled nanoseconds.
    pub flush_ns: u64,
    /// Supplies the length-query cost in modeled nanoseconds.
    pub get_length_ns: u64,
    /// Supplies the additional read/write cost per byte in modeled nanoseconds.
    pub per_byte_ns: u64,
}

/// Describes actual block geometry, private media ownership and completion rules.
#[derive(Clone, Copy, Debug)]
pub struct BlockDescription<'a> {
    /// Retains the original role, selected profile and complete port contracts.
    pub declaration: RoleDeclaration<'a>,
    /// Identifies the immutable base bytes by their BLAKE3 hash.
    pub base_hash: [u8; 32],
    /// Reports the actual immutable base extent in bytes.
    pub length_bytes: u64,
    /// Reports actual mutable-media ownership without implying snapshot permissions.
    pub storage_ownership: BlockStorageOwnership,
    /// Reports the protocol's byte-addressing unit, independently of atomic writes.
    pub address_unit_bytes: u32,
    /// Lists recognized protocol commands; each remains subject to admission.
    pub operations: &'a [BlockOperation],
    /// Bounds one read response's payload by the actual transport frame geometry.
    pub maximum_read_reply_bytes: usize,
    /// Bounds a request according to the selected native durability configuration.
    pub maximum_request_bytes: u64,
    /// Reports the native independently applied write-fragment size.
    pub atomic_write_bytes: u32,
    /// Reports discard alignment; zero retains the native unsupported declaration.
    pub discard_granularity_bytes: u32,
    /// Reports native successful-discard readback semantics.
    pub discard_readback: DiscardReadback,
    /// Bounds bytes that can reside in volatile cache.
    pub volatile_cache_bytes: u64,
    /// Bounds bytes accepted by the controller before cache/media admission.
    pub controller_buffer_bytes: u64,
    /// Reports the actual normal completion stage, without inferring flush durability.
    pub completion_durability: CompletionDurability,
    /// Reports deterministic response timing from the actual model.
    pub latency: BlockLatencyDescription,
}

/// Describes deterministic filesystem response costs without host timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemLatencyDescription {
    /// Supplies the metadata/control floor in modeled nanoseconds.
    pub control_ns: u64,
    /// Supplies the read/readdir floor in modeled nanoseconds.
    pub data_ns: u64,
    /// Supplies the additional cost per encoded frame byte in modeled nanoseconds.
    pub per_byte_ns: u64,
}

/// Identifies a request handled by the selected read-only 9p dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemOperation {
    /// Negotiates the dialect and session message bound.
    Version,
    /// Attaches a fid to the namespace root.
    Attach,
    /// Walks within the pinned namespace.
    Walk,
    /// Opens a fid for reading.
    OpenRead,
    /// Reads immutable file data.
    Read,
    /// Enumerates directories in deterministic order.
    ReadDirectory,
    /// Reads fixed namespace attributes.
    GetAttributes,
    /// Reads an immutable symbolic-link target.
    ReadLink,
    /// Reads filesystem bounds.
    StatFilesystem,
    /// Releases a fid.
    Clunk,
    /// Acknowledges a flush in the synchronous request service.
    Flush,
    /// Walks an extended-attribute fid under the selected dialect.
    WalkExtendedAttribute,
    /// Acknowledges synchronization of the read-only namespace.
    Sync,
}

/// Identifies the selected filesystem request/reply dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemDialect {
    /// Uses the finite read/control subset of 9P2000.L.
    Ninep2000L,
}

/// Describes namespace permissions independently of caller authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemPermissions {
    /// Reports fixed synthetic modes and rejects writes without authenticating users.
    FixedReadOnlyAttributes,
}

/// Describes ownership of filesystem visibility state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemVisibility {
    /// Retains original session/fid versions and replies through admitted reactions.
    OriginalSessionReplies,
}

/// Describes a pinned read-only namespace and its original session semantics.
#[derive(Clone, Copy, Debug)]
pub struct FilesystemDescription<'a> {
    /// Retains the original role and complete namespace/visibility profile.
    pub declaration: RoleDeclaration<'a>,
    /// Names the concrete wire dialect, without claiming another filesystem ABI.
    pub dialect: FilesystemDialect,
    /// Identifies the actual pinned tree's canonical bytes by their BLAKE3 hash.
    pub namespace_hash: [u8; 32],
    /// Lists the selected service's finite read/control request set.
    pub operations: &'a [FilesystemOperation],
    /// States whether namespace writes are rejected by the actual dispatcher.
    pub read_only: bool,
    /// Reports actual namespace permission handling, without inferring POSIX access checks.
    pub permissions: FilesystemPermissions,
    /// Reports original version/reply custody under the selected visibility profile.
    pub visibility: FilesystemVisibility,
    /// Reports the minimum supported session message extent.
    pub minimum_message_bytes: u32,
    /// Reports the maximum supported session message extent.
    pub maximum_message_bytes: u32,
    /// Reports the actual session's effective message extent.
    pub negotiated_message_bytes: u32,
    /// States whether a version exchange has pinned the current session bound.
    pub version_negotiated: bool,
    /// States whether a new version exchange and clunk retire fid bindings.
    pub session_scoped_fids: bool,
    /// Reports deterministic response costs from the actual model.
    pub latency: FilesystemLatencyDescription,
}

/// Describes admitted frame endpoints, latency and retained delivery ordering.
#[derive(Clone, Copy, Debug)]
pub struct NetworkLinkDescription<'a> {
    /// Retains the original link role, port features and full fault/state profile.
    pub declaration: RoleDeclaration<'a>,
    /// Borrows the actual adapter's selected ingress, when exact ingress is enrolled.
    pub input_endpoint: Option<&'a Endpoint>,
    /// Borrows the actual adapter's selected egress, when exact egress is enrolled.
    pub output_endpoint: Option<&'a Endpoint>,
    /// Reports the native configured base latency in shared picoseconds.
    pub base_latency_ps: u64,
    /// Reports the actual native latency floor, without fabricating a graph edge.
    pub latency_floor_ps: u64,
    /// Reports the native base-plus-fault latency before seeded delay transforms.
    pub effective_latency_ps: u64,
    /// Reports the current native partition policy.
    pub partitioned: bool,
    /// Reports the actual upper bound of seeded jitter delay.
    pub jitter_window_ps: u64,
    /// Reports the actual upper bound of seeded reorder delay.
    pub reorder_window_ps: u64,
    /// Borrows the native serialization rate caps in bits per modeled second.
    pub bandwidth_bits_per_second: &'a [u64],
    /// Names the actual retained delivery-key ordering.
    pub delivery_order: FrameDeliveryOrder,
}

/// Describes the native key used for deterministic frame delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDeliveryOrder {
    /// Orders by delivery coordinate, source slot and original native sequence.
    TimeSourceSequence,
}

/// Describes a visible clock's mapping from the coordinator coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockMapping {
    /// Exposes the shared picosecond coordinate without becoming its authority.
    IdentityPicoseconds,
    /// Exposes a separate rational counter with a fixed epoch and drift.
    RationalCounter {
        /// Supplies the base counter-rate numerator.
        numerator: u64,
        /// Supplies its shared-picosecond denominator.
        denominator: u64,
        /// Supplies the shared coordinate of the counter epoch.
        epoch_ps: u64,
        /// Supplies the visible counter value at that epoch.
        epoch_counter: u64,
        /// Supplies fixed drift in parts per billion.
        drift_ppb: i64,
    },
}

/// Describes explicitly implemented alarm semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockAlarms {
    /// Exposes no consumer-programmable alarm service.
    Unsupported,
    /// Retains original requests and exact rational-counter alarm reactions.
    OriginalRationalRequests {
        /// Bounds the complete original request roster without credit renewal.
        maximum_requests: usize,
    },
}

/// Describes the actual visible clock independently of coordinator authority.
#[derive(Clone, Copy, Debug)]
pub struct ClockDescription<'a> {
    /// Retains the exact admitted clock or explicitly selected extension role.
    pub declaration: RoleDeclaration<'a>,
    /// Reports the source-owned immutable coordinate-to-reading transform.
    pub mapping: ClockMapping,
    /// Reports the actual consumer alarm service, if separately selected.
    pub alarms: ClockAlarms,
    /// States that arithmetic overflow refuses instead of silently wrapping.
    pub refuses_overflow: bool,
}

/// Describes bounded controlled-process input and visibility semantics.
#[derive(Clone, Copy, Debug)]
pub struct ExternalDeviceDescription<'a> {
    /// Retains the actual external role and its complete selected native profile.
    pub declaration: RoleDeclaration<'a>,
    /// Reports the admitted coarse publication quantum in shared picoseconds.
    pub quantum_ps: u64,
    /// Reports the physical watchdog budget without using it as simulation time.
    pub host_budget_ns: u64,
    /// States whether native reactions consume retained original staged batches.
    pub original_staged_inputs: bool,
    /// States whether application-level park proves physical suspension.
    pub physical_pause: bool,
    /// States whether the actual implementation preserves native process memory.
    pub native_memory_preservation: bool,
    /// States whether restoration can rewind the original external environment.
    pub external_rewind: bool,
}

/// Checks the immutable roster and descriptor projection without granting authority.
pub(crate) fn checked_role_declaration<'a>(
    descriptor: &'a NodeDescriptor,
    binding: &'a NodeBinding,
    expected: &str,
) -> Result<RoleDeclaration<'a>, Refusal> {
    let [role] = descriptor.roles.as_slice() else {
        return Err(Refusal {
            reason: "role view requires the original single-role descriptor".into(),
        });
    };
    if role.as_str() != expected || binding.compatibility.node_id != descriptor.id {
        return Err(Refusal {
            reason: "requested role is absent from the original descriptor".into(),
        });
    }
    let descriptor_hash = descriptor.identity().map_err(|error| Refusal {
        reason: error.to_string(),
    })?;
    if descriptor_hash != binding.compatibility.descriptor_hash {
        return Err(Refusal {
            reason: "role descriptor differs from its admitted binding".into(),
        });
    }

    Ok(RoleDeclaration {
        role,
        descriptor,
        binding: &binding.compatibility,
    })
}

macro_rules! role_descriptions {
    ($($description:ident),+ $(,)?) => {
        $(impl RoleDescription for $description<'_> {
            fn declaration(&self) -> RoleDeclaration<'_> {
                self.declaration
            }

            fn role_profile(&self) -> &ContentRef {
                &self.declaration.binding.profile_ref
            }
        })+
    };
}

role_descriptions!(
    ComputeDescription,
    BlockDescription,
    FilesystemDescription,
    NetworkLinkDescription,
    ClockDescription,
    ExternalDeviceDescription
);
