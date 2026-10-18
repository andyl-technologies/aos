//! Fault-addressable storage declaration schemas.

use super::*;
/// Storage adapter family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldStorageKind {
    /// Deterministic block device.
    Block,
    /// Deterministic 9p filesystem endpoint.
    NineP,
}

/// Closed flush ordering contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldFlushSemantics {
    /// A flush is an ordered persistence barrier.
    OrderedBarrier,
    /// A flush drains a writeback cache at the barrier.
    WritebackBarrier,
    /// Durability is expressed through force-unit-access requests.
    ForceUnitAccess,
}

/// Closed discard-result contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldDiscardSemantics {
    /// Discarded bytes read back as zero.
    DeterministicZero,
    /// Discarded bytes retain their prior value.
    ReadsOldData,
    /// Discarded reads use a recorded deterministic result.
    UndefinedRecorded,
}

/// Closed successful-completion durability layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldCompletionDurability {
    /// Success may be reported after controller admission.
    ControllerAccepted,
    /// Success may be reported after volatile-cache admission.
    VolatileCacheAccepted,
    /// Success is reported only after durable persistence.
    Durable,
}

/// Immutable storage durability contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePersistence {
    /// Guest-visible logical block size.
    pub logical_block_bytes: u32,
    /// Physical persistence-sector size.
    pub physical_sector_bytes: u32,
    /// Smallest all-or-nothing write size.
    pub atomic_write_bytes: u32,
    /// Exact guest-visible device or namespace length.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub length_bytes: u64,
    /// Discard granularity, or zero when discard is unsupported.
    pub discard_granularity_bytes: u32,
    /// Maximum admitted request size.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub maximum_request_bytes: u64,
    /// Volatile write-cache capacity.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub volatile_cache_bytes: u64,
    /// Controller-accepted write-buffer capacity.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub controller_buffer_bytes: u64,
    /// Flush ordering contract.
    pub flush_semantics: WorldFlushSemantics,
    /// Discard readback contract.
    pub discard_semantics: WorldDiscardSemantics,
    /// Durability layer required before ordinary success completion.
    pub completion_durability: WorldCompletionDurability,
    /// Maximum volatile cache entry count.
    pub cache_entries: u32,
    /// Maximum controller-accepted write-buffer entry count.
    pub controller_entries: u32,
    /// Maximum persistence dependency edge count.
    pub persistence_dependencies: u32,
    /// Maximum retained logical versions per interval.
    pub retained_versions_per_interval: u16,
}

/// Closed storage media geometry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldStorageMedia {
    /// Flash media with erase/program geometry and finite endurance.
    Flash {
        /// Erase-block size.
        #[serde(
            deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
        )]
        erase_block_bytes: u64,
        /// Program-page size.
        program_page_bytes: u32,
        /// Rated erase cycles per block.
        #[serde(
            deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
        )]
        endurance_cycles: u64,
    },
    /// Magnetic media with sector/track geometry.
    Magnetic {
        /// Physical sector size.
        sector_bytes: u32,
        /// Track size.
        #[serde(
            deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
            serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
        )]
        track_bytes: u64,
    },
    /// Volatile or persistent RAM media.
    Ram {
        /// Page size.
        page_bytes: u32,
    },
    /// Remote media accessed through a registered protocol.
    Remote {
        /// Protocol contract ID.
        protocol: SignalId,
    },
}

impl WorldStorageMedia {
    /// Returns exact erase, program-page, and endurance geometry for flash media.
    #[must_use]
    pub const fn flash_geometry(&self) -> Option<(u64, u32, u64)> {
        match self {
            Self::Flash {
                erase_block_bytes,
                program_page_bytes,
                endurance_cycles,
            } => Some((*erase_block_bytes, *program_page_bytes, *endurance_cycles)),
            Self::Magnetic { .. } | Self::Ram { .. } | Self::Remote { .. } => None,
        }
    }
}

/// One storage node's executable durability/media declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageFaultDevice {
    /// Stable storage declaration ID.
    pub id: SignalId,
    /// Referenced block/9p world-node ID.
    pub device: SignalId,
    /// Storage adapter family.
    pub kind: WorldStorageKind,
    /// Durability contract.
    pub persistence: WorldStoragePersistence,
    /// Media geometry.
    pub media: WorldStorageMedia,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageFaultDevice {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
    pub(super) fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.persistence.logical_block_bytes.is_power_of_two()
                && (512..=65_536).contains(&self.persistence.logical_block_bytes),
            "storage logical block geometry",
        )?;
        require(
            self.persistence.physical_sector_bytes.is_power_of_two()
                && self
                    .persistence
                    .physical_sector_bytes
                    .is_multiple_of(self.persistence.logical_block_bytes),
            "storage physical sector geometry",
        )?;
        require(
            self.persistence.atomic_write_bytes > 0
                && self
                    .persistence
                    .atomic_write_bytes
                    .is_multiple_of(self.persistence.logical_block_bytes)
                && self.persistence.atomic_write_bytes <= self.persistence.physical_sector_bytes,
            "storage atomic write geometry",
        )?;
        require(
            self.persistence.length_bytes > 0
                && self
                    .persistence
                    .length_bytes
                    .is_multiple_of(u64::from(self.persistence.logical_block_bytes)),
            "storage length geometry",
        )?;
        require(
            self.persistence.discard_granularity_bytes == 0
                || (self.persistence.discard_granularity_bytes.is_power_of_two()
                    && self
                        .persistence
                        .discard_granularity_bytes
                        .is_multiple_of(self.persistence.logical_block_bytes)),
            "storage discard geometry",
        )?;
        require(
            self.persistence.maximum_request_bytes > 0
                && self.persistence.maximum_request_bytes <= self.persistence.length_bytes
                && self.persistence.maximum_request_bytes <= 67_108_864
                && self
                    .persistence
                    .maximum_request_bytes
                    .is_multiple_of(u64::from(self.persistence.logical_block_bytes)),
            "storage maximum request geometry",
        )?;
        require(
            self.persistence.volatile_cache_bytes <= 68_719_476_736
                && (self.persistence.volatile_cache_bytes == 0)
                    == (self.persistence.cache_entries == 0)
                && (self.persistence.completion_durability
                    != WorldCompletionDurability::VolatileCacheAccepted
                    || self.persistence.volatile_cache_bytes > 0),
            "storage cache byte limit",
        )?;
        require(
            self.persistence.controller_buffer_bytes <= 68_719_476_736
                && (self.persistence.controller_buffer_bytes == 0)
                    == (self.persistence.controller_entries == 0)
                && (self.persistence.completion_durability
                    != WorldCompletionDurability::ControllerAccepted
                    || self.persistence.controller_buffer_bytes > 0),
            "storage controller buffer limit",
        )?;
        require(
            self.persistence.cache_entries <= 4_194_304,
            "storage cache entry limit",
        )?;
        require(
            self.persistence.controller_entries <= 4_194_304,
            "storage controller entry limit",
        )?;
        require(
            self.persistence.persistence_dependencies <= 16_777_216,
            "storage dependency limit",
        )?;
        require(
            self.persistence.retained_versions_per_interval > 0
                && self.persistence.retained_versions_per_interval <= 1_024,
            "storage retained version limit",
        )?;
        match self.media {
            WorldStorageMedia::Flash {
                erase_block_bytes,
                program_page_bytes,
                endurance_cycles,
            } => require(
                erase_block_bytes > 0
                    && program_page_bytes > 0
                    && erase_block_bytes % u64::from(program_page_bytes) == 0
                    && endurance_cycles > 0,
                "flash geometry",
            ),
            WorldStorageMedia::Magnetic {
                sector_bytes,
                track_bytes,
            } => require(
                sector_bytes > 0 && track_bytes > 0 && track_bytes % u64::from(sector_bytes) == 0,
                "magnetic geometry",
            ),
            WorldStorageMedia::Ram { page_bytes } => {
                require(page_bytes.is_power_of_two(), "RAM media page geometry")
            }
            WorldStorageMedia::Remote { .. } => Ok(()),
        }
    }
}

/// One controller namespace bound to a deterministic storage device.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageNamespace {
    /// Stable namespace ID within its controller.
    pub id: SignalId,
    /// Referenced storage-device node ID.
    pub device: SignalId,
    /// Guest-visible namespace capacity.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub capacity_bytes: u64,
    /// Whether force-unit-access requests are accepted.
    pub supports_fua: bool,
    /// Whether discard requests are accepted.
    pub supports_discard: bool,
}
impl WorldStorageNamespace {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic path to a controller or array.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePath {
    /// Stable path ID within its owner.
    pub id: SignalId,
    /// Maximum admitted in-flight operation count.
    pub queue_depth: u32,
    /// Registered path-selection and retry policy ID.
    pub policy: SignalId,
}
impl WorldStoragePath {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic storage controller with explicit namespaces and paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageController {
    /// Stable controller ID.
    pub id: SignalId,
    /// Exact controller state-machine semantic version.
    pub semantic_version: u16,
    /// Closed namespace declarations.
    pub namespaces: Vec<WorldStorageNamespace>,
    /// Closed access-path declarations.
    pub paths: Vec<WorldStoragePath>,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageController {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// Closed storage-array layout family.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldStorageArrayLayout {
    /// Replicates each logical range across members.
    Mirror,
    /// Stripes logical ranges without parity.
    Stripe,
    /// Uses single distributed parity.
    SingleParity,
    /// Uses dual distributed parity.
    DualParity,
}

/// One member of a deterministic storage array.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageArrayMember {
    /// Stable member ID within its array.
    pub id: SignalId,
    /// Referenced storage-device node ID.
    pub device: SignalId,
    /// Stable member position used by parity and selection rules.
    pub ordinal: u16,
}
impl WorldStorageArrayMember {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}

/// One deterministic storage array with explicit members, paths, and quorums.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStorageArray {
    /// Stable array ID.
    pub id: SignalId,
    /// Guest-visible logical block-device node backed by this array.
    pub device: SignalId,
    /// Exact array state-machine and parity semantic version.
    pub semantic_version: u16,
    /// Array layout.
    pub layout: WorldStorageArrayLayout,
    /// Stripe chunk size.
    #[serde(
        deserialize_with = "super::super::toml::deserialize_u64_toml_number_or_string",
        serialize_with = "super::super::toml::serialize_u64_toml_number_or_string"
    )]
    pub chunk_bytes: u64,
    /// Minimum members required for a read.
    pub read_quorum: u16,
    /// Minimum members required for a write.
    pub write_quorum: u16,
    /// Closed member declarations.
    pub members: Vec<WorldStorageArrayMember>,
    /// Closed multipath declarations.
    pub paths: Vec<WorldStoragePath>,
    /// Complete baseline member/path online-state artifact.
    pub member_path_state: FaultObjectId,
    /// Baseline deterministic member-selection artifact.
    pub selection_policy: FaultObjectId,
    /// Baseline bounded rebuild-service artifact.
    pub rebuild_service: FaultObjectId,
    /// Baseline partial-update consistency artifact.
    pub consistency_policy: FaultObjectId,
    /// Baseline typed non-success result for unavailable quorum.
    pub failure_result: FaultObjectId,
    /// Fault-domain memberships.
    pub fault_domains: Vec<SignalId>,
}
impl WorldStorageArray {
    pub(super) const fn id(&self) -> &SignalId {
        &self.id
    }
}
