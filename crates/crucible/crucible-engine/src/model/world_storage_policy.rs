//! Closed, scenario-owned policy data consumed by storage and 9p effects.
//!
//! Storage effects use [`FaultObjectId`] values as stable references. This
//! module gives every such reference a typed, immutable meaning included in
//! the [`World`](super::World) identity. Production adapters therefore never
//! infer behavior from a string or consult host-local configuration.

use std::collections::BTreeSet;

use super::world_faults::{invalid, require};
use super::*;

/// Maximum storage-policy declarations in one World.
pub const HARD_STORAGE_POLICY_ARTIFACTS: usize = 65_536;
/// Maximum entries in one storage-policy declaration.
pub const HARD_STORAGE_POLICY_ENTRIES: usize = 65_536;
/// Maximum bytes carried by one inline storage artifact.
pub const HARD_STORAGE_POLICY_BYTES: usize = 16 * 1024 * 1024;

/// A protocol-neutral terminal storage result.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyResult {
    /// The operation completed successfully.
    Success,
    /// The device is unavailable.
    Offline,
    /// A write targeted read-only storage.
    ReadOnly,
    /// The addressed range is invalid or beyond capacity.
    InvalidRange,
    /// The controller or queue is temporarily busy.
    Busy,
    /// The operation exceeded its modeled deadline.
    Timeout,
    /// The medium reported an uncorrectable error.
    MediumError,
    /// Data-integrity verification failed.
    IntegrityError,
    /// Device or controller I/O failed without a narrower class.
    IoError,
    /// Capacity or allocation was exhausted.
    NoSpace,
    /// A requested object or namespace entry does not exist.
    NotFound,
    /// A retained handle or object version is stale.
    Stale,
}

/// Guest protocol encoding for one terminal result.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoragePolicyTypedResult {
    /// A block-device completion status.
    Block {
        /// Protocol-neutral semantic result.
        result: StoragePolicyResult,
    },
    /// A Linux 9P2000.L `Rlerror` result.
    NineP {
        /// Positive Linux errno encoded in the reply.
        errno: i32,
    },
}

/// Queue discipline for integrated storage service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicyQueueDiscipline {
    /// Oldest admitted request runs first; identity breaks equal-time ties.
    Fifo,
    /// Lowest configured class priority runs first.
    StrictPriority,
    /// Classes receive deterministic weighted round-robin service.
    WeightedRoundRobin,
}

/// One operation class used by a storage service queue.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyServiceClass {
    /// Stable class identity.
    pub class: FaultObjectId,
    /// Operations assigned to the class.
    pub operations: OperationSet,
    /// Lower values run first under strict priority.
    pub priority: u16,
    /// Positive weighted-round-robin share.
    pub weight: PositiveU64,
}

/// Complete deterministic storage service policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicyService {
    /// Queue selection discipline.
    pub discipline: StoragePolicyQueueDiscipline,
    /// Canonically class-ID-ordered operation classes.
    pub classes: Vec<StoragePolicyServiceClass>,
    /// Whether rebuild work shares the foreground byte and IOPS budgets.
    pub rebuild_shares_service: bool,
}

mod lifecycle;
mod media;

pub use lifecycle::*;
pub use media::*;

/// Closed class of storage policy artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoragePolicyArtifactClass {
    /// Guest protocol status or errno.
    TypedResult,
    /// Queue and integrated-service policy.
    Service,
    /// Multipath selection, retry, and recovery policy.
    Path,
    /// Remote-media wire and reconnect protocol.
    RemoteProtocol,
    /// Volatile-cache policy.
    Cache,
    /// Duplicate-completion guest protocol policy.
    DuplicateCompletion,
    /// Controller reset and request-epoch policy.
    ControllerTransition,
    /// Persistence dependency/order policy.
    Persistence,
    /// Flash-retention policy.
    Retention,
    /// Flash read-disturb policy.
    ReadDisturb,
    /// Flash program/erase policy.
    ProgramErase,
    /// Array member-selection policy.
    ArraySelection,
    /// Array member and path state.
    ArrayState,
    /// Array rebuild policy.
    Rebuild,
    /// Array consistency policy.
    ArrayConsistency,
    /// 9p visibility policy.
    NinePVisibility,
    /// Immutable 9p object version.
    NinePObject,
    /// Immutable byte content used by stale/versioned results.
    Bytes,
}

impl StoragePolicyArtifactClass {
    /// Returns the canonical schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedResult => "typed_result",
            Self::Service => "service",
            Self::Path => "path",
            Self::RemoteProtocol => "remote_protocol",
            Self::Cache => "cache",
            Self::DuplicateCompletion => "duplicate_completion",
            Self::ControllerTransition => "controller_transition",
            Self::Persistence => "persistence",
            Self::Retention => "retention",
            Self::ReadDisturb => "read_disturb",
            Self::ProgramErase => "program_erase",
            Self::ArraySelection => "array_selection",
            Self::ArrayState => "array_state",
            Self::Rebuild => "rebuild",
            Self::ArrayConsistency => "array_consistency",
            Self::NinePVisibility => "ninep_visibility",
            Self::NinePObject => "ninep_object",
            Self::Bytes => "bytes",
        }
    }
}

/// Typed storage policy data referenced by effects and World declarations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StoragePolicyArtifactKind {
    /// Guest-visible terminal result.
    TypedResult(StoragePolicyTypedResult),
    /// Queue and service behavior.
    Service(StoragePolicyService),
    /// Multipath selection, retry, and recovery behavior.
    Path(StoragePolicyPath),
    /// Remote-media wire and reconnect behavior.
    RemoteProtocol(StoragePolicyRemoteProtocol),
    /// Volatile write-cache behavior.
    Cache(StoragePolicyCache),
    /// Guest treatment of duplicate completions.
    DuplicateCompletion(StoragePolicyDuplicateCompletion),
    /// Complete controller reset transition.
    ControllerTransition(StoragePolicyControllerTransition),
    /// Persistence DAG behavior.
    Persistence(StoragePolicyPersistence),
    /// Flash retention behavior.
    Retention(StoragePolicyRetention),
    /// Flash read-disturb behavior.
    ReadDisturb(StoragePolicyReadDisturb),
    /// Flash program/erase behavior.
    ProgramErase(StoragePolicyProgramErase),
    /// Array read/write member selection.
    ArraySelection(StoragePolicyArraySelection),
    /// Array member and access-path states.
    ArrayState {
        /// Canonically member-ID-ordered state records.
        members: Vec<StoragePolicyArrayMemberState>,
        /// Canonically path-ID-ordered state records.
        paths: Vec<StoragePolicyArrayPathState>,
    },
    /// Array rebuild service.
    Rebuild(StoragePolicyRebuild),
    /// Array consistency behavior.
    ArrayConsistency(StoragePolicyArrayConsistency),
    /// 9p committed-versus-visible behavior.
    NinePVisibility(StoragePolicyNinePVisibility),
    /// Immutable 9p object version.
    NinePObject(StoragePolicyNinePObject),
    /// Immutable content-addressed bytes for retained values.
    Bytes {
        /// Exact bytes.
        bytes: Vec<u8>,
    },
}

impl StoragePolicyArtifactKind {
    /// Returns the closed class used for reference validation.
    #[must_use]
    pub const fn class(&self) -> StoragePolicyArtifactClass {
        match self {
            Self::TypedResult(_) => StoragePolicyArtifactClass::TypedResult,
            Self::Service(_) => StoragePolicyArtifactClass::Service,
            Self::Path(_) => StoragePolicyArtifactClass::Path,
            Self::RemoteProtocol(_) => StoragePolicyArtifactClass::RemoteProtocol,
            Self::Cache(_) => StoragePolicyArtifactClass::Cache,
            Self::DuplicateCompletion(_) => StoragePolicyArtifactClass::DuplicateCompletion,
            Self::ControllerTransition(_) => StoragePolicyArtifactClass::ControllerTransition,
            Self::Persistence(_) => StoragePolicyArtifactClass::Persistence,
            Self::Retention(_) => StoragePolicyArtifactClass::Retention,
            Self::ReadDisturb(_) => StoragePolicyArtifactClass::ReadDisturb,
            Self::ProgramErase(_) => StoragePolicyArtifactClass::ProgramErase,
            Self::ArraySelection(_) => StoragePolicyArtifactClass::ArraySelection,
            Self::ArrayState { .. } => StoragePolicyArtifactClass::ArrayState,
            Self::Rebuild(_) => StoragePolicyArtifactClass::Rebuild,
            Self::ArrayConsistency(_) => StoragePolicyArtifactClass::ArrayConsistency,
            Self::NinePVisibility(_) => StoragePolicyArtifactClass::NinePVisibility,
            Self::NinePObject(_) => StoragePolicyArtifactClass::NinePObject,
            Self::Bytes { .. } => StoragePolicyArtifactClass::Bytes,
        }
    }
}

/// One stable, scenario-owned storage policy declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldStoragePolicyArtifact {
    /// Stable reference used by effects and other policies.
    pub id: FaultObjectId,
    /// Exact semantic version; version 1 is the only accepted version.
    pub semantic_version: u16,
    /// Typed policy data.
    pub artifact: StoragePolicyArtifactKind,
}

impl WorldStoragePolicyArtifact {
    /// Validates local invariants independent of cross-artifact references.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] for unsupported versions, empty or
    /// excessive tables, malformed protocol results, or inconsistent policy
    /// parameters.
    pub(super) fn validate(&self) -> Result<(), WorldFaultTopologyError> {
        require(
            self.semantic_version == 1,
            "storage policy semantic version",
        )?;
        match &self.artifact {
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::NineP { errno }) => {
                require(*errno > 0, "storage 9p errno")
            }
            StoragePolicyArtifactKind::Service(policy) => {
                require(
                    policy.classes.len() <= HARD_STORAGE_POLICY_ENTRIES,
                    "storage service class count",
                )?;
                require(
                    policy
                        .classes
                        .windows(2)
                        .all(|pair| pair[0].class < pair[1].class),
                    "storage service class canonical identity order",
                )?;
                let operations = policy
                    .classes
                    .iter()
                    .flat_map(|class| class.operations.as_slice())
                    .copied()
                    .collect::<Vec<_>>();
                require(
                    policy
                        .classes
                        .iter()
                        .all(|class| class.operations.adapter() == FaultAdapter::Storage)
                        && operations.iter().copied().collect::<BTreeSet<_>>().len()
                            == operations.len(),
                    "storage service operation assignment",
                )?;
                if policy.discipline != StoragePolicyQueueDiscipline::Fifo {
                    require(!policy.classes.is_empty(), "storage service classes")?;
                }
                Ok(())
            }
            StoragePolicyArtifactKind::Path(policy) => require(
                policy.maximum_attempts.get() <= 65_536
                    && !policy.retry_results.is_empty()
                    && policy.retry_results.len() <= HARD_STORAGE_POLICY_ENTRIES
                    && policy
                        .retry_results
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && policy
                        .retry_results
                        .iter()
                        .all(|result| *result != StoragePolicyResult::Success),
                "storage path retry policy",
            ),
            StoragePolicyArtifactKind::RemoteProtocol(policy) => require(
                policy.maximum_outstanding.get() <= 4_194_304,
                "storage remote protocol outstanding-command bound",
            ),
            StoragePolicyArtifactKind::Retention(policy) => require(
                policy.maximum_changed_bits.get() <= 1_048_576,
                "storage retention changed-bit bound",
            ),
            StoragePolicyArtifactKind::ReadDisturb(policy) => require(
                policy.neighbor_pages.get() <= 65_536
                    && policy.maximum_changed_bits.get() <= 1_048_576,
                "storage read-disturb bound",
            ),
            StoragePolicyArtifactKind::Rebuild(policy) => require(
                policy.queue_depth.get() <= 1_048_576,
                "storage rebuild queue bound",
            ),
            StoragePolicyArtifactKind::ArrayState { members, paths } => {
                require(
                    !members.is_empty()
                        && !paths.is_empty()
                        && members.len() <= HARD_STORAGE_POLICY_ENTRIES
                        && paths.len() <= HARD_STORAGE_POLICY_ENTRIES,
                    "storage array member state count",
                )?;
                require(
                    members
                        .windows(2)
                        .all(|pair| pair[0].member < pair[1].member),
                    "storage array member state canonical identity order",
                )?;
                require(
                    paths.windows(2).all(|pair| pair[0].path < pair[1].path),
                    "storage array path state canonical identity order",
                )
            }
            StoragePolicyArtifactKind::NinePObject(object) => require(
                object.path.starts_with('/')
                    && !object.path.contains("//")
                    && !object
                        .path
                        .split('/')
                        .any(|component| component == "." || component == "..")
                    && object.version <= u64::from(u32::MAX)
                    && object.data.len() <= HARD_STORAGE_POLICY_BYTES
                    && if object.deleted {
                        object.mode == 0 && object.data.is_empty()
                    } else {
                        object.mode & 0o170_000 != 0
                    },
                "storage 9p object artifact",
            ),
            StoragePolicyArtifactKind::NinePVisibility(policy) => require(
                policy.atomic_metadata_and_data == policy.data_visibility_lag_nanos.is_none(),
                "storage 9p metadata/data visibility policy",
            ),
            StoragePolicyArtifactKind::Bytes { bytes } => require(
                !bytes.is_empty() && bytes.len() <= HARD_STORAGE_POLICY_BYTES,
                "storage inline byte artifact",
            ),
            _ => Ok(()),
        }
    }
}

pub(super) fn validate_storage_policy_reference(
    topology: &WorldFaultTopology,
    id: &FaultObjectId,
    expected: StoragePolicyArtifactClass,
    field: &'static str,
) -> Result<(), WorldFaultTopologyError> {
    let artifact = topology
        .storage_policy_artifact(id)
        .ok_or_else(|| invalid(field))?;
    require(artifact.artifact.class() == expected, field)
}

#[cfg(test)]
#[path = "world_storage_policy_test.rs"]
mod tests;
