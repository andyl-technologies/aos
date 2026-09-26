//! Immutable executor capabilities and volatile capacity reports.
//!
//! The component formats deliberately keep compatibility facts separate from
//! daemon-epoch-scoped availability:
//!
//! ```text
//! ExecutorDescriptionV1 = version | daemon_epoch | immutable_capabilities
//! ExecutorCapacityReportV1 = version | daemon_epoch | capability_digest |
//!                            sequence | available_slots | available_resources |
//!                            materialization_locality
//! ```

use std::collections::BTreeSet;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::validate_identifier;
use crate::{
    AttemptResourceLimits, CampaignCodecError, CampaignHash, ConfigurationArtifactId, DaemonEpoch,
    ExecutorCompatibilityProfile, ExecutorService, MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
};

const EXECUTOR_CAPABILITY_SCHEMA_VERSION: u32 = 1;
const MAX_QEMU_PROFILES: usize = 32;
const MAX_STORE_NAMESPACES: usize = 64;
const MAX_MATERIALIZATION_LOCALITIES: usize = 64;

/// Empty versioned request for immutable executor facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescribeExecutorRequest {
    schema_version: u32,
}

impl DescribeExecutorRequest {
    /// Builds the current `DescribeExecutor` request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            schema_version: EXECUTOR_CAPABILITY_SCHEMA_VERSION,
        }
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        codec::encode(&self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_capability_message(bytes, "describe-executor-request-encoded-bytes")
    }
}

impl Default for DescribeExecutorRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl Canonical for DescribeExecutorRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_capability_version(u32::decode(decoder)?)?;
        Ok(Self::new())
    }
}

/// One materialization path supported by an executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutorMaterializationCapability {
    /// Reconstructs a configuration by deterministic replay.
    ThinReplay,
    /// Restores an authenticated exact closure.
    ExactRestore,
    /// Clones a QEMU-owned quiescent template through the public fork protocol.
    HotFork,
}

impl Canonical for ExecutorMaterializationCapability {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::ThinReplay => 0,
            Self::ExactRestore => 1,
            Self::HotFork => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ThinReplay),
            1 => Ok(Self::ExactRestore),
            2 => Ok(Self::HotFork),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "executor-materialization-capability",
                tag,
            }),
        }
    }
}

/// Immutable compatibility and configured ceiling facts for one executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorCapabilitySet {
    compatibility: ExecutorCompatibilityProfile,
    host_architecture: String,
    qemu_profiles: BTreeSet<String>,
    materialization: BTreeSet<ExecutorMaterializationCapability>,
    maximum_slots: u32,
    resource_ceiling: AttemptResourceLimits,
    store_namespaces: BTreeSet<CampaignHash>,
}

impl ExecutorCapabilitySet {
    /// Builds one immutable executor capability set.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when identifiers or sets are empty,
    /// oversized, or noncanonical, when no thin-replay fallback is admitted,
    /// or when the configured slot ceiling is zero.
    pub fn new(
        compatibility: ExecutorCompatibilityProfile,
        host_architecture: impl Into<String>,
        qemu_profiles: BTreeSet<String>,
        materialization: BTreeSet<ExecutorMaterializationCapability>,
        maximum_slots: u32,
        resource_ceiling: AttemptResourceLimits,
        store_namespaces: BTreeSet<CampaignHash>,
    ) -> Result<Self, CampaignCodecError> {
        let host_architecture = host_architecture.into();
        validate_identifier(&host_architecture, "executor host architecture is invalid")?;
        if qemu_profiles.is_empty() || qemu_profiles.len() > MAX_QEMU_PROFILES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor QEMU profile set is empty or oversized",
            });
        }
        for profile in &qemu_profiles {
            validate_identifier(profile, "executor QEMU profile is invalid")?;
        }
        if !materialization.contains(&ExecutorMaterializationCapability::ThinReplay) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor has no thin-replay correctness fallback",
            });
        }
        if maximum_slots == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor maximum slot count is zero",
            });
        }
        if store_namespaces.is_empty() || store_namespaces.len() > MAX_STORE_NAMESPACES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor store-namespace set is empty or oversized",
            });
        }
        let value = Self {
            compatibility,
            host_architecture,
            qemu_profiles,
            materialization,
            maximum_slots,
            resource_ceiling,
            store_namespaces,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
            "executor-capability-set-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the exact lineage compatibility profile.
    #[must_use]
    pub const fn compatibility(&self) -> &ExecutorCompatibilityProfile {
        &self.compatibility
    }

    /// Returns the canonical host architecture identifier.
    #[must_use]
    pub fn host_architecture(&self) -> &str {
        &self.host_architecture
    }

    /// Returns the admitted deterministic QEMU launch profiles.
    #[must_use]
    pub const fn qemu_profiles(&self) -> &BTreeSet<String> {
        &self.qemu_profiles
    }

    /// Returns the supported realization paths.
    #[must_use]
    pub const fn materialization(&self) -> &BTreeSet<ExecutorMaterializationCapability> {
        &self.materialization
    }

    /// Returns the configured concurrent-attempt ceiling.
    #[must_use]
    pub const fn maximum_slots(&self) -> u32 {
        self.maximum_slots
    }

    /// Returns the maximum resources accepted for one attempt.
    #[must_use]
    pub const fn resource_ceiling(&self) -> AttemptResourceLimits {
        self.resource_ceiling
    }

    /// Returns the reachable immutable-store namespaces.
    #[must_use]
    pub const fn store_namespaces(&self) -> &BTreeSet<CampaignHash> {
        &self.store_namespaces
    }

    /// Returns the domain-separated digest bound into volatile reports.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive("crucible.executor-capability-set.v1", &codec::encode(self))
    }
}

impl Canonical for ExecutorCapabilitySet {
    fn encode(&self, encoder: &mut Encoder) {
        self.compatibility.encode(encoder);
        self.host_architecture.encode(encoder);
        self.qemu_profiles.encode(encoder);
        self.materialization.encode(encoder);
        self.maximum_slots.encode(encoder);
        self.resource_ceiling.encode(encoder);
        self.store_namespaces.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ExecutorCompatibilityProfile::decode(decoder)?,
            String::decode(decoder)?,
            decoder.set_bounded(MAX_QEMU_PROFILES, "executor-qemu-profile-count")?,
            decoder.set_bounded(3, "executor-materialization-capability-count")?,
            u32::decode(decoder)?,
            AttemptResourceLimits::decode(decoder)?,
            decoder.set_bounded(MAX_STORE_NAMESPACES, "executor-store-namespace-count")?,
        )
    }
}

/// `DescribeExecutor` response with immutable facts separated from daemon identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorDescription {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    capabilities: ExecutorCapabilitySet,
}

impl ExecutorDescription {
    /// Builds one bounded executor description.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the complete component message
    /// exceeds the executor control-plane bound.
    pub fn new(
        daemon_epoch: DaemonEpoch,
        capabilities: ExecutorCapabilitySet,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            schema_version: EXECUTOR_CAPABILITY_SCHEMA_VERSION,
            daemon_epoch,
            capabilities,
        };
        ensure_capability_message_size(&value, "executor-description-encoded-bytes")?;
        Ok(value)
    }

    /// Returns the daemon incarnation described by this response.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the immutable capability set.
    #[must_use]
    pub const fn capabilities(&self) -> &ExecutorCapabilitySet {
        &self.capabilities
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_capability_message(bytes, "executor-description-encoded-bytes")
    }
}

impl Canonical for ExecutorDescription {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.capabilities.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_capability_version(u32::decode(decoder)?)?;
        Self::new(
            DaemonEpoch::decode(decoder)?,
            ExecutorCapabilitySet::decode(decoder)?,
        )
    }
}

/// One exact or hot materialization believed local to the executor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutorMaterializationLocality {
    configuration: ConfigurationArtifactId,
    capability: ExecutorMaterializationCapability,
}

impl ExecutorMaterializationLocality {
    /// Builds a coarse local materialization hint.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for `ThinReplay`, which is a universal
    /// fallback rather than cached locality.
    pub const fn new(
        configuration: ConfigurationArtifactId,
        capability: ExecutorMaterializationCapability,
    ) -> Result<Self, CampaignCodecError> {
        if matches!(capability, ExecutorMaterializationCapability::ThinReplay) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "thin replay is not materialization locality",
            });
        }
        Ok(Self {
            configuration,
            capability,
        })
    }

    /// Returns the locally materialized configuration.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationArtifactId {
        self.configuration
    }

    /// Returns the local materialization tier.
    #[must_use]
    pub const fn capability(&self) -> ExecutorMaterializationCapability {
        self.capability
    }
}

impl Canonical for ExecutorMaterializationLocality {
    fn encode(&self, encoder: &mut Encoder) {
        self.configuration.encode(encoder);
        self.capability.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ConfigurationArtifactId::decode(decoder)?,
            ExecutorMaterializationCapability::decode(decoder)?,
        )
    }
}

/// Daemon-epoch-scoped operational availability from `WatchCapacity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorCapacityReport {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    capability_digest: CampaignHash,
    sequence: u64,
    available_slots: u32,
    available_vcpus: u32,
    available_resident_bytes: u64,
    available_disk_bytes: u64,
    materialization_locality: BTreeSet<ExecutorMaterializationLocality>,
}

/// Snapshot-bound cursor request for the next volatile capacity report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchExecutorCapacityRequest {
    schema_version: u32,
    daemon_epoch: DaemonEpoch,
    capability_digest: CampaignHash,
    after_sequence: Option<u64>,
}

impl WatchExecutorCapacityRequest {
    /// Builds one request bound to an exact executor description.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the cursor is the reserved zero
    /// sequence or the message exceeds the component bound.
    pub fn new(
        description: &ExecutorDescription,
        after_sequence: Option<u64>,
    ) -> Result<Self, CampaignCodecError> {
        if after_sequence == Some(0) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity cursor sequence is zero",
            });
        }
        let value = Self {
            schema_version: EXECUTOR_CAPABILITY_SCHEMA_VERSION,
            daemon_epoch: description.daemon_epoch(),
            capability_digest: description.capabilities().digest(),
            after_sequence,
        };
        ensure_capability_message_size(&value, "watch-capacity-request-encoded-bytes")?;
        Ok(value)
    }

    /// Returns the expected daemon epoch.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the expected immutable capability digest.
    #[must_use]
    pub const fn capability_digest(&self) -> CampaignHash {
        self.capability_digest
    }

    /// Returns the last capacity sequence already observed.
    #[must_use]
    pub const fn after_sequence(&self) -> Option<u64> {
        self.after_sequence
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_capability_message(bytes, "watch-capacity-request-encoded-bytes")
    }
}

impl Canonical for WatchExecutorCapacityRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.capability_digest.encode(encoder);
        self.after_sequence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_capability_version(u32::decode(decoder)?)?;
        let daemon_epoch = DaemonEpoch::decode(decoder)?;
        let capability_digest = CampaignHash::decode(decoder)?;
        let after_sequence = Option::<u64>::decode(decoder)?;
        if after_sequence == Some(0) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity cursor sequence is zero",
            });
        }
        Ok(Self {
            schema_version: EXECUTOR_CAPABILITY_SCHEMA_VERSION,
            daemon_epoch,
            capability_digest,
            after_sequence,
        })
    }
}

impl ExecutorCapacityReport {
    /// Builds one bounded volatile capacity report.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the sequence is zero or the
    /// materialization-locality set is oversized.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon_epoch: DaemonEpoch,
        capability_digest: CampaignHash,
        sequence: u64,
        available_slots: u32,
        available_vcpus: u32,
        available_resident_bytes: u64,
        available_disk_bytes: u64,
        materialization_locality: BTreeSet<ExecutorMaterializationLocality>,
    ) -> Result<Self, CampaignCodecError> {
        if sequence == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity sequence is zero",
            });
        }
        if materialization_locality.len() > MAX_MATERIALIZATION_LOCALITIES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor materialization-locality set is oversized",
            });
        }
        let value = Self {
            schema_version: EXECUTOR_CAPABILITY_SCHEMA_VERSION,
            daemon_epoch,
            capability_digest,
            sequence,
            available_slots,
            available_vcpus,
            available_resident_bytes,
            available_disk_bytes,
            materialization_locality,
        };
        ensure_capability_message_size(&value, "executor-capacity-report-encoded-bytes")?;
        Ok(value)
    }

    /// Returns the daemon incarnation that emitted this report.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the immutable capability digest this report refines.
    #[must_use]
    pub const fn capability_digest(&self) -> CampaignHash {
        self.capability_digest
    }

    /// Returns the strictly increasing report sequence within the daemon epoch.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns currently available attempt slots.
    #[must_use]
    pub const fn available_slots(&self) -> u32 {
        self.available_slots
    }

    /// Returns currently available virtual CPUs.
    #[must_use]
    pub const fn available_vcpus(&self) -> u32 {
        self.available_vcpus
    }

    /// Returns currently available resident-memory bytes.
    #[must_use]
    pub const fn available_resident_bytes(&self) -> u64 {
        self.available_resident_bytes
    }

    /// Returns currently available writable-disk bytes.
    #[must_use]
    pub const fn available_disk_bytes(&self) -> u64 {
        self.available_disk_bytes
    }

    /// Returns bounded coarse exact/hot locality hints.
    #[must_use]
    pub const fn materialization_locality(&self) -> &BTreeSet<ExecutorMaterializationLocality> {
        &self.materialization_locality
    }

    /// Validates this volatile report against immutable facts and an optional cursor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for another daemon epoch or capability
    /// set, non-increasing sequence, capacity above configured ceilings, or a
    /// locality tier the executor did not advertise.
    pub fn validate_for(
        &self,
        description: &ExecutorDescription,
        after_sequence: Option<u64>,
    ) -> Result<(), CampaignCodecError> {
        let capabilities = description.capabilities();
        if self.daemon_epoch != description.daemon_epoch() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity daemon epoch does not match description",
            });
        }
        if self.capability_digest != capabilities.digest() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity capability digest does not match description",
            });
        }
        if after_sequence.is_some_and(|after| self.sequence <= after) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity sequence did not advance",
            });
        }
        let ceiling = capabilities.resource_ceiling();
        if self.available_slots > capabilities.maximum_slots()
            || self.available_vcpus > ceiling.maximum_vcpus()
            || self.available_resident_bytes > ceiling.maximum_resident_bytes()
            || self.available_disk_bytes > ceiling.maximum_disk_bytes()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity exceeds immutable ceiling",
            });
        }
        if self
            .materialization_locality
            .iter()
            .any(|local| !capabilities.materialization().contains(&local.capability()))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity reports unsupported materialization locality",
            });
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical component-message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_capability_message(bytes, "executor-capacity-report-encoded-bytes")
    }
}

impl Canonical for ExecutorCapacityReport {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.daemon_epoch.encode(encoder);
        self.capability_digest.encode(encoder);
        self.sequence.encode(encoder);
        self.available_slots.encode(encoder);
        self.available_vcpus.encode(encoder);
        self.available_resident_bytes.encode(encoder);
        self.available_disk_bytes.encode(encoder);
        self.materialization_locality.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_capability_version(u32::decode(decoder)?)?;
        Self::new(
            DaemonEpoch::decode(decoder)?,
            CampaignHash::decode(decoder)?,
            u64::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            decoder.set_bounded(
                MAX_MATERIALIZATION_LOCALITIES,
                "executor-materialization-locality-count",
            )?,
        )
    }
}

/// Executor service extension for capability negotiation and capacity polling.
pub trait ExecutorCapabilityService: ExecutorService {
    /// Returns immutable executor facts and the current daemon epoch.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when the service cannot
    /// produce a description.
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error>;

    /// Returns a fresh capacity report strictly after `after_sequence`.
    ///
    /// A loopback implementation may long-poll within its finite transport
    /// deadline. Other clients may consume intervening sequence numbers, and
    /// intermediate volatile capacity states may coalesce; callers therefore
    /// require strict advancement but not contiguous sequences.
    ///
    /// # Errors
    ///
    /// Returns the implementation-specific error when no bounded response can
    /// be produced.
    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error>;
}

fn ensure_capability_message_size(
    value: &impl Canonical,
    limit: &'static str,
) -> Result<(), CampaignCodecError> {
    codec::ensure_encoded_size(value, MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES, limit)
}

fn decode_capability_message<T: Canonical>(
    bytes: &[u8],
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }
    codec::decode(bytes)
}

const fn require_capability_version(version: u32) -> Result<(), CampaignCodecError> {
    if version == EXECUTOR_CAPABILITY_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor capability schema version",
        })
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    fn capabilities() -> ExecutorCapabilitySet {
        let compatibility = ExecutorCompatibilityProfile::new(
            "crucible-v1",
            "qemu-build-v1",
            BTreeMap::from([
                (String::from("control"), 1),
                (String::from("shared-memory"), 2),
            ]),
            2,
            3,
        )
        .expect("compatibility profile");
        ExecutorCapabilitySet::new(
            compatibility,
            "x86_64",
            BTreeSet::from([String::from("deterministic-tcg-v1")]),
            BTreeSet::from([
                ExecutorMaterializationCapability::ThinReplay,
                ExecutorMaterializationCapability::ExactRestore,
            ]),
            8,
            AttemptResourceLimits::new(8, 16 * 1024 * 1024 * 1024, 64 * 1024 * 1024, 1_000_000)
                .expect("resource ceiling"),
            BTreeSet::from([CampaignHash::derive(
                "crucible.test.executor-store-namespace.v1",
                b"local",
            )]),
        )
        .expect("capability set")
    }

    fn configuration() -> ConfigurationArtifactId {
        ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"executor-local-configuration",
        ))
        .expect("configuration ID")
    }

    #[test]
    fn descriptions_and_capacity_reports_are_strict_and_bound_together() {
        let epoch = DaemonEpoch::from_bytes([0x44; 16]).expect("daemon epoch");
        let description =
            ExecutorDescription::new(epoch, capabilities()).expect("executor description");
        let description_bytes = description.canonical_bytes();
        assert_eq!(
            ExecutorDescription::from_canonical_bytes(&description_bytes)
                .expect("description decode"),
            description
        );

        let locality = ExecutorMaterializationLocality::new(
            configuration(),
            ExecutorMaterializationCapability::ExactRestore,
        )
        .expect("exact locality");
        let report = ExecutorCapacityReport::new(
            epoch,
            description.capabilities().digest(),
            7,
            3,
            4,
            8 * 1024 * 1024 * 1024,
            32 * 1024 * 1024,
            BTreeSet::from([locality]),
        )
        .expect("capacity report");
        let report_bytes = report.canonical_bytes();
        assert_eq!(
            ExecutorCapacityReport::from_canonical_bytes(&report_bytes).expect("capacity decode"),
            report
        );
        report
            .validate_for(&description, Some(6))
            .expect("capacity binds description and cursor");
        assert_eq!(
            report.validate_for(&description, Some(7)),
            Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity sequence did not advance"
            })
        );

        let describe_request = DescribeExecutorRequest::new().canonical_bytes();
        assert_eq!(
            DescribeExecutorRequest::from_canonical_bytes(&describe_request)
                .expect("describe request decode"),
            DescribeExecutorRequest::new()
        );
        let watch_request =
            WatchExecutorCapacityRequest::new(&description, Some(6)).expect("watch request");
        let watch_request_bytes = watch_request.canonical_bytes();
        assert_eq!(
            WatchExecutorCapacityRequest::from_canonical_bytes(&watch_request_bytes)
                .expect("watch request decode"),
            watch_request
        );

        assert_eq!(
            CampaignHash::derive(
                "crucible.test.executor-description-vector.v1",
                &description_bytes,
            )
            .to_hex(),
            "add97fb6d82e682a49e5848e22c6ef80c5171d8e58e5a731c85998eb4eb6de05"
        );
        assert_eq!(
            CampaignHash::derive("crucible.test.executor-capacity-vector.v1", &report_bytes,)
                .to_hex(),
            "2605bca86ed120fae85a780f35598decd218bd191963b965b9b1a883a233ef99"
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.describe-executor-request-vector.v1",
                &describe_request,
            )
            .to_hex(),
            "9b31890265d4e6c828b2c5cc9039b7bf4e05edecccc5ad592375c22b67f4c8cc"
        );
        assert_eq!(
            CampaignHash::derive(
                "crucible.test.watch-executor-capacity-request-vector.v1",
                &watch_request_bytes,
            )
            .to_hex(),
            "247857df117af5ab2197580241b33ff8d7c7d0e2e93e6127ad4faaf1d21dd1c6"
        );
    }

    #[test]
    fn capacity_rejects_ceiling_epoch_digest_and_locality_drift() {
        let epoch = DaemonEpoch::from_bytes([0x55; 16]).expect("daemon epoch");
        let description =
            ExecutorDescription::new(epoch, capabilities()).expect("executor description");
        let over_capacity = ExecutorCapacityReport::new(
            epoch,
            description.capabilities().digest(),
            1,
            9,
            8,
            1,
            0,
            BTreeSet::new(),
        )
        .expect("structural report");
        assert_eq!(
            over_capacity.validate_for(&description, None),
            Err(CampaignCodecError::InvalidValue {
                reason: "executor capacity exceeds immutable ceiling"
            })
        );

        assert_eq!(
            ExecutorMaterializationLocality::new(
                configuration(),
                ExecutorMaterializationCapability::ThinReplay,
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "thin replay is not materialization locality"
            })
        );

        let mut bad_version = description.canonical_bytes();
        bad_version[..4].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            ExecutorDescription::from_canonical_bytes(&bad_version),
            Err(CampaignCodecError::InvalidValue {
                reason: "unsupported executor capability schema version"
            })
        );
    }

    #[test]
    fn checked_client_rejects_stale_capacity_from_direct_services() {
        struct FakeExecutor {
            description: ExecutorDescription,
            report: ExecutorCapacityReport,
        }

        impl ExecutorService for FakeExecutor {
            type Error = std::convert::Infallible;

            fn submit_attempt(
                &mut self,
                _request: &crate::SubmitAttemptRequest,
            ) -> Result<crate::SubmitAttemptResponse, Self::Error> {
                panic!("capability-only test does not submit attempts")
            }
        }

        impl ExecutorCapabilityService for FakeExecutor {
            fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
                Ok(self.description.clone())
            }

            fn watch_capacity(
                &mut self,
                _request: &WatchExecutorCapacityRequest,
            ) -> Result<ExecutorCapacityReport, Self::Error> {
                Ok(self.report.clone())
            }
        }

        let epoch = DaemonEpoch::from_bytes([0x66; 16]).expect("daemon epoch");
        let description =
            ExecutorDescription::new(epoch, capabilities()).expect("executor description");
        let report = ExecutorCapacityReport::new(
            epoch,
            description.capabilities().digest(),
            9,
            1,
            1,
            1,
            0,
            BTreeSet::new(),
        )
        .expect("capacity report");
        let mut client = crate::ExecutorClient::new(FakeExecutor {
            description: description.clone(),
            report: report.clone(),
        });
        assert_eq!(
            client.describe_executor().expect("description"),
            description
        );
        assert_eq!(
            client
                .watch_capacity(&description, Some(8))
                .expect("advanced capacity"),
            report
        );
        assert_eq!(
            client.watch_capacity(&description, Some(9)),
            Err(crate::ExecutorClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "executor capacity sequence did not advance"
                }
            ))
        );
    }
}
