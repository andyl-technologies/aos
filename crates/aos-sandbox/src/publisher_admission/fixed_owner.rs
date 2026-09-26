//! Fixed protected ownership for the dormant publisher domain.
//!
//! This is the public ownership boundary. It opens fixed internally selected
//! root-owned journals, decodes one closed protected configuration, retains
//! the authority/state locks, and revalidates the exact fixed object directory
//! before handing sidecar ownership to a short-lived domain service. It
//! accepts no journal, path, clock, capacity, limit, source-release, or
//! root-record scalar from callers.
//!
//! ```text
//! authority-v1.journal:
//!   CONFIG_MAGIC | version | fixed limits/capacity/epoch/root identity | digest
//!   RECOVERY_FENCE_MAGIC | operation | executor | death | incarnation | config | digest
//! state-v1.journal:
//!   canonical publisher-admission protected transactions
//! catalog-observation-v1.journal:
//!   exact externally durable catalog predecessor/successor observation
//! read-grants-v1.journal:
//!   independently revocable current disclosure grants
//! ```

use std::path::Path;

use aos_sandbox_core::{
    CacheDomainId, ObjectDigest, OperationId, ProjectId, PublisherInstanceId, ResourceId,
};
use aos_sandbox_linux::immutable_file::FsVerityPublicationRoot;
use sha2::{Digest as _, Sha256};

use super::RecoveryExecutorFenceV1;
use super::controller_authority::PublisherFixedControllerGrantV1;
use super::dormant_effects::{
    PublisherDormantEffectCapabilityV1, PublisherDormantEffectCompositionV1,
};
use super::durable_catalog::PublisherDurableCatalogOwnerV1;
use super::durable_read_grants::PublisherDurableReadGrantOwnerV1;
use super::executor_registry::PublisherFixedExecutorGrantV1;
use super::service::{
    FIXED_PUBLISHER_OBJECT_ROOT, PublisherDomainServiceConfigV1, PublisherDomainServiceErrorV1,
    PublisherDomainServiceV1,
};
use super::{AdmissionLimits, CapacityPolicyV1, PublicationAuthorityEpoch};
use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

const FIXED_PUBLISHER_ROOT: &str = "/var/lib/aos/sandbox/publisher";
const AUTHORITY_JOURNAL: &str = "authority-v1.journal";
const STATE_JOURNAL: &str = "state-v1.journal";
const CONFIG_KEY: &[u8] = b"\0aos-publisher-fixed-config-v1\0current";
const CONFIG_MAGIC: &[u8; 8] = b"AOSPFC01";
const CONFIG_VERSION: u16 = 1;
const CONFIG_DOMAIN: &[u8] = b"aos.sandbox.publisher.fixed-config.v1\0";
const RECOVERY_FENCE_KEY_PREFIX: &[u8] = b"\0aos-publisher-recovery-fence-v1\0";
const RECOVERY_FENCE_MAGIC: &[u8; 8] = b"AOSPRF01";
const RECOVERY_FENCE_DOMAIN: &[u8] = b"aos.sandbox.publisher.fixed-recovery-fence.v1\0";

/// Reports cold replay of the fixed protected publisher journals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherFixedProtectedOpenReportV1 {
    /// Reports authority/configuration journal recovery.
    pub authority: RecoveryReport,
    /// Reports publisher state journal recovery.
    pub state: RecoveryReport,
    /// Reports independently protected durable-catalog observation recovery.
    pub catalog_observation: RecoveryReport,
    /// Reports independently protected read-grant recovery.
    pub read_grants: RecoveryReport,
}

/// Reports fixed publisher-owner protection or replay failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherFixedProtectedOwnerErrorV1 {
    /// A fixed journal could not be safely opened or replayed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Protected configuration is absent, noncanonical, or internally invalid.
    #[error("fixed publisher protected configuration is invalid")]
    Configuration,
    /// The configured object-directory path or identity is no longer current.
    #[error("fixed publisher object root is not the protected current head")]
    RootCurrentness,
    /// Publisher domain replay or authority reconstruction failed closed.
    #[error(transparent)]
    Domain(#[from] PublisherDomainServiceErrorV1),
    /// Durable catalog-observation custody could not be authenticated.
    #[error("protected durable catalog observation is unavailable")]
    Catalog,
    /// Current read-grant custody could not be authenticated.
    #[error("protected publisher read grants are unavailable")]
    ReadGrants,
}

/// Exclusively owns the fixed dormant publisher journals and root binding.
pub struct PublisherFixedProtectedOwnerV1 {
    authority_journal: Journal,
    state_journal: Journal,
    config: PublisherDomainServiceConfigV1,
    config_digest: ObjectDigest,
}

/// Privately installs grants minted by retained protected source owners.
pub(super) struct PublisherFixedInstallerV1 {
    private: (),
}

impl PublisherFixedInstallerV1 {
    pub(super) const fn new() -> Self {
        Self { private: () }
    }

    pub(super) fn install_clean_controller(
        &mut self,
        grant: PublisherFixedControllerGrantV1,
    ) -> Result<RecoveryReport, PublisherFixedProtectedOwnerErrorV1> {
        let _ = self.private;
        install_fixed_configuration_from_controller(grant.into_config())
    }

    pub(super) fn install_executor_fence(
        &mut self,
        owner: &mut PublisherFixedProtectedOwnerV1,
        grant: PublisherFixedExecutorGrantV1,
    ) -> Result<(), PublisherFixedProtectedOwnerErrorV1> {
        let _ = self.private;
        let (operation, fence) = grant.into_parts();
        owner.install_recovery_fence_from_executor_registry(operation, fence)
    }
}

/// Carries one protected executor fence into fixed physical recovery.
#[must_use = "a cold recovery claim must be consumed by fixed publisher recovery"]
pub struct PublisherFixedColdRecoveryV1 {
    operation: OperationId,
    publisher_instance: PublisherInstanceId,
    fence: RecoveryExecutorFenceV1,
    authority_config_digest: ObjectDigest,
    record_digest: ObjectDigest,
}

impl PublisherFixedColdRecoveryV1 {
    pub(crate) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(crate) const fn publisher_instance(&self) -> PublisherInstanceId {
        self.publisher_instance
    }

    pub(crate) const fn config_digest(&self) -> ObjectDigest {
        self.authority_config_digest
    }

    pub(crate) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    pub(crate) fn into_fence(self) -> RecoveryExecutorFenceV1 {
        self.fence
    }
}

impl PublisherFixedProtectedOwnerV1 {
    /// Opens fixed protected journals and cold-replays complete publisher state.
    ///
    /// This also reopens the internally fixed object directory, compares its
    /// exact device/inode to protected configuration, and runs the full typed
    /// publisher replay once before returning. No authority escapes that replay.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedProtectedOwnerErrorV1`] for an unsafe path,
    /// missing/noncanonical configuration, root replacement, or invalid state.
    pub fn open_fixed_protected()
    -> Result<(Self, PublisherFixedProtectedOpenReportV1), PublisherFixedProtectedOwnerErrorV1>
    {
        let root = Path::new(FIXED_PUBLISHER_ROOT);
        let (authority_journal, authority_report) =
            Journal::open_protected_at(root, AUTHORITY_JOURNAL, authority_journal_limits())?;
        let (state_journal, state_report) =
            Journal::open_protected_at(root, STATE_JOURNAL, state_journal_limits())?;
        let (catalog_observation, catalog_observation_report) =
            PublisherDurableCatalogOwnerV1::open_fixed_protected()
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Catalog)?;
        drop(catalog_observation);
        let (read_grants, read_grants_report) =
            PublisherDurableReadGrantOwnerV1::open_fixed_protected()
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::ReadGrants)?;
        drop(read_grants);
        let (config, config_digest) = read_config(&authority_journal)?;
        validate_fixed_root(config)?;

        let mut owner = Self {
            authority_journal,
            state_journal,
            config,
            config_digest,
        };
        {
            let _cold_replay = owner.claim_domain()?;
        }
        Ok((
            owner,
            PublisherFixedProtectedOpenReportV1 {
                authority: authority_report,
                state: state_report,
                catalog_observation: catalog_observation_report,
                read_grants: read_grants_report,
            },
        ))
    }

    /// Revalidates fixed configuration/root and claims the complete domain.
    ///
    /// The returned service borrows the solely owned state journal. Its public
    /// effect methods accept only authenticated session and opaque descriptor,
    /// root, preparation, or recovery capabilities. Physical preparation and
    /// completion additionally require a sealed capability that this production
    /// construction does not return and cannot mint.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedProtectedOwnerErrorV1`] if protected config,
    /// root identity, or any replayed current head changed or became invalid.
    pub fn claim_domain(
        &mut self,
    ) -> Result<PublisherDomainServiceV1<'_>, PublisherFixedProtectedOwnerErrorV1> {
        let (config, digest) = read_config(&self.authority_journal)?;
        if digest != self.config_digest || !config_equal(config, self.config) {
            return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
        }
        validate_fixed_root(config)?;
        let (durable_catalog, _) = PublisherDurableCatalogOwnerV1::open_fixed_protected()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Catalog)?;
        let (read_grants, _) = PublisherDurableReadGrantOwnerV1::open_fixed_protected()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::ReadGrants)?;
        PublisherDomainServiceV1::claim(
            &mut self.state_journal,
            durable_catalog,
            read_grants,
            config,
        )
        .map_err(Into::into)
    }

    /// Claims the domain together with explicitly injected dormant effects.
    ///
    /// This crate-private composition preserves a callable physical path for
    /// non-production integration without adding an activation path to the
    /// public fixed owner.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedProtectedOwnerErrorV1`] under the same closed
    /// configuration, root-currentness, catalog, and replay conditions as
    /// [`Self::claim_domain`].
    #[allow(
        dead_code,
        reason = "publisher effects remain an explicit dormant source-only integration seam"
    )]
    pub(crate) fn claim_domain_with_injected_effects<'owner, 'activation>(
        &'owner mut self,
        composition: &'activation mut PublisherDormantEffectCompositionV1,
    ) -> Result<
        (
            PublisherDomainServiceV1<'owner>,
            PublisherDormantEffectCapabilityV1<'activation>,
        ),
        PublisherFixedProtectedOwnerErrorV1,
    > {
        let service = self.claim_domain()?;
        let effects = composition.activate();
        Ok((service, effects))
    }

    /// Obtains one protected, operation-bound executor fence for cold recovery.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedProtectedOwnerErrorV1::Configuration`] unless
    /// the fixed authority journal contains one canonical fence bound to the
    /// exact current configuration digest.
    pub fn claim_cold_recovery(
        &self,
        operation: OperationId,
    ) -> Result<PublisherFixedColdRecoveryV1, PublisherFixedProtectedOwnerErrorV1> {
        let key = recovery_fence_key(operation);
        let bytes = self
            .authority_journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherFixedProtectedOwnerErrorV1::Configuration)?;
        decode_recovery_fence(bytes, operation, self.config_digest)
    }

    /// Persists one opaque protected executor fence for fixed cold recovery.
    ///
    /// This crate-private adapter consumes the fence issued by the protected
    /// executor registry; it accepts no death, revocation, incarnation, or
    /// publisher-instance scalar. Exact readback is required before success.
    fn install_recovery_fence_from_executor_registry(
        &mut self,
        operation: OperationId,
        fence: RecoveryExecutorFenceV1,
    ) -> Result<(), PublisherFixedProtectedOwnerErrorV1> {
        let bytes = encode_recovery_fence(operation, &fence, self.config_digest);
        let record_digest = ObjectDigest::from_bytes(
            bytes[136..168]
                .try_into()
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
        );
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&record_digest.as_bytes()[..16]);
        if transaction_id == [0; 16] {
            return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
        }
        let key = recovery_fence_key(operation);
        if let Some(existing) = self
            .authority_journal
            .get(RecordNamespace::PublisherAuthority, &key)
        {
            let existing = decode_recovery_fence(existing, operation, self.config_digest)?;
            if existing.record_digest != record_digest {
                return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
            }
            return Ok(());
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key.clone(),
                bytes,
            )],
        )?;
        self.authority_journal.commit(&transaction)?;
        let readback = self
            .authority_journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherFixedProtectedOwnerErrorV1::Configuration)?;
        let readback = decode_recovery_fence(readback, operation, self.config_digest)?;
        if readback.record_digest != record_digest {
            return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
        }
        Ok(())
    }
}

/// Installs the one immutable fixed configuration from trusted crate integration.
///
/// This deliberately remains crate-private: public callers cannot select a
/// root, journal, clock, limits, or capacity envelope. The fixed authority
/// journal must be empty and the configured device/inode must already match
/// the internally fixed protected object path.
fn install_fixed_configuration_from_controller(
    config: PublisherDomainServiceConfigV1,
) -> Result<RecoveryReport, PublisherFixedProtectedOwnerErrorV1> {
    validate_fixed_root(config)?;
    let (mut journal, report) = Journal::open_protected_at(
        Path::new(FIXED_PUBLISHER_ROOT),
        AUTHORITY_JOURNAL,
        authority_journal_limits(),
    )?;
    if journal
        .records(RecordNamespace::PublisherAuthority)
        .next()
        .is_some()
    {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let bytes = encode_config(config)?;
    let digest = ObjectDigest::from_bytes(
        bytes[bytes.len() - 32..]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::PublisherAuthority,
            CONFIG_KEY.to_vec(),
            bytes,
        )],
    )?;
    journal.commit(&transaction)?;
    let (_, readback) = read_config(&journal)?;
    if readback != digest {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    Ok(report)
}

fn validate_fixed_root(
    config: PublisherDomainServiceConfigV1,
) -> Result<(), PublisherFixedProtectedOwnerErrorV1> {
    let root = FsVerityPublicationRoot::from_protected_absolute_path(Path::new(
        FIXED_PUBLISHER_OBJECT_ROOT,
    ))
    .map_err(|_| PublisherFixedProtectedOwnerErrorV1::RootCurrentness)?;
    root.recheck_protected_path()
        .map_err(|_| PublisherFixedProtectedOwnerErrorV1::RootCurrentness)?;
    if root.device() != config.root_device || root.inode() != config.root_inode {
        return Err(PublisherFixedProtectedOwnerErrorV1::RootCurrentness);
    }
    Ok(())
}

fn read_config(
    journal: &Journal,
) -> Result<(PublisherDomainServiceConfigV1, ObjectDigest), PublisherFixedProtectedOwnerErrorV1> {
    let mut config = None;
    let mut fences = Vec::new();
    for (key, bytes) in journal.records(RecordNamespace::PublisherAuthority) {
        if key == CONFIG_KEY {
            if config.replace(bytes).is_some() {
                return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
            }
        } else if key.starts_with(RECOVERY_FENCE_KEY_PREFIX)
            && key.len() == RECOVERY_FENCE_KEY_PREFIX.len() + 16
        {
            fences.push((key, bytes));
        } else {
            return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
        }
    }
    let decoded = decode_config(config.ok_or(PublisherFixedProtectedOwnerErrorV1::Configuration)?)?;
    for (key, bytes) in fences {
        let operation = OperationId::from_bytes(
            key[RECOVERY_FENCE_KEY_PREFIX.len()..]
                .try_into()
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
        );
        let _validated_recovery = decode_recovery_fence(bytes, operation, decoded.1)?;
    }
    Ok(decoded)
}

fn recovery_fence_key(operation: OperationId) -> Vec<u8> {
    [RECOVERY_FENCE_KEY_PREFIX, operation.as_bytes()].concat()
}

fn decode_recovery_fence(
    bytes: &[u8],
    expected_operation: OperationId,
    expected_config: ObjectDigest,
) -> Result<PublisherFixedColdRecoveryV1, PublisherFixedProtectedOwnerErrorV1> {
    if bytes.len() != 168 || &bytes[..8] != RECOVERY_FENCE_MAGIC {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let operation = OperationId::from_bytes(
        bytes[8..24]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let publisher_instance = PublisherInstanceId::from_bytes(
        bytes[24..40]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let death = ObjectDigest::from_bytes(
        bytes[40..72]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let incarnation = ObjectDigest::from_bytes(
        bytes[72..104]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let config = ObjectDigest::from_bytes(
        bytes[104..136]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let record_digest = ObjectDigest::from_bytes(
        bytes[136..168]
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?,
    );
    let derived = digest_parts(
        RECOVERY_FENCE_DOMAIN,
        &[
            operation.as_bytes(),
            publisher_instance.as_bytes(),
            death.as_bytes(),
            incarnation.as_bytes(),
            config.as_bytes(),
        ],
    );
    if operation != expected_operation
        || config != expected_config
        || derived != record_digest
        || publisher_instance.as_bytes() == &[0; 16]
    {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let fence = RecoveryExecutorFenceV1::from_protected_executor_registry(
        publisher_instance,
        death,
        incarnation,
    )
    .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    Ok(PublisherFixedColdRecoveryV1 {
        operation,
        publisher_instance,
        fence,
        authority_config_digest: config,
        record_digest,
    })
}

fn encode_recovery_fence(
    operation: OperationId,
    fence: &RecoveryExecutorFenceV1,
    config: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(168);
    bytes.extend_from_slice(RECOVERY_FENCE_MAGIC);
    bytes.extend_from_slice(operation.as_bytes());
    bytes.extend_from_slice(fence.publisher_instance().as_bytes());
    bytes.extend_from_slice(fence.death_or_revocation_digest().as_bytes());
    bytes.extend_from_slice(fence.recovery_incarnation().as_bytes());
    bytes.extend_from_slice(config.as_bytes());
    let digest = digest_parts(
        RECOVERY_FENCE_DOMAIN,
        &[
            operation.as_bytes(),
            fence.publisher_instance().as_bytes(),
            fence.death_or_revocation_digest().as_bytes(),
            fence.recovery_incarnation().as_bytes(),
            config.as_bytes(),
        ],
    );
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn decode_config(
    bytes: &[u8],
) -> Result<(PublisherDomainServiceConfigV1, ObjectDigest), PublisherFixedProtectedOwnerErrorV1> {
    const FIXED_BYTES: usize = 251;
    if bytes.len() != FIXED_BYTES || &bytes[..8] != CONFIG_MAGIC {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let mut cursor = ConfigCursor { bytes, offset: 8 };
    if cursor.u16()? != CONFIG_VERSION {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let admission_limits = AdmissionLimits {
        maximum_records: cursor.usize()?,
        maximum_record_bytes: cursor.usize()?,
        maximum_materialized_bytes: cursor.usize()?,
        maximum_outstanding_permits: cursor.usize()?,
        maximum_protocol_bytes: cursor.usize()?,
    }
    .validate()
    .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    let resource = ResourceId::from_bytes(cursor.array()?);
    let project = ProjectId::from_bytes(cursor.array()?);
    if cursor.u8()? != 2 {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let domain = aos_sandbox_core::model::CacheDomain::new(
        aos_sandbox_core::model::CacheDomainKind::Project,
        CacheDomainId::from_bytes(cursor.array()?),
    );
    let capacity = CapacityPolicyV1 {
        resource,
        project,
        domain,
        isolation_policy: ObjectDigest::from_bytes(cursor.array()?),
        maximum_bytes: cursor.u64()?,
        maximum_objects: cursor.u64()?,
        recovery_reserve_bytes: cursor.u64()?,
    }
    .validate()
    .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    let authority_epoch = PublicationAuthorityEpoch::new(cursor.u64()?)
        .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    let maximum_source_releases = cursor.usize()?;
    let maximum_root_records = cursor.usize()?;
    let maximum_catalog_entries = cursor.usize()?;
    let clock_provenance = cursor.array()?;
    let root_device = cursor.u64()?;
    let root_inode = cursor.u64()?;
    let retained_digest = ObjectDigest::from_bytes(cursor.array()?);
    cursor.finish()?;
    let derived_digest = config_digest(&bytes[..bytes.len() - 32]);
    if retained_digest != derived_digest
        || clock_provenance == [0; 16]
        || root_device == 0
        || root_inode == 0
        || maximum_source_releases == 0
        || maximum_root_records == 0
        || maximum_catalog_entries == 0
        || maximum_source_releases > admission_limits.maximum_records
        || maximum_root_records > admission_limits.maximum_records
        || maximum_catalog_entries > admission_limits.maximum_records
    {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    Ok((
        PublisherDomainServiceConfigV1 {
            admission_limits,
            capacity,
            authority_epoch,
            maximum_source_releases,
            maximum_root_records,
            maximum_catalog_entries,
            clock_provenance,
            root_device,
            root_inode,
            authority_config_digest: retained_digest,
        },
        retained_digest,
    ))
}

pub(super) fn encode_config(
    config: PublisherDomainServiceConfigV1,
) -> Result<Vec<u8>, PublisherFixedProtectedOwnerErrorV1> {
    config
        .admission_limits
        .validate()
        .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    config
        .capacity
        .validate()
        .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?;
    if config.capacity.domain.kind() != aos_sandbox_core::model::CacheDomainKind::Project
        || config.clock_provenance == [0; 16]
        || config.root_device == 0
        || config.root_inode == 0
    {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    let mut bytes = Vec::with_capacity(251);
    bytes.extend_from_slice(CONFIG_MAGIC);
    bytes.extend_from_slice(&CONFIG_VERSION.to_be_bytes());
    for value in [
        config.admission_limits.maximum_records,
        config.admission_limits.maximum_record_bytes,
        config.admission_limits.maximum_materialized_bytes,
        config.admission_limits.maximum_outstanding_permits,
        config.admission_limits.maximum_protocol_bytes,
    ] {
        bytes.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?
                .to_be_bytes(),
        );
    }
    bytes.extend_from_slice(config.capacity.resource.as_bytes());
    bytes.extend_from_slice(config.capacity.project.as_bytes());
    bytes.push(2);
    bytes.extend_from_slice(config.capacity.domain.domain_id().as_bytes());
    bytes.extend_from_slice(config.capacity.isolation_policy.as_bytes());
    bytes.extend_from_slice(&config.capacity.maximum_bytes.to_be_bytes());
    bytes.extend_from_slice(&config.capacity.maximum_objects.to_be_bytes());
    bytes.extend_from_slice(&config.capacity.recovery_reserve_bytes.to_be_bytes());
    bytes.extend_from_slice(&config.authority_epoch.get().to_be_bytes());
    for value in [
        config.maximum_source_releases,
        config.maximum_root_records,
        config.maximum_catalog_entries,
    ] {
        bytes.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)?
                .to_be_bytes(),
        );
    }
    bytes.extend_from_slice(&config.clock_provenance);
    bytes.extend_from_slice(&config.root_device.to_be_bytes());
    bytes.extend_from_slice(&config.root_inode.to_be_bytes());
    let digest = config_digest(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    if bytes.len() != 251 {
        return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
    }
    Ok(bytes)
}

pub(super) fn config_equal(
    left: PublisherDomainServiceConfigV1,
    right: PublisherDomainServiceConfigV1,
) -> bool {
    left.admission_limits == right.admission_limits
        && left.capacity == right.capacity
        && left.authority_epoch == right.authority_epoch
        && left.maximum_source_releases == right.maximum_source_releases
        && left.maximum_root_records == right.maximum_root_records
        && left.maximum_catalog_entries == right.maximum_catalog_entries
        && left.clock_provenance == right.clock_provenance
        && left.root_device == right.root_device
        && left.root_inode == right.root_inode
        && left.authority_config_digest == right.authority_config_digest
}

fn config_digest(bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(CONFIG_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

const fn authority_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 4096,
        maximum_transaction_bytes: 1024 * 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 16 * 1024 * 1024,
        maximum_materialized_records: 65_536,
    }
}

const fn state_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 65_536,
        maximum_transaction_bytes: 512 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 512 * 1024 * 1024,
        maximum_materialized_records: 1_000_000,
    }
}

struct ConfigCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl ConfigCursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PublisherFixedProtectedOwnerErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PublisherFixedProtectedOwnerErrorV1::Configuration)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PublisherFixedProtectedOwnerErrorV1::Configuration)?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PublisherFixedProtectedOwnerErrorV1> {
        self.take()
    }

    fn u8(&mut self) -> Result<u8, PublisherFixedProtectedOwnerErrorV1> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, PublisherFixedProtectedOwnerErrorV1> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, PublisherFixedProtectedOwnerErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn usize(&mut self) -> Result<usize, PublisherFixedProtectedOwnerErrorV1> {
        usize::try_from(self.u64()?).map_err(|_| PublisherFixedProtectedOwnerErrorV1::Configuration)
    }

    fn finish(self) -> Result<(), PublisherFixedProtectedOwnerErrorV1> {
        if self.offset != self.bytes.len() {
            return Err(PublisherFixedProtectedOwnerErrorV1::Configuration);
        }
        Ok(())
    }
}
