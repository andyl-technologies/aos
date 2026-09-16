//! LIFE-02 snapshot availability and resumable transfer joins.

use std::marker::PhantomData;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::model::snapshot::ExternalDependency;
use aos_sandbox_core::model::{KeyReference, Signature, SignaturePurpose};
use aos_sandbox_core::{
    AssignmentEpoch, DecodeLimits, IncarnationId, ObjectDigest, OperationId, ProjectId, ResourceId,
    SandboxId, SnapshotId, TrustScopeId, ViewId, descriptor_for_bytes, verify_signature,
};
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

use crate::multi_node::{MultiNodeJournalDomainV1, ProtectedMultiNodeCurrentRecordV1};
use crate::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport,
};

use super::{
    CurrentLifecycleEffectV1, CurrentLifecycleOperationV1, CurrentLifecycleRetentionLedgerV1,
    LifecycleAuthenticatedBrokerEffectV1, LifecycleEffectDomainV1, LifecyclePhase6ErrorV1,
    LifecycleProtectedRetentionAcknowledgementV1, LifecycleResourceV1,
    LifecycleRetentionAcknowledgementV1, LifecycleSnapshotManifestDigestV1,
    LifecycleValidatedSnapshotV1,
};

/// Selects whether restore can proceed without mutable external state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleSnapshotAvailabilityModeV1 {
    /// Every required byte is immutable and durably retained.
    SelfContained,
    /// Restore must revalidate the listed external dependencies.
    External,
}

/// Classifies one exact dependency's restore availability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleSnapshotDependencyClassV1 {
    /// Immutable content with a durable controller-held receipt.
    ImmutableRetained,
    /// Owned held snapshot storage with a durable receipt.
    OwnedHeldStorage,
    /// Mutable external view, even when mounted read-only.
    ExternalMutableView,
    /// Immutable package content that must be reacquired by descriptor.
    ExternalPackage,
    /// Service state requiring an immutable checkpoint at restore.
    ExternalService,
    /// Secret reference requiring fresh authorization.
    ExternalSecret,
    /// Versioned external network or endpoint contract.
    ExternalNetwork,
}

/// Names the dependency-specific owner that authenticated availability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleExternalAvailabilityProviderV1 {
    /// A Mount owner revalidated the exact immutable-view revision.
    MutableViewMount = 1,
    /// A Cache owner reacquired the exact package closure.
    PackageCache = 2,
    /// The named service owner revalidated its exact checkpoint version.
    ServiceCheckpoint = 3,
    /// The named secret issuer authorized the exact opaque version and scope.
    SecretIssuer = 4,
    /// A Network owner revalidated the exact endpoint contract version.
    NetworkContract = 6,
    /// The Storage retention owner authenticated immutable retained custody.
    RetentionStorage = 7,
}

/// Carries lower-domain proof that one exact external dependency is available.
#[derive(Debug, Eq, PartialEq)]
pub struct LifecycleExternalAvailabilityEvidenceV1 {
    operation: OperationId,
    project: ProjectId,
    projection_root: ObjectDigest,
    dependency: ObjectDigest,
    class: LifecycleSnapshotDependencyClassV1,
    identity: [u8; 16],
    provider: LifecycleExternalAvailabilityProviderV1,
    request: ObjectDigest,
    receipt: ObjectDigest,
    producer_inventory: ObjectDigest,
    producer_generation: u64,
    producer_result: ObjectDigest,
    producer_currentness: ObjectDigest,
}

const EXTERNAL_PROVIDER_AUTHORITY_ROOT: &str =
    "/var/lib/aos/sandbox/lifecycle-external-provider-authority";
const EXTERNAL_PROVIDER_AUTHORITY_KEY: &[u8] = b"current-provider-authority-v1";
const EXTERNAL_PROVIDER_AUTHORITY_MAGIC: &[u8; 8] = b"AOSLAPT1";
const EXTERNAL_PROVIDER_AUTHORITY_VERSION: u16 = 1;
const EXTERNAL_PROVIDER_AUTHORITY_DOMAIN: &[u8] =
    b"aos.sandbox.lifecycle.external-provider-authority.v1\0";
const EXTERNAL_PROVIDER_FIXED_BYTES: usize = 8 + 2 + 1 + 5 + 8 + 4 + 32;
const EXTERNAL_PROVIDER_DIGEST_BYTES: usize = 32;
const MAXIMUM_EXTERNAL_PROVIDER_POLICY_BYTES: usize = 64 * 1024;
const EXTERNAL_PROVIDER_CLOCK_FLOOR_KEY: &[u8] = b"provider-clock-floor-v1";
const EXTERNAL_PROVIDER_CLOCK_FLOOR_MAGIC: &[u8; 8] = b"AOSLACF1";
const EXTERNAL_PROVIDER_CLOCK_FLOOR_VERSION: u16 = 1;
const EXTERNAL_PROVIDER_CLOCK_FLOOR_DOMAIN: &[u8] =
    b"aos.sandbox.lifecycle.external-provider-clock-floor.v1\0";
const EXTERNAL_PROVIDER_CLOCK_FLOOR_BYTES: usize = 112;

#[derive(Clone, Copy)]
struct ExternalProviderClockFloorV1 {
    provider: LifecycleExternalAvailabilityProviderV1,
    host_boot: [u8; 16],
    boottime_nanoseconds: u64,
    wall_seconds: i64,
    authority: ObjectDigest,
}

struct LifecycleExternalProviderTrustStateV1 {
    journal: Journal,
    provider: LifecycleExternalAvailabilityProviderV1,
    generation: u64,
    signer: KeyReference,
    trust_scope: TrustScopeId,
    purpose: SignaturePurpose,
    policy: Vec<u8>,
    public_key: [u8; 32],
    pinned_record: Vec<u8>,
    current_digest: ObjectDigest,
}

impl LifecycleExternalProviderTrustStateV1 {
    fn open_fixed(
        provider: LifecycleExternalAvailabilityProviderV1,
        journal_name: &'static str,
    ) -> Result<(Self, RecoveryReport), LifecyclePhase6ErrorV1> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(EXTERNAL_PROVIDER_AUTHORITY_ROOT),
            journal_name,
            external_provider_journal_limits(),
        )
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let pinned_record = journal
            .get(
                RecordNamespace::AuthorityPublication,
                EXTERNAL_PROVIDER_AUTHORITY_KEY,
            )
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?
            .to_vec();
        let authority = decode_external_provider_authority(&pinned_record, provider)?;

        Ok((
            Self {
                journal,
                provider,
                generation: authority.generation,
                signer: authority.signer,
                trust_scope: authority.trust_scope,
                purpose: authority.purpose,
                policy: authority.policy,
                public_key: authority.public_key,
                pinned_record,
                current_digest: authority.current_digest,
            },
            report,
        ))
    }

    fn authenticate<'owner, Readback>(
        &'owner mut self,
        exact_readback: &[u8],
        signature: &Signature,
        expected_provider: LifecycleExternalAvailabilityProviderV1,
        construct: impl FnOnce(ExternalProviderDecodedReadback, ObjectDigest, ObjectDigest) -> Readback,
    ) -> Result<Readback, LifecyclePhase6ErrorV1> {
        let current_record = self
            .journal
            .get(
                RecordNamespace::AuthorityPublication,
                EXTERNAL_PROVIDER_AUTHORITY_KEY,
            )
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?
            .to_vec();
        if current_record != self.pinned_record
            || self.provider != expected_provider
            || self.current_digest.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let current = decode_external_provider_authority(&current_record, expected_provider)?;
        if current.generation != self.generation
            || current.signer != self.signer
            || current.trust_scope != self.trust_scope
            || current.purpose != self.purpose
            || current.policy != self.policy
            || current.public_key != self.public_key
            || current.current_digest != self.current_digest
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }

        let fields = decode_external_provider_readback(exact_readback, expected_provider)?;
        let statement = signature.statement();
        if statement.signer() != &self.signer
            || statement.signer().generation() != self.generation
            || statement.trust_scope() != self.trust_scope
            || statement.purpose() != self.purpose
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let clock_before = self.advance_clock_floor()?;
        let verified = verify_signature(
            signature,
            &self.policy,
            &self.public_key,
            clock_before.wall_seconds,
            external_provider_decode_limits(),
        )
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let clock_after = self.advance_clock_floor()?;
        if clock_after.host_boot != clock_before.host_boot
            || clock_after.boottime_nanoseconds < clock_before.boottime_nanoseconds
            || clock_after.wall_seconds < clock_before.wall_seconds
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let current_record_after = self
            .journal
            .get(
                RecordNamespace::AuthorityPublication,
                EXTERNAL_PROVIDER_AUTHORITY_KEY,
            )
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if current_record_after != self.pinned_record.as_slice()
            || decode_external_provider_authority(current_record_after, expected_provider)?
                .current_digest
                != self.current_digest
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let verified_after = verify_signature(
            signature,
            &self.policy,
            &self.public_key,
            clock_after.wall_seconds,
            external_provider_decode_limits(),
        )
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let expected_subject = descriptor_for_bytes(
            verified_after.subject().media_type().clone(),
            exact_readback,
        );
        if verified.subject() != verified_after.subject()
            || verified.verification_policy() != verified_after.verification_policy()
            || verified_after.subject() != &expected_subject
            || statement.subject() != verified_after.subject()
            || statement.verification_policy() != verified_after.verification_policy()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        validate_external_provider_fields(&fields)?;
        if fields.generation != self.generation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(construct(
            fields,
            verified_after.subject().digest(),
            verified_after.verification_policy().digest(),
        ))
    }

    fn advance_clock_floor(
        &mut self,
    ) -> Result<ExternalProviderClockFloorV1, LifecyclePhase6ErrorV1> {
        let sampled = protected_external_provider_clock(self.provider, self.current_digest)?;
        if let Some(encoded) = self.journal.get(
            RecordNamespace::CliAuthorizationTime,
            EXTERNAL_PROVIDER_CLOCK_FLOOR_KEY,
        ) {
            let retained = decode_external_provider_clock_floor(encoded)?;
            if retained.provider != self.provider
                || sampled.wall_seconds < retained.wall_seconds
                || (sampled.host_boot == retained.host_boot
                    && sampled.boottime_nanoseconds < retained.boottime_nanoseconds)
            {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
        }
        let encoded = encode_external_provider_clock_floor(sampled);
        let transaction_id = external_provider_clock_transaction_id(sampled);
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::CliAuthorizationTime,
                EXTERNAL_PROVIDER_CLOCK_FLOOR_KEY.to_vec(),
                encoded,
            )],
        )
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        self.journal
            .commit(&transaction)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let current = self
            .journal
            .get(
                RecordNamespace::CliAuthorizationTime,
                EXTERNAL_PROVIDER_CLOCK_FLOOR_KEY,
            )
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if decode_external_provider_clock_floor(current)? != sampled {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(sampled)
    }
}

impl PartialEq for ExternalProviderClockFloorV1 {
    fn eq(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self.host_boot == other.host_boot
            && self.boottime_nanoseconds == other.boottime_nanoseconds
            && self.wall_seconds == other.wall_seconds
            && self.authority == other.authority
    }
}

impl Eq for ExternalProviderClockFloorV1 {}

fn protected_external_provider_clock(
    provider: LifecycleExternalAvailabilityProviderV1,
    authority: ObjectDigest,
) -> Result<ExternalProviderClockFloorV1, LifecyclePhase6ErrorV1> {
    let boot_before = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    let before = boottime_nanoseconds()?;
    let wall_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .as_secs()
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let after = boottime_nanoseconds()?;
    let boot_after = KernelBootId::current()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        .into_bytes();
    if boot_before != boot_after || after < before || authority.as_bytes() == &[0; 32] {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(ExternalProviderClockFloorV1 {
        provider,
        host_boot: boot_before,
        boottime_nanoseconds: after,
        wall_seconds,
        authority,
    })
}

fn boottime_nanoseconds() -> Result<u64, LifecyclePhase6ErrorV1> {
    let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(sample.tv_sec).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let nanoseconds =
        u64::try_from(sample.tv_nsec).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)
}

fn encode_external_provider_clock_floor(floor: ExternalProviderClockFloorV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(EXTERNAL_PROVIDER_CLOCK_FLOOR_BYTES);
    bytes.extend_from_slice(EXTERNAL_PROVIDER_CLOCK_FLOOR_MAGIC);
    bytes.extend_from_slice(&EXTERNAL_PROVIDER_CLOCK_FLOOR_VERSION.to_be_bytes());
    bytes.push(floor.provider as u8);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(&floor.host_boot);
    bytes.extend_from_slice(&floor.boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&floor.wall_seconds.to_be_bytes());
    bytes.extend_from_slice(floor.authority.as_bytes());
    let digest = Sha256::new()
        .chain_update(EXTERNAL_PROVIDER_CLOCK_FLOOR_DOMAIN)
        .chain_update(&bytes)
        .finalize();
    bytes.extend_from_slice(&digest);
    bytes
}

fn decode_external_provider_clock_floor(
    bytes: &[u8],
) -> Result<ExternalProviderClockFloorV1, LifecyclePhase6ErrorV1> {
    if bytes.len() != EXTERNAL_PROVIDER_CLOCK_FLOOR_BYTES
        || bytes.get(..8) != Some(EXTERNAL_PROVIDER_CLOCK_FLOOR_MAGIC.as_slice())
        || u16::from_be_bytes(readback_array(bytes, 8)?) != EXTERNAL_PROVIDER_CLOCK_FLOOR_VERSION
        || bytes.get(11..16) != Some([0; 5].as_slice())
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    let provider = match bytes[10] {
        1 => LifecycleExternalAvailabilityProviderV1::MutableViewMount,
        2 => LifecycleExternalAvailabilityProviderV1::PackageCache,
        3 => LifecycleExternalAvailabilityProviderV1::ServiceCheckpoint,
        4 => LifecycleExternalAvailabilityProviderV1::SecretIssuer,
        6 => LifecycleExternalAvailabilityProviderV1::NetworkContract,
        7 => LifecycleExternalAvailabilityProviderV1::RetentionStorage,
        _ => return Err(LifecyclePhase6ErrorV1::StaleAuthority),
    };
    let stored = ObjectDigest::from_bytes(readback_array(bytes, 80)?);
    let computed = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(EXTERNAL_PROVIDER_CLOCK_FLOOR_DOMAIN)
            .chain_update(&bytes[..80])
            .finalize()
            .into(),
    );
    let floor = ExternalProviderClockFloorV1 {
        provider,
        host_boot: readback_array(bytes, 16)?,
        boottime_nanoseconds: u64::from_be_bytes(readback_array(bytes, 32)?),
        wall_seconds: i64::from_be_bytes(readback_array(bytes, 40)?),
        authority: ObjectDigest::from_bytes(readback_array(bytes, 48)?),
    };
    if stored != computed
        || floor.host_boot == [0; 16]
        || floor.boottime_nanoseconds == 0
        || floor.wall_seconds < 0
        || floor.authority.as_bytes() == &[0; 32]
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(floor)
}

fn external_provider_clock_transaction_id(floor: ExternalProviderClockFloorV1) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.external-provider-clock-transaction.v1\0")
        .chain_update([floor.provider as u8])
        .chain_update(floor.host_boot)
        .chain_update(floor.boottime_nanoseconds.to_be_bytes())
        .chain_update(floor.wall_seconds.to_be_bytes())
        .chain_update(floor.authority.as_bytes())
        .finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

macro_rules! provider_readback {
    ($owner:ident, $name:ident, $provider:expr, $journal:literal, $summary:literal) => {
        #[doc = concat!("Owns the fixed protected trust anchor for ", $summary)]
        pub struct $owner(LifecycleExternalProviderTrustStateV1);

        impl $owner {
            /// Opens the internally fixed protected provider-authority journal.
            ///
            /// # Errors
            ///
            /// Returns [`LifecyclePhase6ErrorV1`] unless the fixed current
            /// record, canonical trust policy, sole signer generation, raw
            /// public key, scope, and purpose form one authenticated anchor.
            pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), LifecyclePhase6ErrorV1>
            {
                let (owner, report) =
                    LifecycleExternalProviderTrustStateV1::open_fixed($provider, $journal)?;
                Ok((Self(owner), report))
            }

            /// Authenticates one exact provider readback while retaining this owner borrow.
            ///
            /// # Errors
            ///
            /// Returns [`LifecyclePhase6ErrorV1`] if the fixed trust anchor is
            /// stale or the signature does not bind the exact provider body.
            pub fn authenticate_readback<'owner>(
                &'owner mut self,
                exact_readback: &[u8],
                signature: &Signature,
            ) -> Result<$name<'owner>, LifecyclePhase6ErrorV1> {
                let current_authority = self.0.current_digest;
                self.0.authenticate(
                    exact_readback,
                    signature,
                    $provider,
                    |fields, provider_subject, verification_policy| $name {
                        fields,
                        provider_subject,
                        verification_policy,
                        current_authority,
                        _owner: PhantomData,
                    },
                )
            }
        }

        #[doc = $summary]
        #[derive(Debug)]
        pub struct $name<'owner> {
            fields: ExternalProviderDecodedReadback,
            provider_subject: ObjectDigest,
            verification_policy: ObjectDigest,
            current_authority: ObjectDigest,
            _owner: PhantomData<&'owner mut $owner>,
        }

        impl $name<'_> {
            /// Encodes the exact provider-specific body that must be signed.
            #[must_use]
            pub fn canonical_readback_body(
                current: &CurrentLifecycleOperationV1<'_>,
                identity: [u8; 16],
                version: ObjectDigest,
                request: ObjectDigest,
                result: ObjectDigest,
                inventory: ObjectDigest,
                generation: u64,
            ) -> [u8; 225] {
                encode_external_provider_readback(
                    $provider,
                    current.operation().operation_id(),
                    current.operation().project(),
                    current.projection_root(),
                    identity,
                    version,
                    request,
                    result,
                    inventory,
                    generation,
                )
            }

            const PROVIDER: LifecycleExternalAvailabilityProviderV1 = $provider;
        }
    };
}

provider_readback!(
    LifecycleServiceCheckpointTrustOwnerV1,
    LifecycleServiceCheckpointAvailabilityV1,
    LifecycleExternalAvailabilityProviderV1::ServiceCheckpoint,
    "service-checkpoint-authority-v1.journal",
    "Carries an exact service-checkpoint owner readback."
);
provider_readback!(
    LifecycleSecretIssuerTrustOwnerV1,
    LifecycleSecretIssuerAvailabilityV1,
    LifecycleExternalAvailabilityProviderV1::SecretIssuer,
    "secret-issuer-authority-v1.journal",
    "Carries an exact secret-issuer authorization readback."
);
provider_readback!(
    LifecycleStorageRetentionTrustOwnerV1,
    LifecycleStorageRetentionAvailabilityV1,
    LifecycleExternalAvailabilityProviderV1::RetentionStorage,
    "storage-retention-authority-v1.journal",
    "Carries an exact Storage hold/currentness readback."
);

impl LifecycleStorageRetentionAvailabilityV1<'_> {
    /// Encodes the sole accepted Storage `HoldSnapshot` acknowledgement body.
    #[must_use]
    pub fn canonical_hold_readback_body(
        current: &CurrentLifecycleOperationV1<'_>,
        resource: LifecycleResourceV1,
        inventory: ObjectDigest,
        generation: u64,
    ) -> Result<[u8; 225], LifecyclePhase6ErrorV1> {
        let snapshot = match current.operation().intent() {
            super::LifecycleIntentV1::Snapshot { snapshot, .. }
            | super::LifecycleIntentV1::Hibernate { snapshot, .. } => *snapshot,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if !matches!(resource, LifecycleResourceV1::Snapshot(_))
            || inventory.as_bytes() == &[0; 32]
            || generation == 0
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let (version, request, result) = storage_hold_bindings(
            current.operation().operation_id(),
            current.operation().project(),
            current.projection_root(),
            resource,
            snapshot,
            inventory,
            generation,
        );
        Ok(Self::canonical_readback_body(
            current,
            *resource.as_bytes(),
            version,
            request,
            result,
            inventory,
            generation,
        ))
    }
}

impl LifecycleExternalAvailabilityEvidenceV1 {
    fn from_protected_observation(
        current: &CurrentLifecycleOperationV1<'_>,
        dependency: &ExternalDependency,
        observation: LifecycleEffectObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let (class, _required, identity, version) = external_dependency_binding(dependency);
        let provider = external_dependency_provider(class);
        let effect_domain =
            external_dependency_effect_domain(class).ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let effect = observation.request();
        if effect.operation() != current.operation().operation_id()
            || effect.operation_revision() != current.operation().record_revision()
            || effect.domain() != effect_domain
            || effect.target() != identity
            || effect.prerequisite() != version
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_exact_observation(
            current,
            class,
            identity,
            version,
            provider,
            effect.payload(),
            observation.result(),
            observation.inventory(),
            observation.inventory_generation(),
            ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(observation.inventory_source().as_bytes())
                    .chain_update(observation.inventory_session().as_bytes())
                    .finalize()
                    .into(),
            ),
        )
    }

    fn from_provider_readback(
        current: &CurrentLifecycleOperationV1<'_>,
        dependency: &ExternalDependency,
        authenticated: LifecycleAuthenticatedBrokerEffectV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let (class, _required, identity, version) = external_dependency_binding(dependency);
        let provider = external_dependency_provider(class);
        let effect_domain =
            external_dependency_effect_domain(class).ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let effect = authenticated.lifecycle_request();
        if effect.operation() != current.operation().operation_id()
            || effect.operation_revision() != current.operation().record_revision()
            || effect.domain() != effect_domain
            || effect.target() != identity
            || effect.prerequisite() != version
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let request = effect.payload();
        let observation = authenticated.observe(outcome, inventory)?;
        if observation.request() != effect {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Self::from_exact_observation(
            current,
            class,
            identity,
            version,
            provider,
            request,
            observation.result(),
            observation.inventory(),
            observation.inventory_generation(),
            ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(observation.inventory_source().as_bytes())
                    .chain_update(observation.inventory_session().as_bytes())
                    .finalize()
                    .into(),
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_exact_observation(
        current: &CurrentLifecycleOperationV1<'_>,
        class: LifecycleSnapshotDependencyClassV1,
        identity: [u8; 16],
        version: ObjectDigest,
        provider: LifecycleExternalAvailabilityProviderV1,
        request: ObjectDigest,
        result: ObjectDigest,
        inventory: ObjectDigest,
        generation: u64,
        currentness: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if result.as_bytes() == &[0; 32]
            || inventory.as_bytes() == &[0; 32]
            || generation == 0
            || currentness.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let receipt = external_availability_receipt(
            current, class, identity, version, provider, request, result, inventory,
        );
        Ok(Self {
            operation: current.operation().operation_id(),
            project: current.operation().project(),
            projection_root: current.projection_root(),
            dependency: version,
            class,
            identity,
            provider,
            request,
            receipt,
            producer_inventory: inventory,
            producer_generation: generation,
            producer_result: result,
            producer_currentness: currentness,
        })
    }
}

impl CurrentLifecycleOperationV1<'_> {
    /// Converts one current provider availability proof into a retention acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the proof belongs to this
    /// exact snapshot operation and its provider-derived resource identity.
    pub fn retain_external_dependency(
        &self,
        evidence: LifecycleExternalAvailabilityEvidenceV1,
    ) -> Result<LifecycleProtectedRetentionAcknowledgementV1, LifecyclePhase6ErrorV1> {
        if evidence.operation != self.operation().operation_id()
            || evidence.project != self.operation().project()
            || evidence.projection_root != self.projection_root()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let snapshot = match self.operation().intent() {
            super::LifecycleIntentV1::Snapshot { snapshot, .. }
            | super::LifecycleIntentV1::Hibernate { snapshot, .. } => *snapshot,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let identity = ResourceId::from_bytes(evidence.identity);
        let resource = match evidence.class {
            LifecycleSnapshotDependencyClassV1::ExternalMutableView => {
                LifecycleResourceV1::View(ViewId::from_bytes(evidence.identity))
            }
            LifecycleSnapshotDependencyClassV1::ExternalPackage => {
                LifecycleResourceV1::Environment(identity)
            }
            LifecycleSnapshotDependencyClassV1::ExternalSecret => {
                LifecycleResourceV1::Capability(identity)
            }
            LifecycleSnapshotDependencyClassV1::ExternalService
            | LifecycleSnapshotDependencyClassV1::ExternalNetwork => {
                LifecycleResourceV1::Other(identity)
            }
            LifecycleSnapshotDependencyClassV1::ImmutableRetained
            | LifecycleSnapshotDependencyClassV1::OwnedHeldStorage => {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        };
        LifecycleProtectedRetentionAcknowledgementV1::from_authenticated_provider(
            evidence.operation,
            evidence.project,
            evidence.projection_root,
            resource,
            ResourceId::from_bytes(*snapshot.as_bytes()),
            evidence.provider as u8,
            evidence.producer_generation,
            evidence.producer_result,
            evidence.producer_currentness,
            evidence.receipt,
        )
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
    }

    /// Converts one fixed Storage hold readback into a retention acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the provider readback binds
    /// this operation, the exact resource identity, holder SnapshotId, result,
    /// inventory, generation, and current protected Storage authority.
    pub fn retain_storage_dependency(
        &self,
        resource: LifecycleResourceV1,
        readback: LifecycleStorageRetentionAvailabilityV1<'_>,
    ) -> Result<LifecycleProtectedRetentionAcknowledgementV1, LifecyclePhase6ErrorV1> {
        let snapshot = match self.operation().intent() {
            super::LifecycleIntentV1::Snapshot { snapshot, .. }
            | super::LifecycleIntentV1::Hibernate { snapshot, .. } => *snapshot,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let (fields, provider, provider_subject, verification_policy, current_authority) =
            readback_fields_storage(readback);
        let (expected_version, expected_request, expected_result) = storage_hold_bindings(
            self.operation().operation_id(),
            self.operation().project(),
            self.projection_root(),
            resource,
            snapshot,
            fields.inventory,
            fields.generation,
        );
        if fields.operation != self.operation().operation_id()
            || fields.project != self.operation().project()
            || fields.projection_root != self.projection_root()
            || fields.identity != *resource.as_bytes()
            || provider != LifecycleExternalAvailabilityProviderV1::RetentionStorage
            || !matches!(resource, LifecycleResourceV1::Snapshot(_))
            || fields.version != expected_version
            || fields.request != expected_request
            || fields.result != expected_result
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let currentness = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(fields.inventory.as_bytes())
                .chain_update(provider_subject.as_bytes())
                .chain_update(verification_policy.as_bytes())
                .chain_update(current_authority.as_bytes())
                .finalize()
                .into(),
        );
        let class = LifecycleSnapshotDependencyClassV1::OwnedHeldStorage;
        let receipt = external_availability_receipt(
            self,
            class,
            fields.identity,
            fields.version,
            provider,
            fields.request,
            fields.result,
            fields.inventory,
        );
        LifecycleProtectedRetentionAcknowledgementV1::from_authenticated_provider(
            fields.operation,
            fields.project,
            fields.projection_root,
            resource,
            ResourceId::from_bytes(*snapshot.as_bytes()),
            provider as u8,
            fields.generation,
            fields.result,
            currentness,
            receipt,
        )
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
    }

    /// Joins one exact mutable-view request to a Mount-owner result.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a substituted dependency,
    /// provider, request, signed outcome, or post-effect inventory readback.
    pub(crate) fn observe_external_view_availability(
        &self,
        dependency: &ExternalDependency,
        authenticated: LifecycleAuthenticatedBrokerEffectV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        if !matches!(dependency, ExternalDependency::ImmutableView { .. }) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleExternalAvailabilityEvidenceV1::from_provider_readback(
            self,
            dependency,
            authenticated,
            outcome,
            inventory,
        )
    }

    /// Joins one exact mutable-view dependency to protected Mount evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the fixed-session observation
    /// names this current operation and the exact declared view/version.
    pub fn observe_external_view_availability_from_protected(
        &self,
        dependency: &ExternalDependency,
        observation: LifecycleEffectObservationV1,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        if !matches!(dependency, ExternalDependency::ImmutableView { .. }) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleExternalAvailabilityEvidenceV1::from_protected_observation(
            self,
            dependency,
            observation,
        )
    }

    /// Joins one exact endpoint contract to a Network-owner result.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a non-network dependency or a
    /// substituted contract version, request, result, or Network inventory.
    pub(crate) fn observe_external_network_availability(
        &self,
        dependency: &ExternalDependency,
        authenticated: LifecycleAuthenticatedBrokerEffectV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        if !matches!(dependency, ExternalDependency::Network { .. }) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleExternalAvailabilityEvidenceV1::from_provider_readback(
            self,
            dependency,
            authenticated,
            outcome,
            inventory,
        )
    }

    /// Joins one exact network dependency to protected Network evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the fixed-session observation
    /// names this current operation and the exact declared contract version.
    pub fn observe_external_network_availability_from_protected(
        &self,
        dependency: &ExternalDependency,
        observation: LifecycleEffectObservationV1,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        if !matches!(dependency, ExternalDependency::Network { .. }) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleExternalAvailabilityEvidenceV1::from_protected_observation(
            self,
            dependency,
            observation,
        )
    }

    /// Joins a package dependency to a sealed Cache-owner result and replay.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the exact dependency identity,
    /// lifecycle request, effect result, and post-effect Cache generation agree.
    #[cfg(target_os = "linux")]
    pub fn observe_external_cache_availability(
        &self,
        dependency: &ExternalDependency,
        effect: CurrentLifecycleEffectV1<'_>,
        owner: &mut crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        let (class, _required, identity, version) = external_dependency_binding(dependency);
        let provider = external_dependency_provider(class);
        let ExternalDependency::Package { environment, .. } = dependency else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        let result = owner
            .observe_lifecycle_availability(environment)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        if provider != LifecycleExternalAvailabilityProviderV1::PackageCache
            || effect.operation() != self.operation().operation_id()
            || effect.operation_revision() != self.operation().record_revision()
            || effect.domain() != LifecycleEffectDomainV1::Cache
            || effect.target() != identity
            || effect.prerequisite() != version
            || result.effect()
                != crate::cache_residency::cache_lifecycle_availability_effect_v1(
                    environment,
                    result.currentness(),
                )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let request = effect.payload();
        let observation = effect.observe_cache_availability(result, owner)?;
        LifecycleExternalAvailabilityEvidenceV1::from_exact_observation(
            self,
            class,
            identity,
            version,
            provider,
            request,
            observation.result(),
            observation.inventory(),
            observation.inventory_generation(),
            ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(observation.inventory_source().as_bytes())
                    .chain_update(observation.inventory_session().as_bytes())
                    .finalize()
                    .into(),
            ),
        )
    }

    /// Joins an exact service checkpoint to its service-owner readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a non-service dependency or a
    /// foreign operation, service identity, checkpoint version, or readback.
    pub fn observe_external_service_availability(
        &self,
        dependency: &ExternalDependency,
        readback: LifecycleServiceCheckpointAvailabilityV1<'_>,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        let ExternalDependency::Service { .. } = dependency else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        external_provider_evidence(self, dependency, readback_fields(readback))
    }

    /// Joins an exact secret version to its issuer-owner authorization readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a non-secret dependency or a
    /// foreign operation, issuer-scoped version, request, or readback.
    pub fn observe_external_secret_availability(
        &self,
        dependency: &ExternalDependency,
        readback: LifecycleSecretIssuerAvailabilityV1<'_>,
    ) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
        let ExternalDependency::Secret { .. } = dependency else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        external_provider_evidence(self, dependency, readback_fields_secret(readback))
    }
}

#[allow(clippy::too_many_arguments)]
fn storage_hold_bindings(
    operation: OperationId,
    project: ProjectId,
    projection_root: ObjectDigest,
    resource: LifecycleResourceV1,
    holder: SnapshotId,
    inventory: ObjectDigest,
    generation: u64,
) -> (ObjectDigest, ObjectDigest, ObjectDigest) {
    let version = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.storage-hold-version.v1\0")
            .chain_update(holder.as_bytes())
            .chain_update(resource.as_bytes())
            .finalize()
            .into(),
    );
    let request = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.storage-hold-snapshot-request.v1\0")
            .chain_update(operation.as_bytes())
            .chain_update(project.as_bytes())
            .chain_update(projection_root.as_bytes())
            .chain_update(resource.as_bytes())
            .chain_update(holder.as_bytes())
            .finalize()
            .into(),
    );
    let result = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.storage-hold-snapshot-result.v1\0")
            .chain_update(request.as_bytes())
            .chain_update(inventory.as_bytes())
            .chain_update(generation.to_be_bytes())
            .finalize()
            .into(),
    );
    (version, request, result)
}

type ExternalProviderReadbackFields = (
    ExternalProviderDecodedReadback,
    LifecycleExternalAvailabilityProviderV1,
    ObjectDigest,
    ObjectDigest,
    ObjectDigest,
);

fn readback_fields(
    readback: LifecycleServiceCheckpointAvailabilityV1<'_>,
) -> ExternalProviderReadbackFields {
    (
        readback.fields,
        LifecycleServiceCheckpointAvailabilityV1::PROVIDER,
        readback.provider_subject,
        readback.verification_policy,
        readback.current_authority,
    )
}

fn readback_fields_secret(
    readback: LifecycleSecretIssuerAvailabilityV1<'_>,
) -> ExternalProviderReadbackFields {
    (
        readback.fields,
        LifecycleSecretIssuerAvailabilityV1::PROVIDER,
        readback.provider_subject,
        readback.verification_policy,
        readback.current_authority,
    )
}

fn readback_fields_storage(
    readback: LifecycleStorageRetentionAvailabilityV1<'_>,
) -> ExternalProviderReadbackFields {
    (
        readback.fields,
        LifecycleStorageRetentionAvailabilityV1::PROVIDER,
        readback.provider_subject,
        readback.verification_policy,
        readback.current_authority,
    )
}

fn external_provider_evidence(
    current: &CurrentLifecycleOperationV1<'_>,
    dependency: &ExternalDependency,
    readback: ExternalProviderReadbackFields,
) -> Result<LifecycleExternalAvailabilityEvidenceV1, LifecyclePhase6ErrorV1> {
    let (fields, provider, provider_subject, verification_policy, current_authority) = readback;
    let (class, _required, expected_identity, expected_version) =
        external_dependency_binding(dependency);
    if fields.operation != current.operation().operation_id()
        || fields.project != current.operation().project()
        || fields.projection_root != current.projection_root()
        || fields.identity != expected_identity
        || fields.version != expected_version
        || provider != external_dependency_provider(class)
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let complete_inventory = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.external-provider-current-readback.v1\0")
            .chain_update([provider as u8])
            .chain_update(fields.generation.to_be_bytes())
            .chain_update(fields.inventory.as_bytes())
            .chain_update(provider_subject.as_bytes())
            .chain_update(verification_policy.as_bytes())
            .chain_update(current_authority.as_bytes())
            .chain_update(fields.identity)
            .chain_update(fields.version.as_bytes())
            .finalize()
            .into(),
    );
    LifecycleExternalAvailabilityEvidenceV1::from_exact_observation(
        current,
        class,
        fields.identity,
        fields.version,
        provider,
        fields.request,
        fields.result,
        complete_inventory,
        fields.generation,
        current_authority,
    )
}

#[derive(Clone, Copy, Debug)]
struct ExternalProviderDecodedReadback {
    operation: OperationId,
    project: ProjectId,
    projection_root: ObjectDigest,
    identity: [u8; 16],
    version: ObjectDigest,
    request: ObjectDigest,
    result: ObjectDigest,
    inventory: ObjectDigest,
    generation: u64,
}

fn decode_external_provider_readback(
    bytes: &[u8],
    provider: LifecycleExternalAvailabilityProviderV1,
) -> Result<ExternalProviderDecodedReadback, LifecyclePhase6ErrorV1> {
    const BYTES: usize = 225;
    if bytes.len() != BYTES || &bytes[..8] != b"AOSLAVP1" || bytes[8] != provider as u8 {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let operation = OperationId::from_bytes(readback_array(bytes, 9)?);
    let project = ProjectId::from_bytes(readback_array(bytes, 25)?);
    let projection_root = ObjectDigest::from_bytes(readback_array(bytes, 41)?);
    let identity = readback_array(bytes, 73)?;
    let version = ObjectDigest::from_bytes(readback_array(bytes, 89)?);
    let request = ObjectDigest::from_bytes(readback_array(bytes, 121)?);
    let result = ObjectDigest::from_bytes(readback_array(bytes, 153)?);
    let inventory = ObjectDigest::from_bytes(readback_array(bytes, 185)?);
    let generation = u64::from_be_bytes(readback_array(bytes, 217)?);
    Ok(ExternalProviderDecodedReadback {
        operation,
        project,
        projection_root,
        identity,
        version,
        request,
        result,
        inventory,
        generation,
    })
}

fn validate_external_provider_fields(
    fields: &ExternalProviderDecodedReadback,
) -> Result<(), LifecyclePhase6ErrorV1> {
    if fields.operation.as_bytes() == &[0; 16]
        || fields.project.as_bytes() == &[0; 16]
        || fields.projection_root.as_bytes() == &[0; 32]
        || fields.identity == [0; 16]
        || fields.version.as_bytes() == &[0; 32]
        || fields.request.as_bytes() == &[0; 32]
        || fields.result.as_bytes() == &[0; 32]
        || fields.inventory.as_bytes() == &[0; 32]
        || fields.generation == 0
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_external_provider_readback(
    provider: LifecycleExternalAvailabilityProviderV1,
    operation: OperationId,
    project: ProjectId,
    projection_root: ObjectDigest,
    identity: [u8; 16],
    version: ObjectDigest,
    request: ObjectDigest,
    result: ObjectDigest,
    inventory: ObjectDigest,
    generation: u64,
) -> [u8; 225] {
    let mut bytes = [0_u8; 225];
    bytes[..8].copy_from_slice(b"AOSLAVP1");
    bytes[8] = provider as u8;
    bytes[9..25].copy_from_slice(operation.as_bytes());
    bytes[25..41].copy_from_slice(project.as_bytes());
    bytes[41..73].copy_from_slice(projection_root.as_bytes());
    bytes[73..89].copy_from_slice(&identity);
    bytes[89..121].copy_from_slice(version.as_bytes());
    bytes[121..153].copy_from_slice(request.as_bytes());
    bytes[153..185].copy_from_slice(result.as_bytes());
    bytes[185..217].copy_from_slice(inventory.as_bytes());
    bytes[217..225].copy_from_slice(&generation.to_be_bytes());
    bytes
}

fn readback_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], LifecyclePhase6ErrorV1> {
    bytes
        .get(offset..offset.saturating_add(N))
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

struct DecodedExternalProviderAuthorityV1 {
    generation: u64,
    signer: KeyReference,
    trust_scope: TrustScopeId,
    purpose: SignaturePurpose,
    policy: Vec<u8>,
    public_key: [u8; 32],
    current_digest: ObjectDigest,
}

fn decode_external_provider_authority(
    bytes: &[u8],
    provider: LifecycleExternalAvailabilityProviderV1,
) -> Result<DecodedExternalProviderAuthorityV1, LifecyclePhase6ErrorV1> {
    if bytes.len() < EXTERNAL_PROVIDER_FIXED_BYTES + EXTERNAL_PROVIDER_DIGEST_BYTES
        || bytes.get(..8) != Some(EXTERNAL_PROVIDER_AUTHORITY_MAGIC.as_slice())
        || u16::from_be_bytes(readback_array(bytes, 8)?) != EXTERNAL_PROVIDER_AUTHORITY_VERSION
        || bytes[10] != provider as u8
        || bytes[11..16] != [0; 5]
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let generation = u64::from_be_bytes(readback_array(bytes, 16)?);
    let policy_len = u32::from_be_bytes(readback_array(bytes, 24)?) as usize;
    if generation == 0 || policy_len == 0 || policy_len > MAXIMUM_EXTERNAL_PROVIDER_POLICY_BYTES {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let expected_len = EXTERNAL_PROVIDER_FIXED_BYTES
        .checked_add(policy_len)
        .and_then(|length| length.checked_add(EXTERNAL_PROVIDER_DIGEST_BYTES))
        .ok_or(LifecyclePhase6ErrorV1::Capacity)?;
    if bytes.len() != expected_len {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    let public_key = readback_array(bytes, 28)?;
    let policy_end = EXTERNAL_PROVIDER_FIXED_BYTES + policy_len;
    let policy = bytes[EXTERNAL_PROVIDER_FIXED_BYTES..policy_end].to_vec();
    let stored_digest = ObjectDigest::from_bytes(readback_array(bytes, policy_end)?);
    let computed_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(EXTERNAL_PROVIDER_AUTHORITY_DOMAIN)
            .chain_update(&bytes[..policy_end])
            .finalize()
            .into(),
    );
    if stored_digest != computed_digest {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }

    let trust_policy =
        aos_sandbox_core::format::decode_trust_policy(&policy, external_provider_decode_limits())
            .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    let [signer] = trust_policy.allowed_keys() else {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    };
    if signer.generation() != generation
        || signer.public_key_sha256() != ObjectDigest::from_bytes(Sha256::digest(public_key).into())
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(DecodedExternalProviderAuthorityV1 {
        generation,
        signer: signer.clone(),
        trust_scope: trust_policy.trust_scope(),
        purpose: trust_policy.purpose(),
        policy,
        public_key,
        current_digest: stored_digest,
    })
}

const fn external_provider_decode_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_EXTERNAL_PROVIDER_POLICY_BYTES,
        maximum_collection_items: 64,
        maximum_total_items: 512,
        maximum_byte_string_bytes: 4096,
        maximum_text_bytes: 4096,
        maximum_depth: 16,
    }
}

const fn external_provider_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_EXTERNAL_PROVIDER_POLICY_BYTES + 128,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 8,
        maximum_transaction_bytes: MAXIMUM_EXTERNAL_PROVIDER_POLICY_BYTES + 1024,
        maximum_transactions: 4096,
        maximum_materialized_bytes: 512 * 1024,
        maximum_materialized_records: 64,
    }
}

impl LifecycleSnapshotDependencyClassV1 {
    const fn is_self_contained(self) -> bool {
        matches!(Self::ImmutableRetained | Self::OwnedHeldStorage, self)
    }
}

/// Binds one dependency identity to exact version and availability evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleSnapshotDependencyV1 {
    identity: [u8; 16],
    class: LifecycleSnapshotDependencyClassV1,
    version: ObjectDigest,
    availability_receipt: Option<ObjectDigest>,
    availability_operation: Option<OperationId>,
    availability_project: Option<ProjectId>,
    availability_projection_root: Option<ObjectDigest>,
    availability_producer_inventory: Option<ObjectDigest>,
    required: bool,
}

impl LifecycleSnapshotDependencyV1 {
    /// Derives one exact dependency from protected retention acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for sentinel retained evidence.
    pub fn from_retention(
        acknowledgement: LifecycleRetentionAcknowledgementV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let identity = *acknowledgement.resource().as_bytes();
        let class = if matches!(
            acknowledgement.resource(),
            super::LifecycleResourceV1::Snapshot(_)
        ) {
            LifecycleSnapshotDependencyClassV1::OwnedHeldStorage
        } else {
            LifecycleSnapshotDependencyClassV1::ImmutableRetained
        };
        let version = acknowledgement.claim().digest();
        let availability_receipt = Some(acknowledgement.receipt().digest());
        if identity == [0; 16] || version.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            identity,
            class,
            version,
            availability_receipt,
            availability_operation: None,
            availability_project: None,
            availability_projection_root: None,
            availability_producer_inventory: None,
            required: true,
        })
    }

    /// Derives an exact contract row from one portable external dependency.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a zero availability receipt or
    /// for malformed sentinel fields in the canonical snapshot dependency.
    pub fn from_external(
        dependency: &ExternalDependency,
        availability: Option<&LifecycleExternalAvailabilityEvidenceV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let (class, required, identity, version) = external_dependency_binding(dependency);
        if identity == [0; 16]
            || version.as_bytes() == &[0; 32]
            || availability.is_some_and(|evidence| {
                evidence.dependency != version
                    || evidence.class != class
                    || evidence.identity != identity
                    || evidence.provider != external_dependency_provider(class)
                    || evidence.request.as_bytes() == &[0; 32]
            })
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            identity,
            class,
            version,
            availability_receipt: availability.map(|evidence| evidence.receipt),
            availability_operation: availability.map(|evidence| evidence.operation),
            availability_project: availability.map(|evidence| evidence.project),
            availability_projection_root: availability.map(|evidence| evidence.projection_root),
            availability_producer_inventory: availability
                .map(|evidence| evidence.producer_inventory),
            required,
        })
    }

    /// Returns whether this dependency can enter a self-contained manifest.
    #[must_use]
    pub const fn is_self_contained(self) -> bool {
        self.class.is_self_contained()
    }
}

/// Proves the snapshot's declared availability contract against its manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshotAvailabilityContractV1 {
    operation: OperationId,
    project: ProjectId,
    snapshot: SnapshotId,
    manifest: LifecycleSnapshotManifestDigestV1,
    portable_root: ObjectDigest,
    historical_policy: ObjectDigest,
    source_sandbox: SandboxId,
    source_incarnation: IncarnationId,
    source_assignment_epoch: AssignmentEpoch,
    attachment_views: Vec<ObjectDigest>,
    projection_root: ObjectDigest,
    mode: LifecycleSnapshotAvailabilityModeV1,
    dependencies: Vec<LifecycleSnapshotDependencyV1>,
}

impl LifecycleSnapshotAvailabilityContractV1 {
    /// Validates self-contained versus external dependency semantics.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for unordered/duplicate dependency
    /// identities, external state hidden by a self-contained declaration, or
    /// disagreement with the portable manifest's external dependency count.
    pub fn validate(
        current: &CurrentLifecycleOperationV1<'_>,
        retention: &CurrentLifecycleRetentionLedgerV1<'_>,
        snapshot: SnapshotId,
        validated: &LifecycleValidatedSnapshotV1,
        portable_root: ObjectDigest,
        mode: LifecycleSnapshotAvailabilityModeV1,
        dependencies: Vec<LifecycleSnapshotDependencyV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if retention.projection_root() != current.projection_root()
            || validated
                .acknowledgements()
                .iter()
                .any(|acknowledgement| !acknowledgement.is_bound_to(retention.retention()))
            || snapshot.as_bytes() == &[0; 16]
            || portable_root.as_bytes() == &[0; 32]
            || dependencies.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let external = dependencies
            .iter()
            .filter(|dependency| !dependency.is_self_contained())
            .collect::<Vec<_>>();
        let retained = dependencies
            .iter()
            .filter(|dependency| dependency.is_self_contained())
            .collect::<Vec<_>>();
        let declared_external = validated.snapshot().external_dependencies();
        let external_is_exact = external_dependencies_are_exact(&external, declared_external)?;
        let retained_is_exact =
            retained_dependencies_are_exact(&retained, validated.acknowledgements())?;
        if !retained_is_exact {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        match mode {
            LifecycleSnapshotAvailabilityModeV1::SelfContained
                if !external.is_empty()
                    || !declared_external.is_empty()
                    || dependencies.iter().any(|dependency| {
                        dependency.required && dependency.availability_receipt.is_none()
                    }) =>
            {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
            LifecycleSnapshotAvailabilityModeV1::External
                if !external_is_exact
                    || external.iter().any(|dependency| {
                        dependency.required
                            && (dependency.availability_receipt.is_none()
                                || dependency.availability_operation
                                    != Some(current.operation().operation_id())
                                || dependency.availability_project
                                    != Some(current.operation().project())
                                || dependency.availability_projection_root
                                    != Some(current.projection_root())
                                || dependency
                                    .availability_producer_inventory
                                    .is_none_or(|inventory| inventory.as_bytes() == &[0; 32]))
                    }) =>
            {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
            _ => {}
        }
        let source = validated.snapshot().source_assignment();
        let attachment_views = validated
            .snapshot()
            .attachments()
            .iter()
            .map(|attachment| attachment.view().digest())
            .collect();
        Ok(Self {
            operation: current.operation().operation_id(),
            project: current.operation().project(),
            snapshot,
            manifest: validated.manifest(),
            portable_root,
            historical_policy: validated.snapshot().historical_policy().digest(),
            source_sandbox: source.sandbox(),
            source_incarnation: source.incarnation(),
            source_assignment_epoch: source.epoch(),
            attachment_views,
            projection_root: current.projection_root(),
            mode,
            dependencies,
        })
    }

    /// Returns the logical snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the exact canonical portable manifest commitment.
    #[must_use]
    pub const fn manifest(&self) -> LifecycleSnapshotManifestDigestV1 {
        self.manifest
    }

    /// Returns the declared availability class.
    #[must_use]
    pub const fn mode(&self) -> LifecycleSnapshotAvailabilityModeV1 {
        self.mode
    }

    /// Returns the historical source sandbox carried by the snapshot.
    #[must_use]
    pub const fn source_sandbox(&self) -> SandboxId {
        self.source_sandbox
    }

    /// Returns the historical incarnation that must never be reused.
    #[must_use]
    pub const fn source_incarnation(&self) -> IncarnationId {
        self.source_incarnation
    }

    /// Returns the historical assignment epoch that must be superseded.
    #[must_use]
    pub const fn source_assignment_epoch(&self) -> AssignmentEpoch {
        self.source_assignment_epoch
    }

    /// Returns the historical policy descriptor committed by the snapshot.
    #[must_use]
    pub const fn historical_policy(&self) -> ObjectDigest {
        self.historical_policy
    }

    /// Borrows source attachment views in canonical destination-slot order.
    #[must_use]
    pub fn attachment_views(&self) -> &[ObjectDigest] {
        &self.attachment_views
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }

    /// Borrows the canonical dependency contracts.
    #[must_use]
    pub fn dependencies(&self) -> &[LifecycleSnapshotDependencyV1] {
        &self.dependencies
    }

    /// Returns the complete availability and dependency-set commitment.
    #[must_use]
    pub fn commitment(&self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.snapshot-availability.v1\0")
            .chain_update(self.operation.as_bytes())
            .chain_update(self.project.as_bytes())
            .chain_update(self.snapshot.as_bytes())
            .chain_update(self.manifest.digest().as_bytes())
            .chain_update(self.portable_root.as_bytes())
            .chain_update(self.historical_policy.as_bytes())
            .chain_update(self.source_sandbox.as_bytes())
            .chain_update(self.source_incarnation.as_bytes())
            .chain_update(self.source_assignment_epoch.get().to_be_bytes())
            .chain_update(self.projection_root.as_bytes())
            .chain_update([self.mode as u8])
            .chain_update((self.dependencies.len() as u32).to_be_bytes());
        for dependency in &self.dependencies {
            hasher = hasher
                .chain_update(dependency.identity)
                .chain_update([dependency.class as u8, u8::from(dependency.required)])
                .chain_update(dependency.version.as_bytes())
                .chain_update(
                    dependency
                        .availability_receipt
                        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                        .as_bytes(),
                )
                .chain_update(
                    dependency
                        .availability_operation
                        .map_or([0; 16], |operation| *operation.as_bytes()),
                )
                .chain_update(
                    dependency
                        .availability_project
                        .map_or([0; 16], |project| *project.as_bytes()),
                )
                .chain_update(
                    dependency
                        .availability_projection_root
                        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                        .as_bytes(),
                )
                .chain_update(
                    dependency
                        .availability_producer_inventory
                        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                        .as_bytes(),
                );
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Joins this contract to one protected resumable-transfer projection.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the fixed-owner record carries
    /// the exact transfer, resume boundary, and optional atomic publication.
    pub fn join_transfer(
        &self,
        protected: &ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<LifecycleSnapshotTransferJoinV1, LifecyclePhase6ErrorV1> {
        let record = protected.record().record();
        let state = record
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let transfer = state.manifest();
        let identity = transfer.identity();
        if record.domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || record.operation() != self.operation
            || identity.operation() != self.operation
            || identity.project() != self.project
            || identity.sandbox() != self.source_sandbox
            || identity.incarnation() != self.source_incarnation
            || identity.assignment_epoch() != self.source_assignment_epoch
            || identity.snapshot() != self.snapshot
            || transfer.root().digest() != self.portable_root
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let publication = state.publication();
        if (publication.is_some()
            && self
                .dependencies
                .iter()
                .any(|dependency| dependency.required && dependency.availability_receipt.is_none()))
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(LifecycleSnapshotTransferJoinV1 {
            operation: self.operation,
            project: self.project,
            snapshot: self.snapshot,
            manifest: self.manifest,
            availability: self.commitment(),
            projection_root: self.projection_root,
            transfer_manifest: identity.manifest_digest(),
            resume_boundary: Some(state.resume().next_chunk()),
            resume_commitment: Some(record.payload_digest()),
            completion: publication.map(|value| value.publication_digest),
        })
    }
}

fn external_availability_receipt(
    current: &CurrentLifecycleOperationV1<'_>,
    class: LifecycleSnapshotDependencyClassV1,
    identity: [u8; 16],
    dependency: ObjectDigest,
    provider: LifecycleExternalAvailabilityProviderV1,
    request: ObjectDigest,
    result: ObjectDigest,
    inventory: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.external-availability-receipt.v1\0")
            .chain_update(current.operation().operation_id().as_bytes())
            .chain_update(current.operation().project().as_bytes())
            .chain_update(current.projection_root().as_bytes())
            .chain_update([class as u8, provider as u8])
            .chain_update(identity)
            .chain_update(dependency.as_bytes())
            .chain_update(request.as_bytes())
            .chain_update(result.as_bytes())
            .chain_update(inventory.as_bytes())
            .finalize()
            .into(),
    )
}

const fn external_dependency_provider(
    class: LifecycleSnapshotDependencyClassV1,
) -> LifecycleExternalAvailabilityProviderV1 {
    match class {
        LifecycleSnapshotDependencyClassV1::ExternalMutableView => {
            LifecycleExternalAvailabilityProviderV1::MutableViewMount
        }
        LifecycleSnapshotDependencyClassV1::ExternalPackage => {
            LifecycleExternalAvailabilityProviderV1::PackageCache
        }
        LifecycleSnapshotDependencyClassV1::ExternalService => {
            LifecycleExternalAvailabilityProviderV1::ServiceCheckpoint
        }
        LifecycleSnapshotDependencyClassV1::ExternalSecret => {
            LifecycleExternalAvailabilityProviderV1::SecretIssuer
        }
        LifecycleSnapshotDependencyClassV1::ExternalNetwork => {
            LifecycleExternalAvailabilityProviderV1::NetworkContract
        }
        LifecycleSnapshotDependencyClassV1::ImmutableRetained
        | LifecycleSnapshotDependencyClassV1::OwnedHeldStorage => {
            LifecycleExternalAvailabilityProviderV1::RetentionStorage
        }
    }
}

const fn external_dependency_effect_domain(
    class: LifecycleSnapshotDependencyClassV1,
) -> Option<LifecycleEffectDomainV1> {
    match class {
        LifecycleSnapshotDependencyClassV1::ExternalMutableView => {
            Some(LifecycleEffectDomainV1::Mount)
        }
        LifecycleSnapshotDependencyClassV1::ExternalNetwork => {
            Some(LifecycleEffectDomainV1::Network)
        }
        LifecycleSnapshotDependencyClassV1::ExternalPackage => Some(LifecycleEffectDomainV1::Cache),
        LifecycleSnapshotDependencyClassV1::ImmutableRetained
        | LifecycleSnapshotDependencyClassV1::OwnedHeldStorage
        | LifecycleSnapshotDependencyClassV1::ExternalService
        | LifecycleSnapshotDependencyClassV1::ExternalSecret => None,
    }
}

fn external_dependencies_are_exact(
    actual: &[&LifecycleSnapshotDependencyV1],
    declared: &[ExternalDependency],
) -> Result<bool, LifecyclePhase6ErrorV1> {
    if actual.len() != declared.len() {
        return Ok(false);
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(declared.len())
        .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
    for dependency in declared {
        expected.push(LifecycleSnapshotDependencyV1::from_external(
            dependency, None,
        )?);
    }
    expected.sort_unstable();
    Ok(actual.iter().zip(expected).all(|(actual, expected)| {
        actual.identity == expected.identity
            && actual.class == expected.class
            && actual.version == expected.version
            && actual.required == expected.required
    }))
}

fn retained_dependencies_are_exact(
    actual: &[&LifecycleSnapshotDependencyV1],
    acknowledgements: &[LifecycleRetentionAcknowledgementV1],
) -> Result<bool, LifecyclePhase6ErrorV1> {
    if actual.len() != acknowledgements.len() {
        return Ok(false);
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(acknowledgements.len())
        .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
    for acknowledgement in acknowledgements {
        expected.push(LifecycleSnapshotDependencyV1::from_retention(
            *acknowledgement,
        )?);
    }
    expected.sort_unstable();
    Ok(actual
        .iter()
        .zip(expected)
        .all(|(actual, expected)| *actual == &expected))
}

fn external_dependency_binding(
    dependency: &ExternalDependency,
) -> (
    LifecycleSnapshotDependencyClassV1,
    bool,
    [u8; 16],
    ObjectDigest,
) {
    let mut hasher = Sha256::new().chain_update(b"aos.sandbox.lifecycle.external-dependency.v1\0");
    let (class, required, identity) = match dependency {
        ExternalDependency::ImmutableView { view, required } => {
            hasher = hasher
                .chain_update([1])
                .chain_update(view.digest().as_bytes())
                .chain_update(view.encoded_size().to_be_bytes());
            let digest = view.digest();
            let mut identity = [0; 16];
            identity.copy_from_slice(&digest.as_bytes()[..16]);
            (
                LifecycleSnapshotDependencyClassV1::ExternalMutableView,
                *required,
                identity,
            )
        }
        ExternalDependency::Package {
            environment,
            required,
        } => {
            hasher = hasher
                .chain_update([2])
                .chain_update(environment.digest().as_bytes())
                .chain_update(environment.encoded_size().to_be_bytes());
            let digest = environment.digest();
            let mut identity = [0; 16];
            identity.copy_from_slice(&digest.as_bytes()[..16]);
            (
                LifecycleSnapshotDependencyClassV1::ExternalPackage,
                *required,
                identity,
            )
        }
        ExternalDependency::Secret {
            issuer,
            secret,
            opaque_version,
            restore_scope,
            expires_seconds,
            required,
        } => {
            hasher = hasher
                .chain_update([3])
                .chain_update(issuer.as_bytes())
                .chain_update(secret.as_bytes())
                .chain_update((opaque_version.as_bytes().len() as u16).to_be_bytes())
                .chain_update(opaque_version.as_bytes())
                .chain_update(restore_scope.as_bytes())
                .chain_update(expires_seconds.unwrap_or(i64::MIN).to_be_bytes());
            (
                LifecycleSnapshotDependencyClassV1::ExternalSecret,
                *required,
                *secret.as_bytes(),
            )
        }
        ExternalDependency::Service {
            service,
            checkpoint_version,
            checkpoint_sha256,
            available_until,
            required,
        } => {
            hasher = hasher
                .chain_update([4])
                .chain_update(service.as_bytes())
                .chain_update((checkpoint_version.as_bytes().len() as u16).to_be_bytes())
                .chain_update(checkpoint_version.as_bytes())
                .chain_update(checkpoint_sha256.as_bytes())
                .chain_update(available_until.unwrap_or(i64::MIN).to_be_bytes());
            (
                LifecycleSnapshotDependencyClassV1::ExternalService,
                *required,
                *service.as_bytes(),
            )
        }
        ExternalDependency::Network {
            endpoint,
            contract_version,
            available_until,
            required,
        } => {
            hasher = hasher
                .chain_update([5])
                .chain_update(endpoint.as_bytes())
                .chain_update((contract_version.as_bytes().len() as u16).to_be_bytes())
                .chain_update(contract_version.as_bytes())
                .chain_update(available_until.unwrap_or(i64::MIN).to_be_bytes());
            (
                LifecycleSnapshotDependencyClassV1::ExternalNetwork,
                *required,
                *endpoint.as_bytes(),
            )
        }
    };
    (
        class,
        required,
        identity,
        ObjectDigest::from_bytes(hasher.finalize().into()),
    )
}

/// Retains a lifecycle-to-transfer join without carrying transfer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshotTransferJoinV1 {
    operation: OperationId,
    project: ProjectId,
    snapshot: SnapshotId,
    manifest: LifecycleSnapshotManifestDigestV1,
    availability: ObjectDigest,
    projection_root: ObjectDigest,
    transfer_manifest: ObjectDigest,
    resume_boundary: Option<u32>,
    resume_commitment: Option<ObjectDigest>,
    completion: Option<ObjectDigest>,
}

impl LifecycleSnapshotTransferJoinV1 {
    /// Returns the lifecycle operation that owns this transfer.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the project that owns this transfer.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the lifecycle snapshot identity.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the portable lifecycle manifest commitment.
    #[must_use]
    pub const fn lifecycle_manifest(self) -> LifecycleSnapshotManifestDigestV1 {
        self.manifest
    }

    /// Returns the exact multi-node transfer-manifest commitment.
    #[must_use]
    pub const fn transfer_manifest(self) -> ObjectDigest {
        self.transfer_manifest
    }

    /// Returns the exact availability contract joined to this transfer.
    #[must_use]
    pub const fn availability(self) -> ObjectDigest {
        self.availability
    }

    pub(super) const fn projection_root(self) -> ObjectDigest {
        self.projection_root
    }

    /// Returns the authenticated completion commitment, when durable.
    #[must_use]
    pub const fn completion(self) -> Option<ObjectDigest> {
        self.completion
    }

    /// Returns whether every transfer chunk and dependency is durably complete.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.completion.is_some()
    }

    /// Returns the resumable next-chunk boundary, when staged.
    #[must_use]
    pub const fn resume_boundary(self) -> Option<u32> {
        self.resume_boundary
    }

    /// Returns the authenticated staged-prefix commitment.
    #[must_use]
    pub const fn resume_commitment(self) -> Option<ObjectDigest> {
        self.resume_commitment
    }
}
