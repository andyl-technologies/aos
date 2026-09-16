//! Fixed, protected backend-class evidence verification.
//!
//! The verifier manifest is a root-owned fixed file retained for the lifetime
//! of the provider owner. It contains exactly six independent Ed25519 verifier
//! authorities in canonical role order:
//!
//! ```text
//! AOSSPBV1 | version:u16be=1 | entry-count:u8=6 | reserved[5]=0 |
//! repeated entry {
//!   role:u8 | reserved[7]=0 | authority-id[16] | authority-generation:u64be |
//!   authority-digest[32] | key-id[16] | key-generation:u64be |
//!   public-key[32] | public-key-digest[32]
//! }
//! ```
//!
//! Raw transport output is nonauthorizing. A class is accepted only after all
//! required independent authorities sign the exact plan, proof, evidence,
//! reopen identity, and observed descriptor commitment.

use std::collections::BTreeSet;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_source_provider_protocol::{
    digest_provider_proof, provider_resource_commitment_v1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, Stat};
use rustix::rand::GetRandomFlags;
use sha2::{Digest as _, Sha256};

use crate::{
    AcquirePlanV1, ActiveAcquisitionSnapshotV1, BackendEvidenceClassV1, ProviderLedgerError,
    RawAcquireNotAppliedV1, RawBackendReleaseV1, RawReleaseStillPresentV1, ReleasePlanV1,
};

const FIXED_VERIFIER_ROOT: &str = "/var/lib/aos/source-provider/backend-authority";
const VERIFIER_FILE_NAME: &str = "current-verifiers";
const MAGIC: &[u8; 8] = b"AOSSPBV1";
const VERSION: u16 = 1;
const ENTRY_COUNT: usize = 6;
const HEADER_BYTES: usize = 16;
const ENTRY_BYTES: usize = 152;
const MANIFEST_BYTES: usize = HEADER_BYTES + ENTRY_COUNT * ENTRY_BYTES;
const ATTESTATION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-attestation.v1\0";
const ACQUIRE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-acquire-evidence.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-release-evidence.v1\0";
const REOPEN_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-reopen-evidence.v1\0";
const ACQUIRE_ABSENCE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-acquire-absence.v1\0";
const RELEASE_PRESENCE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-release-presence.v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-observation-challenge.v1\0";
const VERIFIER_SET_DOMAIN: &[u8] = b"aos.sandbox.source-provider.backend-verifier-set.v1\0";
const ACQUIRE_ABSENCE_PURPOSE: u8 = 1;
const RELEASE_PRESENCE_PURPOSE: u8 = 2;
const CHALLENGE_LIFETIME_SECONDS: i64 = 60;
const MAXIMUM_INTERRUPTED_ENTROPY_RETRIES: usize = 8;
const ALL_ROLES: &[BackendVerifierRoleV1] = &[
    BackendVerifierRoleV1::ZfsHold,
    BackendVerifierRoleV1::StorageExport,
    BackendVerifierRoleV1::KernelExportGrant,
    BackendVerifierRoleV1::PublisherReceipt,
    BackendVerifierRoleV1::CacheVerity,
    BackendVerifierRoleV1::ReplicaAuthority,
];

/// Identifies one independent protected backend verifier authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BackendVerifierRoleV1 {
    /// Verifies a ZFS snapshot and its active hold.
    ZfsHold = 1,
    /// Verifies a Storage live-export lease and workspace.
    StorageExport = 2,
    /// Verifies the kernel-coupled local export grant.
    KernelExportGrant = 3,
    /// Verifies an immutable publisher receipt and writer closure.
    PublisherReceipt = 4,
    /// Verifies cache residency and the exact fs-verity measurement set.
    CacheVerity = 5,
    /// Verifies replica authority, checkpoint, lag, and access grant.
    ReplicaAuthority = 6,
}

impl BackendVerifierRoleV1 {
    fn decode(value: u8) -> Result<Self, ProviderLedgerError> {
        match value {
            1 => Ok(Self::ZfsHold),
            2 => Ok(Self::StorageExport),
            3 => Ok(Self::KernelExportGrant),
            4 => Ok(Self::PublisherReceipt),
            5 => Ok(Self::CacheVerity),
            6 => Ok(Self::ReplicaAuthority),
            _ => Err(ProviderLedgerError::Corrupt("backend verifier role")),
        }
    }
}

/// Carries one untrusted detached backend-authority attestation.
///
/// Its fields are descriptive only. Only the fixed protected verifier can
/// authenticate it and produce an internal verified-evidence handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBackendAttestationV1 {
    role: BackendVerifierRoleV1,
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
    statement_digest: ObjectDigest,
    signature: [u8; 64],
}

impl RawBackendAttestationV1 {
    /// Collects an untrusted detached signature and signer projection.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        role: BackendVerifierRoleV1,
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        statement_digest: ObjectDigest,
        signature: [u8; 64],
    ) -> Self {
        Self {
            role,
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            statement_digest,
            signature,
        }
    }

    /// Returns the canonical bytes signed by the named backend authority.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        backend_attestation_signing_message_v1(
            self.role,
            self.authority_id,
            self.authority_generation,
            self.authority_digest,
            self.key_id,
            self.key_generation,
            self.statement_digest,
        )
    }
}

/// Carries a one-shot owner-issued backend observation challenge.
///
/// This value grants no protected authority and is only borrowed by the raw
/// transport. Its private fields prevent a transport from minting a challenge;
/// the fixed verifier consumes and revalidates it with the signed result.
#[derive(Debug)]
pub struct BackendObservationChallengeV1 {
    purpose: u8,
    nonce: [u8; 32],
    issued_seconds: i64,
    valid_until_seconds: i64,
    verifier_set_digest: ObjectDigest,
    plan_binding: ObjectDigest,
    digest: ObjectDigest,
}

impl BackendObservationChallengeV1 {
    /// Returns the nonauthorizing digest that backend authorities must sign.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the last second in which the fixed verifier accepts a response.
    #[must_use]
    pub const fn valid_until_seconds(&self) -> i64 {
        self.valid_until_seconds
    }
}

/// Builds the canonical message signed by one backend verifier authority.
///
/// The returned bytes are nonauthorizing. The fixed provider owner accepts a
/// signature only when every signer field matches its protected verifier
/// manifest and the statement is recomputed from the returned backend facts.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn backend_attestation_signing_message_v1(
    role: BackendVerifierRoleV1,
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
    statement_digest: ObjectDigest,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(ATTESTATION_DOMAIN);
    message.push(role as u8);
    message.extend_from_slice(&[0; 7]);
    message.extend_from_slice(&authority_id);
    message.extend_from_slice(&authority_generation.to_be_bytes());
    message.extend_from_slice(authority_digest.as_bytes());
    message.extend_from_slice(&key_id);
    message.extend_from_slice(&key_generation.to_be_bytes());
    message.extend_from_slice(statement_digest.as_bytes());
    message
}

/// Commits the exact acquisition plan, backend facts, and descriptor identity.
///
/// This digest is nonauthorizing. A transport collects signatures over it;
/// the fixed owner independently recomputes it after kernel observation.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn backend_acquisition_attestation_statement_v1(
    plan: &AcquirePlanV1,
    resource: &aos_sandbox_source_provider_protocol::SourceResourceV1,
    proof: &aos_sandbox_source_provider_protocol::SourceProviderProofV1,
    evidence: &crate::BackendEvidenceV1,
    reopen_identity: &crate::ReopenIdentityV1,
    descriptor_commitment: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(ACQUIRE_DOMAIN);
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.normalized_intent_digest().as_bytes());
    hasher.update(plan.backend_id());
    hasher.update(provider_resource_commitment_v1(resource).as_bytes());
    hasher.update(digest_provider_proof(proof).as_bytes());
    hasher.update(Sha256::digest(evidence.encode()));
    hasher.update(Sha256::digest(reopen_identity.encode()));
    hasher.update(descriptor_commitment.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits the exact release plan and terminal backend evidence.
///
/// This digest is nonauthorizing and is rederived by the fixed owner before it
/// consumes the release permit or seals an already-completed observation.
#[must_use]
pub fn backend_release_attestation_statement_v1(
    plan: &ReleasePlanV1,
    evidence: &crate::BackendEvidenceV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.lease_id());
    hasher.update(plan.lease_digest().as_bytes());
    hasher.update(plan.backend_id());
    hasher.update(Sha256::digest(plan.acquired_evidence().encode()));
    hasher.update(Sha256::digest(evidence.encode()));
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits the exact active acquisition and freshly observed descriptor.
///
/// This digest is nonauthorizing and is rederived by the fixed owner before a
/// reopened descriptor can be returned to inventory or recovery logic.
#[must_use]
pub fn backend_reopen_attestation_statement_v1(
    active: &ActiveAcquisitionSnapshotV1,
    descriptor_commitment: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(REOPEN_DOMAIN);
    hasher.update(active.provider_id());
    hasher.update(active.holder_id());
    hasher.update(active.acquisition_id().as_bytes());
    hasher.update(active.effect_id());
    hasher.update(active.backend_lineage_digest().as_bytes());
    hasher.update(active.lease_id());
    hasher.update(active.lease_digest().as_bytes());
    hasher.update(active.backend_id());
    hasher.update(Sha256::digest(active.evidence().encode()));
    hasher.update(Sha256::digest(active.reopen_identity().encode()));
    hasher.update(descriptor_commitment.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits a protected classification that no Acquire effect was applied.
///
/// Because a fresh plan has not selected a proof class yet, acceptance requires
/// one attestation from every protected class verifier in canonical role order.
#[must_use]
pub fn backend_acquire_absence_attestation_statement_v1(
    plan: &AcquirePlanV1,
    challenge: &BackendObservationChallengeV1,
    observation_generation: u64,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(ACQUIRE_ABSENCE_DOMAIN);
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.normalized_intent_digest().as_bytes());
    hasher.update(plan.backend_id());
    hasher.update(challenge.digest().as_bytes());
    hasher.update(observation_generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits a protected classification that the acquired backend still exists.
///
/// The statement binds the complete retained acquired evidence, its class and
/// generations, and the exact Release plan before execution may be reissued.
#[must_use]
pub fn backend_release_presence_attestation_statement_v1(
    plan: &ReleasePlanV1,
    challenge: &BackendObservationChallengeV1,
    observation_generation: u64,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_PRESENCE_DOMAIN);
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.lease_id());
    hasher.update(plan.lease_digest().as_bytes());
    hasher.update(plan.backend_id());
    hasher.update(Sha256::digest(plan.acquired_evidence().encode()));
    hasher.update(challenge.digest().as_bytes());
    hasher.update(observation_generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl MetadataSnapshot {
    const fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            owner: stat.st_uid,
            group: stat.st_gid,
            links: stat.st_nlink,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

struct VerifierEntryV1 {
    role: BackendVerifierRoleV1,
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
    public_key: [u8; 32],
}

pub(crate) struct ProtectedBackendVerifierV1 {
    directory: OwnedFd,
    directory_metadata: MetadataSnapshot,
    manifest: OwnedFd,
    manifest_metadata: MetadataSnapshot,
    exact_manifest: [u8; MANIFEST_BYTES],
    verifier_set_digest: ObjectDigest,
    entries: [VerifierEntryV1; ENTRY_COUNT],
}

impl core::fmt::Debug for ProtectedBackendVerifierV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBackendVerifierV1([protected verifier set])")
    }
}

pub(crate) struct VerifiedBackendAcquisitionV1 {
    pub(crate) resource: aos_sandbox_source_provider_protocol::SourceResourceV1,
    pub(crate) proof: aos_sandbox_source_provider_protocol::SourceProviderProofV1,
    pub(crate) evidence: crate::BackendEvidenceV1,
    pub(crate) reopen_identity: crate::ReopenIdentityV1,
}

pub(crate) struct VerifiedBackendReleaseV1 {
    pub(crate) evidence: crate::BackendEvidenceV1,
}

pub(crate) struct VerifiedBackendReopenV1;

pub(crate) struct VerifiedAcquireNotAppliedV1;

pub(crate) struct VerifiedReleaseStillPresentV1;

impl ProtectedBackendVerifierV1 {
    pub(crate) fn load_fixed() -> Result<Self, ProviderLedgerError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(ProviderLedgerError::Corrupt(
                "backend verifier owner identity",
            ));
        }
        let group = rustix::process::getegid().as_raw();
        let directory = open_verifier_directory()?;
        let directory_metadata = directory_metadata(&directory, group)?;
        let manifest = open_manifest(&directory)?;
        let manifest_metadata = manifest_metadata(&manifest, group)?;
        rustix::fs::flock(&manifest, FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                if error == rustix::io::Errno::AGAIN {
                    ProviderLedgerError::InvalidTransition(
                        "backend verifier manifest is already in use",
                    )
                } else {
                    ProviderLedgerError::Corrupt("backend verifier manifest lock")
                }
            },
        )?;
        let exact_manifest = read_manifest(&manifest)?;
        if read_manifest(&manifest)? != exact_manifest
            || manifest_metadata(&manifest, group)? != manifest_metadata
        {
            return Err(ProviderLedgerError::Corrupt(
                "backend verifier manifest changed while loading",
            ));
        }
        let entries = decode_manifest(&exact_manifest)?;
        let verifier_set_digest = verifier_set_digest(&exact_manifest);
        let verifier = Self {
            directory,
            directory_metadata,
            manifest,
            manifest_metadata,
            exact_manifest,
            verifier_set_digest,
            entries,
        };
        verifier.revalidate()?;
        Ok(verifier)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_acquisition(
        &self,
        plan: &AcquirePlanV1,
        resource: aos_sandbox_source_provider_protocol::SourceResourceV1,
        proof: aos_sandbox_source_provider_protocol::SourceProviderProofV1,
        evidence: crate::BackendEvidenceV1,
        reopen_identity: crate::ReopenIdentityV1,
        attestations: Vec<RawBackendAttestationV1>,
        descriptor_commitment: ObjectDigest,
    ) -> Result<VerifiedBackendAcquisitionV1, ProviderLedgerError> {
        self.revalidate()?;
        let statement = backend_acquisition_attestation_statement_v1(
            plan,
            &resource,
            &proof,
            &evidence,
            &reopen_identity,
            descriptor_commitment,
        );
        self.verify_required(required_roles(evidence.class()), &attestations, statement)?;
        self.revalidate()?;
        Ok(VerifiedBackendAcquisitionV1 {
            resource,
            proof,
            evidence,
            reopen_identity,
        })
    }

    pub(crate) fn verify_release(
        &self,
        plan: &ReleasePlanV1,
        raw: RawBackendReleaseV1,
    ) -> Result<VerifiedBackendReleaseV1, ProviderLedgerError> {
        self.revalidate()?;
        plan.validate_released_evidence(&raw.evidence)?;
        let statement = backend_release_attestation_statement_v1(plan, &raw.evidence);
        self.verify_required(
            required_roles(plan.evidence_class()),
            &raw.attestations,
            statement,
        )?;
        self.revalidate()?;
        Ok(VerifiedBackendReleaseV1 {
            evidence: raw.evidence,
        })
    }

    pub(crate) fn verify_reopen(
        &self,
        active: &ActiveAcquisitionSnapshotV1,
        class: BackendEvidenceClassV1,
        attestations: &[RawBackendAttestationV1],
        descriptor_commitment: ObjectDigest,
    ) -> Result<VerifiedBackendReopenV1, ProviderLedgerError> {
        self.revalidate()?;
        self.verify_required(
            required_roles(class),
            attestations,
            reopen_statement(active, descriptor_commitment),
        )?;
        self.revalidate()?;
        Ok(VerifiedBackendReopenV1)
    }

    pub(crate) fn verify_acquire_not_applied(
        &self,
        plan: &AcquirePlanV1,
        challenge: BackendObservationChallengeV1,
        raw: RawAcquireNotAppliedV1,
    ) -> Result<VerifiedAcquireNotAppliedV1, ProviderLedgerError> {
        if raw.observation_generation == 0 {
            return Err(ProviderLedgerError::BackendConflict);
        }
        self.revalidate()?;
        self.verify_challenge(
            &challenge,
            ACQUIRE_ABSENCE_PURPOSE,
            acquire_absence_plan_binding(plan),
        )?;
        self.verify_required(
            ALL_ROLES,
            &raw.attestations,
            backend_acquire_absence_attestation_statement_v1(
                plan,
                &challenge,
                raw.observation_generation,
            ),
        )?;
        self.revalidate()?;
        Ok(VerifiedAcquireNotAppliedV1)
    }

    pub(crate) fn verify_release_still_present(
        &self,
        plan: &ReleasePlanV1,
        challenge: BackendObservationChallengeV1,
        raw: RawReleaseStillPresentV1,
    ) -> Result<VerifiedReleaseStillPresentV1, ProviderLedgerError> {
        if raw.observation_generation <= plan.acquired_evidence().observation_generation() {
            return Err(ProviderLedgerError::BackendConflict);
        }
        self.revalidate()?;
        self.verify_challenge(
            &challenge,
            RELEASE_PRESENCE_PURPOSE,
            release_presence_plan_binding(plan),
        )?;
        self.verify_required(
            required_roles(plan.evidence_class()),
            &raw.attestations,
            backend_release_presence_attestation_statement_v1(
                plan,
                &challenge,
                raw.observation_generation,
            ),
        )?;
        self.revalidate()?;
        Ok(VerifiedReleaseStillPresentV1)
    }

    pub(crate) fn issue_acquire_absence_challenge(
        &self,
        plan: &AcquirePlanV1,
    ) -> Result<BackendObservationChallengeV1, ProviderLedgerError> {
        self.issue_challenge(ACQUIRE_ABSENCE_PURPOSE, acquire_absence_plan_binding(plan))
    }

    pub(crate) fn issue_release_presence_challenge(
        &self,
        plan: &ReleasePlanV1,
    ) -> Result<BackendObservationChallengeV1, ProviderLedgerError> {
        self.issue_challenge(
            RELEASE_PRESENCE_PURPOSE,
            release_presence_plan_binding(plan),
        )
    }

    fn issue_challenge(
        &self,
        purpose: u8,
        plan_binding: ObjectDigest,
    ) -> Result<BackendObservationChallengeV1, ProviderLedgerError> {
        self.revalidate()?;
        let issued_seconds = current_unix_seconds()?;
        let valid_until_seconds = issued_seconds
            .checked_add(CHALLENGE_LIFETIME_SECONDS)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let nonce = random_nonce()?;
        let digest = challenge_digest(
            purpose,
            nonce,
            issued_seconds,
            valid_until_seconds,
            self.verifier_set_digest,
            plan_binding,
        );
        self.revalidate()?;
        Ok(BackendObservationChallengeV1 {
            purpose,
            nonce,
            issued_seconds,
            valid_until_seconds,
            verifier_set_digest: self.verifier_set_digest,
            plan_binding,
            digest,
        })
    }

    fn verify_challenge(
        &self,
        challenge: &BackendObservationChallengeV1,
        purpose: u8,
        plan_binding: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        let now = current_unix_seconds()?;
        if challenge.purpose != purpose
            || challenge.nonce == [0; 32]
            || challenge.verifier_set_digest != self.verifier_set_digest
            || challenge.plan_binding != plan_binding
            || challenge.issued_seconds < 0
            || challenge.valid_until_seconds
                != challenge
                    .issued_seconds
                    .checked_add(CHALLENGE_LIFETIME_SECONDS)
                    .ok_or(ProviderLedgerError::BackendConflict)?
            || now < challenge.issued_seconds
            || now > challenge.valid_until_seconds
            || challenge.digest
                != challenge_digest(
                    purpose,
                    challenge.nonce,
                    challenge.issued_seconds,
                    challenge.valid_until_seconds,
                    self.verifier_set_digest,
                    plan_binding,
                )
        {
            return Err(ProviderLedgerError::BackendConflict);
        }
        Ok(())
    }

    fn verify_required(
        &self,
        roles: &[BackendVerifierRoleV1],
        attestations: &[RawBackendAttestationV1],
        statement_digest: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        if attestations.len() != roles.len()
            || attestations
                .iter()
                .zip(roles)
                .any(|(attestation, role)| attestation.role != *role)
        {
            return Err(ProviderLedgerError::BackendConflict);
        }
        for attestation in attestations {
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.role == attestation.role)
                .ok_or(ProviderLedgerError::BackendConflict)?;
            if attestation.statement_digest != statement_digest
                || attestation.authority_id != entry.authority_id
                || attestation.authority_generation != entry.authority_generation
                || attestation.authority_digest != entry.authority_digest
                || attestation.key_id != entry.key_id
                || attestation.key_generation != entry.key_generation
            {
                return Err(ProviderLedgerError::BackendConflict);
            }
            let key = VerifyingKey::from_bytes(&entry.public_key)
                .map_err(|_| ProviderLedgerError::Corrupt("backend verifier public key"))?;
            let signature = Signature::from_bytes(&attestation.signature);
            key.verify_strict(&attestation.signing_message(), &signature)
                .map_err(|_| ProviderLedgerError::BackendConflict)?;
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<(), ProviderLedgerError> {
        let group = rustix::process::getegid().as_raw();
        if rustix::process::geteuid().as_raw() != 0
            || directory_metadata(&self.directory, group)? != self.directory_metadata
            || manifest_metadata(&self.manifest, group)? != self.manifest_metadata
            || read_manifest(&self.manifest)? != self.exact_manifest
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let reopened = open_manifest(&self.directory)?;
        if manifest_metadata(&reopened, group)? != self.manifest_metadata
            || read_manifest(&reopened)? != self.exact_manifest
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let reopened_directory = open_verifier_directory()?;
        if directory_metadata(&reopened_directory, group)? != self.directory_metadata {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let path_manifest = open_manifest(&reopened_directory)?;
        if manifest_metadata(&path_manifest, group)? != self.manifest_metadata
            || read_manifest(&path_manifest)? != self.exact_manifest
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(())
    }
}

fn open_verifier_directory() -> Result<OwnedFd, ProviderLedgerError> {
    let filesystem_root = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProviderLedgerError::Corrupt("backend verifier filesystem root"))?;
    let root = BeneathRoot::from_owned(filesystem_root)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier filesystem root"))?;
    let resolved = root
        .resolve(
            Path::new(FIXED_VERIFIER_ROOT)
                .strip_prefix("/")
                .map_err(|_| ProviderLedgerError::Corrupt("backend verifier fixed path"))?,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier directory"))?;
    let resolved = BeneathRoot::from_resolved(resolved)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier directory"))?;
    rustix::io::fcntl_dupfd_cloexec(resolved.as_fd(), 0)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier directory"))
}

fn acquire_absence_plan_binding(plan: &AcquirePlanV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.acquire-absence-plan.v1\0");
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.normalized_intent_digest().as_bytes());
    hasher.update(plan.backend_id());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn release_presence_plan_binding(plan: &ReleasePlanV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.release-presence-plan.v1\0");
    hasher.update(plan.provider_id());
    hasher.update(plan.holder_id());
    hasher.update(plan.session_binding().as_bytes());
    hasher.update(plan.attempt_digest().as_bytes());
    hasher.update(plan.acquisition_id().as_bytes());
    hasher.update(plan.effect_id());
    hasher.update(plan.lease_id());
    hasher.update(plan.lease_digest().as_bytes());
    hasher.update(plan.backend_id());
    hasher.update(Sha256::digest(plan.acquired_evidence().encode()));
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn challenge_digest(
    purpose: u8,
    nonce: [u8; 32],
    issued_seconds: i64,
    valid_until_seconds: i64,
    verifier_set_digest: ObjectDigest,
    plan_binding: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update([purpose]);
    hasher.update([0; 7]);
    hasher.update(nonce);
    hasher.update(issued_seconds.to_be_bytes());
    hasher.update(valid_until_seconds.to_be_bytes());
    hasher.update(verifier_set_digest.as_bytes());
    hasher.update(plan_binding.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn verifier_set_digest(manifest: &[u8; MANIFEST_BYTES]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(VERIFIER_SET_DOMAIN);
    hasher.update(manifest);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn current_unix_seconds() -> Result<i64, ProviderLedgerError> {
    let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if seconds < 0 {
        Err(ProviderLedgerError::Unavailable)
    } else {
        Ok(seconds)
    }
}

fn random_nonce() -> Result<[u8; 32], ProviderLedgerError> {
    let mut nonce = [0_u8; 32];
    let mut offset = 0;
    let mut interruptions = 0;
    while offset < nonce.len() {
        match rustix::rand::getrandom(&mut nonce[offset..], GetRandomFlags::empty()) {
            Ok(0) => return Err(ProviderLedgerError::Unavailable),
            Ok(written) if written <= nonce.len() - offset => offset += written,
            Ok(_) => return Err(ProviderLedgerError::Unavailable),
            Err(rustix::io::Errno::INTR) if interruptions < MAXIMUM_INTERRUPTED_ENTROPY_RETRIES => {
                interruptions += 1;
            }
            Err(_) => return Err(ProviderLedgerError::Unavailable),
        }
    }
    if nonce == [0; 32] {
        Err(ProviderLedgerError::Unavailable)
    } else {
        Ok(nonce)
    }
}

fn required_roles(class: BackendEvidenceClassV1) -> &'static [BackendVerifierRoleV1] {
    match class {
        BackendEvidenceClassV1::ZfsHeldSnapshot => &[BackendVerifierRoleV1::ZfsHold],
        BackendEvidenceClassV1::LocalLiveExport => &[
            BackendVerifierRoleV1::StorageExport,
            BackendVerifierRoleV1::KernelExportGrant,
        ],
        BackendEvidenceClassV1::ImmutablePublisherTree => &[
            BackendVerifierRoleV1::PublisherReceipt,
            BackendVerifierRoleV1::CacheVerity,
        ],
        BackendEvidenceClassV1::BestEffortReplica => &[BackendVerifierRoleV1::ReplicaAuthority],
    }
}

fn reopen_statement(
    active: &ActiveAcquisitionSnapshotV1,
    descriptor_commitment: ObjectDigest,
) -> ObjectDigest {
    backend_reopen_attestation_statement_v1(active, descriptor_commitment)
}

fn decode_manifest(
    bytes: &[u8; MANIFEST_BYTES],
) -> Result<[VerifierEntryV1; ENTRY_COUNT], ProviderLedgerError> {
    if &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10] != ENTRY_COUNT as u8
        || bytes[11..16] != [0; 5]
    {
        return Err(ProviderLedgerError::Corrupt(
            "backend verifier manifest header",
        ));
    }
    let mut entries = Vec::with_capacity(ENTRY_COUNT);
    let mut authority_ids = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for index in 0..ENTRY_COUNT {
        let offset = HEADER_BYTES + index * ENTRY_BYTES;
        if bytes[offset + 1..offset + 8] != [0; 7] {
            return Err(ProviderLedgerError::Corrupt(
                "backend verifier entry reserved bytes",
            ));
        }
        let role = BackendVerifierRoleV1::decode(bytes[offset])?;
        let authority_id = array(bytes, offset + 8)?;
        let authority_generation = u64_at(bytes, offset + 24)?;
        let authority_digest = ObjectDigest::from_bytes(array(bytes, offset + 32)?);
        let key_id = array(bytes, offset + 64)?;
        let key_generation = u64_at(bytes, offset + 80)?;
        let public_key = array(bytes, offset + 88)?;
        let public_key_digest = ObjectDigest::from_bytes(array(bytes, offset + 120)?);
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ProviderLedgerError::Corrupt("backend verifier public key"))?;
        if role as usize != index + 1
            || authority_id == [0; 16]
            || authority_generation == 0
            || authority_digest.as_bytes() == &[0; 32]
            || key_id == [0; 16]
            || key_generation == 0
            || public_key == [0; 32]
            || key.is_weak()
            || ObjectDigest::from_bytes(Sha256::digest(public_key).into()) != public_key_digest
            || !authority_ids.insert(authority_id)
            || !key_ids.insert(key_id)
            || !public_keys.insert(public_key)
        {
            return Err(ProviderLedgerError::Corrupt("backend verifier entry"));
        }
        entries.push(VerifierEntryV1 {
            role,
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key,
        });
    }
    entries
        .try_into()
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier entry count"))
}

fn directory_metadata(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<MetadataSnapshot, ProviderLedgerError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier directory"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_mode & 0o7777 != 0o550
    {
        return Err(ProviderLedgerError::Corrupt(
            "backend verifier directory metadata",
        ));
    }
    Ok(MetadataSnapshot::from_stat(&stat))
}

fn open_manifest(directory: &OwnedFd) -> Result<OwnedFd, ProviderLedgerError> {
    rustix::fs::openat(
        directory,
        VERIFIER_FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderLedgerError::Corrupt("backend verifier manifest open"))
}

fn manifest_metadata(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<MetadataSnapshot, ProviderLedgerError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier manifest inspect"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o440
        || usize::try_from(stat.st_size).ok() != Some(MANIFEST_BYTES)
    {
        return Err(ProviderLedgerError::Corrupt(
            "backend verifier manifest metadata",
        ));
    }
    Ok(MetadataSnapshot::from_stat(&stat))
}

fn read_manifest(descriptor: &OwnedFd) -> Result<[u8; MANIFEST_BYTES], ProviderLedgerError> {
    let mut output = [0; MANIFEST_BYTES];
    let mut offset = 0;
    while offset < output.len() {
        let count = rustix::io::pread(descriptor, &mut output[offset..], offset as u64)
            .map_err(|_| ProviderLedgerError::Corrupt("backend verifier manifest read"))?;
        if count == 0 {
            return Err(ProviderLedgerError::Corrupt(
                "backend verifier manifest truncated",
            ));
        }
        offset += count;
    }
    let mut trailing = [0_u8; 1];
    if rustix::io::pread(descriptor, &mut trailing, MANIFEST_BYTES as u64)
        .map_err(|_| ProviderLedgerError::Corrupt("backend verifier manifest read"))?
        != 0
    {
        return Err(ProviderLedgerError::Corrupt(
            "backend verifier manifest trailing bytes",
        ));
    }
    Ok(output)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProviderLedgerError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProviderLedgerError::Corrupt(
            "backend verifier manifest truncated",
        ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ProviderLedgerError> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}
