//! Dormant domain-publisher dispatcher and fixed authority owner.
//!
//! The owner joins canonical local messages only to already authenticated,
//! opaque session and filesystem capabilities. It owns the replayed admission,
//! accounting, source-release, root-registry, read-catalog, and protected-store
//! projections as one unit. The physical preparation and completion paths also
//! require a sealed effect capability that production construction cannot mint.
//! This source path creates no listener, route, socket, systemd unit, or
//! activation hook.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use aos_sandbox_core::format::encode_publisher_admission_request_v1;
use aos_sandbox_core::{
    ObjectDescriptor, ObjectDigest, OperationId, RawClockProvenance, RawPairedClockSample,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::immutable_file::{
    FsVerityBacking, FsVerityDigest, FsVerityPublicationRoot, ObservedSealedPublicationFile,
};
use sha2::{Digest as _, Sha256};

use super::dormant_effects::PublisherDormantEffectCapabilityV1;
use super::durable_catalog::PublisherDurableCatalogOwnerV1;
use super::fixed_owner::PublisherFixedColdRecoveryV1;
use super::{
    AdmissionDecisionStateV1, AdmissionError, AdmissionLedger, AdmissionLimits,
    CacheReadDecisionV1, CacheReadOpenErrorV1, CapacityPolicyV1, CommittedAdmissionFrontier,
    CompletionDispositionV1, CompletionReceiptV1, DescriptorAccessV1, DescriptorCommitmentV1,
    ObservedDescriptorV1, OpenForReadRequestV1, ProtectedMutationBranchV1,
    ProtectedStoreCommitToken, PublicationAuthorityEpoch, PublicationPermitId,
    PublisherLocalBodyV1, PublisherLocalMessageV1, PublisherLocalProtocolError,
    PublisherProtectedJournalOwnerV1, ReadCatalogProjectionV1, RecoveryDispositionV1,
    RecoveryObservationV1, RecoveryPhysicalCustodyV1, SourceReleaseError, SourceReleaseRegistry,
    SourceReleaseV1,
};
use crate::journal::Journal;
use crate::publisher_control::RuntimeJoinedPublisherRequest;
use crate::publisher_roots::{
    PublicationRootCustody, PublicationRootId, PublicationRootRecordV1, PublicationRootRegistry,
    PublicationRootRegistryError, RootObservationError,
};
use crate::publisher_sessions::AuthenticatedPublisherRecord;
use crate::{ProtectedOwnershipClockError, SignedPublisherPlan};

use super::linux_bridge::{
    PreparedLinuxPublisherArtifactV1, PublisherLinuxBridgeErrorV1, RecoveredLinuxPreparationV1,
    materialize_linux_artifact, plan_linux_artifact, publish_and_settle_linux_artifact,
    recover_prepared_linux_artifact,
};
use super::protocol::{
    decode_local_backing_message_from_carrier_v1, decode_local_message_v1,
    decode_local_source_message_from_carrier_v1, encode_local_message_v1,
};
use super::read_authority::authorize_cache_read_v1;

const ROOT_BOOT_DOMAIN: &[u8] = b"aos.sandbox.publisher.root-live-boot.v1\0";
const SOURCE_DESCRIPTOR_DOMAIN: &[u8] = b"aos.sandbox.publisher.source-descriptor.v1\0";
const BACKING_DESCRIPTOR_DOMAIN: &[u8] = b"aos.sandbox.publisher.backing-descriptor.v1\0";
const PREPARE_INTENT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher.prepare-intent-transaction.v1\0";
const PREPARE_SEALED_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher.prepare-sealed-transaction.v1\0";
const COLD_RECOVERY_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher.cold-recovery-transaction.v1\0";
const COLD_ABSENCE_DOMAIN: &[u8] = b"aos.sandbox.publisher.cold-absence.v1\0";
pub(crate) const FIXED_PUBLISHER_OBJECT_ROOT: &str = "/var/lib/aos/sandbox/publisher/objects";

/// Derives the non-authorizing commitment for one readable source descriptor.
///
/// The fixed carrier repeats this exact Linux observation after descriptor
/// transfer. This helper grants no admission, publication, or verification
/// authority; it only lets a producer commit its intended source identity.
///
/// # Errors
///
/// Returns [`PublisherDomainServiceErrorV1`] unless `source` is a CLOEXEC,
/// read-only, non-`O_PATH` regular-file description.
pub fn publisher_source_descriptor_commitment_v1(
    source: BorrowedFd<'_>,
) -> Result<DescriptorCommitmentV1, PublisherDomainServiceErrorV1> {
    DescriptorCommitmentV1::first(
        readable_source_identity(source)?,
        DescriptorAccessV1::ReadableSource,
    )
    .map_err(Into::into)
}

/// Binds one independently verified received backing to its transport record.
///
/// The caller must obtain the expected fs-verity measurement and size from
/// current catalog authority before constructing `backing`. This commitment
/// alone grants neither publication nor disclosure authority.
///
/// # Errors
///
/// Returns an error if boot identity is unavailable or the backing does not
/// use the publisher's fixed SHA-256 fs-verity profile.
pub fn publisher_received_backing_descriptor_commitment_v1(
    backing: &FsVerityBacking,
) -> Result<DescriptorCommitmentV1, PublisherDomainServiceErrorV1> {
    let observed = backing.identity();
    let identity = backing_descriptor_identity_v1(
        observed.device(),
        observed.inode(),
        observed.bytes(),
        backing.verified_verity(),
    )?;
    DescriptorCommitmentV1::first(identity, DescriptorAccessV1::ReadOnlyImmutableBacking)
        .map_err(Into::into)
}

/// Decodes a received backing response against independently expected facts.
///
/// `backing` must be admitted from the transferred FD using the current
/// catalog's expected measurement and size. The caller must also authenticate
/// the transport peer and request correlation; this helper checks exact
/// request, object, catalog entry, descriptor identity, and descriptor role.
///
/// # Errors
///
/// Returns an error for an unavailable boot identity, malformed framing, or
/// any response or transferred-FD mismatch.
pub fn decode_publisher_open_found_from_carrier_v1(
    bytes: &[u8],
    backing: &FsVerityBacking,
    expected_request_id: [u8; 16],
    expected_object: &ObjectDescriptor,
    expected_catalog_entry_digest: ObjectDigest,
) -> Result<PublisherLocalMessageV1, PublisherDomainServiceErrorV1> {
    let observed = backing.identity();
    let identity = backing_descriptor_identity_v1(
        observed.device(),
        observed.inode(),
        observed.bytes(),
        backing.verified_verity(),
    )?;
    let message = decode_local_backing_message_from_carrier_v1(bytes, identity)?;
    let PublisherLocalBodyV1::OpenFound {
        object,
        catalog_entry_digest,
        ..
    } = &message.body
    else {
        return Err(PublisherLocalProtocolError::DescriptorMismatch.into());
    };
    if message.request_id != expected_request_id
        || object != expected_object
        || *catalog_entry_digest != expected_catalog_entry_digest
    {
        return Err(PublisherLocalProtocolError::DescriptorMismatch.into());
    }
    Ok(message)
}

/// Configures one fixed dormant publisher domain owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublisherDomainServiceConfigV1 {
    /// Bounded admission and durable replay limits.
    pub(crate) admission_limits: AdmissionLimits,
    /// Exact cache-domain accounting policy.
    pub(crate) capacity: CapacityPolicyV1,
    /// Current controller authority epoch for a new empty journal.
    pub(crate) authority_epoch: PublicationAuthorityEpoch,
    /// Maximum retained source-release records.
    pub(crate) maximum_source_releases: usize,
    /// Maximum retained root-registry records.
    pub(crate) maximum_root_records: usize,
    /// Maximum active immutable catalog entries.
    pub(crate) maximum_catalog_entries: usize,
    /// Protected paired-clock adapter identity used by runtime joins.
    pub(crate) clock_provenance: [u8; 16],
    /// Protected expected device for the fixed object directory.
    pub(crate) root_device: u64,
    /// Protected expected inode for the fixed object directory.
    pub(crate) root_inode: u64,
    /// Exact protected fixed-configuration record digest.
    pub(crate) authority_config_digest: ObjectDigest,
}

/// Owns every mutable projection for one networkless publisher domain.
///
/// Construction claims the sole protected publisher journal. No reducer or
/// registry owner token is exposed, and all public effect methods require an
/// opaque authenticated session, root, descriptor, or recovery capability.
pub struct PublisherDomainServiceV1<'journal> {
    protected: PublisherProtectedJournalOwnerV1<'journal>,
    ledger: AdmissionLedger,
    sources: SourceReleaseRegistry,
    roots: PublicationRootRegistry,
    catalog: ReadCatalogProjectionV1,
    durable_catalog: PublisherDurableCatalogOwnerV1,
    read_grants: super::durable_read_grants::PublisherDurableReadGrantOwnerV1,
    committed: Option<CommittedAdmissionFrontier>,
    clock: PublisherServiceClockV1,
    maximum_catalog_entries: usize,
    root_device: u64,
    root_inode: u64,
    authority_config_digest: ObjectDigest,
}

/// Retains a root descriptor paired to one authenticated publisher execution.
///
/// This non-cloneable capability has no scalar constructor and exposes neither
/// its descriptor nor filesystem mechanics.
#[must_use = "publisher root custody must be retained or explicitly released"]
pub struct PublisherRootCapabilityV1 {
    custody: PublicationRootCustody,
}

impl PublisherRootCapabilityV1 {
    fn recheck_fixed(
        &self,
        expected_device: u64,
        expected_inode: u64,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        let root = self.custody.mechanics();
        root.recheck_protected_path()
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if root.device() != expected_device || root.inode() != expected_inode {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        Ok(())
    }
}

/// Retains one readable descriptor and its body-bound carrier observation.
///
/// Only the crate's descriptor carrier can construct this value. Public callers
/// cannot turn an arbitrary file descriptor or digest into publisher input.
#[must_use = "an adopted publisher source must be dispatched or discarded"]
pub struct AdoptedPublisherSourceV1 {
    source: OwnedFd,
    observation: ObservedDescriptorV1,
}

impl AdoptedPublisherSourceV1 {
    /// Adopts a descriptor only after the fixed carrier produced its observation.
    pub(crate) const fn from_carrier(source: OwnedFd, observation: ObservedDescriptorV1) -> Self {
        Self {
            source,
            observation,
        }
    }
}

/// Reports a committed admission awaiting protected controller signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherAdmissionDispatchV1 {
    /// Exact admitted operation.
    pub operation: OperationId,
    /// Durable decision commitment.
    pub decision_digest: ObjectDigest,
    /// Canonical publisher-domain plan that the fixed signer may sign.
    pub canonical_plan: Vec<u8>,
}

impl PublisherAdmissionDispatchV1 {
    /// Builds the typed response only from the exact protected signer output.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] if the signature covers a
    /// different operation or canonical plan.
    pub fn signed_response(
        &self,
        signed: &SignedPublisherPlan,
    ) -> Result<PublisherLocalBodyV1, PublisherDomainServiceErrorV1> {
        if signed.plan().fields().request.operation != self.operation
            || signed.canonical_plan() != self.canonical_plan
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        Ok(PublisherLocalBodyV1::AdmissionResult {
            operation: self.operation,
            decision_digest: self.decision_digest,
            canonical_plan: self.canonical_plan.clone(),
            signature: signed.canonical_signature().to_vec(),
        })
    }
}

/// Reports an issued permit and its terminal protected completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherCompletionDispatchV1 {
    /// One-shot permit made durable before the filesystem effect.
    pub permit: PublicationPermitId,
    /// Complete permit commitment.
    pub permit_digest: ObjectDigest,
    /// Terminal durable accounting and catalog receipt.
    pub receipt: CompletionReceiptV1,
}

impl PublisherCompletionDispatchV1 {
    /// Builds the typed permit response for canonical encoding.
    #[must_use]
    pub fn permit_response(&self) -> PublisherLocalBodyV1 {
        PublisherLocalBodyV1::CompletionPermit {
            operation: self.receipt.operation,
            permit: self.permit,
            permit_digest: self.permit_digest,
        }
    }

    /// Builds the typed durable-receipt response for canonical encoding.
    #[must_use]
    pub fn receipt_response(&self) -> PublisherLocalBodyV1 {
        PublisherLocalBodyV1::CommitReceipt {
            operation: self.receipt.operation,
            permit: self.receipt.permit,
            receipt_digest: self.receipt.receipt_digest,
        }
    }
}

/// Reports an observation-only recovery disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherRecoveryDispatchV1 {
    /// Exact recovered operation.
    pub operation: OperationId,
    /// Closed protocol disposition; it grants no new effect.
    pub disposition: CompletionDispositionV1,
    /// Exact trusted physical observation committed by recovery.
    pub observation_digest: ObjectDigest,
}

/// Reports fixed cold recovery of an interrupted preparation.
#[must_use = "cold preparation recovery must be completed or acknowledged"]
pub enum PublisherColdPreparationRecoveryV1<'root> {
    /// Exact sealed private evidence was durably installed and remains pinned.
    Prepared(PreparedLinuxPublisherArtifactV1<'root>),
    /// Exact bounded absence was committed and the reservation was released.
    NoEffect(PublisherRecoveryDispatchV1),
    /// Existing prepared/permit state was observed and durably reduced.
    Observed(PublisherRecoveryDispatchV1),
}

/// Returns one already-open sealed backing or a uniform concealed result.
#[must_use = "a publisher read result must be sent or deliberately discarded"]
pub enum PublisherReadOpenV1<'root> {
    /// A current grant and catalog entry authorized this pinned backing.
    Found {
        /// Exact descriptor authorized by the protected catalog.
        object: ObjectDescriptor,
        /// Commitment to the catalog entry used for this open.
        catalog_entry_digest: ObjectDigest,
        /// Already-open fs-verity-sealed descriptor under retained root custody.
        backing: ObservedSealedPublicationFile<'root>,
    },
    /// Absence and denied disclosure share one response shape.
    NotFoundOrConcealed {
        /// Commitment to the exact authenticated read request.
        request_digest: ObjectDigest,
    },
}

impl PublisherReadOpenV1<'_> {
    /// Builds the response body while retaining the exact opened descriptor.
    ///
    /// The `Found` descriptor must travel in the same atomic carrier record
    /// as this body. A descriptorless concealed result uses the same request
    /// commitment for absence and authorization denial.
    ///
    /// # Errors
    ///
    /// Returns an error if boot identity or the fixed SHA-256 backing
    /// commitment cannot be observed.
    pub fn response(&self) -> Result<PublisherLocalBodyV1, PublisherDomainServiceErrorV1> {
        match self {
            Self::Found {
                object,
                catalog_entry_digest,
                backing,
            } => {
                let identity = backing_descriptor_identity_v1(
                    backing.device(),
                    backing.inode(),
                    backing.bytes(),
                    backing.observed_verity_digest(),
                )?;
                let backing = DescriptorCommitmentV1::first(
                    identity,
                    DescriptorAccessV1::ReadOnlyImmutableBacking,
                )?;
                Ok(PublisherLocalBodyV1::OpenFound {
                    object: object.clone(),
                    catalog_entry_digest: *catalog_entry_digest,
                    backing,
                })
            }
            Self::NotFoundOrConcealed { request_digest } => {
                Ok(PublisherLocalBodyV1::OpenNotFoundOrConcealed {
                    request_digest: *request_digest,
                })
            }
        }
    }
}

impl PublisherRecoveryDispatchV1 {
    /// Builds the typed recovery response for canonical encoding.
    #[must_use]
    pub fn response(&self) -> PublisherLocalBodyV1 {
        PublisherLocalBodyV1::RecoveryResult {
            operation: self.operation,
            disposition: self.disposition,
            observation_digest: self.observation_digest,
        }
    }
}

/// Reports dormant dispatcher and fixed-owner failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherDomainServiceErrorV1 {
    /// Service configuration or an empty/current authority frontier is invalid.
    #[error("publisher domain service authority is unavailable")]
    AuthorityUnavailable,
    /// The message is not its exact canonical typed representation.
    #[error(transparent)]
    Protocol(#[from] PublisherLocalProtocolError),
    /// Authenticated session facts disagree with the requested operation.
    #[error("publisher authenticated session differs from the request")]
    SessionMismatch,
    /// The protected admission reducer rejected the transition.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Current protected source-release authority rejected the request.
    #[error(transparent)]
    Source(#[from] SourceReleaseError),
    /// Current root-registry authority rejected the request.
    #[error(transparent)]
    RootRegistry(#[from] PublicationRootRegistryError),
    /// Live descriptor custody differs from current root authority.
    #[error(transparent)]
    RootObservation(#[from] RootObservationError),
    /// Concrete Linux immutable publication could not finish safely.
    #[error("publisher immutable-file effect failed or requires recovery")]
    LinuxEffect,
    /// A partial deterministic inode was durably observed and authority was poisoned.
    #[error("publisher materialization is durably quarantined")]
    MaterializationQuarantined,
    /// Protected clock or kernel boot identity could not be observed.
    #[error("publisher protected clock is unavailable")]
    Clock,
    /// The supplied source is not the exact readable descriptor in the message.
    #[error("publisher source descriptor observation differs")]
    SourceDescriptor,
    /// Protected read-grant currentness could not be confirmed.
    #[error("publisher read-grant authority is unavailable")]
    ReadGrant,
    /// The committed read backing could not be opened as its sealed identity.
    #[error(transparent)]
    ReadBacking(#[from] CacheReadOpenErrorV1),
    /// The authenticated publisher response could not be sent exactly.
    #[error(transparent)]
    ResponseTransport(#[from] crate::publisher_sessions::PublisherSessionError),
}

impl<'journal> PublisherDomainServiceV1<'journal> {
    /// Claims a protected journal and reconstructs the complete publisher domain.
    ///
    /// An empty journal starts with no committed frontier; administrative source
    /// or root installation creates the first checkpoint. A nonempty journal
    /// must replay to the configured authority epoch exactly.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for invalid limits, protected
    /// replay, epoch mismatch, catalog reconstruction, or clock initialization.
    pub(super) fn claim(
        journal: &'journal mut Journal,
        durable_catalog: PublisherDurableCatalogOwnerV1,
        read_grants: super::durable_read_grants::PublisherDurableReadGrantOwnerV1,
        config: PublisherDomainServiceConfigV1,
    ) -> Result<Self, PublisherDomainServiceErrorV1> {
        if config.root_device == 0
            || config.root_inode == 0
            || config.authority_config_digest.as_bytes() == &[0; 32]
        {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        read_grants
            .current_registry()
            .map_err(|_| PublisherDomainServiceErrorV1::ReadGrant)?;
        let protected = PublisherProtectedJournalOwnerV1::claim(
            journal,
            config.admission_limits,
            config.capacity,
            config.maximum_source_releases,
            config.maximum_root_records,
        )
        .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let replay = protected
            .replay_authority()
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let (ledger, sources, roots, committed) = match replay {
            Some(replay) => {
                if replay.checkpoint.epoch != config.authority_epoch {
                    return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
                }
                let head = replay
                    .records
                    .last()
                    .map(|record| record.envelope.digest)
                    .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
                let token = ProtectedStoreCommitToken::from_durable_adapter(
                    replay.checkpoint.clone(),
                    head,
                );
                let committed = replay.ledger.confirm_committed(token)?;
                (replay.ledger, replay.sources, replay.roots, Some(committed))
            }
            None => (
                AdmissionLedger::empty(
                    config.admission_limits,
                    config.authority_epoch,
                    config.capacity,
                )?,
                SourceReleaseRegistry::replay(config.maximum_source_releases, Vec::new())?,
                PublicationRootRegistry::replay(config.maximum_root_records, Vec::new())?,
                None,
            ),
        };
        let catalog = ledger.read_catalog_projection(config.maximum_catalog_entries)?;
        if let Some(observation) = durable_catalog.current() {
            let ledger_generation = ledger.latest_catalog_generation().unwrap_or(0);
            let absorbed = observation.generation() <= ledger_generation
                && ledger
                    .receipt(observation.operation())
                    .is_some_and(|receipt| {
                        receipt.catalog_generation == observation.generation()
                            && receipt.catalog_entry == *observation.entry()
                    });
            let ahead = observation.prior_generation() == ledger_generation
                && ledger_generation.checked_add(1) == Some(observation.generation())
                && ledger
                    .artifact(observation.operation())
                    .and_then(|artifact| {
                        ledger
                            .intended_catalog_entry(
                                observation.operation(),
                                artifact.artifact_digest,
                            )
                            .ok()
                    })
                    .as_ref()
                    == Some(observation.entry());
            if !absorbed && !ahead {
                return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
            }
        }
        let clock = PublisherServiceClockV1::open(config.clock_provenance)?;
        Ok(Self {
            protected,
            ledger,
            sources,
            roots,
            catalog,
            durable_catalog,
            read_grants,
            committed,
            clock,
            maximum_catalog_entries: config.maximum_catalog_entries,
            root_device: config.root_device,
            root_inode: config.root_inode,
            authority_config_digest: config.authority_config_digest,
        })
    }

    /// Installs one controller-resolved source release through the sole journal.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for invalid/conflicting source
    /// facts, reducer bounds, or protected commit failure.
    pub(crate) fn install_source_release(
        &mut self,
        transaction_id: [u8; 16],
        release: SourceReleaseV1,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        require_transaction(transaction_id)?;
        let mut ledger = self.ledger.clone();
        let mut sources = self.sources.clone();
        let mutation = ledger.install_source_release(&mut sources, release)?;
        self.commit_projection(transaction_id, ledger, mutation.into_iter().collect())?;
        self.sources = sources;
        Ok(())
    }

    /// Revokes one source release for new admissions without cancelling permits.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for an absent release,
    /// invalid transaction identity, or protected commit failure.
    pub(crate) fn revoke_source_release(
        &mut self,
        transaction_id: [u8; 16],
        release: ObjectDigest,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        require_transaction(transaction_id)?;
        let mut ledger = self.ledger.clone();
        let mut sources = self.sources.clone();
        let mutation = ledger.revoke_source_release(&mut sources, release)?;
        self.commit_projection(transaction_id, ledger, mutation.into_iter().collect())?;
        self.sources = sources;
        Ok(())
    }

    /// Installs one initial protected publication-root record.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for an invalid registry
    /// successor, scope conflict, reducer bound, or protected commit failure.
    pub(crate) fn install_publication_root(
        &mut self,
        transaction_id: [u8; 16],
        root: PublicationRootRecordV1,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        require_transaction(transaction_id)?;
        let mut ledger = self.ledger.clone();
        let mut roots = self.roots.clone();
        let mutation = ledger.install_root(&mut roots, root)?;
        self.commit_projection(transaction_id, ledger, mutation.into_iter().collect())?;
        self.roots = roots;
        Ok(())
    }

    /// Moves one active publication root to its protected draining successor.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for an absent or non-active
    /// root, generation conflict, reducer bound, or protected commit failure.
    pub(crate) fn begin_publication_root_draining(
        &mut self,
        transaction_id: [u8; 16],
        root_id: PublicationRootId,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        require_transaction(transaction_id)?;
        let mut ledger = self.ledger.clone();
        let mut roots = self.roots.clone();
        let mutation = ledger.drain_root(&mut roots, root_id)?;
        self.commit_projection(transaction_id, ledger, mutation.into_iter().collect())?;
        self.roots = roots;
        Ok(())
    }

    /// Drains one root and installs its scoped replacement atomically.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for a mismatched replacement,
    /// invalid transition, reducer bound, or protected commit failure.
    pub(crate) fn replace_publication_root(
        &mut self,
        transaction_id: [u8; 16],
        current: PublicationRootId,
        replacement: PublicationRootRecordV1,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        require_transaction(transaction_id)?;
        let mut ledger = self.ledger.clone();
        let mut roots = self.roots.clone();
        let mutations = ledger.advance_root(&mut roots, current, replacement)?;
        self.commit_projection(transaction_id, ledger, mutations)?;
        self.roots = roots;
        Ok(())
    }

    /// Retires one drained root after all durable and live obligations disappear.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] while permits, catalog entries,
    /// uncertain effects, live custody, or protected settlement prevent retirement.
    pub(crate) fn retire_publication_root(
        &mut self,
        root_id: PublicationRootId,
    ) -> Result<PublicationRootRecordV1, PublisherDomainServiceErrorV1> {
        let retired = self
            .protected
            .settle_root_retirement(&mut self.ledger, &mut self.roots, root_id)
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        self.committed = self.frontier_from_ledger()?;
        Ok(retired)
    }

    /// Pairs one fixed root descriptor to a freshly authenticated publisher record.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] when the record is stale, its
    /// configured service scope differs, boot observation fails, or Linux/root
    /// mechanics are not the exact active fs-verity/no-replace profile.
    pub fn adopt_fixed_publication_root(
        &mut self,
        record: &AuthenticatedPublisherRecord<'_>,
        root_id: PublicationRootId,
    ) -> Result<PublisherRootCapabilityV1, PublisherDomainServiceErrorV1> {
        record
            .recheck()
            .map_err(|_| PublisherDomainServiceErrorV1::SessionMismatch)?;
        let retained = self.roots.active(root_id)?;
        let root = FsVerityPublicationRoot::from_protected_absolute_path(Path::new(
            FIXED_PUBLISHER_OBJECT_ROOT,
        ))
        .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        root.recheck_protected_path()
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if root.device() != self.root_device || root.inode() != self.root_inode {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        let scope = record.scope();
        if retained.service_node != scope.node
            || retained.service_principal != scope.principal
            || retained.project != scope.project
            || retained.resource != scope.cache_resource
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let boot = KernelBootId::current()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?
            .into_bytes();
        let boot_commitment = digest_parts(
            ROOT_BOOT_DOMAIN,
            &[
                &boot,
                record.instance().as_bytes(),
                record.channel_binding().as_bytes(),
                retained.record_digest.as_bytes(),
            ],
        );
        let observation = crate::publisher_roots::FreshServiceObservationV1::new(
            scope.node,
            scope.principal,
            boot_commitment,
        );
        let custody = PublicationRootCustody::pair(&mut self.roots, root_id, root, observation)?;
        Ok(PublisherRootCapabilityV1 { custody })
    }

    /// Releases one live root capability from the registry retirement guard.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] if the registry no longer
    /// retains this exact live boot custody.
    pub fn release_publication_root(
        &mut self,
        root: PublisherRootCapabilityV1,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        root.custody.release(&mut self.roots)?;
        Ok(())
    }

    /// Resolves a publisher's own read request against independent current grants.
    ///
    /// The publisher session authenticates the holder and project, but does not
    /// itself grant disclosure. A protected read grant, committed catalog entry,
    /// and retained root must all agree before a sealed backing can be opened.
    /// Other read clients require their own authenticated session class.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed message, stale publisher session,
    /// unavailable protected grant owner, or failed root observation. Missing
    /// or mismatched grant and catalog state share the concealed decision.
    fn authorize_publisher_open_for_read<'authority>(
        &'authority self,
        record: &AuthenticatedPublisherRecord<'_>,
        root: &'authority PublisherRootCapabilityV1,
    ) -> Result<CacheReadDecisionV1<'authority>, PublisherDomainServiceErrorV1> {
        record
            .recheck()
            .map_err(|_| PublisherDomainServiceErrorV1::SessionMismatch)?;
        let message = decode_local_message_v1(record.payload(), &[])?;
        let PublisherLocalBodyV1::OpenForRead {
            holder,
            project,
            object,
            read_authority_digest,
            catalog_generation,
        } = &message.body
        else {
            return Err(PublisherLocalProtocolError::Malformed.into());
        };

        let request = OpenForReadRequestV1::new(
            *holder,
            *project,
            object.clone(),
            *read_authority_digest,
            *catalog_generation,
        );
        let concealed = || CacheReadDecisionV1::NotFoundOrConcealed {
            request_digest: request.request_digest(),
        };
        let scope = record.scope();
        let root_record = root.custody.record();
        if *holder != scope.principal
            || *project != scope.project
            || root_record.service_node != scope.node
            || root_record.service_principal != scope.principal
            || root_record.project != scope.project
            || root_record.resource != scope.cache_resource
        {
            return Ok(concealed());
        }

        root.recheck_fixed(self.root_device, self.root_inode)?;
        let grants = self
            .read_grants
            .current_registry()
            .map_err(|_| PublisherDomainServiceErrorV1::ReadGrant)?;
        let Some(authority) = grants.select_current(*holder) else {
            return Ok(concealed());
        };
        let Some(catalog) = self.catalog.select_current(object, *catalog_generation) else {
            return Ok(concealed());
        };
        let read_root = match root.custody.authorize_retained_read(&self.roots) {
            Ok(read_root) => read_root,
            Err(_) => return Ok(concealed()),
        };
        let decision =
            authorize_cache_read_v1(&request, authority, catalog, &self.roots, read_root);
        record
            .recheck()
            .map_err(|_| PublisherDomainServiceErrorV1::SessionMismatch)?;
        Ok(decision)
    }

    /// Opens one publisher-self read only while its session remains current.
    ///
    /// The returned descriptor is already sealed and pinned. This handoff does
    /// not issue a read grant or authenticate a different read-client role.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid session or request, unavailable grant
    /// authority, or a committed backing that fails exact seal observation.
    pub fn dispatch_publisher_open_for_read<'authority>(
        &'authority self,
        record: &AuthenticatedPublisherRecord<'_>,
        root: &'authority PublisherRootCapabilityV1,
    ) -> Result<PublisherReadOpenV1<'authority>, PublisherDomainServiceErrorV1> {
        let decision = self.authorize_publisher_open_for_read(record, root)?;
        let opened = match decision {
            CacheReadDecisionV1::Found(authorized) => {
                let object = authorized.object().clone();
                let catalog_entry_digest = authorized.catalog_entry_digest();
                let backing = authorized.into_open_sealed()?;
                PublisherReadOpenV1::Found {
                    object,
                    catalog_entry_digest,
                    backing,
                }
            }
            CacheReadDecisionV1::NotFoundOrConcealed { request_digest } => {
                PublisherReadOpenV1::NotFoundOrConcealed { request_digest }
            }
        };
        record
            .recheck()
            .map_err(|_| PublisherDomainServiceErrorV1::SessionMismatch)?;
        Ok(opened)
    }

    /// Sends one authorized read result on the exact authenticated publisher channel.
    ///
    /// A found descriptor and its commitment travel in one atomic packet. The
    /// publisher must still verify received object bytes before using them as
    /// portable content; this response does not issue a new read grant.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed request bytes, failed current authority
    /// or backing observation, response encoding, or an uncertain channel send.
    pub fn serve_publisher_open_for_read(
        &self,
        record: &mut AuthenticatedPublisherRecord<'_>,
        root: &PublisherRootCapabilityV1,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        let request = decode_local_message_v1(record.payload(), &[])?;
        if !matches!(&request.body, PublisherLocalBodyV1::OpenForRead { .. }) {
            return Err(PublisherLocalProtocolError::Malformed.into());
        }

        let result = self.dispatch_publisher_open_for_read(record, root)?;
        let response = result.response()?;
        let bytes = encode_local_message_v1(request.request_id, &response)?;
        match &result {
            PublisherReadOpenV1::Found { backing, .. } => {
                record.send_response(&bytes, Some(backing.as_fd()))?;
            }
            PublisherReadOpenV1::NotFoundOrConcealed { .. } => {
                record.send_response(&bytes, None)?;
            }
        }
        Ok(())
    }

    /// Opens the fixed object root under one protected cold-recovery fence.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] unless the claim belongs to
    /// this exact protected configuration, operation, executor, root record,
    /// device, inode, and current registry head.
    pub fn adopt_fixed_recovery_root(
        &mut self,
        claim: &PublisherFixedColdRecoveryV1,
    ) -> Result<PublisherRootCapabilityV1, PublisherDomainServiceErrorV1> {
        if claim.config_digest() != self.authority_config_digest {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        let decision = self
            .ledger
            .decision(claim.operation())
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let root_record = self
            .ledger
            .selected_root_record(claim.operation())
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if decision.publisher_instance != claim.publisher_instance() {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let root = FsVerityPublicationRoot::from_protected_absolute_path(Path::new(
            FIXED_PUBLISHER_OBJECT_ROOT,
        ))
        .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if root.device() != self.root_device || root.inode() != self.root_inode {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        let custody = PublicationRootCustody::pair_fixed_recovery(
            &mut self.roots,
            root_record.root_id,
            decision.selected_root_digest,
            root,
            claim.record_digest(),
        )?;
        Ok(PublisherRootCapabilityV1 { custody })
    }

    /// Recovers one interrupted preparation under fixed root and executor custody.
    ///
    /// The method derives both names, performs bounded exact inode, fs-verity,
    /// allocation and final-name observations, then commits either the exact
    /// prepared-artifact CAS or a no-effect recovery record before returning.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for stale protected claims,
    /// conflicting physical/catalog facts, or ambiguous durable commits.
    pub fn recover_fixed_preparation<'root>(
        &mut self,
        claim: PublisherFixedColdRecoveryV1,
        root: &'root PublisherRootCapabilityV1,
    ) -> Result<PublisherColdPreparationRecoveryV1<'root>, PublisherDomainServiceErrorV1> {
        root.recheck_fixed(self.root_device, self.root_inode)?;
        if claim.config_digest() != self.authority_config_digest
            || root.custody.record().record_digest
                != self
                    .ledger
                    .decision(claim.operation())
                    .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
                    .selected_root_digest
            || claim.publisher_instance()
                != self
                    .ledger
                    .decision(claim.operation())
                    .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
                    .publisher_instance
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let recovery_transaction = digest_parts(
            COLD_RECOVERY_TRANSACTION_DOMAIN,
            &[
                claim.record_digest().as_bytes(),
                committed.head().as_bytes(),
            ],
        );
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&recovery_transaction.as_bytes()[..16]);
        require_transaction(transaction_id)?;
        if self.ledger.artifact(claim.operation()).is_some() {
            let operation = claim.operation();
            let authorized_root = root.custody.authorize_retained_completion(&self.roots)?;
            let artifact = self
                .ledger
                .artifact(operation)
                .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let intended = self
                .ledger
                .intended_catalog_entry(operation, artifact.artifact_digest)?;
            let durable_catalog = self
                .durable_catalog
                .current_for_recovery(
                    operation,
                    self.ledger.latest_catalog_generation().unwrap_or(0),
                    &intended,
                )
                .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let observation = super::linux_bridge::observe_cold_linux_recovery(
                &self.ledger,
                &self.catalog,
                durable_catalog.as_ref(),
                root.custody.mechanics(),
                authorized_root,
                operation,
                claim.into_fence(),
            )
            .map_err(map_linux)?;
            let observation_digest = observation.observation_digest();
            let had_active_capacity = self.ledger.decision(operation).is_some_and(|decision| {
                matches!(
                    decision.state,
                    AdmissionDecisionStateV1::CompletionPermitted
                        | AdmissionDecisionStateV1::RevocationPending
                        | AdmissionDecisionStateV1::Uncertain
                )
            });
            let mut ledger = self.ledger.clone();
            let result = ledger.recover(observation)?;
            let mutations = result.mutations().to_vec();
            let terminal_or_poisoned = ledger.decision(operation).is_some_and(|decision| {
                matches!(
                    decision.state,
                    AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted
                )
            }) || ledger.checkpoint()?.poisoned;
            if had_active_capacity && terminal_or_poisoned && !mutations.is_empty() {
                self.protected
                    .ensure_recovery_capacity(operation)
                    .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
                let branch = ProtectedMutationBranchV1::seal(ledger, mutations)?;
                let token = self
                    .protected
                    .commit_recovery_capacity_branch(transaction_id, operation, &branch)
                    .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
                let committed_ledger = branch.ledger.clone();
                self.committed = Some(committed_ledger.confirm_committed(token)?);
                self.ledger = committed_ledger;
            } else {
                self.commit_projection(transaction_id, ledger, mutations)?;
            }
            self.catalog = self
                .ledger
                .read_catalog_projection(self.maximum_catalog_entries)?;
            let committed = self
                .committed
                .as_ref()
                .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let (_, disposition) = result.committed_disposition(&self.ledger, committed)?;
            return Ok(PublisherColdPreparationRecoveryV1::Observed(
                PublisherRecoveryDispatchV1 {
                    operation,
                    disposition: protocol_disposition(
                        disposition,
                        self.ledger
                            .decision(operation)
                            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
                            .state,
                    ),
                    observation_digest,
                },
            ));
        }
        let recovered = recover_prepared_linux_artifact(
            &self.ledger,
            committed,
            &root.custody,
            claim.operation(),
        )
        .map_err(map_linux)?;
        match recovered {
            RecoveredLinuxPreparationV1::Prepared(preparation, prepared) => {
                let mut ledger = self.ledger.clone();
                let mutation = ledger.prepare_artifact(preparation)?;
                self.commit_projection(transaction_id, ledger, mutation.into_iter().collect())?;
                return Ok(PublisherColdPreparationRecoveryV1::Prepared(prepared));
            }
            RecoveredLinuxPreparationV1::Failed(failure) => {
                let operation = claim.operation();
                let _fence = claim.into_fence();
                let authorized_root = root.custody.authorize(&self.roots)?;
                let observation = failure.into_recovery_observation(authorized_root);
                let observation_digest = observation.observation_digest();
                let mut ledger = self.ledger.clone();
                let result = ledger.recover(observation)?;
                self.commit_projection(transaction_id, ledger, result.mutations().to_vec())?;
                let committed = self
                    .committed
                    .as_ref()
                    .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
                let (_, disposition) = result.committed_disposition(&self.ledger, committed)?;
                return Ok(PublisherColdPreparationRecoveryV1::Observed(
                    PublisherRecoveryDispatchV1 {
                        operation,
                        disposition: protocol_disposition(
                            disposition,
                            self.ledger
                                .decision(operation)
                                .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
                                .state,
                        ),
                        observation_digest,
                    },
                ));
            }
            RecoveredLinuxPreparationV1::Absent => {}
        }

        let authorized_root = root.custody.authorize(&self.roots)?;
        let observation_digest = digest_parts(
            COLD_ABSENCE_DOMAIN,
            &[
                claim.operation().as_bytes(),
                root.custody.record().record_digest.as_bytes(),
                claim.record_digest().as_bytes(),
                committed.head().as_bytes(),
            ],
        );
        let physical = RecoveryPhysicalCustodyV1::seal_from_physical_adapter(
            authorized_root,
            None,
            None,
            None,
            None,
            None,
            None,
            observation_digest,
        );
        let observation =
            RecoveryObservationV1::no_effect_from_physical_adapter(claim.operation(), physical);
        let operation = claim.operation();
        let _fence = claim.into_fence();
        let mut ledger = self.ledger.clone();
        let result = ledger.recover(observation)?;
        let mutations = result.mutations().to_vec();
        self.commit_projection(transaction_id, ledger, mutations)?;
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let (_, disposition) = result.committed_disposition(&self.ledger, committed)?;
        Ok(PublisherColdPreparationRecoveryV1::NoEffect(
            PublisherRecoveryDispatchV1 {
                operation,
                disposition: protocol_disposition(
                    disposition,
                    self.ledger
                        .decision(operation)
                        .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
                        .state,
                ),
                observation_digest,
            },
        ))
    }

    /// Adopts one exact readable source under the fixed Linux carrier profile.
    ///
    /// This call derives descriptor identity directly from the received file
    /// description and exact canonical body. It accepts no observation scalar,
    /// verifier object, or callback from its caller.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] unless the message is a
    /// canonical prepare request and the descriptor is a CLOEXEC, read-only,
    /// non-`O_PATH` regular file matching its exact carrier commitment.
    pub fn adopt_source_descriptor(
        &self,
        message: &PublisherLocalMessageV1,
        source: OwnedFd,
    ) -> Result<AdoptedPublisherSourceV1, PublisherDomainServiceErrorV1> {
        message.validate_canonical()?;
        let commitment = match &message.body {
            PublisherLocalBodyV1::PrepareArtifact { source, .. } => *source,
            _ => return Err(PublisherDomainServiceErrorV1::SessionMismatch),
        };
        let identity = readable_source_identity(source.as_fd())?;
        let observation = ObservedDescriptorV1::from_carrier(
            0,
            identity,
            DescriptorAccessV1::ReadableSource,
            message.body_digest,
        );
        if !observation.matches(commitment, message.body_digest) {
            return Err(PublisherDomainServiceErrorV1::SourceDescriptor);
        }
        Ok(AdoptedPublisherSourceV1::from_carrier(source, observation))
    }

    /// Decodes and adopts one descriptor-bearing carrier record in one boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for malformed/noncanonical
    /// bytes or when the exact received descriptor does not satisfy and match
    /// the readable-source commitment.
    pub fn decode_and_adopt_source_descriptor(
        &self,
        bytes: &[u8],
        source: OwnedFd,
    ) -> Result<(PublisherLocalMessageV1, AdoptedPublisherSourceV1), PublisherDomainServiceErrorV1>
    {
        let identity = readable_source_identity(source.as_fd())?;
        let message = decode_local_source_message_from_carrier_v1(bytes, identity)?;
        let adopted = self.adopt_source_descriptor(&message, source)?;
        Ok((message, adopted))
    }

    /// Dispatches a canonical registration body into durable admission.
    ///
    /// The result deliberately contains no signature. A fixed protected signer
    /// must consume the canonical plan after this method returns; arbitrary
    /// signing callbacks are not accepted by this owner.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] unless the canonical message,
    /// fresh joined holder/publisher execution, source release, root selection,
    /// clock, accounting reservation, and protected commit all agree exactly.
    pub fn dispatch_admission(
        &mut self,
        message: &PublisherLocalMessageV1,
        joined: &mut RuntimeJoinedPublisherRequest<'_>,
        root: &PublisherRootCapabilityV1,
    ) -> Result<PublisherAdmissionDispatchV1, PublisherDomainServiceErrorV1> {
        root.recheck_fixed(self.root_device, self.root_inode)?;
        message.validate_canonical()?;
        let (publisher_instance, challenge, canonical_request) = match &message.body {
            PublisherLocalBodyV1::RegisterChallenge {
                publisher_instance,
                challenge,
                canonical_request,
            } => (*publisher_instance, *challenge, canonical_request),
            _ => return Err(PublisherDomainServiceErrorV1::SessionMismatch),
        };
        let request = joined.request();
        let fields = request.plan().fields();
        let target_instance = fields.target.instance;
        let holder = fields.request.holder;
        let project = fields.target.project;
        let resource = request.cache_resource();
        let domain = fields.target.cache_domain;
        let content = fields.request.content.clone();
        let source_release = fields.request.source_authorization;
        let request_challenge = request.challenge();
        let expected_request = encode_publisher_admission_request_v1(request);
        if publisher_instance != target_instance
            || challenge != request_challenge
            || canonical_request != &expected_request
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let now = self
            .clock
            .wall_seconds()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?;
        let source = self.sources.authorize(
            source_release,
            holder,
            project,
            resource,
            domain,
            &content,
            now,
        )?;
        let authorized_root = root.custody.authorize(&self.roots)?;
        let current_root = self.roots.select_current(&authorized_root)?;
        let execution =
            super::LivePublisherExecution::recheck(joined, &mut || self.clock.sample())?;
        let admitted = self.ledger.derive_admission(
            committed,
            execution,
            source,
            &current_root,
            &mut || self.clock.wall_seconds(),
        )?;
        let operation = admitted.operation();
        let decision_digest = admitted.decision_digest();
        let mut ledger = self.ledger.clone();
        let result = ledger.admit(admitted, &mut || self.clock.wall_seconds())?;
        let mutations = result.mutations().to_vec();
        self.commit_projection(message.request_id, ledger, mutations)?;
        let decision = self
            .ledger
            .decision(operation)
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if decision.decision_digest != decision_digest {
            return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
        }
        Ok(PublisherAdmissionDispatchV1 {
            operation,
            decision_digest,
            canonical_plan: decision.canonical_plan.clone(),
        })
    }

    /// Dispatches a canonical source-descriptor request into sealed preparation.
    ///
    /// `effects` must come from the explicit non-production dormant composition;
    /// the fixed production owner cannot mint it.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] unless descriptor carrier
    /// binding, live execution, source/root currentness, exact copied bytes,
    /// fs-verity SHA-256, allocation, names, and protected preparation agree.
    pub fn dispatch_prepare<'root>(
        &mut self,
        effects: &mut PublisherDormantEffectCapabilityV1<'_>,
        message: &PublisherLocalMessageV1,
        joined: &mut RuntimeJoinedPublisherRequest<'_>,
        root: &'root PublisherRootCapabilityV1,
        source: AdoptedPublisherSourceV1,
    ) -> Result<PreparedLinuxPublisherArtifactV1<'root>, PublisherDomainServiceErrorV1> {
        root.recheck_fixed(self.root_device, self.root_inode)?;
        message.validate_canonical()?;
        let (operation, decision_digest, commitment) = match &message.body {
            PublisherLocalBodyV1::PrepareArtifact {
                operation,
                decision_digest,
                source,
            } => (*operation, *decision_digest, *source),
            _ => return Err(PublisherDomainServiceErrorV1::SessionMismatch),
        };
        if !source.observation.matches(commitment, message.body_digest)
            || self
                .ledger
                .decision(operation)
                .is_none_or(|decision| decision.decision_digest != decision_digest)
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let request = joined.request();
        let fields = request.plan().fields();
        let holder = fields.request.holder;
        let project = fields.target.project;
        let resource = request.cache_resource();
        let domain = fields.target.cache_domain;
        let content = fields.request.content.clone();
        let source_release = fields.request.source_authorization;
        let now = self
            .clock
            .wall_seconds()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?;
        let (intent, planned) = {
            let authorized_source = self.sources.authorize(
                source_release,
                holder,
                project,
                resource,
                domain,
                &content,
                now,
            )?;
            let authorized_root = root.custody.authorize(&self.roots)?;
            let current_root = self.roots.select_current(&authorized_root)?;
            let execution =
                super::LivePublisherExecution::recheck(joined, &mut || self.clock.sample())?;
            let authority = self.ledger.authorize_materialization(
                committed,
                operation,
                execution,
                authorized_source,
                &current_root,
                &mut || self.clock.wall_seconds(),
            )?;
            plan_linux_artifact(&authority, operation, content.clone()).map_err(map_linux)?
        };
        let intent_digest = intent.digest();
        let mut ledger = self.ledger.clone();
        let mutation = ledger.record_preparation_intent(intent)?;
        self.commit_projection(
            phase_transaction_id(PREPARE_INTENT_TRANSACTION_DOMAIN, message.request_id)?,
            ledger,
            mutation.into_iter().collect(),
        )?;

        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let now = self
            .clock
            .wall_seconds()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?;
        let authorized_source = self.sources.authorize(
            source_release,
            holder,
            project,
            resource,
            domain,
            &content,
            now,
        )?;
        let authorized_root = root.custody.authorize(&self.roots)?;
        let current_root = self.roots.select_current(&authorized_root)?;
        let execution =
            super::LivePublisherExecution::recheck(joined, &mut || self.clock.sample())?;
        let authority = self.ledger.authorize_materialization(
            committed,
            operation,
            execution,
            authorized_source,
            &current_root,
            &mut || self.clock.wall_seconds(),
        )?;
        let committed_intent =
            self.ledger
                .authorize_committed_preparation(committed, authority, intent_digest)?;
        let materialization = materialize_linux_artifact(
            effects,
            &committed_intent,
            &root.custody,
            planned,
            source.source,
        );
        drop(committed_intent);
        let (preparation, prepared) = match materialization {
            Ok(prepared) => prepared,
            Err(failure) => {
                let authorized_root = root.custody.authorize(&self.roots)?;
                let observation = failure.into_recovery_observation(authorized_root);
                let mut ledger = self.ledger.clone();
                let result = ledger.recover(observation)?;
                self.commit_projection(
                    phase_transaction_id(PREPARE_SEALED_TRANSACTION_DOMAIN, message.request_id)?,
                    ledger,
                    result.mutations().to_vec(),
                )?;
                let committed = self
                    .committed
                    .as_ref()
                    .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
                let (_, disposition) = result.committed_disposition(&self.ledger, committed)?;
                return Err(if disposition == RecoveryDispositionV1::Poisoned {
                    PublisherDomainServiceErrorV1::MaterializationQuarantined
                } else {
                    PublisherDomainServiceErrorV1::LinuxEffect
                });
            }
        };
        let mut ledger = self.ledger.clone();
        let mutation = ledger.prepare_artifact(preparation)?;
        self.commit_projection(
            phase_transaction_id(PREPARE_SEALED_TRANSACTION_DOMAIN, message.request_id)?,
            ledger,
            mutation.into_iter().collect(),
        )?;
        Ok(prepared)
    }

    /// Issues a permit, performs exact no-replace publication, and settles it.
    ///
    /// `effects` must come from the explicit non-production dormant composition;
    /// the fixed production owner cannot mint it.
    ///
    /// The capacity reservation and permit commit precede the first naming
    /// effect. Protected poison custody remains live across rename, ambiguity
    /// recovery, directory synchronization, catalog insertion, and settlement.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] for a mismatched request or
    /// prepared pin, stale authenticated execution/root/source, protected-store
    /// failure, or a Linux outcome that cannot prove exact durable completion.
    pub fn dispatch_completion(
        &mut self,
        effects: &mut PublisherDormantEffectCapabilityV1<'_>,
        message: &PublisherLocalMessageV1,
        joined: &mut RuntimeJoinedPublisherRequest<'_>,
        root: &PublisherRootCapabilityV1,
        prepared: PreparedLinuxPublisherArtifactV1<'_>,
    ) -> Result<PublisherCompletionDispatchV1, PublisherDomainServiceErrorV1> {
        root.recheck_fixed(self.root_device, self.root_inode)?;
        message.validate_canonical()?;
        let (operation, artifact_digest) = match &message.body {
            PublisherLocalBodyV1::RequestCompletion {
                operation,
                artifact_digest,
            } => (*operation, *artifact_digest),
            _ => return Err(PublisherDomainServiceErrorV1::SessionMismatch),
        };
        if prepared.operation() != operation || prepared.artifact_digest() != artifact_digest {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
            .clone();
        let request = joined.request();
        let fields = request.plan().fields();
        let target_instance = fields.target.instance;
        let holder = fields.request.holder;
        let project = fields.target.project;
        let resource = request.cache_resource();
        let domain = fields.target.cache_domain;
        let content = fields.request.content.clone();
        let source_release = fields.request.source_authorization;
        let now = self
            .clock
            .wall_seconds()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?;
        let source = self.sources.authorize(
            source_release,
            holder,
            project,
            resource,
            domain,
            &content,
            now,
        )?;
        let authorized_root = root.custody.authorize(&self.roots)?;
        let current_root = self.roots.select_current(&authorized_root)?;
        let execution =
            super::LivePublisherExecution::recheck(joined, &mut || self.clock.sample())?;
        let mut ledger = self.ledger.clone();
        let issue = ledger.issue_completion_permit(
            &committed,
            execution,
            &source,
            &current_root,
            operation,
            &mut || self.clock.wall_seconds(),
        )?;
        let issue_mutations = issue.mutations().to_vec();
        if issue_mutations.is_empty() {
            self.protected
                .ensure_completion_capacity(message.request_id, operation)
                .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        } else {
            let branch = ProtectedMutationBranchV1::seal(ledger.clone(), issue_mutations)?;
            let token = self
                .protected
                .issue_completion_capacity(message.request_id, &branch)
                .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let committed_ledger = branch.ledger.clone();
            self.committed = Some(committed_ledger.confirm_committed(token)?);
            self.ledger = committed_ledger;
        }
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
            .clone();
        let permit_record = self
            .ledger
            .decision(operation)
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        if permit_record.publisher_instance != target_instance {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let execution =
            super::LivePublisherExecution::recheck(joined, &mut || self.clock.sample())?;
        let retained = self.ledger.authorize_retained_completion(
            &committed,
            execution,
            &self.roots,
            &root.custody,
            operation,
            artifact_digest,
        )?;
        let permit = retained.permit();
        let permit_digest = retained.record().permit_digest;
        let receipt = publish_and_settle_linux_artifact(
            effects,
            &mut self.protected,
            &mut self.ledger,
            &committed,
            retained,
            prepared,
            &mut self.catalog,
            &mut self.durable_catalog,
        )
        .map_err(map_linux)?;
        self.committed = self.frontier_from_ledger()?;
        Ok(PublisherCompletionDispatchV1 {
            permit,
            permit_digest,
            receipt,
        })
    }

    /// Dispatches one opaque physical recovery observation into protected state.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherDomainServiceErrorV1`] unless the message identifies
    /// the exact retained decision and the non-forgeable observation satisfies
    /// the recovery reducer and protected commit.
    pub fn dispatch_recovery(
        &mut self,
        message: &PublisherLocalMessageV1,
        observation: RecoveryObservationV1<'_>,
    ) -> Result<PublisherRecoveryDispatchV1, PublisherDomainServiceErrorV1> {
        message.validate_canonical()?;
        let (operation, decision_digest) = match &message.body {
            PublisherLocalBodyV1::ObserveRecovery {
                operation,
                decision_digest,
            } => (*operation, *decision_digest),
            _ => return Err(PublisherDomainServiceErrorV1::SessionMismatch),
        };
        if self
            .ledger
            .decision(operation)
            .is_none_or(|decision| decision.decision_digest != decision_digest)
        {
            return Err(PublisherDomainServiceErrorV1::SessionMismatch);
        }
        let observation_digest = observation.observation_digest();
        let had_active_capacity = self.ledger.decision(operation).is_some_and(|decision| {
            matches!(
                decision.state,
                AdmissionDecisionStateV1::CompletionPermitted
                    | AdmissionDecisionStateV1::RevocationPending
                    | AdmissionDecisionStateV1::Uncertain
            )
        });
        let mut ledger = self.ledger.clone();
        let result = ledger.recover(observation)?;
        let mutations = result.mutations().to_vec();
        let terminal_or_poisoned = ledger.decision(operation).is_some_and(|decision| {
            matches!(
                decision.state,
                AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted
            )
        }) || ledger.checkpoint()?.poisoned;
        if had_active_capacity && terminal_or_poisoned && !mutations.is_empty() {
            self.protected
                .ensure_recovery_capacity(operation)
                .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let branch = ProtectedMutationBranchV1::seal(ledger, mutations)?;
            let token = self
                .protected
                .commit_recovery_capacity_branch(message.request_id, operation, &branch)
                .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
            let committed_ledger = branch.ledger.clone();
            self.committed = Some(committed_ledger.confirm_committed(token)?);
            self.ledger = committed_ledger;
        } else {
            self.commit_projection(message.request_id, ledger, mutations)?;
        }
        self.catalog = self
            .ledger
            .read_catalog_projection(self.maximum_catalog_entries)?;
        let committed = self
            .committed
            .as_ref()
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let (operation, disposition) = result.committed_disposition(&self.ledger, committed)?;
        let decision_state = self
            .ledger
            .decision(operation)
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?
            .state;
        Ok(PublisherRecoveryDispatchV1 {
            operation,
            disposition: protocol_disposition(disposition, decision_state),
            observation_digest,
        })
    }

    fn commit_projection(
        &mut self,
        transaction_id: [u8; 16],
        ledger: AdmissionLedger,
        mutations: Vec<super::LedgerMutation>,
    ) -> Result<(), PublisherDomainServiceErrorV1> {
        if mutations.is_empty() {
            if self.committed.is_none() {
                return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
            }
            return Ok(());
        }
        let branch = ProtectedMutationBranchV1::seal(ledger.clone(), mutations)?;
        let token = self
            .protected
            .commit_state_branch(transaction_id, &branch)
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let committed_ledger = branch.ledger.clone();
        let frontier = committed_ledger.confirm_committed(token)?;
        self.ledger = committed_ledger;
        self.committed = Some(frontier);
        Ok(())
    }

    fn frontier_from_ledger(
        &self,
    ) -> Result<Option<CommittedAdmissionFrontier>, PublisherDomainServiceErrorV1> {
        let replay = self
            .protected
            .replay_authority()
            .map_err(|_| PublisherDomainServiceErrorV1::AuthorityUnavailable)?
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let head = replay
            .records
            .last()
            .map(|record| record.envelope.digest)
            .ok_or(PublisherDomainServiceErrorV1::AuthorityUnavailable)?;
        let token = ProtectedStoreCommitToken::from_durable_adapter(replay.checkpoint, head);
        Ok(Some(self.ledger.confirm_committed(token)?))
    }
}

struct PublisherServiceClockV1 {
    provenance: RawClockProvenance,
    boot: [u8; 16],
}

impl PublisherServiceClockV1 {
    fn open(identity: [u8; 16]) -> Result<Self, PublisherDomainServiceErrorV1> {
        let provenance = RawClockProvenance::new_untrusted(identity)
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?;
        let boot = KernelBootId::current()
            .map_err(|_| PublisherDomainServiceErrorV1::Clock)?
            .into_bytes();
        Ok(Self { provenance, boot })
    }

    fn sample(&mut self) -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let boottime_nanoseconds = u64::try_from(boottime.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| value.checked_add(boottime.tv_nsec as u64))
            .ok_or(ProtectedOwnershipClockError)?;
        RawPairedClockSample::new_untrusted(
            self.provenance,
            self.boot,
            realtime.tv_sec,
            boottime_nanoseconds,
        )
        .map_err(|_| ProtectedOwnershipClockError)
    }

    fn wall_seconds(&mut self) -> Result<i64, ProtectedOwnershipClockError> {
        Ok(self.sample()?.wall_seconds())
    }
}

fn require_transaction(transaction_id: [u8; 16]) -> Result<(), PublisherDomainServiceErrorV1> {
    if transaction_id == [0; 16] {
        return Err(PublisherDomainServiceErrorV1::AuthorityUnavailable);
    }
    Ok(())
}

fn phase_transaction_id(
    domain: &[u8],
    request_id: [u8; 16],
) -> Result<[u8; 16], PublisherDomainServiceErrorV1> {
    let digest = digest_parts(domain, &[&request_id]);
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    require_transaction(transaction_id)?;
    Ok(transaction_id)
}

fn map_linux(_error: PublisherLinuxBridgeErrorV1) -> PublisherDomainServiceErrorV1 {
    PublisherDomainServiceErrorV1::LinuxEffect
}

fn protocol_disposition(
    value: RecoveryDispositionV1,
    decision: AdmissionDecisionStateV1,
) -> CompletionDispositionV1 {
    match value {
        RecoveryDispositionV1::NoWork => match decision {
            AdmissionDecisionStateV1::Completed => CompletionDispositionV1::Committed,
            AdmissionDecisionStateV1::Aborted => CompletionDispositionV1::AbortedBeforeEffect,
            _ => CompletionDispositionV1::RecoveryRequired,
        },
        RecoveryDispositionV1::ObserveOnly => CompletionDispositionV1::RecoveryRequired,
        RecoveryDispositionV1::Quarantine | RecoveryDispositionV1::Poisoned => {
            CompletionDispositionV1::AuthorityUnavailable
        }
    }
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

fn backing_descriptor_identity_v1(
    device: u64,
    inode: u64,
    bytes: u64,
    verified_verity: FsVerityDigest,
) -> Result<ObjectDigest, PublisherDomainServiceErrorV1> {
    let FsVerityDigest::Sha256(verity) = verified_verity else {
        return Err(PublisherLocalProtocolError::Malformed.into());
    };
    let boot = KernelBootId::current()
        .map_err(|_| PublisherDomainServiceErrorV1::Clock)?
        .into_bytes();
    Ok(digest_parts(
        BACKING_DESCRIPTOR_DOMAIN,
        &[
            &boot,
            &device.to_be_bytes(),
            &inode.to_be_bytes(),
            &bytes.to_be_bytes(),
            &verity,
        ],
    ))
}

fn readable_source_identity(
    source: BorrowedFd<'_>,
) -> Result<ObjectDigest, PublisherDomainServiceErrorV1> {
    let descriptor_flags = rustix::io::fcntl_getfd(source)
        .map_err(|_| PublisherDomainServiceErrorV1::SourceDescriptor)?;
    let status_flags = rustix::fs::fcntl_getfl(source)
        .map_err(|_| PublisherDomainServiceErrorV1::SourceDescriptor)?;
    let stat =
        rustix::fs::fstat(source).map_err(|_| PublisherDomainServiceErrorV1::SourceDescriptor)?;
    let bytes =
        u64::try_from(stat.st_size).map_err(|_| PublisherDomainServiceErrorV1::SourceDescriptor)?;
    if !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        || status_flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        || status_flags.contains(rustix::fs::OFlags::PATH)
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
    {
        return Err(PublisherDomainServiceErrorV1::SourceDescriptor);
    }
    let boot = KernelBootId::current()
        .map_err(|_| PublisherDomainServiceErrorV1::SourceDescriptor)?
        .into_bytes();
    Ok(digest_parts(
        SOURCE_DESCRIPTOR_DOMAIN,
        &[
            &boot,
            &stat.st_dev.to_be_bytes(),
            &stat.st_ino.to_be_bytes(),
            &bytes.to_be_bytes(),
            &(stat.st_mode as u64).to_be_bytes(),
            &stat.st_uid.to_be_bytes(),
            &stat.st_gid.to_be_bytes(),
            &stat.st_nlink.to_be_bytes(),
        ],
    ))
}
