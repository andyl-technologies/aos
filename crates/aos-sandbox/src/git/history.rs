//! Durable Git repository, receive, publication, export, pack, and fork history.
//!
//! Records retain exact plans and evidence without granting repository authority.

use std::collections::BTreeMap;

use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{ObjectDigest, PrincipalId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::{
    GitAdvertisedRefV1, GitAtomicCasDigestV1, GitBoottimeV1, GitCheapForkStatusV1, GitCheapForkV1,
    GitExportGenerationDigestV1, GitExportGenerationV1, GitModelError, GitPackConsumerV1,
    GitPackGenerationDigestV1, GitPackGenerationPredecessorV1, GitPackLeaseStatusV1,
    GitReceivePlanV1, GitRefMapDigestV1, GitRepositoryV1, GitTrustedBoottimeV1,
    GitWholeObjectDatabaseV1, ImmutablePackGenerationV1, MAXIMUM_GIT_HISTORY_RECORDS,
    MAXIMUM_GIT_PACK_LEASES, git_ref_map_digest_v1,
};

/// Stores one exact materialized mutable-repository revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRepositoryStateV1 {
    repository: GitRepositoryV1,
    predecessor: Option<ObjectDigest>,
    refs: Vec<GitAdvertisedRefV1>,
    ref_map: GitRefMapDigestV1,
    database: GitWholeObjectDatabaseV1,
}

impl GitRepositoryStateV1 {
    /// Constructs one canonical repository state snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for a broken first-record shape, non-canonical
    /// refs, format mismatch, or a ref absent from the complete graph roots.
    pub fn new(
        repository: GitRepositoryV1,
        predecessor: Option<ObjectDigest>,
        refs: Vec<GitAdvertisedRefV1>,
        database: GitWholeObjectDatabaseV1,
    ) -> Result<Self, GitModelError> {
        let ref_map = git_ref_map_digest_v1(repository.format(), &refs)?;
        let isolated_audience = match database.audience().disclosure().kind() {
            CacheDomainKind::Private => {
                database.audience().disclosure().domain_id().as_bytes()
                    == repository.sandbox().as_bytes()
            }
            CacheDomainKind::Project => {
                database.audience().disclosure().domain_id().as_bytes()
                    == repository.project().as_bytes()
            }
            CacheDomainKind::TrustDomain | CacheDomainKind::Public => false,
        };
        if (repository.revision().get() == 1) != predecessor.is_none()
            || database.graph().format() != repository.format()
            || !isolated_audience
            || refs.iter().any(|entry| {
                database
                    .graph()
                    .roots()
                    .binary_search(&entry.object())
                    .is_err()
            })
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            repository,
            predecessor,
            refs,
            ref_map,
            database,
        })
    }

    /// Constructs the exact repository successor published by a receive plan.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] if the derived successor repository state is
    /// inconsistent with the plan's checked ref and whole-ODB evidence.
    pub fn from_receive(
        plan: &GitReceivePlanV1,
        predecessor: ObjectDigest,
    ) -> Result<Self, GitModelError> {
        let current = plan.repository();
        let successor = GitRepositoryV1::new(
            current.repository(),
            current.project(),
            current.sandbox(),
            current.workspace(),
            current.format(),
            plan.successor_revision(),
        )?;
        let mut successor_refs = Vec::new();
        successor_refs
            .try_reserve_exact(plan.successor_refs().len())
            .map_err(|_| GitModelError::Allocation)?;
        successor_refs.extend_from_slice(plan.successor_refs());
        let state = Self::new(
            successor,
            Some(predecessor),
            successor_refs,
            plan.post_database().clone(),
        )?;
        if state.ref_map() != plan.post_ref_map() {
            return Err(GitModelError::InvalidModel);
        }
        Ok(state)
    }

    /// Borrows the path-free repository identity and revision.
    #[must_use]
    pub const fn repository(&self) -> &GitRepositoryV1 {
        &self.repository
    }

    /// Returns the complete canonical ref-map commitment.
    #[must_use]
    pub const fn ref_map(&self) -> GitRefMapDigestV1 {
        self.ref_map
    }

    /// Borrows complete logical, physical, validation, and audience evidence.
    #[must_use]
    pub const fn database(&self) -> &GitWholeObjectDatabaseV1 {
        &self.database
    }

    /// Borrows the complete canonical ref map.
    #[must_use]
    pub fn refs(&self) -> &[GitAdvertisedRefV1] {
        &self.refs
    }

    /// Returns the exact predecessor snapshot commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Commits this complete repository snapshot for exact successor lineage.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        let repository = &self.repository;
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.git.repository-state.v1\0")
                .chain_update(repository.repository().as_bytes())
                .chain_update(repository.project().as_bytes())
                .chain_update(repository.sandbox().as_bytes())
                .chain_update(repository.workspace().as_bytes())
                .chain_update([repository.format() as u8])
                .chain_update(repository.revision().get().to_be_bytes())
                .chain_update(
                    self.predecessor
                        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                        .as_bytes(),
                )
                .chain_update(self.ref_map.digest().as_bytes())
                .chain_update(self.database.graph().object_database().digest().as_bytes())
                .chain_update(self.database.physical().inventory().digest().as_bytes())
                .chain_update(self.database.audience_commitment().digest().as_bytes())
                .chain_update(self.database.validator().trust().digest().as_bytes())
                .finalize()
                .into(),
        )
    }
}

/// Selects a durable receive/quarantine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitReceivePhaseV1 {
    /// Exact receive plan is admitted but no quarantine is durable.
    Admitted = 1,
    /// The exact quarantine body is sealed.
    Quarantined = 2,
    /// Whole-ODB and validation-policy evidence is complete.
    Validated = 3,
    /// Atomic ref/ODB CAS published the successor revision.
    Published = 4,
    /// Validation rejected the quarantine without publication.
    Rejected = 5,
}

/// Retains one complete monotone receive transaction snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitReceiveHistoryRecordV1 {
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    plan: GitReceivePlanV1,
    phase: GitReceivePhaseV1,
    sealed_quarantine: Option<ObjectDigest>,
    validation: Option<ObjectDigest>,
    publication: Option<GitAtomicCasDigestV1>,
    failure: Option<ObjectDigest>,
}

impl GitReceiveHistoryRecordV1 {
    /// Constructs one closed receive history snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a broken record chain or an
    /// evidence shape inconsistent with the selected receive phase.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        plan: GitReceivePlanV1,
        phase: GitReceivePhaseV1,
        sealed_quarantine: Option<ObjectDigest>,
        validation: Option<ObjectDigest>,
        publication: Option<GitAtomicCasDigestV1>,
        failure: Option<ObjectDigest>,
    ) -> Result<Self, GitModelError> {
        let shape = match phase {
            GitReceivePhaseV1::Admitted => {
                sealed_quarantine.is_none()
                    && validation.is_none()
                    && publication.is_none()
                    && failure.is_none()
            }
            GitReceivePhaseV1::Quarantined => {
                sealed_quarantine.is_some()
                    && validation.is_none()
                    && publication.is_none()
                    && failure.is_none()
            }
            GitReceivePhaseV1::Validated => {
                sealed_quarantine.is_some()
                    && validation.is_some()
                    && publication.is_none()
                    && failure.is_none()
            }
            GitReceivePhaseV1::Published => {
                sealed_quarantine.is_some()
                    && validation.is_some()
                    && publication == Some(plan.atomic_cas())
                    && failure.is_none()
            }
            GitReceivePhaseV1::Rejected => {
                sealed_quarantine.is_some() && publication.is_none() && failure.is_some()
            }
        };
        let quarantine_matches =
            sealed_quarantine.is_none_or(|digest| digest == plan.quarantine_digest().digest());
        let validation_matches = validation.is_none_or(|digest| {
            digest
                == plan
                    .post_database()
                    .validator()
                    .report()
                    .descriptor()
                    .digest()
        });
        if revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor.is_none()
            || !shape
            || !quarantine_matches
            || !validation_matches
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            revision,
            predecessor,
            plan,
            phase,
            sealed_quarantine,
            validation,
            publication,
            failure,
        })
    }

    /// Borrows the exact immutable receive plan.
    #[must_use]
    pub const fn plan(&self) -> &GitReceivePlanV1 {
        &self.plan
    }

    /// Returns the receive-history revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the exact predecessor record commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Returns the durable receive phase.
    #[must_use]
    pub const fn phase(&self) -> GitReceivePhaseV1 {
        self.phase
    }

    /// Returns the sealed quarantine commitment, when durable.
    #[must_use]
    pub const fn sealed_quarantine(&self) -> Option<ObjectDigest> {
        self.sealed_quarantine
    }

    /// Returns the graph-validation report commitment, when durable.
    #[must_use]
    pub const fn validation(&self) -> Option<ObjectDigest> {
        self.validation
    }

    /// Returns the atomic publication commitment, when durable.
    #[must_use]
    pub const fn publication(&self) -> Option<GitAtomicCasDigestV1> {
        self.publication
    }

    /// Returns the terminal rejection commitment, when durable.
    #[must_use]
    pub const fn failure(&self) -> Option<ObjectDigest> {
        self.failure
    }

    /// Commits the complete receive snapshot for exact history lineage.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        let plan = &self.plan;
        let repository = plan.repository();
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.git.receive-history-record.v1\0")
            .chain_update(self.revision.get().to_be_bytes())
            .chain_update(
                self.predecessor
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            )
            .chain_update([self.phase as u8])
            .chain_update(plan.exchange().as_bytes())
            .chain_update(repository.repository().as_bytes())
            .chain_update(repository.project().as_bytes())
            .chain_update(repository.sandbox().as_bytes())
            .chain_update(repository.workspace().as_bytes())
            .chain_update(repository.revision().get().to_be_bytes())
            .chain_update(plan.successor_revision().get().to_be_bytes())
            .chain_update(plan.protocol().digest().digest().as_bytes())
            .chain_update(plan.principal().as_bytes())
            .chain_update(plan.channel_binding().digest().as_bytes())
            .chain_update(plan.expires_at_unix_seconds().to_be_bytes())
            .chain_update(plan.maximum_input_bytes().to_be_bytes())
            .chain_update(plan.maximum_output_bytes().to_be_bytes())
            .chain_update(plan.pre_ref_map().digest().as_bytes())
            .chain_update(plan.post_ref_map().digest().as_bytes())
            .chain_update(
                plan.pre_database()
                    .graph()
                    .object_database()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(
                plan.pre_database()
                    .physical()
                    .inventory()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(
                plan.pre_database()
                    .audience_commitment()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(
                plan.post_database()
                    .graph()
                    .object_database()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(
                plan.post_database()
                    .physical()
                    .inventory()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(
                plan.post_database()
                    .audience_commitment()
                    .digest()
                    .as_bytes(),
            )
            .chain_update(plan.quarantine_digest().digest().as_bytes())
            .chain_update(plan.validation_policy().digest().as_bytes())
            .chain_update(plan.atomic_cas().digest().as_bytes())
            .chain_update((plan.current_refs().len() as u32).to_be_bytes());
        for reference in plan.current_refs() {
            hasher = hasher
                .chain_update((reference.name().as_bytes().len() as u16).to_be_bytes())
                .chain_update(reference.name().as_bytes())
                .chain_update(reference.object().as_bytes());
        }
        hasher = hasher.chain_update((plan.transitions().len() as u32).to_be_bytes());
        for transition in plan.transitions() {
            hasher = hasher
                .chain_update((transition.name().as_bytes().len() as u16).to_be_bytes())
                .chain_update(transition.name().as_bytes());
            for object in [transition.expected(), transition.proposed()] {
                hasher = hasher.chain_update([u8::from(object.is_some())]);
                if let Some(object) = object {
                    hasher = hasher.chain_update(object.as_bytes());
                }
            }
            hasher = hasher.chain_update(
                transition
                    .ancestry()
                    .map_or(ObjectDigest::from_bytes([0; 32]), |value| {
                        value.report().digest()
                    })
                    .as_bytes(),
            );
        }
        for digest in [
            self.sealed_quarantine,
            self.validation,
            self.publication.map(|value| value.digest()),
            self.failure,
        ] {
            hasher = hasher.chain_update(
                digest
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            );
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Retains exact atomic publication evidence for a receive successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitPublicationRecordV1 {
    repository: ResourceId,
    predecessor_revision: Revision,
    successor_revision: Revision,
    atomic_cas: GitAtomicCasDigestV1,
    published_at: u64,
}

impl GitPublicationRecordV1 {
    /// Constructs exact publication evidence from a checked receive plan.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a sentinel publication time.
    pub fn from_receive(plan: &GitReceivePlanV1, published_at: u64) -> Result<Self, GitModelError> {
        if published_at == 0 || published_at == u64::MAX {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            repository: plan.repository().repository(),
            predecessor_revision: plan.repository().revision(),
            successor_revision: plan.successor_revision(),
            atomic_cas: plan.atomic_cas(),
            published_at,
        })
    }

    /// Reconstructs checked publication evidence from canonical durable fields.
    pub(super) fn from_stored(
        repository: ResourceId,
        predecessor_revision: Revision,
        successor_revision: Revision,
        atomic_cas: GitAtomicCasDigestV1,
        published_at: u64,
    ) -> Result<Self, GitModelError> {
        if repository.as_bytes() == &[0; 16]
            || predecessor_revision.get() == 0
            || !predecessor_revision
                .checked_next()
                .is_ok_and(|next| next == successor_revision)
            || published_at == 0
            || published_at == u64::MAX
        {
            return Err(GitModelError::CorruptEncoding);
        }
        Ok(Self {
            repository,
            predecessor_revision,
            successor_revision,
            atomic_cas,
            published_at,
        })
    }

    /// Returns the published repository identity.
    #[must_use]
    pub const fn repository(self) -> ResourceId {
        self.repository
    }

    /// Returns the compared predecessor revision.
    #[must_use]
    pub const fn predecessor_revision(self) -> Revision {
        self.predecessor_revision
    }

    /// Returns the committed successor revision.
    #[must_use]
    pub const fn successor_revision(self) -> Revision {
        self.successor_revision
    }

    /// Returns the exact receive CAS commitment.
    #[must_use]
    pub const fn atomic_cas(self) -> GitAtomicCasDigestV1 {
        self.atomic_cas
    }

    /// Returns the durable publication time.
    #[must_use]
    pub const fn published_at(self) -> u64 {
        self.published_at
    }
}

/// Wraps an export generation with its exact history predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitExportHistoryRecordV1 {
    export: GitExportGenerationV1,
    predecessor: Option<(Revision, GitExportGenerationDigestV1)>,
}

impl GitExportHistoryRecordV1 {
    /// Constructs one exact export lineage record.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless generation one has no
    /// predecessor and every later generation names its immediate predecessor.
    pub fn new(
        export: GitExportGenerationV1,
        predecessor: Option<(Revision, GitExportGenerationDigestV1)>,
    ) -> Result<Self, GitModelError> {
        let valid = match (export.generation().get(), predecessor) {
            (1, None) => true,
            (2.., Some((generation, _))) => generation
                .checked_next()
                .is_ok_and(|next| next == export.generation()),
            _ => false,
        };
        if !valid {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            export,
            predecessor,
        })
    }

    /// Borrows the complete immutable export generation.
    #[must_use]
    pub const fn export(&self) -> &GitExportGenerationV1 {
        &self.export
    }

    /// Returns the immediate immutable export predecessor.
    #[must_use]
    pub const fn predecessor(&self) -> Option<(Revision, GitExportGenerationDigestV1)> {
        self.predecessor
    }
}

/// Retains an exact pack pin and bounded lease without carrying authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitPackLeaseV1 {
    pub(super) project: aos_sandbox_core::ProjectId,
    pub(super) repository: ResourceId,
    pub(super) pack_generation: ResourceId,
    pub(super) generation: Revision,
    pub(super) generation_digest: GitPackGenerationDigestV1,
    pub(super) export: ResourceId,
    pub(super) export_generation: Revision,
    pub(super) export_digest: GitExportGenerationDigestV1,
    pub(super) consumer: GitPackConsumerV1,
    pub(super) lease: ResourceId,
    pub(super) lease_revision: Revision,
    pub(super) principal: PrincipalId,
    pub(super) boot: super::GitBootIdV1,
    pub(super) observed_at: GitBoottimeV1,
    pub(super) expires_at: u64,
    pub(super) pin_receipt: ObjectDigest,
    pub(super) status: GitPackLeaseStatusV1,
    pub(super) closed_at: Option<u64>,
    pub(super) predecessor_boot: Option<super::GitBootIdV1>,
}

impl GitPackLeaseV1 {
    /// Constructs one exact pack pin and lease.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pack: &ImmutablePackGenerationV1,
        consumer: GitPackConsumerV1,
        lease: ResourceId,
        principal: PrincipalId,
        expires_at: u64,
        pin_receipt: ObjectDigest,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        let observed_at = current_boottime.observed();
        let consumer_valid = match consumer {
            GitPackConsumerV1::Repository(identity) | GitPackConsumerV1::Export(identity) => {
                identity.as_bytes() != &[0; 16]
            }
        };
        if lease.as_bytes() == &[0; 16]
            || !consumer_valid
            || principal.as_bytes() == &[0; 16]
            || expires_at == 0
            || expires_at == u64::MAX
            || expires_at <= observed_at.get()
            || pin_receipt.as_bytes() == &[0; 32]
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            project: pack.project(),
            repository: pack.repository(),
            pack_generation: pack.pack_generation(),
            generation: pack.generation(),
            generation_digest: pack.generation_digest(),
            export: pack.export(),
            export_generation: pack.export_generation(),
            export_digest: pack.export_digest(),
            consumer,
            lease,
            lease_revision: Revision::new(1),
            principal,
            boot: current_boottime.boot(),
            observed_at,
            expires_at,
            pin_receipt,
            status: GitPackLeaseStatusV1::Active,
            closed_at: None,
            predecessor_boot: None,
        })
    }

    /// Returns the exact current lease revision.
    #[must_use]
    pub const fn lease_revision(self) -> Revision {
        self.lease_revision
    }

    /// Returns the source project whose export is pinned.
    #[must_use]
    pub const fn project(self) -> aos_sandbox_core::ProjectId {
        self.project
    }

    /// Returns the source repository whose export is pinned.
    #[must_use]
    pub const fn repository(self) -> ResourceId {
        self.repository
    }

    /// Returns the immutable pack lineage identity.
    #[must_use]
    pub const fn pack_generation(self) -> ResourceId {
        self.pack_generation
    }

    /// Returns the exact retained pack generation.
    #[must_use]
    pub const fn generation(self) -> Revision {
        self.generation
    }

    /// Returns the complete retained pack-generation commitment.
    #[must_use]
    pub const fn generation_digest(self) -> GitPackGenerationDigestV1 {
        self.generation_digest
    }

    /// Returns the exact source export identity.
    #[must_use]
    pub const fn export(self) -> ResourceId {
        self.export
    }

    /// Returns the exact source export generation.
    #[must_use]
    pub const fn export_generation(self) -> Revision {
        self.export_generation
    }

    /// Returns the exact source export commitment.
    #[must_use]
    pub const fn export_digest(self) -> GitExportGenerationDigestV1 {
        self.export_digest
    }

    /// Returns the immutable pack consumer.
    #[must_use]
    pub const fn consumer(self) -> GitPackConsumerV1 {
        self.consumer
    }

    /// Returns the stable lease identity.
    #[must_use]
    pub const fn lease(self) -> ResourceId {
        self.lease
    }

    /// Returns the authenticated lease principal.
    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    /// Returns the exact kernel boot owning the lease deadline.
    #[must_use]
    pub const fn boot(self) -> super::GitBootIdV1 {
        self.boot
    }

    /// Returns the trusted time at which this lease revision was admitted.
    #[must_use]
    pub const fn observed_at(self) -> GitBoottimeV1 {
        self.observed_at
    }

    /// Returns the current expiry deadline.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Returns the exact durable pin receipt.
    #[must_use]
    pub const fn pin_receipt(self) -> ObjectDigest {
        self.pin_receipt
    }

    /// Returns the durable lease state.
    #[must_use]
    pub const fn status(self) -> GitPackLeaseStatusV1 {
        self.status
    }

    /// Returns the exact release or expiry observation time.
    #[must_use]
    pub const fn closed_at(self) -> Option<u64> {
        self.closed_at
    }

    /// Returns the authenticated predecessor boot invalidated by this record.
    #[must_use]
    pub const fn predecessor_boot(self) -> Option<super::GitBootIdV1> {
        self.predecessor_boot
    }

    /// Creates an immediate renewal successor under the current revision.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless this lease is active,
    /// the revision is immediate, expiry strictly increases, and the new pin
    /// receipt is nonzero.
    pub fn renew(
        self,
        expected_revision: Revision,
        expires_at: u64,
        pin_receipt: ObjectDigest,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        let observed_at = current_boottime.observed();
        let next = self
            .lease_revision
            .checked_next()
            .map_err(|_| GitModelError::InvalidModel)?;
        if self.status != GitPackLeaseStatusV1::Active
            || current_boottime.boot() != self.boot
            || expected_revision != self.lease_revision
            || observed_at.get() >= self.expires_at
            || observed_at <= self.observed_at
            || expires_at <= self.expires_at
            || expires_at <= observed_at.get()
            || expires_at == u64::MAX
            || pin_receipt.as_bytes() == &[0; 32]
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            lease_revision: next,
            observed_at,
            expires_at,
            pin_receipt,
            ..self
        })
    }

    /// Creates an immediate release or expiry successor under the current revision.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a stale revision, terminal
    /// lease, invalid status, or expiry asserted before its recorded deadline.
    pub fn close(
        self,
        expected_revision: Revision,
        status: GitPackLeaseStatusV1,
        current_boottime: &GitTrustedBoottimeV1,
    ) -> Result<Self, GitModelError> {
        let next = self
            .lease_revision
            .checked_next()
            .map_err(|_| GitModelError::InvalidModel)?;
        let observed_at = current_boottime.observed().get();
        let valid_expiry =
            status != GitPackLeaseStatusV1::Expired || observed_at >= self.expires_at;
        if self.status != GitPackLeaseStatusV1::Active
            || current_boottime.boot() != self.boot
            || expected_revision != self.lease_revision
            || observed_at <= self.observed_at.get()
            || !matches!(
                status,
                GitPackLeaseStatusV1::Released | GitPackLeaseStatusV1::Expired
            )
            || !valid_expiry
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            lease_revision: next,
            observed_at: current_boottime.observed(),
            status,
            closed_at: Some(observed_at),
            ..self
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_stored(
        project: aos_sandbox_core::ProjectId,
        repository: ResourceId,
        pack_generation: ResourceId,
        generation: Revision,
        generation_digest: GitPackGenerationDigestV1,
        export: ResourceId,
        export_generation: Revision,
        export_digest: GitExportGenerationDigestV1,
        consumer: GitPackConsumerV1,
        lease: ResourceId,
        lease_revision: Revision,
        principal: PrincipalId,
        boot: super::GitBootIdV1,
        observed_at: GitBoottimeV1,
        expires_at: u64,
        pin_receipt: ObjectDigest,
        status: GitPackLeaseStatusV1,
        closed_at: Option<u64>,
        predecessor_boot: Option<super::GitBootIdV1>,
    ) -> Result<Self, GitModelError> {
        let consumer_valid = match consumer {
            GitPackConsumerV1::Repository(identity) | GitPackConsumerV1::Export(identity) => {
                identity.as_bytes() != &[0; 16]
            }
        };
        if project.as_bytes() == &[0; 16]
            || repository.as_bytes() == &[0; 16]
            || pack_generation.as_bytes() == &[0; 16]
            || generation.get() == 0
            || generation.get() == u64::MAX
            || export.as_bytes() == &[0; 16]
            || export_generation.get() == 0
            || export_generation.get() == u64::MAX
            || !consumer_valid
            || lease.as_bytes() == &[0; 16]
            || principal.as_bytes() == &[0; 16]
            || expires_at == 0
            || expires_at == u64::MAX
            || pin_receipt.as_bytes() == &[0; 32]
            || lease_revision.get() == 0
            || lease_revision.get() == u64::MAX
            || (expires_at <= observed_at.get() && status == GitPackLeaseStatusV1::Active)
            || (lease_revision.get() == 1 && status != GitPackLeaseStatusV1::Active)
            || (status == GitPackLeaseStatusV1::Active) != closed_at.is_none()
            || (status == GitPackLeaseStatusV1::Active && predecessor_boot.is_some())
            || closed_at.is_some_and(|value| value == 0 || value == u64::MAX)
            || closed_at.is_some_and(|value| value != observed_at.get())
            || (status == GitPackLeaseStatusV1::Expired
                && closed_at.is_none_or(|value| value < expires_at))
            || (status == GitPackLeaseStatusV1::Invalidated
                && predecessor_boot.is_none_or(|previous| previous == boot))
            || (status != GitPackLeaseStatusV1::Invalidated && predecessor_boot.is_some())
        {
            return Err(GitModelError::CorruptEncoding);
        }
        Ok(Self {
            project,
            repository,
            pack_generation,
            generation,
            generation_digest,
            export,
            export_generation,
            export_digest,
            consumer,
            lease,
            lease_revision,
            principal,
            boot,
            observed_at,
            expires_at,
            pin_receipt,
            status,
            closed_at,
            predecessor_boot,
        })
    }
}

/// Replays independent Git lineages under an explicit compaction floor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitDurableHistoryV1 {
    pub(super) repositories: BTreeMap<ResourceId, GitRepositoryStateV1>,
    pub(super) repository_revisions: BTreeMap<(ResourceId, Revision), GitRepositoryStateV1>,
    pub(super) receives: BTreeMap<ResourceId, GitReceiveHistoryRecordV1>,
    pub(super) receive_records: BTreeMap<(ResourceId, Revision), GitReceiveHistoryRecordV1>,
    pub(super) publications: BTreeMap<(ResourceId, Revision), GitPublicationRecordV1>,
    pub(super) exports: BTreeMap<ResourceId, GitExportHistoryRecordV1>,
    pub(super) export_generations: BTreeMap<(ResourceId, Revision), GitExportHistoryRecordV1>,
    pub(super) packs: BTreeMap<(ResourceId, Revision), ImmutablePackGenerationV1>,
    pub(super) pack_leases: BTreeMap<ResourceId, GitPackLeaseV1>,
    pub(super) pack_lease_records: BTreeMap<(ResourceId, Revision), GitPackLeaseV1>,
    pub(super) retired_packs: BTreeMap<(ResourceId, Revision), super::GitRetiredPackSummaryV1>,
    pub(super) terminal_lease_tombstones: BTreeMap<ResourceId, super::GitTerminalLeaseTombstoneV1>,
    pub(super) terminal_fork_tombstones: BTreeMap<ResourceId, super::GitTerminalForkTombstoneV1>,
    pub(super) cheap_forks: BTreeMap<ResourceId, GitCheapForkV1>,
    pub(super) replay_floor: Option<Revision>,
}

impl GitDurableHistoryV1 {
    pub(super) fn ensure_record_capacity(&self, additional: usize) -> Result<(), GitModelError> {
        let retained = self
            .repository_revisions
            .len()
            .checked_add(self.receive_records.len())
            .and_then(|count| count.checked_add(self.publications.len()))
            .and_then(|count| count.checked_add(self.export_generations.len()))
            .and_then(|count| count.checked_add(self.packs.len()))
            .and_then(|count| count.checked_add(self.pack_leases.len()))
            .and_then(|count| count.checked_add(self.pack_lease_records.len()))
            .and_then(|count| count.checked_add(self.retired_packs.len()))
            .and_then(|count| count.checked_add(self.terminal_lease_tombstones.len()))
            .and_then(|count| count.checked_add(self.terminal_fork_tombstones.len()))
            .and_then(|count| count.checked_add(self.cheap_forks.len()))
            .and_then(|count| count.checked_add(additional))
            .ok_or(GitModelError::InvalidModel)?;
        if retained > MAXIMUM_GIT_HISTORY_RECORDS {
            Err(GitModelError::InvalidModel)
        } else {
            Ok(())
        }
    }

    /// Returns the latest validated repository state.
    #[must_use]
    pub fn repository(&self, identity: ResourceId) -> Option<&GitRepositoryStateV1> {
        self.repositories.get(&identity)
    }

    /// Returns one exact retained repository revision.
    #[must_use]
    pub fn repository_revision(
        &self,
        identity: ResourceId,
        revision: Revision,
    ) -> Option<&GitRepositoryStateV1> {
        self.repository_revisions.get(&(identity, revision))
    }

    /// Returns the latest validated immutable export generation.
    #[must_use]
    pub fn export(&self, identity: ResourceId) -> Option<&GitExportHistoryRecordV1> {
        self.exports.get(&identity)
    }

    /// Returns one exact retained immutable export generation.
    #[must_use]
    pub fn export_generation(
        &self,
        identity: ResourceId,
        generation: Revision,
    ) -> Option<&GitExportHistoryRecordV1> {
        self.export_generations.get(&(identity, generation))
    }

    /// Returns the latest validated immutable pack generation.
    #[must_use]
    pub fn pack(&self, identity: ResourceId) -> Option<&ImmutablePackGenerationV1> {
        self.packs
            .range((identity, Revision::new(0))..=(identity, Revision::new(u64::MAX)))
            .next_back()
            .map(|(_, pack)| pack)
    }

    /// Applies one repository successor after its record digest was checked.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a forked or skipped revision.
    pub fn apply_repository(&mut self, state: GitRepositoryStateV1) -> Result<(), GitModelError> {
        let identity = state.repository.repository();
        if let Some(previous) = self.repositories.get(&identity) {
            let next = previous
                .repository
                .revision()
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?;
            if state.repository.revision() != next
                || state.predecessor != Some(previous.complete_digest())
                || state.database().audience() != previous.database().audience()
                || !self.publications.values().any(|publication| {
                    publication.repository == identity
                        && publication.predecessor_revision == previous.repository.revision()
                        && publication.successor_revision == state.repository.revision()
                        && self.receives.values().any(|receive| {
                            receive.phase == GitReceivePhaseV1::Published
                                && receive.plan.atomic_cas() == publication.atomic_cas
                                && receive.plan.successor_revision() == state.repository.revision()
                                && receive.plan.post_ref_map() == state.ref_map()
                                && receive.plan.post_database() == state.database()
                        })
                })
            {
                return Err(GitModelError::InvalidModel);
            }
        } else if state.repository.revision().get() != 1 || state.predecessor.is_some() {
            return Err(GitModelError::InvalidModel);
        }
        let key = (identity, state.repository().revision());
        if self.repository_revisions.contains_key(&key) {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(1)?;
        self.repository_revisions.insert(key, state.clone());
        self.repositories.insert(identity, state);
        Ok(())
    }

    /// Applies one monotone receive/quarantine history snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for changed plan input, a forked
    /// record chain, phase regression, or progress after a terminal phase.
    pub fn apply_receive(
        &mut self,
        record: GitReceiveHistoryRecordV1,
    ) -> Result<(), GitModelError> {
        if record.phase() == GitReceivePhaseV1::Published {
            return Err(GitModelError::InvalidModel);
        }
        self.apply_receive_record(record)
    }

    fn apply_receive_record(
        &mut self,
        record: GitReceiveHistoryRecordV1,
    ) -> Result<(), GitModelError> {
        let identity = record.plan.exchange();
        let repository_matches = self
            .repositories
            .get(&record.plan.repository().repository())
            .is_some_and(|current| {
                current.repository() == record.plan.repository()
                    && current.ref_map() == record.plan.pre_ref_map()
                    && current.database() == record.plan.pre_database()
            });
        if !repository_matches {
            return Err(GitModelError::InvalidModel);
        }
        if let Some(previous) = self.receives.get(&identity) {
            let next = previous
                .revision
                .checked_next()
                .map_err(|_| GitModelError::InvalidModel)?;
            let previous_terminal = matches!(
                previous.phase,
                GitReceivePhaseV1::Published | GitReceivePhaseV1::Rejected
            );
            let edge = matches!(
                (previous.phase, record.phase),
                (GitReceivePhaseV1::Admitted, GitReceivePhaseV1::Quarantined)
                    | (GitReceivePhaseV1::Quarantined, GitReceivePhaseV1::Validated)
                    | (GitReceivePhaseV1::Quarantined, GitReceivePhaseV1::Rejected)
                    | (GitReceivePhaseV1::Validated, GitReceivePhaseV1::Published)
                    | (GitReceivePhaseV1::Validated, GitReceivePhaseV1::Rejected)
            );
            if previous_terminal
                || !edge
                || record.revision != next
                || record.predecessor != Some(previous.complete_digest())
                || record.plan != previous.plan
            {
                return Err(GitModelError::InvalidModel);
            }
        } else if record.revision.get() != 1
            || record.predecessor.is_some()
            || record.phase != GitReceivePhaseV1::Admitted
        {
            return Err(GitModelError::InvalidModel);
        }
        let key = (identity, record.revision);
        if self.receive_records.contains_key(&key) {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(1)?;
        self.receive_records.insert(key, record.clone());
        self.receives.insert(identity, record);
        Ok(())
    }

    /// Applies a published receive, publication witness, and repository successor atomically.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless the receive is in its
    /// `Published` phase and every pre/post repository commitment links exactly.
    pub fn apply_published_receive(
        &mut self,
        record: GitReceiveHistoryRecordV1,
        published_at: u64,
    ) -> Result<(), GitModelError> {
        if record.phase() != GitReceivePhaseV1::Published {
            return Err(GitModelError::InvalidModel);
        }
        let receive_predecessor = self
            .receives
            .get(&record.plan().exchange())
            .filter(|previous| previous.phase() == GitReceivePhaseV1::Validated)
            .ok_or(GitModelError::InvalidModel)?;
        if !receive_predecessor
            .revision
            .checked_next()
            .is_ok_and(|revision| revision == record.revision)
            || record.predecessor != Some(receive_predecessor.complete_digest())
        {
            return Err(GitModelError::InvalidModel);
        }
        let current = self
            .repositories
            .get(&record.plan().repository().repository())
            .ok_or(GitModelError::InvalidModel)?;
        let repository_predecessor = current.complete_digest();
        let successor = GitRepositoryStateV1::from_receive(record.plan(), repository_predecessor)?;
        let publication = GitPublicationRecordV1::from_receive(record.plan(), published_at)?;

        let mut next = self.clone();
        next.apply_receive_record(record)?;
        next.apply_publication(publication)?;
        next.apply_repository(successor)?;
        *self = next;
        Ok(())
    }

    /// Retains one unique atomic publication witness.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a conflicting witness at the
    /// same repository successor revision.
    fn apply_publication(
        &mut self,
        publication: GitPublicationRecordV1,
    ) -> Result<(), GitModelError> {
        let key = (publication.repository, publication.successor_revision);
        let receive_matches = self.receives.values().any(|receive| {
            receive.phase == GitReceivePhaseV1::Published
                && receive.plan.repository().repository() == publication.repository
                && receive.plan.repository().revision() == publication.predecessor_revision
                && receive.plan.successor_revision() == publication.successor_revision
                && receive.plan.atomic_cas() == publication.atomic_cas
        });
        if !receive_matches
            || self
                .publications
                .get(&key)
                .is_some_and(|existing| existing != &publication)
        {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(usize::from(!self.publications.contains_key(&key)))?;
        self.publications.insert(key, publication);
        Ok(())
    }

    /// Applies one immediate immutable export successor.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a forked export lineage or
    /// reuse of an export identity for another repository.
    pub fn apply_export(&mut self, record: GitExportHistoryRecordV1) -> Result<(), GitModelError> {
        let identity = record.export.export();
        let source_matches = self
            .repository_revisions
            .get(&(
                record.export.repository(),
                record.export.repository_revision(),
            ))
            .is_some_and(|source| {
                source.repository().project() == record.export.project()
                    && source.repository().revision() == record.export.repository_revision()
                    && source.ref_map() == record.export.ref_map()
                    && source.database() == record.export.database()
            });
        if !source_matches {
            return Err(GitModelError::InvalidModel);
        }
        match self.exports.get(&identity) {
            None if record.export.generation().get() == 1 && record.predecessor.is_none() => {}
            Some(previous)
                if previous.export.repository() == record.export.repository()
                    && record.predecessor
                        == Some((
                            previous.export.generation(),
                            previous.export.generation_digest(),
                        )) => {}
            _ => return Err(GitModelError::InvalidModel),
        }
        let key = (identity, record.export.generation());
        if self.export_generations.contains_key(&key) {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(1)?;
        self.export_generations.insert(key, record.clone());
        self.exports.insert(identity, record);
        Ok(())
    }

    /// Applies one immediate immutable pack successor.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a forked pack lineage.
    pub fn apply_pack(&mut self, pack: ImmutablePackGenerationV1) -> Result<(), GitModelError> {
        let identity = pack.pack_generation();
        let export_matches = self.export_generations.values().any(|record| {
            record.export.project() == pack.project()
                && record.export.repository() == pack.repository()
                && record.export.export() == pack.export()
                && record.export.generation() == pack.export_generation()
                && record.export.generation_digest() == pack.export_digest()
                && record.export.database() == pack.database()
        });
        if !export_matches {
            return Err(GitModelError::InvalidModel);
        }
        let previous = self.pack(identity);
        let retired = self.latest_retired_pack(identity);
        match (previous, retired) {
            (None, None) if pack.generation().get() == 1 && pack.predecessor().is_none() => {}
            (Some(previous), _)
                if pack.predecessor()
                    == Some(GitPackGenerationPredecessorV1::new(
                        previous.generation(),
                        previous.generation_digest(),
                    )?) => {}
            (None, Some(previous))
                if previous
                    .generation()
                    .checked_next()
                    .is_ok_and(|generation| generation == pack.generation())
                    && pack.predecessor()
                        == Some(GitPackGenerationPredecessorV1::new(
                            previous.generation(),
                            previous.generation_digest(),
                        )?) => {}
            _ => return Err(GitModelError::InvalidModel),
        }
        let key = (identity, pack.generation());
        if self.packs.contains_key(&key) || self.retired_packs.contains_key(&key) {
            return Err(GitModelError::InvalidModel);
        }
        self.ensure_record_capacity(1)?;
        self.packs.insert(key, pack);
        Ok(())
    }

    /// Retains one unique pack pin and lease.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for a conflicting lease identity
    /// or an unknown pack generation commitment.
    pub fn apply_pack_lease(
        &mut self,
        lease: GitPackLeaseV1,
        verifier: &super::GitJournalVerifierV1,
    ) -> Result<(), GitModelError> {
        let current_boottime = verifier.current_boottime();
        let current = current_boottime.observed();
        let authenticated_boot = verifier.boot_rollover().authenticates(lease.boot());
        let current_active = lease.status() != GitPackLeaseStatusV1::Active
            || (lease.boot() == current_boottime.boot()
                && lease.observed_at() <= current
                && lease.expires_at() > current.get());
        let authenticated_invalidation = lease.status() != GitPackLeaseStatusV1::Invalidated
            || lease.predecessor_boot().is_some_and(|boot| {
                boot != lease.boot() && verifier.boot_rollover().authenticates(boot)
            });
        if !authenticated_boot || !current_active || !authenticated_invalidation {
            return Err(GitModelError::InvalidModel);
        }
        self.apply_replayed_pack_lease(lease)
    }

    pub(super) fn apply_replayed_pack_lease(
        &mut self,
        lease: GitPackLeaseV1,
    ) -> Result<(), GitModelError> {
        self.apply_replayed_pack_lease_scoped(lease, false)
    }

    pub(super) fn apply_replayed_pack_lease_scoped(
        &mut self,
        lease: GitPackLeaseV1,
        allow_repository_consumer: bool,
    ) -> Result<(), GitModelError> {
        let previous = self.pack_leases.get(&lease.lease);
        let valid_successor = previous.is_none_or(|old| {
            old.status == GitPackLeaseStatusV1::Active
                && old
                    .lease_revision
                    .checked_next()
                    .is_ok_and(|revision| revision == lease.lease_revision)
                && old.pack_generation == lease.pack_generation
                && old.generation == lease.generation
                && old.generation_digest == lease.generation_digest
                && old.project == lease.project
                && old.repository == lease.repository
                && old.export == lease.export
                && old.export_generation == lease.export_generation
                && old.export_digest == lease.export_digest
                && old.consumer == lease.consumer
                && old.principal == lease.principal
                && (lease.status != GitPackLeaseStatusV1::Active
                    || lease.expires_at > old.expires_at)
                && (lease.status == GitPackLeaseStatusV1::Active) == lease.closed_at.is_none()
                && ((old.boot == lease.boot
                    && lease.predecessor_boot.is_none()
                    && lease.observed_at > old.observed_at)
                    || (lease.status == GitPackLeaseStatusV1::Invalidated
                        && lease.predecessor_boot == Some(old.boot)
                        && lease.boot != old.boot))
        });
        let closes_dependent_fork = !allow_repository_consumer
            && lease.status != GitPackLeaseStatusV1::Active
            && self.cheap_forks.values().any(|fork| {
                fork.lease().lease() == lease.lease
                    && matches!(
                        fork.status(),
                        GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                    )
            });
        let pack = self.packs.get(&(lease.pack_generation, lease.generation));
        let consumer_matches = pack.is_some_and(|pack| {
            pack.project() == lease.project
                && pack.repository() == lease.repository
                && pack.export() == lease.export
                && pack.export_generation() == lease.export_generation
                && pack.export_digest() == lease.export_digest
                && match lease.consumer {
                    GitPackConsumerV1::Repository(repository) => {
                        allow_repository_consumer
                            && (self.cheap_forks.get(&repository).is_none_or(|fork| {
                                fork.source_repository() == lease.repository
                                    && fork.source_export() == lease.export_digest
                            }))
                    }
                    GitPackConsumerV1::Export(export) => pack.export() == export,
                }
        });
        if self.terminal_lease_tombstones.contains_key(&lease.lease)
            || pack.is_none_or(|pack| pack.generation_digest() != lease.generation_digest)
            || !consumer_matches
            || !valid_successor
            || (previous.is_none()
                && (lease.lease_revision.get() != 1
                    || lease.status != GitPackLeaseStatusV1::Active))
            || self
                .pack_lease_records
                .contains_key(&(lease.lease, lease.lease_revision))
            || closes_dependent_fork
        {
            return Err(GitModelError::InvalidModel);
        }
        if !self.pack_leases.contains_key(&lease.lease) {
            if self.pack_leases.len() >= MAXIMUM_GIT_PACK_LEASES {
                return Err(GitModelError::InvalidModel);
            }
        }
        self.ensure_record_capacity(if previous.is_some() { 1 } else { 2 })?;
        self.pack_lease_records
            .insert((lease.lease, lease.lease_revision), lease);
        self.pack_leases.insert(lease.lease, lease);
        Ok(())
    }

    pub(super) fn apply_pack_lease_with_forks(
        &mut self,
        lease: GitPackLeaseV1,
        forks: &[GitCheapForkV1],
    ) -> Result<(), GitModelError> {
        let previous = self.pack_leases.get(&lease.lease()).copied();
        let dependent_count = self
            .cheap_forks
            .values()
            .filter(|fork| {
                fork.lease().lease() == lease.lease()
                    && matches!(
                        fork.status(),
                        GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                    )
            })
            .count();
        let mut expected_targets = Vec::new();
        expected_targets
            .try_reserve_exact(dependent_count)
            .map_err(|_| GitModelError::Allocation)?;
        expected_targets.extend(self.cheap_forks.iter().filter_map(|(target, fork)| {
            (fork.lease().lease() == lease.lease()
                && matches!(
                    fork.status(),
                    GitCheapForkStatusV1::Attached | GitCheapForkStatusV1::Detached
                ))
            .then_some(*target)
        }));
        let mut supplied_targets = Vec::new();
        supplied_targets
            .try_reserve_exact(forks.len())
            .map_err(|_| GitModelError::Allocation)?;
        supplied_targets.extend(
            forks
                .iter()
                .map(|fork| fork.target().repository().repository()),
        );
        expected_targets.sort_unstable();
        supplied_targets.sort_unstable();
        if supplied_targets.windows(2).any(|pair| pair[0] == pair[1])
            || match previous {
                None => forks.len() != 1,
                Some(_) => expected_targets != supplied_targets,
            }
            || (lease.status() != GitPackLeaseStatusV1::Active
                && forks.iter().any(|fork| {
                    !matches!(
                        fork.status(),
                        GitCheapForkStatusV1::Converted | GitCheapForkStatusV1::Tombstoned
                    ) || fork.lease() != lease
                }))
            || (lease.status() == GitPackLeaseStatusV1::Active
                && forks.iter().any(|fork| fork.lease() != lease))
        {
            return Err(GitModelError::InvalidModel);
        }

        let mut next = self.clone();
        next.apply_replayed_pack_lease_scoped(lease, true)?;
        for fork in forks {
            next.apply_replayed_cheap_fork(fork.clone())?;
        }
        *self = next;
        Ok(())
    }
}
