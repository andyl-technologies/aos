//! Admission, artifact, permit, and completion state machine.
//!
//! Every effect-bearing method consumes or borrows an opaque predecessor minted
//! by this module. Public record structs remain inspectable for diagnostics, but
//! cannot be passed back as authority. The reducer is journal-neutral: returned
//! [`LedgerMutation`] values must be committed atomically by the later protected
//! journal adapter before any corresponding external response or effect.
//!
//! The opaque authority tokens and their consuming reducer intentionally remain
//! co-located: module privacy is the boundary that prevents decoded records or
//! pre-commit observations from constructing effect authority. Formats,
//! accounting, replay, recovery, source authority, roots, and protocol bodies
//! are split into focused modules; separating this final owner would either
//! broaden constructors or duplicate the transition invariants.

use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::format::{
    encode_publisher_admission_request_v1, encode_publisher_domain_plan,
};
use aos_sandbox_core::{ObjectDigest, OperationId, PublicationReservationId};

#[cfg(target_os = "linux")]
use crate::ownership_authority::ProtectedOwnershipClockError;
#[cfg(target_os = "linux")]
use crate::publisher_control::RuntimeJoinedPublisherRequest;
#[cfg(target_os = "linux")]
use crate::publisher_roots::{
    AuthorizedPublicationRoot, CurrentPublicationRoot, PublicationRootCustody,
    PublicationRootRegistry,
};
#[cfg(target_os = "linux")]
use crate::runtime_authority::RuntimeAuthorityStateV1;

use super::accounting::{AccountingError, CapacityPolicyV1, PublicationAccounting};
use super::format::encode_protected_record_v1;
use super::model::{
    AdmissionDecisionStateV1, AdmissionDecisionV1, AdmissionLimits, ArtifactCommitmentV1,
    ChallengeConsumptionV1, CompletionPermitStateV1, CompletionPermitV1, CompletionReceiptV1,
    LedgerMutation, ProtectedRecordKindV1, PublicationAuthorityEpoch, PublicationPermitId,
    RecoveryObservationReceiptV1, digest_parts, validate_nonzero,
};
use super::payload::{
    accounting_payload, artifact_payload, challenge_key_bytes, challenge_payload,
    checkpoint_payload, decision_payload, decode_plan_content, eviction_payload, permit_payload,
    receipt_payload, recovery_observation_payload, source_release_payload,
};
use super::source::{AuthorizedSourceRelease, SourceReleaseError};

const DECISION_DOMAIN: &[u8] = b"aos.sandbox.publisher.admission-decision.v1\0";
#[cfg(target_os = "linux")]
const RUNTIME_DOMAIN: &[u8] = b"aos.sandbox.publisher.runtime-join.v1\0";
const ARTIFACT_DOMAIN: &[u8] = b"aos.sandbox.publisher.prepared-artifact.v1\0";
const PERMIT_DOMAIN: &[u8] = b"aos.sandbox.publisher.completion-permit.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.publisher.completion-receipt.v1\0";
const EVICTION_DOMAIN: &[u8] = b"aos.sandbox.publisher.catalog-eviction.v1\0";

/// Prevents registry mutation outside the combined protected-owner reducer.
pub(crate) struct RootRegistryOwnerToken(());

/// Prevents source mutation outside the combined protected-owner reducer.
pub(crate) struct SourceRegistryOwnerToken(());

/// Opaque live-join-derived plan that may enter durable admission.
///
/// There is no decoder or public field constructor. Static signed plans,
/// challenge audit receipts, and persisted runtime observations cannot create
/// this value.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub struct AdmittedPublisherPlan<'authority, 'request> {
    decision: AdmissionDecisionV1,
    challenge: ChallengeConsumptionV1,
    requested_bytes: u64,
    not_before_seconds: i64,
    expires_seconds: i64,
    origin_frontier: CommittedAdmissionFrontier,
    _runtime: LivePublisherExecution<'authority, 'request>,
    _source: AuthorizedSourceRelease<'authority>,
    _root: &'authority CurrentPublicationRoot<'authority>,
}

#[cfg(target_os = "linux")]
impl<'authority, 'request> AdmittedPublisherPlan<'authority, 'request> {
    pub(super) fn from_runtime_join(
        execution: LivePublisherExecution<'authority, 'request>,
        source_authority: AuthorizedSourceRelease<'authority>,
        root_selection: &'authority CurrentPublicationRoot<'authority>,
        authority_epoch: PublicationAuthorityEpoch,
        capacity_policy: CapacityPolicyV1,
        now_seconds: i64,
        limits: AdmissionLimits,
        origin_frontier: CommittedAdmissionFrontier,
    ) -> Result<Self, AdmissionError> {
        let limits = limits.validate()?;
        let joined = execution.joined;
        let request = joined.request();
        let plan = request.plan();
        let fields = plan.fields();
        let source = source_authority.release();
        if !root_selection.is_current() {
            return Err(AdmissionError::AuthorityMismatch);
        }
        let root_authority = root_selection.root();
        let root_checkpoint = root_selection.checkpoint();
        let root = root_authority.record();
        if fields.request.source_authorization != source_authority.digest()
            || fields.authority.root_registry_generation != root_checkpoint.generation
            || capacity_policy.resource != request.cache_resource()
            || capacity_policy.project != fields.target.project
            || capacity_policy.domain != fields.target.cache_domain
            || capacity_policy.isolation_policy != fields.target.isolation_policy
            || root.project != fields.target.project
            || root.service_node != fields.target.node
            || root.service_principal != fields.target.principal
            || root.resource != request.cache_resource()
            || root.domain != fields.target.cache_domain
            || root.isolation_policy != fields.target.isolation_policy
            || root.role
                != crate::publisher_roots::PublicationRootRoleV1::ImmutablePublicationObjects
            || source.release_digest != fields.request.source_authorization
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        source.authorize(
            fields.request.holder,
            fields.target.project,
            request.cache_resource(),
            fields.target.cache_domain,
            &fields.request.content,
            now_seconds,
        )?;
        let binding = joined.runtime().binding();
        if binding.state() != RuntimeAuthorityStateV1::Bound
            || binding.holder() != Some(fields.request.holder)
        {
            return Err(AdmissionError::RuntimeMismatch);
        }
        let canonical_request = encode_publisher_admission_request_v1(request);
        let canonical_plan = encode_publisher_domain_plan(plan);
        if canonical_request.len() > limits.maximum_protocol_bytes
            || canonical_plan.len() > limits.maximum_protocol_bytes
        {
            return Err(AdmissionError::LimitExceeded("canonical request"));
        }
        let runtime_binding_digest = runtime_join_digest(joined);
        let decision_digest = digest_parts(
            DECISION_DOMAIN,
            &[
                fields.request.operation.as_bytes(),
                fields.request.reservation.as_bytes(),
                fields.target.instance.as_bytes(),
                &canonical_request,
                &canonical_plan,
                runtime_binding_digest.as_bytes(),
                source.release_digest.as_bytes(),
                root_checkpoint.registry_digest.as_bytes(),
                &root_checkpoint.generation.to_be_bytes(),
                root_authority.record_digest().as_bytes(),
                &root_authority.generation().to_be_bytes(),
                &authority_epoch.get().to_be_bytes(),
            ],
        );
        let decision = AdmissionDecisionV1 {
            operation: fields.request.operation,
            reservation: fields.request.reservation,
            publisher_instance: fields.target.instance,
            canonical_request,
            canonical_plan,
            runtime_binding_digest,
            source_release_digest: source.release_digest,
            root_registry_digest: root_checkpoint.registry_digest,
            root_registry_generation: root_checkpoint.generation,
            selected_root_digest: root_authority.record_digest(),
            selected_root_generation: root_authority.generation(),
            authority_epoch,
            state: AdmissionDecisionStateV1::Admitted,
            decision_digest,
        };
        let challenge = ChallengeConsumptionV1 {
            publisher_instance: fields.target.instance,
            challenge: request.challenge(),
            request_commitment: fields.request.commitment.digest(),
            operation: fields.request.operation,
            reservation: fields.request.reservation,
            decision_digest,
        };
        let not_before_seconds = source.not_before_seconds;
        let expires_seconds = source.expires_seconds;
        Ok(Self {
            decision,
            challenge,
            requested_bytes: fields.request.maximum_bytes,
            not_before_seconds,
            expires_seconds,
            origin_frontier,
            _runtime: execution,
            _source: source_authority,
            _root: root_selection,
        })
    }

    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.decision.operation
    }

    /// Returns the immutable admission decision digest.
    #[must_use]
    pub const fn decision_digest(&self) -> ObjectDigest {
        self.decision.decision_digest
    }
}

/// Opaque preparation for one exact sealed private artifact.
#[derive(Debug)]
pub struct ArtifactPreparation {
    artifact: ArtifactCommitmentV1,
    origin_frontier: CommittedAdmissionFrontier,
}

/// Carries one fresh verify-and-seal observation from immutable-file mechanics.
///
/// Construction is crate-private. It contains portable commitments only; the
/// trusted Linux adapter must retain the actual descriptor until the protected
/// prepared-artifact record commits.
#[derive(Debug, Eq, PartialEq)]
pub struct FreshSealedArtifactObservation {
    content: aos_sandbox_core::ObjectDescriptor,
    verity_sha256: [u8; 32],
    private_name_digest: ObjectDigest,
    final_name_digest: ObjectDigest,
    bytes: u64,
    allocated_bytes: u64,
}

impl FreshSealedArtifactObservation {
    /// Captures an already copied, byte-verified, freshly sealed inode.
    pub(crate) const fn from_immutable_file_adapter(
        content: aos_sandbox_core::ObjectDescriptor,
        verity_sha256: [u8; 32],
        private_name_digest: ObjectDigest,
        final_name_digest: ObjectDigest,
        bytes: u64,
        allocated_bytes: u64,
    ) -> Self {
        Self {
            content,
            verity_sha256,
            private_name_digest,
            final_name_digest,
            bytes,
            allocated_bytes,
        }
    }
}

/// Seals singular immutable-file custody for one completion effect.
///
/// This opaque non-Clone value is minted only by the trusted immutable-file
/// adapter while it retains the prepared inode and final-name transaction.
/// The adapter commits the deterministic expected effect and parent-sync
/// observations before starting work; post-effect custody must match them
/// exactly. Scalar protocol fields cannot recreate effect custody.
#[must_use = "completion effect custody must enter a protected settlement"]
pub struct CompletionEffectCustodyV1 {
    operation: OperationId,
    artifact_digest: ObjectDigest,
    root_record_digest: ObjectDigest,
    private_name_digest: ObjectDigest,
    final_name_digest: ObjectDigest,
    prepared_observation_digest: ObjectDigest,
    expected_physical_effect_digest: ObjectDigest,
    expected_parent_sync_digest: ObjectDigest,
}

impl CompletionEffectCustodyV1 {
    /// Seals live no-replace publication custody inside the trusted adapter.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when any physical or synchronization
    /// commitment is the zero sentinel, or the private and final names match.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_from_immutable_file_adapter(
        operation: OperationId,
        artifact_digest: ObjectDigest,
        root_record_digest: ObjectDigest,
        private_name_digest: ObjectDigest,
        final_name_digest: ObjectDigest,
        prepared_observation_digest: ObjectDigest,
        expected_physical_effect_digest: ObjectDigest,
        expected_parent_sync_digest: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        validate_nonzero(&[
            ("completion operation", operation.as_bytes()),
            ("completion artifact", artifact_digest.as_bytes()),
            ("completion root", root_record_digest.as_bytes()),
            ("completion private name", private_name_digest.as_bytes()),
            ("completion final name", final_name_digest.as_bytes()),
            (
                "completion prepared observation",
                prepared_observation_digest.as_bytes(),
            ),
            (
                "completion expected physical effect",
                expected_physical_effect_digest.as_bytes(),
            ),
            (
                "completion expected parent sync",
                expected_parent_sync_digest.as_bytes(),
            ),
        ])?;
        if private_name_digest == final_name_digest {
            return Err(AdmissionError::ArtifactMismatch);
        }
        Ok(Self {
            operation,
            artifact_digest,
            root_record_digest,
            private_name_digest,
            final_name_digest,
            prepared_observation_digest,
            expected_physical_effect_digest,
            expected_parent_sync_digest,
        })
    }
}

/// Seals the adapter's post-effect final-name and parent-sync observation.
///
/// This non-Clone value is distinct from pre-effect custody and is retained
/// beside it until the protected completion or poison branch is acknowledged.
#[must_use = "completion effect observation must enter protected settlement"]
pub struct CompletionEffectObservationV1 {
    operation: OperationId,
    artifact_digest: ObjectDigest,
    root_record_digest: ObjectDigest,
    final_name_digest: ObjectDigest,
    physical_effect_digest: ObjectDigest,
    parent_sync_digest: ObjectDigest,
}

impl CompletionEffectObservationV1 {
    /// Seals a completed no-replace and parent-synchronization observation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when any exact identity or observation is a
    /// zero sentinel.
    pub(crate) fn seal_from_immutable_file_adapter(
        operation: OperationId,
        artifact_digest: ObjectDigest,
        root_record_digest: ObjectDigest,
        final_name_digest: ObjectDigest,
        physical_effect_digest: ObjectDigest,
        parent_sync_digest: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        validate_nonzero(&[
            ("completion operation", operation.as_bytes()),
            ("completion artifact", artifact_digest.as_bytes()),
            ("completion root", root_record_digest.as_bytes()),
            ("completion final name", final_name_digest.as_bytes()),
            (
                "completion physical effect",
                physical_effect_digest.as_bytes(),
            ),
            ("completion parent sync", parent_sync_digest.as_bytes()),
        ])?;
        Ok(Self {
            operation,
            artifact_digest,
            root_record_digest,
            final_name_digest,
            physical_effect_digest,
            parent_sync_digest,
        })
    }
}

/// Borrows post-commit authority for one exact materialization attempt.
///
/// The token joins the current retained decision with fresh runtime, source,
/// and root borrows. It cannot be decoded, persisted, or retained after any of
/// those authorities changes.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub struct MaterializationAuthority<'authority, 'request> {
    decision: &'authority AdmissionDecisionV1,
    committed: CommittedAdmissionFrontier,
    _runtime: LivePublisherExecution<'authority, 'request>,
    _source: AuthorizedSourceRelease<'authority>,
    _root: &'authority CurrentPublicationRoot<'authority>,
}

impl ArtifactPreparation {
    /// Binds physical seal evidence and derived names to one admitted operation.
    ///
    /// Name digests must come from the protected publisher's deterministic name
    /// derivation. Device and inode numbers are intentionally absent: they are
    /// live observation evidence and never durable authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for sentinel/mismatched facts, wrong size or
    /// content, equal names, or a non-SHA-256 seal sentinel.
    #[cfg(target_os = "linux")]
    pub(crate) fn for_authority(
        authority: &MaterializationAuthority<'_, '_>,
        observation: FreshSealedArtifactObservation,
    ) -> Result<Self, AdmissionError> {
        let FreshSealedArtifactObservation {
            content,
            verity_sha256,
            private_name_digest,
            final_name_digest,
            bytes,
            allocated_bytes,
        } = observation;
        validate_nonzero(&[
            ("verity measurement", &verity_sha256),
            ("private name", private_name_digest.as_bytes()),
            ("final name", final_name_digest.as_bytes()),
        ])?;
        if private_name_digest == final_name_digest {
            return Err(AdmissionError::ArtifactMismatch);
        }
        let requested_content = decode_plan_content(authority.decision)?;
        if content != requested_content
            || bytes != content.encoded_size()
            || allocated_bytes < bytes
            || allocated_bytes
                > aos_sandbox_core::format::decode_publisher_domain_plan(
                    &authority.decision.canonical_plan,
                    aos_sandbox_core::DecodeLimits::default(),
                )
                .map_err(|_| AdmissionError::ArtifactMismatch)?
                .fields()
                .request
                .maximum_bytes
        {
            return Err(AdmissionError::ArtifactMismatch);
        }
        let artifact_digest = digest_parts(
            ARTIFACT_DOMAIN,
            &[
                authority.decision.operation.as_bytes(),
                authority.decision.publisher_instance.as_bytes(),
                authority.decision.decision_digest.as_bytes(),
                &authority.decision.selected_root_generation.to_be_bytes(),
                content.media_type().as_str().as_bytes(),
                content.digest().as_bytes(),
                &content.encoded_size().to_be_bytes(),
                &verity_sha256,
                private_name_digest.as_bytes(),
                final_name_digest.as_bytes(),
                &bytes.to_be_bytes(),
                &allocated_bytes.to_be_bytes(),
            ],
        );
        Ok(Self {
            artifact: ArtifactCommitmentV1 {
                operation: authority.decision.operation,
                publisher_instance: authority.decision.publisher_instance,
                decision_digest: authority.decision.decision_digest,
                root_generation: authority.decision.selected_root_generation,
                content,
                verity_sha256,
                private_name_digest,
                final_name_digest,
                bytes,
                allocated_bytes,
                artifact_digest,
            },
            origin_frontier: authority.committed.clone(),
        })
    }

    /// Returns the exact prepared-artifact digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.artifact.artifact_digest
    }
}

/// Carries independently observed terminal catalog facts.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct CompletionResult {
    /// One-shot permit returned by the controller.
    permit: PublicationPermitId,
    /// Exact operation.
    operation: OperationId,
    /// Exact durable catalog head immediately before insertion.
    prior_catalog_generation: u64,
    /// Monotone committed catalog generation.
    catalog_generation: u64,
    /// Fully typed canonical catalog entry committed durably.
    catalog_entry: super::CommittedReadEntryV1,
}

/// Carries a trusted adapter's pinned physical and durable catalog observation.
///
/// Construction is crate-private and must follow exact final-name observation,
/// parent synchronization, atomic catalog commit, and catalog synchronization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCatalogObservation {
    prior_catalog_generation: u64,
    catalog_generation: u64,
    catalog_entry: super::CommittedReadEntryV1,
}

/// Retains every singular owner required by one ordinary completion effect.
///
/// The trusted adapter receives this value before changing the final name or
/// catalog. Dropping it at any point durably selects its sealed poison branch
/// while the live executor, root descriptor, physical effect, catalog, ledger,
/// and protected-store borrows are still retained.
#[must_use = "completion authority must be observed and durably settled"]
#[cfg(target_os = "linux")]
pub struct CompletionAuthorityV1<'owners, 'authority, 'request> {
    permit: RetainedCompletionPermit<'authority, 'request>,
    _effect: CompletionEffectCustodyV1,
    intended_entry: super::CommittedReadEntryV1,
    ledger: &'owners mut AdmissionLedger,
    catalog: Option<super::read_authority::ExclusiveCatalogInsertionCustody<'owners>>,
    primary: ProtectedMutationBranchV1,
    poison: ProtectedMutationBranchV1,
    receipt: Option<CompletionReceiptV1>,
    store: &'owners mut dyn CapacityProtectedStoreSettlementV1,
    settled: bool,
}

/// Retains an observed completion until one protected branch is acknowledged.
#[must_use = "observed completion must settle to acknowledged success or poison"]
#[cfg(target_os = "linux")]
pub struct CompletionSettlementV1<'owners, 'authority, 'request> {
    // Declaration order keeps the live executor, descriptor root, and physical
    // effect inside `authority` until its poison-on-drop transaction finishes.
    authority: CompletionAuthorityV1<'owners, 'authority, 'request>,
    _effect_observation: CompletionEffectObservationV1,
    primary_allowed: bool,
}

/// Authorizes one catalog removal while retaining every singular owner.
///
/// Dropping this value before reporting the physical result durably settles
/// its precomputed poison branch; it never silently releases effect custody.
#[must_use = "catalog eviction authority must be consumed by its durable adapter"]
pub struct CatalogEvictionAuthorizationV1<'catalog> {
    operation: OperationId,
    catalog_entry_digest: ObjectDigest,
    prior_catalog_generation: u64,
    ledger: &'catalog mut AdmissionLedger,
    custody: Option<super::ExclusiveCatalogEvictionCustody<'catalog>>,
    poison: Option<ProtectedMutationBranchV1>,
    store: &'catalog mut dyn StateOnlyProtectedStoreSettlementV1,
    settled: bool,
}

impl Drop for CatalogEvictionAuthorizationV1<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Some(poison) = self.poison.as_ref() else {
            self.ledger.latch_unacknowledged_poison();
            if let Some(custody) = self.custody.take() {
                custody.poison();
            }
            self.settled = true;
            return;
        };
        let receipt = self.store.settle(None, poison);
        let acknowledged = match receipt {
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => poison.acknowledge(token).is_ok(),
            ProtectedStoreSettlementReceiptV1::Primary(_) => false,
        };
        if acknowledged {
            if let Some(custody) = self.custody.take() {
                custody.poison();
            }
            *self.ledger = poison.ledger.clone();
        } else {
            self.ledger.latch_unacknowledged_poison();
            if let Some(custody) = self.custody.take() {
                custody.poison();
            }
        }
        self.settled = true;
    }
}

/// Carries a durable unpinned catalog-removal observation and retained authority.
pub struct CatalogEvictionObservation<'catalog> {
    authorization: CatalogEvictionAuthorizationV1<'catalog>,
    _eviction_catalog_generation: u64,
}

/// Retains eviction, catalog, ledger, and store custody until acknowledgement.
#[must_use = "catalog eviction must settle to an acknowledged success or poison branch"]
pub struct CatalogEvictionCommitV1<'catalog> {
    observation: Option<CatalogEvictionObservation<'catalog>>,
    primary: Option<ProtectedMutationBranchV1>,
    eviction: Option<super::CatalogEvictionReceiptV1>,
    settled: bool,
}

impl<'catalog> CatalogEvictionObservation<'catalog> {
    /// Captures removal without releasing any protected or catalog custody.
    pub(crate) fn from_durable_catalog_adapter(
        authorization: CatalogEvictionAuthorizationV1<'catalog>,
        eviction_catalog_generation: u64,
    ) -> CatalogEvictionCommitV1<'catalog> {
        let mut staged = (*authorization.ledger).clone();
        let expected_generation = authorization.prior_catalog_generation.checked_add(1);
        let result = if expected_generation == Some(eviction_catalog_generation) {
            staged.evict_catalog_entry_in_place(
                authorization.operation,
                authorization.catalog_entry_digest,
                authorization.prior_catalog_generation,
                eviction_catalog_generation,
            )
        } else {
            Err(AdmissionError::CompletionMismatch)
        };
        let (primary, eviction) = match result {
            Ok((eviction, mutations)) => match ProtectedMutationBranchV1::seal(staged, mutations) {
                Ok(primary) => (Some(primary), Some(eviction)),
                Err(_) => (None, None),
            },
            Err(_) => (None, None),
        };
        CatalogEvictionCommitV1 {
            observation: Some(Self {
                authorization,
                _eviction_catalog_generation: eviction_catalog_generation,
            }),
            primary,
            eviction,
            settled: false,
        }
    }
}

impl CatalogEvictionCommitV1<'_> {
    fn poison(&self) -> Option<&ProtectedMutationBranchV1> {
        self.observation.as_ref()?.authorization.poison.as_ref()
    }

    fn settle_store(&mut self, primary: bool) -> Option<ProtectedStoreSettlementReceiptV1> {
        let primary = primary.then(|| self.primary.as_ref()).flatten();
        let observation = self.observation.as_mut()?;
        Some(
            observation
                .authorization
                .store
                .settle(primary, observation.authorization.poison.as_ref()?),
        )
    }

    fn install_primary(&mut self, token: ProtectedStoreCommitToken) -> Result<(), AdmissionError> {
        let primary = self
            .primary
            .as_ref()
            .ok_or(AdmissionError::AuthorityMismatch)?;
        primary.acknowledge(token)?;
        let observation = self.observation.as_mut().ok_or(AdmissionError::Poisoned)?;
        observation
            .authorization
            .custody
            .take()
            .ok_or(AdmissionError::Poisoned)?
            .commit();
        *observation.authorization.ledger = primary.ledger.clone();
        observation.authorization.settled = true;
        self.settled = true;
        Ok(())
    }

    fn install_poison(&mut self, token: ProtectedStoreCommitToken) -> Result<(), AdmissionError> {
        let poison = self.poison().ok_or(AdmissionError::Poisoned)?;
        poison.acknowledge(token)?;
        let poisoned = poison.ledger.clone();
        let observation = self.observation.as_mut().ok_or(AdmissionError::Poisoned)?;
        if let Some(custody) = observation.authorization.custody.take() {
            custody.poison();
        }
        *observation.authorization.ledger = poisoned;
        observation.authorization.settled = true;
        self.settled = true;
        Ok(())
    }

    fn latch_unacknowledged_poison(&mut self) {
        if let Some(observation) = self.observation.as_mut() {
            observation
                .authorization
                .ledger
                .latch_unacknowledged_poison();
            if let Some(custody) = observation.authorization.custody.take() {
                custody.poison();
            }
            observation.authorization.settled = true;
        }
    }

    /// Settles the exact eviction branch before releasing catalog state.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] only if a trusted store returns a token for
    /// neither precomputed branch. Invalid observations settle as poison.
    pub(crate) fn settle(mut self) -> Result<super::CatalogEvictionReceiptV1, AdmissionError> {
        let has_primary = self.primary.is_some();
        let receipt = self
            .settle_store(has_primary)
            .ok_or(AdmissionError::Poisoned)?;
        match receipt {
            ProtectedStoreSettlementReceiptV1::Primary(token) => {
                self.install_primary(token)?;
                self.eviction.take().ok_or(AdmissionError::Poisoned)
            }
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => {
                self.install_poison(token)?;
                Err(AdmissionError::Poisoned)
            }
        }
    }
}

impl Drop for CatalogEvictionCommitV1<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if self.poison().is_none() {
            self.latch_unacknowledged_poison();
            return;
        }
        let receipt = self.settle_store(false);
        let acknowledged = match receipt {
            Some(ProtectedStoreSettlementReceiptV1::Poisoned(token)) => {
                self.install_poison(token).is_ok()
            }
            Some(ProtectedStoreSettlementReceiptV1::Primary(_)) | None => false,
        };
        if !acknowledged {
            self.latch_unacknowledged_poison();
        }
    }
}

/// Retains root-registry and ledger ownership through durable retirement.
#[must_use = "root retirement must settle to an acknowledged success or poison branch"]
pub(crate) struct RootRetirementCommitV1<'registry> {
    ledger: &'registry mut AdmissionLedger,
    registry: &'registry mut crate::publisher_roots::PublicationRootRegistry,
    primary: ProtectedMutationBranchV1,
    staged_registry: crate::publisher_roots::PublicationRootRegistry,
    poison: Option<ProtectedMutationBranchV1>,
    retired: crate::publisher_roots::PublicationRootRecordV1,
    store: &'registry mut dyn StateOnlyProtectedStoreSettlementV1,
    settled: bool,
}

impl RootRetirementCommitV1<'_> {
    /// Installs retirement only after its exact protected checkpoint is durable.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the trusted adapter acknowledges neither
    /// exact precomputed branch. A poison settlement keeps the root unusable.
    pub(crate) fn settle(
        mut self,
    ) -> Result<crate::publisher_roots::PublicationRootRecordV1, AdmissionError> {
        let receipt = self.store.settle(
            Some(&self.primary),
            self.poison.as_ref().ok_or(AdmissionError::Poisoned)?,
        );
        match receipt {
            ProtectedStoreSettlementReceiptV1::Primary(token) => {
                self.primary.acknowledge(token)?;
                *self.ledger = self.primary.ledger.clone();
                *self.registry = self.staged_registry.clone();
                self.settled = true;
                Ok(self.retired.clone())
            }
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => {
                self.install_acknowledged_poison(token)?;
                Err(AdmissionError::Poisoned)
            }
        }
    }

    fn install_acknowledged_poison(
        &mut self,
        token: ProtectedStoreCommitToken,
    ) -> Result<(), AdmissionError> {
        let poison = self.poison.as_ref().ok_or(AdmissionError::Poisoned)?;
        poison.acknowledge(token)?;
        *self.ledger = poison.ledger.clone();
        self.registry.poison();
        self.settled = true;
        Ok(())
    }
}

impl Drop for RootRetirementCommitV1<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Some(poison) = self.poison.as_ref() else {
            self.ledger.latch_unacknowledged_poison();
            self.registry.poison();
            return;
        };
        let receipt = self.store.settle(None, poison);
        let acknowledged = match receipt {
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => poison.acknowledge(token).is_ok(),
            ProtectedStoreSettlementReceiptV1::Primary(_) => false,
        };
        if acknowledged {
            *self.ledger = poison.ledger.clone();
            self.registry.poison();
            self.settled = true;
        } else {
            self.ledger.latch_unacknowledged_poison();
            self.registry.poison();
        }
    }
}

impl CommittedCatalogObservation {
    /// Captures one already durable physical/catalog result.
    pub(crate) const fn from_durable_adapter(
        prior_catalog_generation: u64,
        catalog_generation: u64,
        catalog_entry: super::CommittedReadEntryV1,
    ) -> Self {
        Self {
            prior_catalog_generation,
            catalog_generation,
            catalog_entry,
        }
    }

    pub(super) const fn catalog_entry_digest(&self) -> ObjectDigest {
        self.catalog_entry.entry_digest
    }

    pub(super) const fn prior_generation(&self) -> u64 {
        self.prior_catalog_generation
    }

    pub(super) const fn generation(&self) -> u64 {
        self.catalog_generation
    }

    pub(super) const fn entry(&self) -> &super::CommittedReadEntryV1 {
        &self.catalog_entry
    }
}

impl CompletionResult {
    /// Captures one terminal observation from the trusted catalog adapter.
    #[cfg(target_os = "linux")]
    const fn observed(
        permit: &RetainedCompletionPermit<'_, '_>,
        observation: CommittedCatalogObservation,
    ) -> Self {
        Self {
            permit: permit.permit.permit,
            operation: permit.permit.operation,
            prior_catalog_generation: observation.prior_catalog_generation,
            catalog_generation: observation.catalog_generation,
            catalog_entry: observation.catalog_entry,
        }
    }

    /// Binds an already durable catalog observation to a retained permit.
    ///
    /// This recovery-only constructor does not grant permission to create an
    /// effect. It merely reconstructs the exact terminal result that protected
    /// replay may accept for an outstanding, revocation-pending, or uncertain
    /// permit after failover.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless the operation, artifact, and retained
    /// permit state exactly match the durable observation.
    pub(super) fn from_recovery_observation(
        ledger: &AdmissionLedger,
        operation: OperationId,
        observation: CommittedCatalogObservation,
    ) -> Result<Self, AdmissionError> {
        let permit = ledger
            .permits
            .get(operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        let artifact = ledger
            .artifacts
            .get(operation.as_bytes())
            .ok_or(AdmissionError::ArtifactMismatch)?;
        if permit.artifact_digest != artifact.artifact_digest
            || !matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding
                    | CompletionPermitStateV1::RevocationPending
                    | CompletionPermitStateV1::Uncertain
            )
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        Ok(Self {
            permit: permit.permit,
            operation,
            prior_catalog_generation: observation.prior_catalog_generation,
            catalog_generation: observation.catalog_generation,
            catalog_entry: observation.catalog_entry,
        })
    }

    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn catalog_entry_digest(&self) -> ObjectDigest {
        self.catalog_entry.entry_digest
    }
}

#[cfg(target_os = "linux")]
impl CompletionAuthorityV1<'_, '_, '_> {
    fn settle_store(&mut self, primary_allowed: bool) -> ProtectedStoreSettlementReceiptV1 {
        let primary = primary_allowed.then_some(&self.primary);
        self.store.settle(primary, &self.poison)
    }

    fn install_primary(&mut self, token: ProtectedStoreCommitToken) -> Result<(), AdmissionError> {
        if self.catalog.is_none() {
            return Err(AdmissionError::Poisoned);
        }
        self.primary.acknowledge(token)?;
        let Some(catalog) = self.catalog.take() else {
            std::process::abort();
        };
        catalog.commit();
        *self.ledger = self.primary.ledger.clone();
        self.settled = true;
        Ok(())
    }

    fn install_acknowledged_poison(
        &mut self,
        token: ProtectedStoreCommitToken,
    ) -> Result<(), AdmissionError> {
        if self.catalog.is_none() {
            return Err(AdmissionError::Poisoned);
        }
        self.poison.acknowledge(token)?;
        let poisoned = self.poison.ledger.clone();
        let Some(catalog) = self.catalog.take() else {
            std::process::abort();
        };
        catalog.poison();
        *self.ledger = poisoned;
        self.settled = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for CompletionAuthorityV1<'_, '_, '_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let receipt = self.settle_store(false);
        let acknowledged = match receipt {
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => {
                self.install_acknowledged_poison(token).is_ok()
            }
            ProtectedStoreSettlementReceiptV1::Primary(_) => false,
        };
        if !acknowledged {
            // Returning would release the live executor, descriptor, catalog,
            // ledger, and effect custody without durable poison. The trusted
            // store contract therefore makes an invalid receipt process-fatal.
            std::process::abort();
        }
    }
}

#[cfg(target_os = "linux")]
impl<'owners, 'authority, 'request> CompletionSettlementV1<'owners, 'authority, 'request> {
    /// Captures the durable no-replace and catalog outcome without releasing custody.
    pub(crate) fn from_durable_adapter(
        authority: CompletionAuthorityV1<'owners, 'authority, 'request>,
        observation: CommittedCatalogObservation,
        effect_observation: CompletionEffectObservationV1,
    ) -> Self {
        let primary_allowed = authority.catalog.as_ref().is_some_and(|catalog| {
            catalog.prior_generation() == observation.prior_catalog_generation
                && catalog.entry() == &authority.intended_entry
                && observation.catalog_entry == authority.intended_entry
                && effect_observation.operation == authority._effect.operation
                && effect_observation.artifact_digest == authority._effect.artifact_digest
                && effect_observation.root_record_digest == authority._effect.root_record_digest
                && effect_observation.final_name_digest == authority._effect.final_name_digest
                && effect_observation.physical_effect_digest
                    == authority._effect.expected_physical_effect_digest
                && effect_observation.parent_sync_digest
                    == authority._effect.expected_parent_sync_digest
                && authority.receipt.as_ref().is_some_and(|receipt| {
                    receipt.catalog_generation == observation.catalog_generation
                        && receipt.catalog_entry == observation.catalog_entry
                })
        });
        Self {
            authority,
            _effect_observation: effect_observation,
            primary_allowed,
        }
    }

    /// Settles completion before exposing its exact terminal receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the trusted store selects poison or
    /// acknowledges neither precomputed branch. Any error drops the retained
    /// authority through its acknowledged poison path.
    pub(crate) fn settle(mut self) -> Result<CompletionReceiptV1, AdmissionError> {
        let receipt = self.authority.settle_store(self.primary_allowed);
        match receipt {
            ProtectedStoreSettlementReceiptV1::Primary(token) => {
                if !self.primary_allowed {
                    return Err(AdmissionError::AuthorityMismatch);
                }
                self.authority.install_primary(token)?;
                self.authority
                    .receipt
                    .take()
                    .ok_or(AdmissionError::Poisoned)
            }
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => {
                self.authority.install_acknowledged_poison(token)?;
                Err(AdmissionError::Poisoned)
            }
        }
    }
}

/// Returns an admitted decision and the exact atomic protected mutations.
#[derive(Clone, Debug)]
pub struct AdmissionResult {
    /// Immutable admitted decision.
    decision: AdmissionDecisionV1,
    /// Reservation account committed with the decision.
    account: super::CapacityAccountV1,
    /// Mutations that must become durable atomically.
    mutations: Vec<LedgerMutation>,
    /// Whether this was exact idempotent replay.
    replayed: bool,
}

/// Returns a retained completion permit and its protected mutations.
#[derive(Clone, Debug)]
pub struct PermitIssueResult {
    /// Exact one-shot permit.
    permit: CompletionPermitV1,
    /// Mutations that must become durable before the permit escapes.
    mutations: Vec<LedgerMutation>,
    /// Whether this was exact permit replay.
    replayed: bool,
}

/// Borrows one retained, unspent, exact completion authority.
///
/// Decoded [`CompletionPermitV1`] records are diagnostics only. This opaque
/// value can be minted only from the current fully replayed ledger. It owns the
/// exact protected permit snapshot while retaining the short live-executor and
/// root-custody borrows; terminal commit rechecks that snapshot against the
/// ledger before accepting the result.
#[cfg(target_os = "linux")]
pub struct RetainedCompletionPermit<'authority, 'request> {
    permit: CompletionPermitV1,
    _execution: LivePublisherExecution<'authority, 'request>,
    _root: AuthorizedPublicationRoot<'authority>,
}

/// Borrows one freshly rechecked live publisher execution.
///
/// The future ingress adapter may mint this only immediately after
/// [`RuntimeJoinedPublisherRequest::recheck`] succeeds on its protected clock.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub struct LivePublisherExecution<'execution, 'request> {
    joined: &'execution RuntimeJoinedPublisherRequest<'request>,
}

#[cfg(target_os = "linux")]
impl<'execution, 'request> LivePublisherExecution<'execution, 'request> {
    /// Rechecks and consumes a mutable joined request into one fresh-use token.
    ///
    /// The mutable borrow is mandatory: callers cannot assert that some earlier
    /// recheck happened. A token is short lived and must be reacquired for every
    /// admission, materialization, permit issuance, or retained completion use.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::RuntimeMismatch`] when holder ingress, runtime
    /// authority, execution continuity, or the protected clock is no longer current.
    pub(crate) fn recheck<T>(
        joined: &'execution mut RuntimeJoinedPublisherRequest<'request>,
        clock: &mut T,
    ) -> Result<Self, AdmissionError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        joined
            .recheck(clock)
            .map_err(|_| AdmissionError::RuntimeMismatch)?;
        Ok(Self { joined })
    }
}

/// Proves that the current in-memory frontier was acknowledged by protection.
///
/// Only the crate-sealed protected-journal settlement owner can mint this
/// opaque value after an atomic commit and durability synchronization. Every
/// use rechecks its exact checkpoint, sequence, and chain head, so a stale
/// frontier cannot authorize work after any subsequent ledger mutation. The
/// owner remains dormant and is not a production activation path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedAdmissionFrontier {
    sequence: u64,
    head: ObjectDigest,
    checkpoint: AuthorityCheckpointV1,
}

/// Carries one opaque synchronized protected-store acknowledgement.
///
/// Only the protected-store adapter can construct this token after atomically
/// writing every mutation through the terminal checkpoint and synchronizing
/// the rollback-resistant chain head.
#[derive(Debug, Eq, PartialEq)]
pub struct ProtectedStoreCommitToken {
    checkpoint: AuthorityCheckpointV1,
    head: ObjectDigest,
}

/// Owns one sealed alternative protected-store successor.
#[derive(Debug)]
pub(crate) struct ProtectedMutationBranchV1 {
    pub(crate) ledger: AdmissionLedger,
    pub(crate) mutations: Vec<LedgerMutation>,
}

impl ProtectedMutationBranchV1 {
    /// Seals one staged projection with its terminal checkpoint mutation.
    pub(crate) fn seal(
        mut ledger: AdmissionLedger,
        mut mutations: Vec<LedgerMutation>,
    ) -> Result<Self, AdmissionError> {
        let (_, checkpoint) = ledger.seal_for_commit()?;
        mutations.push(checkpoint);
        Ok(Self { ledger, mutations })
    }

    /// Verifies a synchronized acknowledgement for this exact branch.
    pub(crate) fn acknowledge(
        &self,
        token: ProtectedStoreCommitToken,
    ) -> Result<(), AdmissionError> {
        self.ledger.confirm_committed(token)?;
        Ok(())
    }
}

/// Reports which precomputed alternative a protected store made durable.
pub(crate) enum ProtectedStoreSettlementReceiptV1 {
    /// The requested semantic successor and checkpoint are durable.
    Primary(ProtectedStoreCommitToken),
    /// The fail-closed poison successor and checkpoint are durable.
    Poisoned(ProtectedStoreCommitToken),
}

/// Settles an effect-bearing transition to exactly one synchronized branch.
///
/// Implementations are trusted protected-store adapters. They must resolve
/// uncertain append outcomes internally and may not return until either the
/// primary branch or the poison branch is durably synchronized. If `primary`
/// is absent, only the poison branch is legal. Unrecoverable storage loss is a
/// process-fatal condition rather than a returned, reusable authority state.
pub(crate) trait StateOnlyProtectedStoreSettlementV1 {
    fn settle(
        &mut self,
        primary: Option<&ProtectedMutationBranchV1>,
        poison: &ProtectedMutationBranchV1,
    ) -> ProtectedStoreSettlementReceiptV1;
}

/// Settles a permit-terminal transition with its exact capacity reservation.
///
/// Only the protected publisher journal's capacity-bearing adapter implements
/// this trait. A state-only store can therefore never commit completion,
/// terminal repair, or their poison alternative without atomic reservation
/// deletion.
pub(crate) trait CapacityProtectedStoreSettlementV1 {
    fn settle(
        &mut self,
        primary: Option<&ProtectedMutationBranchV1>,
        poison: &ProtectedMutationBranchV1,
    ) -> ProtectedStoreSettlementReceiptV1;
}

impl ProtectedStoreCommitToken {
    /// Captures an acknowledgement returned by the trusted durable adapter.
    pub(crate) const fn from_durable_adapter(
        checkpoint: AuthorityCheckpointV1,
        head: ObjectDigest,
    ) -> Self {
        Self { checkpoint, head }
    }
}

impl AdmissionResult {
    /// Returns mutations only to the protected-store adapter.
    pub(crate) fn mutations(&self) -> &[LedgerMutation] {
        &self.mutations
    }

    /// Releases the decision for signing only at its exact committed frontier.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the supplied frontier is stale or belongs
    /// to another ledger state.
    pub(crate) fn committed_decision<'result>(
        &'result self,
        ledger: &AdmissionLedger,
        committed: &CommittedAdmissionFrontier,
    ) -> Result<&'result AdmissionDecisionV1, AdmissionError> {
        ledger.require_committed(committed)?;
        let retained = ledger
            .decisions
            .get(self.decision.operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        if retained.decision_digest != self.decision.decision_digest {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(&self.decision)
    }
}

impl PermitIssueResult {
    /// Returns mutations only to the protected-store adapter.
    pub(crate) fn mutations(&self) -> &[LedgerMutation] {
        &self.mutations
    }

    /// Releases a permit response only at its exact committed frontier.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the frontier is stale or the permit is no
    /// longer the exact current outstanding record.
    pub(crate) fn committed_permit<'result>(
        &'result self,
        ledger: &AdmissionLedger,
        committed: &CommittedAdmissionFrontier,
    ) -> Result<&'result CompletionPermitV1, AdmissionError> {
        ledger.require_committed(committed)?;
        let retained = ledger
            .permits
            .get(self.permit.operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        if retained != &self.permit || retained.state != CompletionPermitStateV1::Outstanding {
            return Err(AdmissionError::InvalidTransition);
        }
        Ok(&self.permit)
    }
}

#[cfg(target_os = "linux")]
impl RetainedCompletionPermit<'_, '_> {
    /// Returns the exact one-shot permit identity.
    #[must_use]
    pub const fn permit(&self) -> PublicationPermitId {
        self.permit.permit
    }

    /// Returns the exact artifact the permit may complete.
    #[must_use]
    pub const fn artifact_digest(&self) -> ObjectDigest {
        self.permit.artifact_digest
    }

    /// Returns the protected root generation bound by the permit.
    #[must_use]
    pub const fn root_generation(&self) -> u64 {
        self.permit.root_generation
    }

    pub(super) const fn record(&self) -> &CompletionPermitV1 {
        &self.permit
    }
}

/// Reports publisher admission and transition failures.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// Configured replay or protocol limits are invalid.
    #[error("publisher admission limits are invalid")]
    InvalidLimits,
    /// Controller kernel realtime could not be sampled.
    #[error("publisher admission realtime is unavailable")]
    ClockUnavailable,
    /// A mandatory identity or digest is zero.
    #[error("publisher admission contains invalid {0}")]
    InvalidIdentity(&'static str),
    /// A bounded dimension is exhausted.
    #[error("publisher admission limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Current protected source, root, policy, or accounting facts disagree.
    #[error("publisher admission authority precondition differs")]
    AuthorityMismatch,
    /// Fresh runtime holder or assignment evidence differs.
    #[error("publisher admission runtime evidence differs")]
    RuntimeMismatch,
    /// Operation, reservation, challenge, or permit identity conflicts.
    #[error("publisher admission identity conflicts with retained state")]
    IdentityConflict,
    /// Operation is absent.
    #[error("publisher admission operation is absent")]
    OperationAbsent,
    /// Requested state transition is illegal.
    #[error("publisher admission state transition is invalid")]
    InvalidTransition,
    /// Prepared artifact differs from the exact admission.
    #[error("publisher prepared artifact differs from admission")]
    ArtifactMismatch,
    /// Completion result differs from the outstanding permit.
    #[error("publisher completion result differs from its permit")]
    CompletionMismatch,
    /// Protected authority is poisoned pending reopen/recovery.
    #[error("publisher admission authority is poisoned")]
    Poisoned,
    /// Checked generation or sequence is exhausted.
    #[error("publisher admission generation is exhausted")]
    GenerationExhausted,
    /// Protected record encoding failed.
    #[error(transparent)]
    Codec(#[from] super::ProtectedRecordCodecError),
    /// Source release is absent, stale, revoked, or mismatched.
    #[error(transparent)]
    Source(#[from] SourceReleaseError),
    /// Capacity accounting failed closed.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

/// Owns one fully replayed publisher admission authority projection.
#[derive(Clone, Debug)]
pub struct AdmissionLedger {
    limits: AdmissionLimits,
    authority_epoch: PublicationAuthorityEpoch,
    decisions: BTreeMap<[u8; 16], AdmissionDecisionV1>,
    challenges: BTreeMap<([u8; 16], [u8; 32]), ChallengeConsumptionV1>,
    artifacts: BTreeMap<[u8; 16], ArtifactCommitmentV1>,
    permits: BTreeMap<[u8; 16], CompletionPermitV1>,
    receipts: BTreeMap<[u8; 16], CompletionReceiptV1>,
    evictions: BTreeMap<[u8; 16], super::CatalogEvictionReceiptV1>,
    recovery_observations: Vec<RecoveryObservationReceiptV1>,
    source_heads: BTreeMap<[u8; 32], super::SourceReleaseV1>,
    root_records: BTreeMap<[u8; 32], crate::publisher_roots::PublicationRootRecordV1>,
    root_checkpoint_history: BTreeMap<u64, ObjectDigest>,
    accounting: PublicationAccounting,
    sequence: u64,
    predecessor: Option<ObjectDigest>,
    materialized_bytes: usize,
    last_kind: Option<ProtectedRecordKindV1>,
    poisoned: bool,
}

impl AdmissionLedger {
    pub(super) const fn limits(&self) -> AdmissionLimits {
        self.limits
    }

    pub(super) fn from_replayed(
        limits: AdmissionLimits,
        authority_epoch: PublicationAuthorityEpoch,
        capacity: CapacityPolicyV1,
        challenges: Vec<ChallengeConsumptionV1>,
        decisions: Vec<AdmissionDecisionV1>,
        accounts: Vec<super::CapacityAccountV1>,
        artifacts: Vec<ArtifactCommitmentV1>,
        permits: Vec<CompletionPermitV1>,
        receipts: Vec<CompletionReceiptV1>,
        evictions: Vec<super::CatalogEvictionReceiptV1>,
        recovery_observations: Vec<RecoveryObservationReceiptV1>,
        source_heads: Vec<super::SourceReleaseV1>,
        root_records: Vec<crate::publisher_roots::PublicationRootRecordV1>,
        sequence: u64,
        predecessor: Option<ObjectDigest>,
        materialized_bytes: usize,
        poisoned: bool,
        compacted_floor: bool,
    ) -> Result<Self, AdmissionError> {
        let accounting = if compacted_floor {
            PublicationAccounting::replay_compacted(capacity, accounts)?
        } else {
            PublicationAccounting::replay(capacity, accounts)?
        };
        let mut retained_roots = BTreeMap::new();
        let mut ordered_roots = BTreeMap::new();
        let mut root_checkpoint_history = BTreeMap::new();
        for root in root_records {
            ordered_roots.insert((*root.root_id.as_bytes(), root.generation), root.clone());
            if retained_roots
                .insert(*root.record_digest.as_bytes(), root)
                .is_some()
            {
                return Err(AdmissionError::IdentityConflict);
            }
            let generation = u64::try_from(ordered_roots.len())
                .map_err(|_| AdmissionError::LimitExceeded("root records"))?;
            root_checkpoint_history.insert(
                generation,
                crate::publisher_roots::registry_digest(&ordered_roots),
            );
        }
        let mut ledger = Self {
            limits: limits.validate()?,
            authority_epoch,
            decisions: BTreeMap::new(),
            challenges: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            permits: BTreeMap::new(),
            receipts: BTreeMap::new(),
            evictions: BTreeMap::new(),
            recovery_observations,
            source_heads: source_heads
                .into_iter()
                .map(|source| (*source.release_digest.as_bytes(), source))
                .collect(),
            root_records: retained_roots,
            root_checkpoint_history,
            accounting,
            sequence,
            predecessor,
            materialized_bytes,
            last_kind: Some(ProtectedRecordKindV1::AuthorityCheckpoint),
            poisoned,
        };
        for challenge in challenges {
            let key = (
                *challenge.publisher_instance.as_bytes(),
                *challenge.challenge.as_bytes(),
            );
            if ledger.challenges.insert(key, challenge).is_some() {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        for decision in decisions {
            let key = *decision.operation.as_bytes();
            if let Some(previous) = ledger.decisions.get(&key) {
                if previous.decision_digest != decision.decision_digest
                    || !valid_decision_successor(previous.state, decision.state)
                {
                    return Err(AdmissionError::IdentityConflict);
                }
            } else if !compacted_floor && decision.state != AdmissionDecisionStateV1::Admitted {
                return Err(AdmissionError::IdentityConflict);
            }
            ledger.decisions.insert(key, decision);
        }
        for artifact in artifacts {
            let key = *artifact.operation.as_bytes();
            if ledger.artifacts.insert(key, artifact).is_some() {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        for permit in permits {
            let key = *permit.operation.as_bytes();
            if ledger.permits.values().any(|retained| {
                retained.permit == permit.permit && retained.operation != permit.operation
            }) {
                return Err(AdmissionError::IdentityConflict);
            }
            if let Some(previous) = ledger.permits.get(&key) {
                if previous.permit_digest != permit.permit_digest
                    || !valid_permit_successor(previous.state, permit.state)
                {
                    return Err(AdmissionError::IdentityConflict);
                }
            } else if !compacted_floor && permit.state != CompletionPermitStateV1::Outstanding {
                return Err(AdmissionError::IdentityConflict);
            }
            ledger.permits.insert(key, permit);
        }
        for receipt in receipts {
            let key = *receipt.operation.as_bytes();
            if ledger.receipts.insert(key, receipt).is_some() {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        for eviction in evictions {
            let key = *eviction.operation.as_bytes();
            if ledger.evictions.insert(key, eviction).is_some() {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        let mut recovery_digests = BTreeMap::new();
        for receipt in &ledger.recovery_observations {
            let artifact = ledger.artifacts.get(receipt.operation.as_bytes());
            let decision = ledger.decisions.get(receipt.operation.as_bytes());
            let completion = ledger.receipts.get(receipt.operation.as_bytes());
            if receipt.physical_observation_digest.as_bytes() == &[0; 32]
                || decision
                    .is_none_or(|value| value.selected_root_digest != receipt.physical_root_digest)
                || (receipt.outcome != super::RecoveryObservationKindCodeV1::Contradiction
                    && receipt.artifact_digest.is_some_and(|digest| {
                        artifact.is_none_or(|value| value.artifact_digest != digest)
                    }))
                || receipt.executor_instance.is_some_and(|executor| {
                    artifact.is_none_or(|value| value.publisher_instance != executor)
                })
                || (receipt.executor_instance.is_some() != receipt.executor_fence_digest.is_some())
                || (receipt.outcome != super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                    && receipt.catalog_entry_digest.is_some_and(|digest| {
                        completion.is_none_or(|value| value.catalog_entry_digest != digest)
                    }))
                || (matches!(
                    receipt.outcome,
                    super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                        | super::RecoveryObservationKindCodeV1::FinalCatalogRepaired
                        | super::RecoveryObservationKindCodeV1::Committed
                ) != receipt.catalog_entry_digest.is_some())
                || (!matches!(
                    receipt.outcome,
                    super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                        | super::RecoveryObservationKindCodeV1::FinalCatalogRepaired
                ) && receipt.repair_prior_catalog_generation != 0)
                || ((receipt.outcome == super::RecoveryObservationKindCodeV1::FinalCatalogRepaired)
                    != receipt.repair_authorization_digest.is_some())
                || (receipt.outcome == super::RecoveryObservationKindCodeV1::FinalCatalogRepaired
                    && !ledger.recovery_observations.iter().any(|prior| {
                        prior.outcome == super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                            && prior.operation == receipt.operation
                            && prior.artifact_digest == receipt.artifact_digest
                            && prior.catalog_entry_digest == receipt.catalog_entry_digest
                            && prior.repair_prior_catalog_generation
                                == receipt.repair_prior_catalog_generation
                            && prior.executor_instance == receipt.executor_instance
                            && prior.executor_fence_digest == receipt.executor_fence_digest
                            && Some(prior.receipt_digest) == receipt.repair_authorization_digest
                    }))
                || (receipt.outcome == super::RecoveryObservationKindCodeV1::NoEffect
                    && artifact.is_some())
                || recovery_digests
                    .insert(*receipt.receipt_digest.as_bytes(), receipt.operation)
                    .is_some()
            {
                return Err(AdmissionError::IdentityConflict);
            }
        }
        let operations: Vec<[u8; 16]> = ledger.decisions.keys().copied().collect();
        for operation in operations {
            let decision = ledger
                .decisions
                .get_mut(&operation)
                .ok_or(AdmissionError::Poisoned)?;
            if ledger.receipts.contains_key(&operation) {
                decision.state = AdmissionDecisionStateV1::Completed;
            } else if let Some(permit) = ledger.permits.get(&operation) {
                decision.state = match permit.state {
                    CompletionPermitStateV1::Outstanding => {
                        AdmissionDecisionStateV1::CompletionPermitted
                    }
                    CompletionPermitStateV1::RevocationPending => {
                        AdmissionDecisionStateV1::RevocationPending
                    }
                    CompletionPermitStateV1::Uncertain => AdmissionDecisionStateV1::Uncertain,
                    CompletionPermitStateV1::Spent => AdmissionDecisionStateV1::Completed,
                    CompletionPermitStateV1::RetiredWithoutEffect => {
                        AdmissionDecisionStateV1::Aborted
                    }
                };
            } else if ledger
                .accounting
                .account(decision.reservation)
                .is_some_and(|account| account.state == super::ReservationStateV1::Uncertain)
            {
                decision.state = AdmissionDecisionStateV1::Uncertain;
            } else if ledger.artifacts.contains_key(&operation) {
                decision.state = AdmissionDecisionStateV1::ArtifactPrepared;
            } else if ledger
                .accounting
                .account(decision.reservation)
                .is_some_and(|account| account.state == super::ReservationStateV1::Released)
            {
                decision.state = AdmissionDecisionStateV1::Aborted;
            }
        }
        ledger.validate_projection()?;
        ledger.ensure_record_capacity(0)?;
        Ok(ledger)
    }

    fn validate_projection(&self) -> Result<(), AdmissionError> {
        let mut active_catalog = BTreeMap::new();
        for (operation, receipt) in &self.receipts {
            if !self.evictions.contains_key(operation)
                && active_catalog
                    .insert(receipt.catalog_entry.object().clone(), *operation)
                    .is_some()
            {
                return Err(AdmissionError::Poisoned);
            }
        }
        let mut catalog_generations: Vec<u64> = self
            .receipts
            .values()
            .map(|receipt| receipt.catalog_generation)
            .chain(
                self.evictions
                    .values()
                    .map(|eviction| eviction.eviction_catalog_generation),
            )
            .collect();
        catalog_generations.sort_unstable();
        if catalog_generations
            .windows(2)
            .any(|window| window[0].checked_add(1) != Some(window[1]))
        {
            return Err(AdmissionError::Poisoned);
        }
        for decision in self.decisions.values() {
            let request = aos_sandbox_core::format::decode_publisher_admission_request_v1(
                &decision.canonical_request,
                aos_sandbox_core::DecodeLimits::default(),
            )
            .map_err(|_| AdmissionError::Poisoned)?;
            let fields = request.plan().fields();
            let challenge = self.challenges.values().find(|challenge| {
                challenge.operation == decision.operation
                    && challenge.reservation == decision.reservation
                    && challenge.decision_digest == decision.decision_digest
            });
            let account = self.accounting.account(decision.reservation);
            let source = self
                .source_heads
                .get(decision.source_release_digest.as_bytes());
            let root = self
                .root_records
                .get(decision.selected_root_digest.as_bytes());
            let Some(challenge) = challenge else {
                return Err(AdmissionError::Poisoned);
            };
            let Some(account) = account else {
                return Err(AdmissionError::Poisoned);
            };
            let Some(source) = source else {
                return Err(AdmissionError::Poisoned);
            };
            let Some(root) = root else {
                return Err(AdmissionError::Poisoned);
            };
            let capacity = self.accounting.policy();
            if challenge.publisher_instance != decision.publisher_instance
                || challenge.challenge != request.challenge()
                || challenge.request_commitment != fields.request.commitment.digest()
                || fields.request.operation != decision.operation
                || fields.request.reservation != decision.reservation
                || fields.target.instance != decision.publisher_instance
                || fields.authority.root_registry_generation != decision.root_registry_generation
                || self
                    .root_checkpoint_history
                    .get(&decision.root_registry_generation)
                    != Some(&decision.root_registry_digest)
                || account.authority_epoch != decision.authority_epoch
                || account.resource != source.cache_resource
                || account.project != source.project
                || account.domain != source.cache_domain
                || account.reserved_bytes != fields.request.maximum_bytes
                || source.project != fields.target.project
                || source.content != fields.request.content
                || root.project != fields.target.project
                || root.generation != decision.selected_root_generation
                || root.resource != source.cache_resource
                || root.domain != fields.target.cache_domain
                || root.isolation_policy != fields.target.isolation_policy
                || root.service_node != fields.target.node
                || root.service_principal != fields.target.principal
                || capacity.resource != root.resource
                || capacity.project != root.project
                || capacity.domain != root.domain
                || capacity.isolation_policy != root.isolation_policy
            {
                return Err(AdmissionError::Poisoned);
            }
            if let Some(artifact) = self.artifacts.get(decision.operation.as_bytes()) {
                if artifact.decision_digest != decision.decision_digest
                    || artifact.publisher_instance != decision.publisher_instance
                    || artifact.root_generation != decision.selected_root_generation
                    || artifact.content != fields.request.content
                    || artifact.bytes != artifact.content.encoded_size()
                    || artifact.allocated_bytes < artifact.bytes
                    || artifact.verity_sha256 == [0; 32]
                    || artifact.private_name_digest.as_bytes() == &[0; 32]
                    || artifact.final_name_digest.as_bytes() == &[0; 32]
                    || artifact.private_name_digest == artifact.final_name_digest
                {
                    return Err(AdmissionError::Poisoned);
                }
                if !self.permits.contains_key(decision.operation.as_bytes())
                    && !matches!(
                        account.state,
                        super::ReservationStateV1::Reserved | super::ReservationStateV1::Uncertain
                    )
                {
                    return Err(AdmissionError::Poisoned);
                }
            } else if matches!(account.state, super::ReservationStateV1::Resident) {
                return Err(AdmissionError::Poisoned);
            }
            if let Some(permit) = self.permits.get(decision.operation.as_bytes()) {
                let artifact = self
                    .artifacts
                    .get(decision.operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?;
                if permit.decision_digest != decision.decision_digest
                    || permit.artifact_digest != artifact.artifact_digest
                    || permit.reservation != decision.reservation
                    || permit.publisher_instance != decision.publisher_instance
                    || permit.root_generation != decision.selected_root_generation
                    || permit.authority_epoch != decision.authority_epoch
                {
                    return Err(AdmissionError::Poisoned);
                }
                let has_receipt = self.receipts.contains_key(decision.operation.as_bytes());
                if (permit.state == CompletionPermitStateV1::Spent) != has_receipt
                    || (permit.state == CompletionPermitStateV1::RetiredWithoutEffect
                        && (account.state != super::ReservationStateV1::Released || has_receipt))
                    || (permit.state == CompletionPermitStateV1::Uncertain
                        && account.state != super::ReservationStateV1::Uncertain)
                    || (matches!(
                        permit.state,
                        CompletionPermitStateV1::Outstanding
                            | CompletionPermitStateV1::RevocationPending
                    ) && account.state != super::ReservationStateV1::Reserved)
                {
                    return Err(AdmissionError::Poisoned);
                }
            }
            if let Some(receipt) = self.receipts.get(decision.operation.as_bytes()) {
                let permit = self
                    .permits
                    .get(decision.operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?;
                let artifact = self
                    .artifacts
                    .get(decision.operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?;
                if permit.state != CompletionPermitStateV1::Spent
                    || receipt.permit != permit.permit
                    || receipt.artifact_digest != permit.artifact_digest
                    || decision.state != AdmissionDecisionStateV1::Completed
                    || !matches!(
                        account.state,
                        super::ReservationStateV1::Resident | super::ReservationStateV1::Evicted
                    )
                    || (account.state == super::ReservationStateV1::Resident
                        && account.resident_bytes != receipt.resident_bytes)
                    || receipt.catalog_generation == 0
                    || receipt.catalog_entry_digest.as_bytes() == &[0; 32]
                    || receipt.catalog_entry.digest() != receipt.catalog_entry_digest
                    || receipt.catalog_entry.object() != &artifact.content
                    || receipt.catalog_entry.project() != fields.target.project
                    || receipt.catalog_entry.resource() != source.cache_resource
                    || receipt.catalog_entry.domain() != fields.target.cache_domain
                    || receipt.catalog_entry.root_id() != root.root_id
                    || receipt.catalog_entry.root_digest() != decision.selected_root_digest
                    || receipt.catalog_entry.root_generation() != decision.selected_root_generation
                    || receipt.catalog_entry.backing_digest()
                        != ObjectDigest::from_bytes(artifact.verity_sha256)
                    || receipt.catalog_entry.allocated() != artifact.allocated_bytes
                {
                    return Err(AdmissionError::Poisoned);
                }
            }
            if let Some(eviction) = self.evictions.get(decision.operation.as_bytes()) {
                let receipt = self
                    .receipts
                    .get(decision.operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?;
                let derived = digest_parts(
                    EVICTION_DOMAIN,
                    &[
                        eviction.operation.as_bytes(),
                        eviction.catalog_entry_digest.as_bytes(),
                        &eviction.prior_catalog_generation.to_be_bytes(),
                        &eviction.eviction_catalog_generation.to_be_bytes(),
                        &eviction.released_bytes.to_be_bytes(),
                    ],
                );
                if eviction.operation != decision.operation
                    || eviction.catalog_entry_digest != receipt.catalog_entry_digest
                    || eviction.prior_catalog_generation < receipt.catalog_generation
                    || eviction.prior_catalog_generation.checked_add(1)
                        != Some(eviction.eviction_catalog_generation)
                    || eviction.released_bytes != receipt.resident_bytes
                    || eviction.eviction_digest != derived
                    || account.state != super::ReservationStateV1::Evicted
                {
                    return Err(AdmissionError::Poisoned);
                }
            }
        }
        if self.challenges.len() != self.decisions.len()
            || self.accounting.accounts().count() != self.decisions.len()
            || self
                .artifacts
                .keys()
                .any(|operation| !self.decisions.contains_key(operation))
            || self
                .permits
                .keys()
                .any(|operation| !self.decisions.contains_key(operation))
            || self
                .receipts
                .keys()
                .any(|operation| !self.decisions.contains_key(operation))
            || self
                .evictions
                .keys()
                .any(|operation| !self.receipts.contains_key(operation))
            || self.recovery_observations.iter().any(|observation| {
                !self
                    .decisions
                    .contains_key(observation.operation.as_bytes())
            })
        {
            return Err(AdmissionError::Poisoned);
        }
        Ok(())
    }
    /// Creates an empty authority projection for a protected cache partition.
    ///
    /// This is a model constructor, not a protected-journal opener. A production
    /// adapter must instead replay canonical records and a rollback-protected
    /// checkpoint before enabling authority.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for invalid limits or capacity policy.
    pub fn empty(
        limits: AdmissionLimits,
        authority_epoch: PublicationAuthorityEpoch,
        capacity: CapacityPolicyV1,
    ) -> Result<Self, AdmissionError> {
        let limits = limits.validate()?;
        Ok(Self {
            limits,
            authority_epoch,
            decisions: BTreeMap::new(),
            challenges: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            permits: BTreeMap::new(),
            receipts: BTreeMap::new(),
            evictions: BTreeMap::new(),
            recovery_observations: Vec::new(),
            source_heads: BTreeMap::new(),
            root_records: BTreeMap::new(),
            root_checkpoint_history: BTreeMap::new(),
            accounting: PublicationAccounting::replay(capacity, Vec::new())?,
            sequence: 0,
            predecessor: None,
            materialized_bytes: 0,
            last_kind: None,
            poisoned: false,
        })
    }

    /// Derives admission solely from current owner state and live authorities.
    ///
    /// The caller supplies the controller's kernel-backed realtime reader, not
    /// a time scalar received from protocol input. Epoch, capacity, and limits
    /// come from this fully replayed owner projection.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when realtime acquisition fails or any exact
    /// request, runtime, source, root, policy, or bound differs.
    #[cfg(target_os = "linux")]
    pub(crate) fn derive_admission<'authority, 'request, E>(
        &self,
        committed: &CommittedAdmissionFrontier,
        execution: LivePublisherExecution<'authority, 'request>,
        source: AuthorizedSourceRelease<'authority>,
        root: &'authority CurrentPublicationRoot<'authority>,
        realtime: &mut impl FnMut() -> Result<i64, E>,
    ) -> Result<AdmittedPublisherPlan<'authority, 'request>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        let root_checkpoint = root.checkpoint();
        let selected_root = root.root().record();
        let root_is_ledger_head =
            self.root_checkpoint_history
                .last_key_value()
                .is_some_and(|(generation, digest)| {
                    *generation == root_checkpoint.generation
                        && *digest == root_checkpoint.registry_digest
                });
        if self.source_heads.get(source.digest().as_bytes()) != Some(source.release())
            || self
                .root_records
                .get(selected_root.record_digest.as_bytes())
                != Some(selected_root)
            || !root_is_ledger_head
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        let now_seconds = realtime().map_err(|_| AdmissionError::ClockUnavailable)?;
        AdmittedPublisherPlan::from_runtime_join(
            execution,
            source,
            root,
            self.authority_epoch,
            self.accounting.policy(),
            now_seconds,
            self.limits,
            committed.clone(),
        )
    }

    /// Emits one source-release successor into the single protected chain.
    fn record_source_release(
        &mut self,
        release: &super::SourceReleaseV1,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        if self
            .source_heads
            .get(release.release_digest.as_bytes())
            .is_some_and(|current| current == release)
        {
            return Ok(None);
        }
        let additional = usize::from(
            !self
                .source_heads
                .contains_key(release.release_digest.as_bytes()),
        );
        self.ensure_record_capacity(additional)?;
        let mutation = self.append(
            ProtectedRecordKindV1::SourceRelease,
            release.release_digest.as_bytes().to_vec(),
            source_release_payload(release),
        )?;
        self.source_heads
            .insert(*release.release_digest.as_bytes(), release.clone());
        Ok(Some(mutation))
    }

    /// Installs and emits one source release as one staged protected successor.
    pub(crate) fn install_source_release(
        &mut self,
        registry: &mut super::SourceReleaseRegistry,
        release: super::SourceReleaseV1,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = SourceRegistryOwnerToken(());
        let retained = staged_registry.install(&owner, release)?;
        let mutation = staged_ledger.record_source_release(retained)?;
        *self = staged_ledger;
        *registry = staged_registry;
        Ok(mutation)
    }

    /// Revokes and emits one source release without cancelling old permits.
    pub(crate) fn revoke_source_release(
        &mut self,
        registry: &mut super::SourceReleaseRegistry,
        release: ObjectDigest,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = SourceRegistryOwnerToken(());
        let retained = staged_registry.revoke(&owner, release)?;
        let mutation = staged_ledger.record_source_release(&retained)?;
        *self = staged_ledger;
        *registry = staged_registry;
        Ok(mutation)
    }

    /// Emits one root-registry successor into the single protected chain.
    fn record_root_successor(
        &mut self,
        root: &crate::publisher_roots::PublicationRootRecordV1,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        if self
            .root_records
            .get(root.record_digest.as_bytes())
            .is_some_and(|current| current == root)
        {
            return Ok(None);
        }
        self.ensure_record_capacity(1)?;
        let mut key = root.root_id.as_bytes().to_vec();
        key.extend_from_slice(&root.generation.to_be_bytes());
        let payload = crate::publisher_roots::encode_root_record_v1(root)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let mutation = self.append(ProtectedRecordKindV1::RootRegistry, key, payload)?;
        self.root_records
            .insert(*root.record_digest.as_bytes(), root.clone());
        let ordered: BTreeMap<([u8; 16], u64), _> = self
            .root_records
            .values()
            .map(|record| {
                (
                    (*record.root_id.as_bytes(), record.generation),
                    record.clone(),
                )
            })
            .collect();
        let generation = u64::try_from(ordered.len())
            .map_err(|_| AdmissionError::LimitExceeded("root records"))?;
        self.root_checkpoint_history.insert(
            generation,
            crate::publisher_roots::registry_digest(&ordered),
        );
        Ok(Some(mutation))
    }

    /// Atomically stages an initial protected root and its global ledger record.
    pub(crate) fn install_root(
        &mut self,
        registry: &mut crate::publisher_roots::PublicationRootRegistry,
        root: crate::publisher_roots::PublicationRootRecordV1,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = RootRegistryOwnerToken(());
        let retained = staged_registry
            .install_initial(&owner, root)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let mutation = staged_ledger.record_root_successor(&retained)?;
        *self = staged_ledger;
        *registry = staged_registry;
        Ok(mutation)
    }

    /// Atomically starts root draining and records its protected successor.
    pub(crate) fn drain_root(
        &mut self,
        registry: &mut crate::publisher_roots::PublicationRootRegistry,
        root_id: crate::publisher_roots::PublicationRootId,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = RootRegistryOwnerToken(());
        let retained = staged_registry
            .begin_draining(&owner, root_id)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let mutation = staged_ledger.record_root_successor(&retained)?;
        *self = staged_ledger;
        *registry = staged_registry;
        Ok(mutation)
    }

    /// Atomically drains one active root and installs its scoped replacement.
    pub(crate) fn advance_root(
        &mut self,
        registry: &mut crate::publisher_roots::PublicationRootRegistry,
        current_root: crate::publisher_roots::PublicationRootId,
        replacement: crate::publisher_roots::PublicationRootRecordV1,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        let current = registry
            .active(current_root)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        if current.project != replacement.project
            || current.resource != replacement.resource
            || current.domain != replacement.domain
            || current.isolation_policy != replacement.isolation_policy
            || current.role != replacement.role
            || current.filesystem_profile != replacement.filesystem_profile
            || current.root_id == replacement.root_id
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = RootRegistryOwnerToken(());
        let drained = staged_registry
            .begin_draining(&owner, current_root)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let installed = staged_registry
            .install_initial(&owner, replacement)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let drained_mutation = staged_ledger
            .record_root_successor(&drained)?
            .ok_or(AdmissionError::IdentityConflict)?;
        let installed_mutation = staged_ledger
            .record_root_successor(&installed)?
            .ok_or(AdmissionError::IdentityConflict)?;
        *self = staged_ledger;
        *registry = staged_registry;
        Ok(vec![drained_mutation, installed_mutation])
    }

    /// Prepares obligation-free root retirement under retained durable custody.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless the root is draining, registry-owned
    /// custody and ledger obligations are both empty, and both the retirement
    /// and poison successors fit the configured protected-store bounds.
    pub(crate) fn retire_root<'registry>(
        &'registry mut self,
        registry: &'registry mut crate::publisher_roots::PublicationRootRegistry,
        root_id: crate::publisher_roots::PublicationRootId,
        store: &'registry mut dyn StateOnlyProtectedStoreSettlementV1,
    ) -> Result<RootRetirementCommitV1<'registry>, AdmissionError> {
        self.ensure_healthy()?;
        let mut staged_ledger = self.clone();
        let mut staged_registry = registry.clone();
        let owner = RootRegistryOwnerToken(());
        let retained = staged_registry
            .retire(&owner, root_id, &staged_ledger)
            .map_err(|_| AdmissionError::AuthorityMismatch)?;
        let mutation = staged_ledger
            .record_root_successor(&retained)?
            .ok_or(AdmissionError::IdentityConflict)?;
        let primary = ProtectedMutationBranchV1::seal(staged_ledger, vec![mutation])?;
        let poison_digest = digest_parts(
            b"aos.sandbox.publisher.root-retirement-poison.v1\0",
            &[root_id.as_bytes(), retained.record_digest.as_bytes()],
        );
        let poison = self.sealed_poison_branch(poison_digest)?;
        Ok(RootRetirementCommitV1 {
            ledger: self,
            registry,
            primary,
            staged_registry,
            poison: Some(poison),
            retired: retained,
            store,
            settled: false,
        })
    }

    /// Atomically models challenge consumption, reservation, and admission.
    ///
    /// The returned mutations must commit together before signing or
    /// materialization. Exact replay returns the original decision without
    /// reserving twice.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for poisoned authority, conflicts, capacity,
    /// bounds, epoch mismatch, or encoding failure.
    #[cfg(target_os = "linux")]
    pub fn admit<E>(
        &mut self,
        admitted: AdmittedPublisherPlan<'_, '_>,
        realtime: &mut impl FnMut() -> Result<i64, E>,
    ) -> Result<AdmissionResult, AdmissionError> {
        let now_seconds = realtime().map_err(|_| AdmissionError::ClockUnavailable)?;
        let mut staged = self.clone();
        let result = staged.admit_in_place(admitted, now_seconds)?;
        *self = staged;
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn admit_in_place(
        &mut self,
        admitted: AdmittedPublisherPlan<'_, '_>,
        now_seconds: i64,
    ) -> Result<AdmissionResult, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(&admitted.origin_frontier)?;
        if now_seconds < admitted.not_before_seconds || now_seconds >= admitted.expires_seconds {
            return Err(AdmissionError::Source(SourceReleaseError::Expired));
        }
        if admitted.decision.authority_epoch != self.authority_epoch {
            return Err(AdmissionError::AuthorityMismatch);
        }
        if let Some(existing) = self.decisions.get(admitted.decision.operation.as_bytes()) {
            if existing.decision_digest == admitted.decision.decision_digest {
                let account = self
                    .accounting
                    .account(existing.reservation)
                    .ok_or(AdmissionError::Poisoned)?
                    .clone();
                return Ok(AdmissionResult {
                    decision: existing.clone(),
                    account,
                    mutations: Vec::new(),
                    replayed: true,
                });
            }
            return Err(AdmissionError::IdentityConflict);
        }
        let challenge_key = (
            *admitted.challenge.publisher_instance.as_bytes(),
            *admitted.challenge.challenge.as_bytes(),
        );
        if self.challenges.contains_key(&challenge_key)
            || self
                .decisions
                .values()
                .any(|decision| decision.reservation == admitted.decision.reservation)
        {
            return Err(AdmissionError::IdentityConflict);
        }
        self.ensure_record_capacity(3)?;
        let account = self.accounting.reserve(
            admitted.decision.reservation,
            self.authority_epoch,
            admitted.requested_bytes,
        )?;
        let challenge_mutation = self.append(
            ProtectedRecordKindV1::ChallengeConsumption,
            challenge_key_bytes(&admitted.challenge),
            challenge_payload(&admitted.challenge),
        )?;
        let account_mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        let decision_mutation = self.append(
            ProtectedRecordKindV1::AdmissionDecision,
            admitted.decision.operation.as_bytes().to_vec(),
            decision_payload(&admitted.decision),
        )?;
        self.challenges.insert(challenge_key, admitted.challenge);
        self.decisions.insert(
            *admitted.decision.operation.as_bytes(),
            admitted.decision.clone(),
        );
        Ok(AdmissionResult {
            decision: admitted.decision,
            account,
            mutations: vec![challenge_mutation, account_mutation, decision_mutation],
            replayed: false,
        })
    }

    /// Retains exact prepared-artifact evidence before any permit is issued.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absent/non-admitted operation, mismatched
    /// artifact, conflict, poisoned authority, or encoding failure.
    pub fn prepare_artifact(
        &mut self,
        preparation: ArtifactPreparation,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(&preparation.origin_frontier)?;
        let operation = preparation.artifact.operation;
        if let Some(existing) = self.artifacts.get(operation.as_bytes()) {
            return if existing == &preparation.artifact {
                Ok(None)
            } else {
                Err(AdmissionError::IdentityConflict)
            };
        }
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        if decision.state != AdmissionDecisionStateV1::Admitted
            || decision.decision_digest != preparation.artifact.decision_digest
            || decision.publisher_instance != preparation.artifact.publisher_instance
            || decision.selected_root_generation != preparation.artifact.root_generation
        {
            return Err(AdmissionError::ArtifactMismatch);
        }
        self.ensure_record_capacity(1)?;
        let payload = artifact_payload(&preparation.artifact);
        let key = operation.as_bytes().to_vec();
        let mutation = self.append(ProtectedRecordKindV1::PreparedArtifact, key, payload)?;
        let decision = self
            .decisions
            .get_mut(operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::ArtifactPrepared;
        self.artifacts
            .insert(*operation.as_bytes(), preparation.artifact);
        Ok(Some(mutation))
    }

    /// Issues or exactly replays one artifact-bound completion permit.
    ///
    /// The permit cannot authorize a different executor, artifact, root,
    /// operation, reservation, or authority epoch. Replay returns it only while
    /// it remains outstanding at this exact committed frontier.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absent/mismatched state, outstanding-permit
    /// capacity, poisoned authority, identity conflict, or encoding failure.
    #[cfg(target_os = "linux")]
    pub fn issue_completion_permit<'authority, 'request, E>(
        &mut self,
        committed: &CommittedAdmissionFrontier,
        execution: LivePublisherExecution<'authority, 'request>,
        source: &'authority AuthorizedSourceRelease<'authority>,
        root: &'authority CurrentPublicationRoot<'authority>,
        operation: OperationId,
        realtime: &mut impl FnMut() -> Result<i64, E>,
    ) -> Result<PermitIssueResult, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        self.validate_current_operation(&execution, source, root, operation, realtime)?;
        if let Some(existing) = self.permits.get(operation.as_bytes()) {
            if existing.state != CompletionPermitStateV1::Outstanding
                || self
                    .decisions
                    .get(operation.as_bytes())
                    .is_none_or(|decision| {
                        decision.state != AdmissionDecisionStateV1::CompletionPermitted
                    })
            {
                return Err(AdmissionError::InvalidTransition);
            }
            return Ok(PermitIssueResult {
                permit: existing.clone(),
                mutations: Vec::new(),
                replayed: true,
            });
        }
        if self.outstanding_permit_count() >= self.limits.maximum_outstanding_permits {
            return Err(AdmissionError::LimitExceeded("outstanding permits"));
        }
        self.ensure_record_capacity(1)?;
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let artifact = self
            .artifacts
            .get(operation.as_bytes())
            .ok_or(AdmissionError::ArtifactMismatch)?
            .clone();
        if decision.state != AdmissionDecisionStateV1::ArtifactPrepared
            || artifact.decision_digest != decision.decision_digest
        {
            return Err(AdmissionError::InvalidTransition);
        }
        let permit_digest = digest_parts(
            PERMIT_DOMAIN,
            &[
                operation.as_bytes(),
                decision.reservation.as_bytes(),
                artifact.artifact_digest.as_bytes(),
                decision.decision_digest.as_bytes(),
                decision.publisher_instance.as_bytes(),
                &decision.selected_root_generation.to_be_bytes(),
                &self.authority_epoch.get().to_be_bytes(),
            ],
        );
        let mut permit_bytes = [0_u8; 16];
        permit_bytes.copy_from_slice(&permit_digest.as_bytes()[..16]);
        let permit_id = PublicationPermitId::from_bytes(permit_bytes)?;
        let permit = CompletionPermitV1 {
            permit: permit_id,
            operation,
            reservation: decision.reservation,
            artifact_digest: artifact.artifact_digest,
            decision_digest: decision.decision_digest,
            publisher_instance: decision.publisher_instance,
            root_generation: decision.selected_root_generation,
            authority_epoch: self.authority_epoch,
            state: CompletionPermitStateV1::Outstanding,
            permit_digest,
        };
        let mutation = self.append(
            ProtectedRecordKindV1::CompletionPermit,
            permit.permit.as_bytes().to_vec(),
            permit_payload(&permit),
        )?;
        let decision = self
            .decisions
            .get_mut(operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::CompletionPermitted;
        self.permits.insert(*operation.as_bytes(), permit.clone());
        Ok(PermitIssueResult {
            permit,
            mutations: vec![mutation],
            replayed: false,
        })
    }

    /// Revalidates every revocable authority required to start new work.
    #[cfg(target_os = "linux")]
    fn validate_current_operation<E>(
        &self,
        execution: &LivePublisherExecution<'_, '_>,
        source: &AuthorizedSourceRelease<'_>,
        root: &CurrentPublicationRoot<'_>,
        operation: OperationId,
        realtime: &mut impl FnMut() -> Result<i64, E>,
    ) -> Result<(), AdmissionError> {
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let request = execution.joined.request();
        let fields = request.plan().fields();
        let now_seconds = realtime().map_err(|_| AdmissionError::ClockUnavailable)?;
        source.release().authorize(
            fields.request.holder,
            fields.target.project,
            request.cache_resource(),
            fields.target.cache_domain,
            &fields.request.content,
            now_seconds,
        )?;

        let selected_root = root.root();
        let root_checkpoint = root.checkpoint();
        let global_root_is_current =
            self.root_checkpoint_history
                .last_key_value()
                .is_some_and(|(generation, digest)| {
                    *generation == root_checkpoint.generation
                        && *digest == root_checkpoint.registry_digest
                });
        if !root.is_current()
            || fields.request.operation != operation
            || source.digest() != decision.source_release_digest
            || self.source_heads.get(source.digest().as_bytes()) != Some(source.release())
            || encode_publisher_admission_request_v1(request) != decision.canonical_request
            || encode_publisher_domain_plan(request.plan()) != decision.canonical_plan
            || runtime_join_digest(execution.joined) != decision.runtime_binding_digest
            || decision.root_registry_digest != root_checkpoint.registry_digest
            || decision.root_registry_generation != root_checkpoint.generation
            || !global_root_is_current
            || selected_root.record_digest() != decision.selected_root_digest
            || selected_root.generation() != decision.selected_root_generation
            || self
                .root_records
                .get(selected_root.record_digest().as_bytes())
                != Some(selected_root.record())
            || selected_root.record().service_node != fields.target.node
            || selected_root.record().service_principal != fields.target.principal
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(())
    }

    /// Revalidates one retained permit for its exact live executor and artifact.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when authority is poisoned, the operation is
    /// absent, the executor/artifact differs, or failover recovery has made the
    /// effect uncertain. Revocation-pending permits remain usable because their
    /// already-issued completion obligation cannot be cancelled retroactively.
    #[cfg(target_os = "linux")]
    pub fn authorize_retained_completion<'authority, 'request>(
        &self,
        committed: &CommittedAdmissionFrontier,
        execution: LivePublisherExecution<'authority, 'request>,
        roots: &'authority PublicationRootRegistry,
        custody: &'authority PublicationRootCustody,
        operation: OperationId,
        artifact_digest: ObjectDigest,
    ) -> Result<RetainedCompletionPermit<'authority, 'request>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        let permit = self
            .permits
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let request = execution.joined.request();
        let fields = request.plan().fields();
        let target = &request.plan().fields().target;
        let selected_root = custody
            .authorize_retained_completion(roots)
            .map_err(|_| AdmissionError::CompletionMismatch)?;
        if permit.publisher_instance != target.instance
            || permit.artifact_digest != artifact_digest
            || encode_publisher_admission_request_v1(request) != decision.canonical_request
            || encode_publisher_domain_plan(request.plan()) != decision.canonical_plan
            || runtime_join_digest(execution.joined) != decision.runtime_binding_digest
            || selected_root.record_digest() != decision.selected_root_digest
            || self
                .root_records
                .get(selected_root.record_digest().as_bytes())
                != Some(selected_root.record())
            || selected_root.generation() != permit.root_generation
            || fields.request.operation != operation
            || selected_root.record().service_node != target.node
            || selected_root.record().service_principal != target.principal
            || !matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding | CompletionPermitStateV1::RevocationPending
            )
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        Ok(RetainedCompletionPermit {
            permit: permit.clone(),
            _execution: execution,
            _root: selected_root,
        })
    }

    /// Seals every owner required to perform one ordinary completion effect.
    ///
    /// This method consumes the fresh retained permit and physical adapter
    /// custody, exclusively borrows the catalog insertion point and ledger,
    /// and precomputes poison before the no-replace or catalog effect begins.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless the permit is the exact current
    /// outstanding record, the physical and catalog intent match its prepared
    /// artifact and retained root, and both protected branches fit all bounds.
    #[allow(clippy::too_many_arguments)]
    #[cfg(target_os = "linux")]
    pub(crate) fn authorize_completion<'owners, 'authority, 'request>(
        &'owners mut self,
        committed: &CommittedAdmissionFrontier,
        permit: RetainedCompletionPermit<'authority, 'request>,
        effect: CompletionEffectCustodyV1,
        intended_entry: super::CommittedReadEntryV1,
        catalog: &'owners mut super::ReadCatalogProjectionV1,
        store: &'owners mut dyn CapacityProtectedStoreSettlementV1,
    ) -> Result<CompletionAuthorityV1<'owners, 'authority, 'request>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        let retained = self
            .permits
            .get(permit.permit.operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        let artifact = self
            .artifacts
            .get(permit.permit.operation.as_bytes())
            .ok_or(AdmissionError::ArtifactMismatch)?;
        let decision = self
            .decisions
            .get(permit.permit.operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        if retained != permit.record()
            || !matches!(
                retained.state,
                CompletionPermitStateV1::Outstanding | CompletionPermitStateV1::RevocationPending
            )
            || self.receipts.contains_key(retained.operation.as_bytes())
            || !matches!(
                decision.state,
                AdmissionDecisionStateV1::CompletionPermitted
                    | AdmissionDecisionStateV1::RevocationPending
            )
            || effect.operation != retained.operation
            || effect.artifact_digest != retained.artifact_digest
            || effect.artifact_digest != artifact.artifact_digest
            || effect.root_record_digest != permit._root.record_digest()
            || effect.root_record_digest != decision.selected_root_digest
            || effect.private_name_digest != artifact.private_name_digest
            || effect.final_name_digest != artifact.final_name_digest
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        self.validate_recovery_catalog_entry(
            retained.operation,
            retained.artifact_digest,
            &intended_entry,
        )?;
        let prior_catalog_generation = self.latest_catalog_generation().unwrap_or(0);
        let next_catalog_generation = prior_catalog_generation
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        if catalog.generation() != prior_catalog_generation
            || catalog.contains_object(intended_entry.object())
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let poison_digest = digest_parts(
            b"aos.sandbox.publisher.completion-poison.v1\0",
            &[
                retained.operation.as_bytes(),
                retained.permit.as_bytes(),
                retained.artifact_digest.as_bytes(),
                effect.root_record_digest.as_bytes(),
                effect.private_name_digest.as_bytes(),
                effect.final_name_digest.as_bytes(),
                effect.prepared_observation_digest.as_bytes(),
                effect.expected_physical_effect_digest.as_bytes(),
                effect.expected_parent_sync_digest.as_bytes(),
                intended_entry.digest().as_bytes(),
                &prior_catalog_generation.to_be_bytes(),
                &next_catalog_generation.to_be_bytes(),
            ],
        );
        let poison = self.sealed_poison_branch(poison_digest)?;
        let expected_catalog = CommittedCatalogObservation {
            prior_catalog_generation,
            catalog_generation: next_catalog_generation,
            catalog_entry: intended_entry.clone(),
        };
        let completion = CompletionResult::observed(&permit, expected_catalog);
        let mut staged = self.clone();
        let (receipt, mutations) = staged.complete_in_place(completion)?;
        let primary = ProtectedMutationBranchV1::seal(staged, mutations)?;
        let catalog = catalog
            .begin_exclusive_insertion(prior_catalog_generation, intended_entry.clone())
            .map_err(|_| AdmissionError::CompletionMismatch)?;
        Ok(CompletionAuthorityV1 {
            permit,
            _effect: effect,
            intended_entry,
            ledger: self,
            catalog: Some(catalog),
            primary,
            poison,
            receipt: Some(receipt),
            store,
            settled: false,
        })
    }

    /// Joins the committed decision to current live source, root, and runtime.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless every current authority exactly matches
    /// the retained admitted decision and original canonical request.
    #[cfg(target_os = "linux")]
    pub(crate) fn authorize_materialization<'authority, 'request, E>(
        &'authority self,
        committed: &CommittedAdmissionFrontier,
        operation: OperationId,
        execution: LivePublisherExecution<'authority, 'request>,
        source: AuthorizedSourceRelease<'authority>,
        root: &'authority CurrentPublicationRoot<'authority>,
        realtime: &mut impl FnMut() -> Result<i64, E>,
    ) -> Result<MaterializationAuthority<'authority, 'request>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let joined = execution.joined;
        let request = joined.request();
        let fields = request.plan().fields();
        let now_seconds = realtime().map_err(|_| AdmissionError::ClockUnavailable)?;
        source.release().authorize(
            fields.request.holder,
            fields.target.project,
            request.cache_resource(),
            fields.target.cache_domain,
            &fields.request.content,
            now_seconds,
        )?;
        let selected_root = root.root();
        let root_checkpoint = root.checkpoint();
        if decision.state != AdmissionDecisionStateV1::Admitted
            || !root.is_current()
            || request.plan().fields().request.operation != operation
            || encode_publisher_admission_request_v1(request) != decision.canonical_request
            || encode_publisher_domain_plan(request.plan()) != decision.canonical_plan
            || request.plan().fields().request.source_authorization != source.digest()
            || decision.source_release_digest != source.digest()
            || self.source_heads.get(source.digest().as_bytes()) != Some(source.release())
            || decision.root_registry_digest != root_checkpoint.registry_digest
            || decision.root_registry_generation != root_checkpoint.generation
            || decision.selected_root_digest != selected_root.record_digest()
            || self
                .root_checkpoint_history
                .last_key_value()
                .is_none_or(|(generation, digest)| {
                    *generation != root_checkpoint.generation
                        || *digest != root_checkpoint.registry_digest
                })
            || self
                .root_records
                .get(selected_root.record_digest().as_bytes())
                != Some(selected_root.record())
            || decision.selected_root_generation != selected_root.generation()
            || decision.runtime_binding_digest != runtime_join_digest(joined)
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(MaterializationAuthority {
            decision,
            committed: committed.clone(),
            _runtime: execution,
            _source: source,
            _root: root,
        })
    }

    /// Confirms that a trusted protected-store adapter committed this frontier.
    ///
    /// This seam accepts only the opaque acknowledgement minted by the durable
    /// adapter after atomic commit and required synchronization.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the committed sequence or hash-chain head
    /// differs from this exact projection.
    pub(crate) fn confirm_committed(
        &self,
        token: ProtectedStoreCommitToken,
    ) -> Result<CommittedAdmissionFrontier, AdmissionError> {
        if self.last_kind != Some(ProtectedRecordKindV1::AuthorityCheckpoint)
            || token.checkpoint != self.checkpoint()?
            || token.checkpoint.sequence != self.sequence
            || self.predecessor != Some(token.head)
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(CommittedAdmissionFrontier {
            sequence: token.checkpoint.sequence,
            head: token.head,
            checkpoint: token.checkpoint,
        })
    }

    /// Stages completion inside a sealed settlement or recovery transaction.
    pub(super) fn complete_in_place(
        &mut self,
        result: CompletionResult,
    ) -> Result<(CompletionReceiptV1, Vec<LedgerMutation>), AdmissionError> {
        self.ensure_healthy()?;
        let artifact = self
            .artifacts
            .get(result.operation.as_bytes())
            .ok_or(AdmissionError::ArtifactMismatch)?;
        let decision = self
            .decisions
            .get(result.operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let request = aos_sandbox_core::format::decode_publisher_admission_request_v1(
            &decision.canonical_request,
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| AdmissionError::CompletionMismatch)?;
        let fields = request.plan().fields();
        let selected_root = self
            .root_records
            .get(decision.selected_root_digest.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        let entry = &result.catalog_entry;
        if entry.object() != &artifact.content
            || entry.project() != fields.target.project
            || entry.resource() != request.cache_resource()
            || entry.domain() != fields.target.cache_domain
            || entry.root_id() != selected_root.root_id
            || entry.root_digest() != decision.selected_root_digest
            || entry.root_generation() != decision.selected_root_generation
            || entry.backing_digest() != ObjectDigest::from_bytes(artifact.verity_sha256)
            || entry.allocated() != artifact.allocated_bytes
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let artifact_digest = artifact.artifact_digest;
        let catalog_entry_digest = entry.digest();
        let resident_bytes = entry.allocated();
        if let Some(receipt) = self.receipts.get(result.operation.as_bytes()) {
            return if receipt.permit == result.permit
                && receipt.artifact_digest == artifact_digest
                && receipt.catalog_generation == result.catalog_generation
                && receipt.catalog_entry_digest == catalog_entry_digest
                && receipt.resident_bytes == resident_bytes
            {
                Ok((receipt.clone(), Vec::new()))
            } else {
                Err(AdmissionError::CompletionMismatch)
            };
        }
        if result
            .prior_catalog_generation
            .checked_add(1)
            .is_none_or(|next| next != result.catalog_generation)
            || self
                .latest_catalog_generation()
                .is_some_and(|current| current != result.prior_catalog_generation)
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        if self.receipts.iter().any(|(operation, retained)| {
            operation != result.operation.as_bytes()
                && !self.evictions.contains_key(operation)
                && retained.catalog_entry.object() == result.catalog_entry.object()
        }) {
            return Err(AdmissionError::IdentityConflict);
        }
        let mut permit = self
            .permits
            .get(result.operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?
            .clone();
        if permit.permit != result.permit
            || permit.artifact_digest != artifact_digest
            || !matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding
                    | CompletionPermitStateV1::RevocationPending
                    | CompletionPermitStateV1::Uncertain
            )
            || result.catalog_generation == 0
            || catalog_entry_digest.as_bytes() == &[0; 32]
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let mut next_accounting = self.accounting.clone();
        let account = next_accounting.commit_residency(permit.reservation, resident_bytes)?;
        permit.state = CompletionPermitStateV1::Spent;
        let receipt_digest = digest_parts(
            RECEIPT_DOMAIN,
            &[
                result.permit.as_bytes(),
                result.operation.as_bytes(),
                artifact_digest.as_bytes(),
                &result.catalog_generation.to_be_bytes(),
                catalog_entry_digest.as_bytes(),
                &resident_bytes.to_be_bytes(),
            ],
        );
        let receipt = CompletionReceiptV1 {
            permit: result.permit,
            operation: result.operation,
            artifact_digest,
            catalog_generation: result.catalog_generation,
            catalog_entry_digest,
            catalog_entry: result.catalog_entry.clone(),
            resident_bytes,
            receipt_digest,
        };
        self.ensure_record_capacity(1)?;
        let permit_mutation = self.append(
            ProtectedRecordKindV1::CompletionPermit,
            permit.permit.as_bytes().to_vec(),
            permit_payload(&permit),
        )?;
        self.accounting = next_accounting;
        self.permits.insert(*result.operation.as_bytes(), permit);
        let decision = self
            .decisions
            .get_mut(result.operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::Completed;
        let accounting_mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        let receipt_mutation = self.append(
            ProtectedRecordKindV1::CompletionReceipt,
            result.operation.as_bytes().to_vec(),
            receipt_payload(&receipt),
        )?;
        self.receipts
            .insert(*result.operation.as_bytes(), receipt.clone());
        Ok((
            receipt,
            vec![permit_mutation, accounting_mutation, receipt_mutation],
        ))
    }

    /// Authorizes exact eviction while precomputing its durable poison branch.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless the entry is the unique current
    /// catalog resident, its completion is retained, and both protected
    /// successor branches fit configured bounds before any removal begins.
    pub(crate) fn authorize_catalog_eviction<'catalog>(
        &'catalog mut self,
        committed: &CommittedAdmissionFrontier,
        catalog: &'catalog mut super::ReadCatalogProjectionV1,
        operation: OperationId,
        store: &'catalog mut dyn StateOnlyProtectedStoreSettlementV1,
    ) -> Result<CatalogEvictionAuthorizationV1<'catalog>, AdmissionError> {
        self.ensure_healthy()?;
        self.require_committed(committed)?;
        if self.evictions.contains_key(operation.as_bytes()) {
            return Err(AdmissionError::InvalidTransition);
        }
        let receipt = self
            .receipts
            .get(operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        let catalog_entry_digest = receipt.catalog_entry_digest;
        let prior_catalog_generation = self
            .latest_catalog_generation()
            .ok_or(AdmissionError::CompletionMismatch)?;
        if catalog.generation() != prior_catalog_generation
            || receipt.catalog_generation > prior_catalog_generation
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let eviction_catalog_generation = prior_catalog_generation
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        let poison_digest = digest_parts(
            b"aos.sandbox.publisher.catalog-eviction-poison.v1\0",
            &[
                operation.as_bytes(),
                catalog_entry_digest.as_bytes(),
                &prior_catalog_generation.to_be_bytes(),
                &eviction_catalog_generation.to_be_bytes(),
            ],
        );
        let poison = self.sealed_poison_branch(poison_digest)?;
        let custody = catalog
            .begin_exclusive_eviction(operation, catalog_entry_digest)
            .map_err(|_| AdmissionError::CompletionMismatch)?;
        Ok(CatalogEvictionAuthorizationV1 {
            operation,
            catalog_entry_digest,
            prior_catalog_generation,
            ledger: self,
            poison: Some(poison),
            custody: Some(custody),
            store,
            settled: false,
        })
    }

    /// Derives the exact current read catalog from durable completion and eviction records.
    ///
    /// Caller-provided catalog membership is never accepted. Duplicate active
    /// object entries fail closed, including duplicates that would otherwise
    /// expose scope selection through lookup behavior.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when authority is poisoned, the projection
    /// exceeds its bound, or durable active entries conflict.
    pub fn read_catalog_projection(
        &self,
        maximum_entries: usize,
    ) -> Result<super::ReadCatalogProjectionV1, AdmissionError> {
        self.ensure_healthy()?;
        let active = self
            .receipts
            .iter()
            .filter(|(operation, _)| !self.evictions.contains_key(*operation))
            .map(|(_, receipt)| receipt.catalog_entry.clone());
        super::ReadCatalogProjectionV1::replay(
            self.latest_catalog_generation().unwrap_or(0),
            maximum_entries,
            active,
        )
        .map_err(|_| AdmissionError::CompletionMismatch)
    }

    fn evict_catalog_entry_in_place(
        &mut self,
        operation: OperationId,
        catalog_entry_digest: ObjectDigest,
        prior_catalog_generation: u64,
        eviction_catalog_generation: u64,
    ) -> Result<(super::CatalogEvictionReceiptV1, Vec<LedgerMutation>), AdmissionError> {
        self.ensure_healthy()?;
        if let Some(existing) = self.evictions.get(operation.as_bytes()) {
            return if existing.catalog_entry_digest == catalog_entry_digest
                && existing.prior_catalog_generation == prior_catalog_generation
                && existing.eviction_catalog_generation == eviction_catalog_generation
            {
                Ok((existing.clone(), Vec::new()))
            } else {
                Err(AdmissionError::IdentityConflict)
            };
        }
        let receipt = self
            .receipts
            .get(operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        if receipt.catalog_entry_digest != catalog_entry_digest
            || receipt.catalog_generation > prior_catalog_generation
            || self.latest_catalog_generation() != Some(prior_catalog_generation)
            || prior_catalog_generation.checked_add(1) != Some(eviction_catalog_generation)
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let mut accounting = self.accounting.clone();
        let account = accounting.evict_residency(decision.reservation)?;
        let eviction_digest = digest_parts(
            EVICTION_DOMAIN,
            &[
                operation.as_bytes(),
                catalog_entry_digest.as_bytes(),
                &prior_catalog_generation.to_be_bytes(),
                &eviction_catalog_generation.to_be_bytes(),
                &receipt.resident_bytes.to_be_bytes(),
            ],
        );
        let eviction = super::CatalogEvictionReceiptV1 {
            operation,
            catalog_entry_digest,
            prior_catalog_generation,
            eviction_catalog_generation,
            released_bytes: receipt.resident_bytes,
            eviction_digest,
        };
        self.ensure_record_capacity(1)?;
        let account_mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        let eviction_mutation = self.append(
            ProtectedRecordKindV1::CatalogEviction,
            operation.as_bytes().to_vec(),
            eviction_payload(&eviction),
        )?;
        self.accounting = accounting;
        self.evictions
            .insert(*operation.as_bytes(), eviction.clone());
        Ok((eviction, vec![account_mutation, eviction_mutation]))
    }

    /// Initiates revocation without cancelling an outstanding obligation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for an absent operation, poisoned authority,
    /// terminal state, or encoding failure.
    pub fn initiate_revocation(
        &mut self,
        operation: OperationId,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        let decision_state = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?
            .state;
        if decision_state == AdmissionDecisionStateV1::Uncertain {
            return Ok(Vec::new());
        }
        match decision_state {
            AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted => {
                return Ok(Vec::new());
            }
            AdmissionDecisionStateV1::CompletionPermitted
            | AdmissionDecisionStateV1::RevocationPending => {
                let mut permit = self
                    .permits
                    .get(operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?
                    .clone();
                if decision_state == AdmissionDecisionStateV1::RevocationPending
                    && permit.state == CompletionPermitStateV1::RevocationPending
                {
                    return Ok(Vec::new());
                }
                if permit.state != CompletionPermitStateV1::Spent {
                    permit.state = CompletionPermitStateV1::RevocationPending;
                }
                let mutation = self.append(
                    ProtectedRecordKindV1::CompletionPermit,
                    permit.permit.as_bytes().to_vec(),
                    permit_payload(&permit),
                )?;
                self.permits.insert(*operation.as_bytes(), permit);
                let decision = self
                    .decisions
                    .get_mut(operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?;
                decision.state = AdmissionDecisionStateV1::RevocationPending;
                Ok(vec![mutation])
            }
            AdmissionDecisionStateV1::Admitted | AdmissionDecisionStateV1::ArtifactPrepared => {
                // Artifact preparation may already have performed allocation or
                // sealing. Only recovery may decide whether release is safe.
                if self.artifacts.contains_key(operation.as_bytes()) {
                    return self.mark_uncertain(operation);
                }
                let mut decision = self
                    .decisions
                    .get(operation.as_bytes())
                    .ok_or(AdmissionError::Poisoned)?
                    .clone();
                decision.state = AdmissionDecisionStateV1::RevocationPending;
                let mutation = self.append(
                    ProtectedRecordKindV1::AdmissionDecision,
                    operation.as_bytes().to_vec(),
                    decision_payload(&decision),
                )?;
                self.decisions.insert(*operation.as_bytes(), decision);
                Ok(vec![mutation])
            }
            AdmissionDecisionStateV1::Uncertain => Ok(Vec::new()),
            AdmissionDecisionStateV1::Poisoned => Err(AdmissionError::Poisoned),
        }
    }

    /// Releases a definitely pre-effect admission and its reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if any artifact/permit/receipt exists, the
    /// operation is absent, authority is poisoned, or accounting fails.
    pub fn abort_before_effect(
        &mut self,
        operation: OperationId,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        if self.artifacts.contains_key(operation.as_bytes())
            || self.permits.contains_key(operation.as_bytes())
            || self.receipts.contains_key(operation.as_bytes())
        {
            return Err(AdmissionError::InvalidTransition);
        }
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?
            .clone();
        if decision.state == AdmissionDecisionStateV1::Aborted {
            return Ok(Vec::new());
        }
        if !matches!(
            decision.state,
            AdmissionDecisionStateV1::Admitted | AdmissionDecisionStateV1::RevocationPending
        ) {
            return Err(AdmissionError::InvalidTransition);
        }
        let mut next_accounting = self.accounting.clone();
        let account = next_accounting.release_without_effect(decision.reservation)?;
        let mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        self.accounting = next_accounting;
        let decision = self
            .decisions
            .get_mut(operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::Aborted;
        Ok(vec![mutation])
    }

    /// Immediately latches uncertainty while retaining the full reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absence, terminal state, or accounting
    /// failure. Once a contradiction is reported, [`Self::poison`] must be used.
    pub fn mark_uncertain(
        &mut self,
        operation: OperationId,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        let mut staged = self.clone();
        let mutations = staged.mark_uncertain_in_place(operation)?;
        *self = staged;
        Ok(mutations)
    }

    fn mark_uncertain_in_place(
        &mut self,
        operation: OperationId,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?
            .clone();
        if matches!(
            decision.state,
            AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted
        ) {
            return Err(AdmissionError::InvalidTransition);
        }
        if decision.state == AdmissionDecisionStateV1::Uncertain
            && self
                .accounting
                .account(decision.reservation)
                .is_some_and(|account| account.state == super::ReservationStateV1::Uncertain)
            && self
                .permits
                .get(operation.as_bytes())
                .is_none_or(|permit| permit.state == CompletionPermitStateV1::Uncertain)
        {
            return Ok(Vec::new());
        }
        let mut next_accounting = self.accounting.clone();
        let account = next_accounting.mark_uncertain(decision.reservation)?;
        let accounting_mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        self.accounting = next_accounting;
        let decision = self
            .decisions
            .get_mut(operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::Uncertain;
        let mut mutations = vec![accounting_mutation];
        if let Some(mut permit) = self.permits.get(operation.as_bytes()).cloned() {
            permit.state = CompletionPermitStateV1::Uncertain;
            mutations.push(self.append(
                ProtectedRecordKindV1::CompletionPermit,
                permit.permit.as_bytes().to_vec(),
                permit_payload(&permit),
            )?);
            self.permits.insert(*operation.as_bytes(), permit);
        }
        Ok(mutations)
    }

    /// Retires a fenced permit only after recovery proves complete absence.
    pub(super) fn retire_permit_without_effect(
        &mut self,
        operation: OperationId,
        artifact_digest: ObjectDigest,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        let mut staged = self.clone();
        let mutations = staged.retire_permit_without_effect_in_place(operation, artifact_digest)?;
        *self = staged;
        Ok(mutations)
    }

    fn retire_permit_without_effect_in_place(
        &mut self,
        operation: OperationId,
        artifact_digest: ObjectDigest,
    ) -> Result<Vec<LedgerMutation>, AdmissionError> {
        self.ensure_healthy()?;
        let mut permit = self
            .permits
            .get(operation.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?
            .clone();
        if permit.state == CompletionPermitStateV1::RetiredWithoutEffect
            && self
                .accounting
                .account(permit.reservation)
                .is_some_and(|account| account.state == super::ReservationStateV1::Released)
        {
            return Ok(Vec::new());
        }
        if permit.artifact_digest != artifact_digest
            || !matches!(
                permit.state,
                CompletionPermitStateV1::Outstanding
                    | CompletionPermitStateV1::RevocationPending
                    | CompletionPermitStateV1::Uncertain
            )
        {
            return Err(AdmissionError::InvalidTransition);
        }
        let mut accounting = self.accounting.clone();
        let account = accounting.release_without_effect(permit.reservation)?;
        permit.state = CompletionPermitStateV1::RetiredWithoutEffect;
        self.ensure_record_capacity(0)?;
        let permit_mutation = self.append(
            ProtectedRecordKindV1::CompletionPermit,
            permit.permit.as_bytes().to_vec(),
            permit_payload(&permit),
        )?;
        let account_mutation = self.append(
            ProtectedRecordKindV1::Accounting,
            account.reservation.as_bytes().to_vec(),
            accounting_payload(&account),
        )?;
        self.accounting = accounting;
        self.permits.insert(*operation.as_bytes(), permit);
        let decision = self
            .decisions
            .get_mut(operation.as_bytes())
            .ok_or(AdmissionError::Poisoned)?;
        decision.state = AdmissionDecisionStateV1::Aborted;
        Ok(vec![permit_mutation, account_mutation])
    }

    /// Latches a contradiction before attempting its durable poison record.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Poisoned`] when a poison successor already
    /// exists, or a generation, capacity, or codec error when the diagnostic
    /// mutation cannot be represented. The in-memory authority remains
    /// poisoned if record encoding fails after the latch is set.
    pub fn poison(
        &mut self,
        reason_digest: ObjectDigest,
    ) -> Result<LedgerMutation, AdmissionError> {
        self.ensure_healthy()?;
        if reason_digest.as_bytes() == &[0; 32] {
            return Err(AdmissionError::InvalidIdentity("poison reason"));
        }
        self.ensure_record_capacity(1)?;
        self.poisoned = true;
        self.append(
            ProtectedRecordKindV1::Poison,
            b"authority".to_vec(),
            reason_digest.as_bytes().to_vec(),
        )
    }

    /// Precomputes the only durable fallback for an unsettled physical effect.
    pub(super) fn sealed_poison_branch(
        &self,
        reason_digest: ObjectDigest,
    ) -> Result<ProtectedMutationBranchV1, AdmissionError> {
        let mut poisoned = self.clone();
        let mutation = poisoned.poison(reason_digest)?;
        ProtectedMutationBranchV1::seal(poisoned, vec![mutation])
    }

    /// Latches process-local denial after a trusted settlement contract violation.
    ///
    /// Reopen still requires protected replay. This latch ensures no authority
    /// can escape from the current owner if an adapter returns an invalid token.
    pub(super) fn latch_unacknowledged_poison(&mut self) {
        self.poisoned = true;
    }

    pub(super) fn record_recovery_observation(
        &mut self,
        receipt: RecoveryObservationReceiptV1,
    ) -> Result<Option<LedgerMutation>, AdmissionError> {
        if let Some(retained) = self
            .recovery_observations
            .iter()
            .find(|retained| retained.receipt_digest == receipt.receipt_digest)
        {
            return if retained == &receipt {
                Ok(None)
            } else {
                Err(AdmissionError::IdentityConflict)
            };
        }
        self.ensure_record_capacity(1)?;
        let mut key = receipt.operation.as_bytes().to_vec();
        key.extend_from_slice(receipt.receipt_digest.as_bytes());
        let mutation = self.append(
            ProtectedRecordKindV1::RecoveryObservation,
            key,
            recovery_observation_payload(&receipt),
        )?;
        self.recovery_observations.push(receipt);
        Ok(Some(mutation))
    }

    /// Returns the number of retained unresolved completion obligations.
    #[must_use]
    pub fn outstanding_permit_count(&self) -> usize {
        self.permits
            .values()
            .filter(|permit| {
                matches!(
                    permit.state,
                    CompletionPermitStateV1::Outstanding
                        | CompletionPermitStateV1::RevocationPending
                        | CompletionPermitStateV1::Uncertain
                )
            })
            .count()
    }

    /// Resolves one decision for diagnostics, never as effect authority.
    #[must_use]
    pub fn decision(&self, operation: OperationId) -> Option<&AdmissionDecisionV1> {
        self.decisions.get(operation.as_bytes())
    }

    /// Returns whether all authoritative reads and effects are denied.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(super) fn decisions(&self) -> impl Iterator<Item = &AdmissionDecisionV1> {
        self.decisions.values()
    }

    pub(super) fn permits(&self) -> impl Iterator<Item = &CompletionPermitV1> {
        self.permits.values()
    }

    pub(super) fn artifact(&self, operation: OperationId) -> Option<&ArtifactCommitmentV1> {
        self.artifacts.get(operation.as_bytes())
    }

    pub(super) fn receipt(&self, operation: OperationId) -> Option<&CompletionReceiptV1> {
        self.receipts.get(operation.as_bytes())
    }

    pub(super) fn validate_recovery_catalog_entry(
        &self,
        operation: OperationId,
        artifact_digest: ObjectDigest,
        entry: &super::CommittedReadEntryV1,
    ) -> Result<(), AdmissionError> {
        let artifact = self
            .artifacts
            .get(operation.as_bytes())
            .ok_or(AdmissionError::ArtifactMismatch)?;
        let decision = self
            .decisions
            .get(operation.as_bytes())
            .ok_or(AdmissionError::OperationAbsent)?;
        let request = aos_sandbox_core::format::decode_publisher_admission_request_v1(
            &decision.canonical_request,
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| AdmissionError::CompletionMismatch)?;
        let root = self
            .root_records
            .get(decision.selected_root_digest.as_bytes())
            .ok_or(AdmissionError::CompletionMismatch)?;
        if artifact.artifact_digest != artifact_digest
            || entry.object() != &artifact.content
            || entry.project() != request.plan().fields().target.project
            || entry.resource() != request.cache_resource()
            || entry.domain() != request.plan().fields().target.cache_domain
            || entry.root_id() != root.root_id
            || entry.root_digest() != decision.selected_root_digest
            || entry.root_generation() != decision.selected_root_generation
            || entry.backing_digest() != ObjectDigest::from_bytes(artifact.verity_sha256)
            || entry.allocated() != artifact.allocated_bytes
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        Ok(())
    }

    pub(super) fn has_recovery_observation(&self, receipt: &RecoveryObservationReceiptV1) -> bool {
        self.recovery_observations
            .iter()
            .any(|retained| retained == receipt)
    }

    pub(super) fn accounts(&self) -> impl Iterator<Item = &super::CapacityAccountV1> {
        self.accounting.accounts()
    }

    pub(crate) fn root_obligations(
        &self,
        root_id: crate::publisher_roots::PublicationRootId,
    ) -> crate::publisher_roots::PublicationRootObligationsV1 {
        let retained_generations: BTreeMap<[u8; 32], u64> = self
            .root_records
            .values()
            .filter(|record| record.root_id == root_id)
            .map(|record| (*record.record_digest.as_bytes(), record.generation))
            .collect();
        let matches_root = |decision: &&AdmissionDecisionV1| {
            retained_generations
                .get(decision.selected_root_digest.as_bytes())
                .is_some_and(|generation| *generation == decision.selected_root_generation)
        };
        crate::publisher_roots::PublicationRootObligationsV1 {
            outstanding_permits: self
                .decisions
                .values()
                .filter(matches_root)
                .filter(|decision| {
                    self.permits
                        .get(decision.operation.as_bytes())
                        .is_some_and(|permit| {
                            matches!(
                                permit.state,
                                CompletionPermitStateV1::Outstanding
                                    | CompletionPermitStateV1::RevocationPending
                                    | CompletionPermitStateV1::Uncertain
                            )
                        })
                })
                .count() as u64,
            catalog_entries: self
                .decisions
                .values()
                .filter(matches_root)
                .filter(|decision| {
                    self.receipts.contains_key(decision.operation.as_bytes())
                        && !self.evictions.contains_key(decision.operation.as_bytes())
                })
                .count() as u64,
            uncertain_effects: self
                .decisions
                .values()
                .filter(matches_root)
                .filter(|decision| decision.state == AdmissionDecisionStateV1::Uncertain)
                .count() as u64,
        }
    }

    pub(super) const fn authority_epoch(&self) -> PublicationAuthorityEpoch {
        self.authority_epoch
    }

    pub(super) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn has_terminal_checkpoint(&self) -> bool {
        matches!(
            self.last_kind,
            Some(ProtectedRecordKindV1::AuthorityCheckpoint)
        )
    }

    pub(super) fn projection_digest(&self) -> Result<ObjectDigest, AdmissionError> {
        let mut values = Vec::<Vec<u8>>::new();
        values.push(self.authority_epoch.get().to_be_bytes().to_vec());
        let policy = self.accounting.policy();
        values.push(policy.resource.as_bytes().to_vec());
        values.push(policy.project.as_bytes().to_vec());
        values.push(policy.domain.domain_id().as_bytes().to_vec());
        values.push(policy.isolation_policy.as_bytes().to_vec());
        values.push(policy.maximum_bytes.to_be_bytes().to_vec());
        values.push(policy.maximum_objects.to_be_bytes().to_vec());
        values.push(policy.recovery_reserve_bytes.to_be_bytes().to_vec());
        for source in self.source_heads.values() {
            values.push(source_release_payload(source));
        }
        for root in self.root_records.values() {
            values.push(
                crate::publisher_roots::encode_root_record_v1(root)
                    .map_err(|_| AdmissionError::AuthorityMismatch)?,
            );
        }
        for challenge in self.challenges.values() {
            let mut value = challenge_key_bytes(challenge);
            value.extend_from_slice(&challenge_payload(challenge));
            values.push(value);
        }
        for decision in self.decisions.values() {
            values.push(decision_payload(decision));
        }
        for account in self.accounts() {
            values.push(accounting_payload(account));
        }
        for artifact in self.artifacts.values() {
            values.push(artifact_payload(artifact));
        }
        for permit in self.permits.values() {
            values.push(permit_payload(permit));
        }
        for receipt in self.receipts.values() {
            values.push(receipt_payload(receipt));
        }
        for eviction in self.evictions.values() {
            values.push(eviction_payload(eviction));
        }
        for observation in &self.recovery_observations {
            values.push(recovery_observation_payload(observation));
        }
        values.push(vec![u8::from(self.poisoned)]);
        let parts: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
        Ok(digest_parts(
            b"aos.sandbox.publisher.authority-projection.v1\0",
            &parts,
        ))
    }

    pub(super) fn set_failover_epoch(&mut self, epoch: PublicationAuthorityEpoch) {
        self.authority_epoch = epoch;
    }

    pub(super) fn append_checkpoint(
        &mut self,
        checkpoint: &super::AuthorityCheckpointV1,
    ) -> Result<LedgerMutation, AdmissionError> {
        self.ensure_record_capacity(0)?;
        self.append(
            ProtectedRecordKindV1::AuthorityCheckpoint,
            checkpoint.epoch.get().to_be_bytes().to_vec(),
            checkpoint_payload(checkpoint),
        )
    }

    fn ensure_healthy(&self) -> Result<(), AdmissionError> {
        if self.poisoned {
            return Err(AdmissionError::Poisoned);
        }
        Ok(())
    }

    pub(super) fn require_committed(
        &self,
        committed: &CommittedAdmissionFrontier,
    ) -> Result<(), AdmissionError> {
        if !self.has_terminal_checkpoint()
            || committed.sequence != self.sequence
            || self.predecessor != Some(committed.head)
            || committed.checkpoint != self.checkpoint()?
        {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(())
    }

    pub(super) fn retained_record_count(&self) -> Result<usize, AdmissionError> {
        self.source_heads
            .len()
            .checked_add(self.root_records.len())
            .and_then(|value| value.checked_add(self.challenges.len()))
            .and_then(|value| value.checked_add(self.decisions.len()))
            .and_then(|value| value.checked_add(self.accounting.accounts().count()))
            .and_then(|value| value.checked_add(self.artifacts.len()))
            .and_then(|value| value.checked_add(self.permits.len()))
            .and_then(|value| value.checked_add(self.receipts.len()))
            .and_then(|value| value.checked_add(self.evictions.len()))
            .and_then(|value| value.checked_add(self.recovery_observations.len()))
            .and_then(|value| value.checked_add(usize::from(self.poisoned)))
            // One terminal checkpoint slot is always reserved so any accepted
            // semantic transition can still become durable authority.
            .and_then(|value| value.checked_add(1))
            .ok_or(AdmissionError::LimitExceeded("records"))
    }

    fn ensure_record_capacity(&self, additional: usize) -> Result<(), AdmissionError> {
        let retained = self
            .retained_record_count()?
            .checked_add(additional)
            .ok_or(AdmissionError::LimitExceeded("records"))?;
        if retained > self.limits.maximum_records {
            return Err(AdmissionError::LimitExceeded("records"));
        }
        Ok(())
    }

    pub(super) fn latest_catalog_generation(&self) -> Option<u64> {
        self.receipts
            .values()
            .map(|receipt| receipt.catalog_generation)
            .chain(
                self.evictions
                    .values()
                    .map(|eviction| eviction.eviction_catalog_generation),
            )
            .max()
    }

    pub(super) fn recovery_observations(
        &self,
    ) -> impl DoubleEndedIterator<Item = &RecoveryObservationReceiptV1> {
        self.recovery_observations.iter()
    }

    fn append(
        &mut self,
        kind: ProtectedRecordKindV1,
        key: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<LedgerMutation, AdmissionError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        let value = encode_protected_record_v1(
            kind,
            sequence,
            &key,
            self.predecessor,
            &payload,
            self.limits,
        )?;
        let decoded = super::decode_protected_record_v1(&value, self.limits)?;
        let next_materialized = self
            .materialized_bytes
            .checked_add(value.len())
            .ok_or(AdmissionError::LimitExceeded("materialized bytes"))?;
        if next_materialized > self.limits.maximum_materialized_bytes {
            return Err(AdmissionError::LimitExceeded("materialized bytes"));
        }
        self.sequence = sequence;
        self.predecessor = Some(decoded.digest);
        self.materialized_bytes = next_materialized;
        self.last_kind = Some(kind);
        Ok(LedgerMutation { kind, key, value })
    }
}

#[cfg(target_os = "linux")]
fn runtime_join_digest(joined: &RuntimeJoinedPublisherRequest<'_>) -> ObjectDigest {
    let binding = joined.runtime().binding();
    digest_parts(
        RUNTIME_DOMAIN,
        &[
            binding.digest().as_bytes(),
            binding.assignment_digest().as_bytes(),
            binding.publication_digest().as_bytes(),
            binding.lease_digest().as_bytes(),
            &binding.revision().to_be_bytes(),
            &binding.lease_generation().to_be_bytes(),
            &joined
                .runtime()
                .deadline_boottime_nanoseconds()
                .to_be_bytes(),
        ],
    )
}

fn valid_decision_successor(
    previous: AdmissionDecisionStateV1,
    next: AdmissionDecisionStateV1,
) -> bool {
    matches!(
        (previous, next),
        (
            AdmissionDecisionStateV1::Admitted,
            AdmissionDecisionStateV1::ArtifactPrepared
        ) | (
            AdmissionDecisionStateV1::Admitted,
            AdmissionDecisionStateV1::RevocationPending
        ) | (
            AdmissionDecisionStateV1::ArtifactPrepared,
            AdmissionDecisionStateV1::CompletionPermitted
        ) | (
            AdmissionDecisionStateV1::ArtifactPrepared,
            AdmissionDecisionStateV1::Uncertain
        ) | (
            AdmissionDecisionStateV1::CompletionPermitted,
            AdmissionDecisionStateV1::RevocationPending
        ) | (
            AdmissionDecisionStateV1::CompletionPermitted,
            AdmissionDecisionStateV1::Completed
        ) | (
            AdmissionDecisionStateV1::RevocationPending,
            AdmissionDecisionStateV1::Uncertain
        ) | (
            AdmissionDecisionStateV1::RevocationPending,
            AdmissionDecisionStateV1::Completed
        ) | (
            AdmissionDecisionStateV1::Uncertain,
            AdmissionDecisionStateV1::Completed
        )
    )
}

fn valid_permit_successor(
    previous: CompletionPermitStateV1,
    next: CompletionPermitStateV1,
) -> bool {
    matches!(
        (previous, next),
        (
            CompletionPermitStateV1::Outstanding,
            CompletionPermitStateV1::RevocationPending
        ) | (
            CompletionPermitStateV1::Outstanding,
            CompletionPermitStateV1::Uncertain
        ) | (
            CompletionPermitStateV1::Outstanding,
            CompletionPermitStateV1::Spent
        ) | (
            CompletionPermitStateV1::Outstanding,
            CompletionPermitStateV1::RetiredWithoutEffect
        ) | (
            CompletionPermitStateV1::RevocationPending,
            CompletionPermitStateV1::Uncertain
        ) | (
            CompletionPermitStateV1::RevocationPending,
            CompletionPermitStateV1::Spent
        ) | (
            CompletionPermitStateV1::RevocationPending,
            CompletionPermitStateV1::RetiredWithoutEffect
        ) | (
            CompletionPermitStateV1::Uncertain,
            CompletionPermitStateV1::Spent
        ) | (
            CompletionPermitStateV1::Uncertain,
            CompletionPermitStateV1::RetiredWithoutEffect
        )
    )
}
