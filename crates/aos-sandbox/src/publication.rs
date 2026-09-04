//! Atomically publishes complete controller authority bundles.
//!
//! Publication has three explicit phases. A proposal owns typed, verified
//! inputs but has no durable meaning. Preparation validates the complete
//! audience set and freezes a bounded byte-exact record. Publication writes a
//! content-addressed prepared record and the sandbox's current pointer in one
//! journal transaction, together with its idempotency decision. Consequently a
//! crash can leave neither visible or both visible, but never a partial current
//! authority bundle.
//!
//! Replay revalidates canonical encodings and every structural cross-link, but
//! this store intentionally owns no trust anchors or public keys. Journal
//! recovery therefore does not replace cryptographic verification by the
//! privileged broker before dispatch.
//! Durable publication encoding and its isolated journal namespace are V3.
//! V1 or V2 current or prepared state produces an explicit migration-required
//! error before reads or writes.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, BrokerMethod};
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature, encode_signature,
};
use aos_sandbox_core::model::SignaturePurpose;
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, CanonicalAssignmentManifestV1, DecodeLimits,
    ObjectDigest, OperationId, OwnershipLease, RawPairedClockSample, SandboxId,
    descriptor_for_bytes,
};
use sha2::{Digest as _, Sha256};

use crate::{
    BrokerDispatchAttemptError, BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1,
    BrokerDispatchTemplateV1, IdempotencyKey, IdempotencyOutcome, Journal, JournalError,
    JournalRecord, JournalTransaction, OwnershipTransactionReceiptV1, RecordNamespace,
    SignedOwnershipLease,
};
use aos_sandbox_ownership_protocol::{OwnershipClaimAction, OwnershipClaimV1};

mod draft;
mod format;

use draft::{
    decode_draft, draft_digest, encode_bound_draft, encode_draft, encode_proposal,
    encode_recovered_draft, encode_target, validate_draft, validate_encoded_size,
    validate_proposal,
};
use format::{decode_current, decode_prepared, encode_current, validate_encoded_publication};

const MAGIC: &[u8; 8] = b"AOSCPUB3";
const LEGACY_V2_MAGIC: &[u8; 8] = b"AOSCPUB2";
const LEGACY_V1_MAGIC: &[u8; 8] = b"AOSCPUB1";
const VERSION: u16 = 3;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-publication.v3\0";
const TEMPLATE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.broker-dispatch-template.v1\0";
const MAXIMUM_TEMPLATES: usize = 256;
const JOURNAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
const CURRENT_HEADER_BYTES: usize = 186;
const CURRENT_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.current.v3/";
const PREPARED_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.prepared.v3/";
const LEGACY_V2_CURRENT_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.current.v2/";
const LEGACY_V2_PREPARED_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.prepared.v2/";
const LEGACY_CURRENT_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.current.v1/";
const LEGACY_PREPARED_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.prepared.v1/";
const DRAFT_MAGIC: &[u8; 8] = b"AOSCDRF1";
const DRAFT_VERSION: u16 = 1;
const DRAFT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-authority-draft.v1\0";
const MAXIMUM_PUBLICATION_DRAFT_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_PUBLICATION_BYTES: usize = JOURNAL_RECORD_BYTES
    - JOURNAL_RECORD_HEADER_BYTES
    - CURRENT_KEY_PREFIX.len()
    - 16
    - CURRENT_HEADER_BYTES;

/// Freezes lease-independent controller authority inputs for one assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPublicationDraftV1 {
    manifest: CanonicalAssignmentManifestV1,
    required_audiences: Vec<BrokerAudience>,
    templates: Vec<RecoveredBrokerDispatchTemplateV1>,
    ownership_authority: aos_sandbox_core::model::KeyReference,
    digest: ObjectDigest,
    bytes: Vec<u8>,
}

impl AuthorityPublicationDraftV1 {
    /// Validates and freezes a complete lease-independent authority draft.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] unless audiences are canonical
    /// and complete, one to 256 checked templates are canonically ordered,
    /// templates sharing an audience carry one exact plan and signature, every
    /// plan matches the manifest assignment/node/desired generation and one
    /// exact ownership authority, and the canonical encoding is bounded.
    pub fn new(
        manifest: CanonicalAssignmentManifestV1,
        required_audiences: Vec<BrokerAudience>,
        templates: Vec<BrokerDispatchTemplateV1>,
    ) -> Result<Self, AuthorityPublicationError> {
        validate_draft(&manifest, &required_audiences, &templates)?;
        let bytes = encode_draft(&manifest, &required_audiences, &templates)?;
        if bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
        decode_draft(&bytes).map_err(|_| AuthorityPublicationError::InvalidDraft)
    }

    /// Decodes a self-contained draft from hostile controller-local bytes.
    ///
    /// Decoding reconstructs exact signed-plan and template artifacts and
    /// checks their canonical encoding and semantic cross-links. It does not
    /// re-establish signature trust; protected brokers still verify recovered
    /// artifacts before granting authority.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError::InvalidDraft`] for invalid framing,
    /// bounds, manifest, audience codes, trailing or non-canonical bytes, or
    /// any inconsistent signed-plan or template cross-link.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityPublicationError> {
        if bytes.len() < 18
            || bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES
            || &bytes[..8] != DRAFT_MAGIC
            || bytes[8..10] != DRAFT_VERSION.to_be_bytes()
        {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        decode_draft(bytes).map_err(|_| AuthorityPublicationError::InvalidDraft)
    }

    /// Returns the canonical assignment manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }
    /// Returns the canonical required broker audiences.
    #[must_use]
    pub fn required_audiences(&self) -> &[BrokerAudience] {
        &self.required_audiences
    }
    /// Returns the exact structurally recovered, non-authorizing templates.
    #[must_use]
    pub fn templates(&self) -> &[RecoveredBrokerDispatchTemplateV1] {
        &self.templates
    }
    /// Returns the common exact ownership-authority key generation.
    #[must_use]
    pub const fn ownership_authority(&self) -> &aos_sandbox_core::model::KeyReference {
        &self.ownership_authority
    }
    /// Returns the domain-separated digest of the canonical draft.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
    /// Returns the exact bounded canonical controller-local encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Binds checked ownership artifacts and prepares the current V3 publication.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] if the lease does not match the
    /// manifest and common authority or complete publication validation fails.
    pub fn bind_lease(
        self,
        claim: &OwnershipClaimV1,
        lease: SignedOwnershipLease,
    ) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
        let assignment = self
            .manifest
            .broker_assignment()
            .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
        let lease_assignment = lease.assignment();
        let claim_assignment = claim.assignment();
        if lease_assignment.sandbox() != assignment.sandbox()
            || lease_assignment.incarnation() != assignment.incarnation()
            || lease_assignment.epoch() != assignment.epoch()
            || lease_assignment.digest() != assignment.digest()
            || lease.node() != self.manifest.manifest().node()
            || lease.signer() != &self.ownership_authority
            || claim_assignment.sandbox() != assignment.sandbox()
            || claim_assignment.incarnation() != assignment.incarnation()
            || claim_assignment.epoch() != assignment.epoch()
            || claim_assignment.digest() != assignment.digest()
            || claim.node() != self.manifest.manifest().node()
            || claim.desired_generation() != self.manifest.manifest().desired_generation()
        {
            return Err(AuthorityPublicationError::ContextMismatch);
        }
        let receipt =
            OwnershipTransactionReceiptV1::from_canonical_bytes(lease.canonical_receipt())
                .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
        receipt
            .verify_context(&self.ownership_authority, claim, lease.canonical_lease())
            .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
        let bytes = encode_bound_draft(&self, &lease)?;
        if bytes.len() > MAXIMUM_PUBLICATION_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
        let digest = publication_digest(&bytes);
        let prepared = PreparedAuthorityPublicationV1 {
            sandbox: self.manifest.manifest().sandbox(),
            incarnation: *self.manifest.manifest().incarnation().as_bytes(),
            epoch: self.manifest.manifest().epoch().get(),
            desired_generation: self.manifest.manifest().desired_generation().get(),
            assignment_digest: self.manifest.digest(),
            node: *self.manifest.manifest().node().as_bytes(),
            lease_generation: lease.generation(),
            lease_digest: lease.digest(),
            receipt_authority: receipt.authority().clone(),
            receipt_action: receipt.action(),
            receipt_request_id: *receipt.request_id(),
            receipt_claim_digest: receipt.claim_digest(),
            source_draft_digest: self.digest,
            digest,
            bytes,
        };
        validate_encoded_publication(
            &prepared.bytes,
            prepared.sandbox,
            prepared.incarnation,
            prepared.epoch,
            prepared.desired_generation,
            prepared.assignment_digest,
            prepared.node,
            prepared.lease_generation,
            prepared.lease_digest,
        )
        .map_err(|_| AuthorityPublicationError::InvalidDraft)?;
        Ok(prepared)
    }
}

/// Owns uncommitted authority inputs for one assignment generation.
#[derive(Clone, Debug)]
pub struct AuthorityPublicationProposalV1 {
    manifest: CanonicalAssignmentManifestV1,
    lease: SignedOwnershipLease,
    required_audiences: Vec<BrokerAudience>,
    templates: Vec<BrokerDispatchTemplateV1>,
}

impl AuthorityPublicationProposalV1 {
    /// Constructs one non-durable publication proposal.
    #[must_use]
    pub fn new(
        manifest: CanonicalAssignmentManifestV1,
        lease: SignedOwnershipLease,
        required_audiences: Vec<BrokerAudience>,
        templates: Vec<BrokerDispatchTemplateV1>,
    ) -> Self {
        Self {
            manifest,
            lease,
            required_audiences,
            templates,
        }
    }

    /// Validates completeness and freezes exact durable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] unless audiences are canonical and
    /// complete, every plan/lease shares the manifest assignment, node, and
    /// ownership signer, and the encoded bundle fits its fixed bound.
    pub fn prepare(self) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
        validate_proposal(&self)?;
        validate_encoded_size(&self)?;
        let bytes = encode_proposal(&self)?;
        if bytes.len() > MAXIMUM_PUBLICATION_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
        let digest = publication_digest(&bytes);
        let receipt =
            OwnershipTransactionReceiptV1::from_canonical_bytes(self.lease.canonical_receipt())
                .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
        Ok(PreparedAuthorityPublicationV1 {
            sandbox: self.manifest.manifest().sandbox(),
            incarnation: *self.manifest.manifest().incarnation().as_bytes(),
            epoch: self.manifest.manifest().epoch().get(),
            desired_generation: self.manifest.manifest().desired_generation().get(),
            assignment_digest: self.manifest.digest(),
            node: *self.manifest.manifest().node().as_bytes(),
            lease_generation: self.lease.generation(),
            lease_digest: self.lease.digest(),
            receipt_authority: receipt.authority().clone(),
            receipt_action: receipt.action(),
            receipt_request_id: *receipt.request_id(),
            receipt_claim_digest: receipt.claim_digest(),
            source_draft_digest: draft_digest(&encode_draft(
                &self.manifest,
                &self.required_audiences,
                &self.templates,
            )?),
            digest,
            bytes,
        })
    }
}

/// Carries one complete validated bundle before its atomic journal commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorityPublicationV1 {
    sandbox: SandboxId,
    incarnation: [u8; 16],
    epoch: u64,
    desired_generation: u64,
    assignment_digest: ObjectDigest,
    node: [u8; 16],
    lease_generation: u64,
    lease_digest: ObjectDigest,
    receipt_authority: aos_sandbox_core::model::KeyReference,
    receipt_action: OwnershipClaimAction,
    receipt_request_id: [u8; 16],
    receipt_claim_digest: ObjectDigest,
    source_draft_digest: ObjectDigest,
    digest: ObjectDigest,
    bytes: Vec<u8>,
}

/// Carries one validated publication mutation into atomic gate activation.
///
/// The fields and constructor remain crate-private so reconciliation cannot
/// compose arbitrary desired-state mutations or activation facts.
pub(crate) struct AuthorityPublicationActivationV1 {
    records: [JournalRecord; 2],
    sandbox: SandboxId,
    assignment_digest: ObjectDigest,
    source_draft_digest: ObjectDigest,
    ownership_authority: aos_sandbox_core::model::KeyReference,
    publication_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    receipt_action: OwnershipClaimAction,
    receipt_request_id: [u8; 16],
    receipt_claim_digest: ObjectDigest,
    prepared: PreparedAuthorityPublicationV1,
}

pub(crate) struct AuthorityPublicationActivationPartsV1 {
    pub(crate) records: [JournalRecord; 2],
    pub(crate) sandbox: SandboxId,
    pub(crate) assignment_digest: ObjectDigest,
    pub(crate) source_draft_digest: ObjectDigest,
    pub(crate) ownership_authority: aos_sandbox_core::model::KeyReference,
    pub(crate) publication_digest: ObjectDigest,
    pub(crate) lease_generation: u64,
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) receipt_action: OwnershipClaimAction,
    pub(crate) receipt_request_id: [u8; 16],
    pub(crate) receipt_claim_digest: ObjectDigest,
    pub(crate) prepared: PreparedAuthorityPublicationV1,
}

impl AuthorityPublicationActivationV1 {
    pub(crate) fn into_parts(self) -> AuthorityPublicationActivationPartsV1 {
        AuthorityPublicationActivationPartsV1 {
            records: self.records,
            sandbox: self.sandbox,
            assignment_digest: self.assignment_digest,
            source_draft_digest: self.source_draft_digest,
            ownership_authority: self.ownership_authority,
            publication_digest: self.publication_digest,
            lease_generation: self.lease_generation,
            lease_digest: self.lease_digest,
            receipt_action: self.receipt_action,
            receipt_request_id: self.receipt_request_id,
            receipt_claim_digest: self.receipt_claim_digest,
            prepared: self.prepared,
        }
    }
}

impl PreparedAuthorityPublicationV1 {
    /// Returns the content digest of the complete frozen publication.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the bound ownership-lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the descriptor digest of the bound ownership lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns exact durable publication bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Replays one structurally validated atomically current publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAuthorityPublicationV1 {
    prepared: PreparedAuthorityPublicationV1,
    lease: RecoveredOwnershipLeaseV1,
    templates: Vec<RecoveredBrokerDispatchTemplateV1>,
}

impl CurrentAuthorityPublicationV1 {
    /// Returns the complete publication digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.prepared.digest
    }

    /// Returns exact bytes committed during preparation.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.prepared.bytes
    }

    /// Returns the current lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.prepared.lease_generation
    }

    /// Returns the current exact lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.prepared.lease_digest
    }

    /// Returns the exact structurally recovered ownership lease.
    ///
    /// Recovery preserves the signed bytes but does not re-establish
    /// cryptographic trust; every privileged broker must verify them.
    #[must_use]
    pub const fn lease(&self) -> &RecoveredOwnershipLeaseV1 {
        &self.lease
    }

    /// Returns every immutable current dispatch template in publication order.
    #[must_use]
    pub fn templates(&self) -> &[RecoveredBrokerDispatchTemplateV1] {
        &self.templates
    }
}

/// Retains one exact ownership lease recovered from the current publication.
///
/// This type proves canonical structure and publication cross-links, not
/// signature authenticity. It therefore cannot authorize a privileged effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredOwnershipLeaseV1 {
    lease: OwnershipLease,
    canonical_lease: Vec<u8>,
    canonical_signature: Vec<u8>,
    canonical_receipt: Vec<u8>,
    canonical_receipt_signature: Vec<u8>,
    digest: ObjectDigest,
}

impl RecoveredOwnershipLeaseV1 {
    /// Returns the decoded immutable lease semantics.
    #[must_use]
    pub const fn lease(&self) -> &OwnershipLease {
        &self.lease
    }

    /// Returns the exact canonical lease bytes.
    #[must_use]
    pub fn canonical_lease(&self) -> &[u8] {
        &self.canonical_lease
    }

    /// Returns the exact canonical detached-signature bytes.
    #[must_use]
    pub fn canonical_signature(&self) -> &[u8] {
        &self.canonical_signature
    }

    /// Returns the exact canonical ownership-transaction receipt bytes.
    #[must_use]
    pub fn canonical_receipt(&self) -> &[u8] {
        &self.canonical_receipt
    }

    /// Returns the exact canonical detached receipt-signature bytes.
    #[must_use]
    pub fn canonical_receipt_signature(&self) -> &[u8] {
        &self.canonical_receipt_signature
    }

    /// Returns the descriptor digest of the exact canonical lease bytes.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Retains one exact non-authorizing dispatch template recovered as current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredBrokerDispatchTemplateV1 {
    digest: ObjectDigest,
    audience: BrokerAudience,
    plan: BrokerAuthorizationPlan,
    canonical_plan: Vec<u8>,
    canonical_plan_signature: Vec<u8>,
    method: BrokerMethod,
    body_without_deadline: Vec<u8>,
    descriptor_roles: Vec<BrokerDescriptorRole>,
    semantics: BrokerDispatchSemanticIdentityV1,
}

impl RecoveredBrokerDispatchTemplateV1 {
    /// Returns the exact immutable template digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the sole broker audience named by the recovered plan.
    #[must_use]
    pub const fn audience(&self) -> BrokerAudience {
        self.audience
    }

    /// Returns the decoded immutable broker plan.
    #[must_use]
    pub const fn plan(&self) -> &BrokerAuthorizationPlan {
        &self.plan
    }

    /// Returns the exact canonical broker-plan bytes.
    #[must_use]
    pub fn canonical_plan(&self) -> &[u8] {
        &self.canonical_plan
    }

    /// Returns the exact canonical broker-plan signature bytes.
    #[must_use]
    pub fn canonical_plan_signature(&self) -> &[u8] {
        &self.canonical_plan_signature
    }

    /// Returns the closed local broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact deadline-free protobuf body.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.body_without_deadline
    }

    /// Returns exact ancillary descriptor roles in transport order.
    #[must_use]
    pub fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        &self.descriptor_roles
    }

    /// Returns the structurally cross-linked portable request semantics.
    #[must_use]
    pub const fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.semantics
    }
}

#[derive(Debug)]
struct RecoveredPublicationArtifactsV1 {
    lease: RecoveredOwnershipLeaseV1,
    templates: Vec<RecoveredBrokerDispatchTemplateV1>,
}

/// Reports whether atomic publication committed or replayed a prior decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityPublicationOutcome {
    /// A complete new publication became current.
    Published(OperationId),
    /// The exact idempotent request was already durably accepted.
    Replay(OperationId),
}

/// Publishes and replays authority bundles through an existing journal.
pub struct AuthorityPublicationStore<'a> {
    journal: &'a mut Journal,
}

impl<'a> AuthorityPublicationStore<'a> {
    /// Borrows the sole journal writer used for publication.
    #[must_use]
    pub const fn new(journal: &'a mut Journal) -> Self {
        Self { journal }
    }

    /// Atomically installs a prepared bundle as current.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] for idempotency conflict, stale or
    /// equivocating assignment/lease generations, corrupt prior state, invalid
    /// transaction identity, or journal durability failure.
    pub fn publish(
        &mut self,
        prepared: &PreparedAuthorityPublicationV1,
        idempotency_key: &IdempotencyKey,
        operation_id: OperationId,
        transaction_id: [u8; 16],
    ) -> Result<AuthorityPublicationOutcome, AuthorityPublicationError> {
        if let Some(existing) = self.journal.get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(prepared.digest),
        ) && existing != prepared.bytes
        {
            return Err(AuthorityPublicationError::PreparedConflict);
        }
        self.validate_namespace()?;
        let request_digest = *prepared.digest.as_bytes();
        match self
            .journal
            .check_idempotency(idempotency_key, request_digest)
        {
            IdempotencyOutcome::Replay(operation) => {
                let recovered = self
                    .prepared(prepared.digest)?
                    .ok_or(AuthorityPublicationError::CorruptCurrent)?;
                if &recovered != prepared {
                    return Err(AuthorityPublicationError::CorruptCurrent);
                }
                return Ok(AuthorityPublicationOutcome::Replay(operation));
            }
            IdempotencyOutcome::Conflict => {
                return Err(AuthorityPublicationError::IdempotencyConflict);
            }
            IdempotencyOutcome::Vacant => {}
        }

        if let Some(current) = self.current(prepared.sandbox)? {
            validate_successor(&current.prepared, prepared)?;
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest),
                    prepared.bytes.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    current_key(prepared.sandbox),
                    encode_current(prepared),
                ),
                JournalRecord::idempotency(idempotency_key, request_digest, operation_id),
            ],
        )?;
        self.journal.commit(&transaction)?;
        Ok(AuthorityPublicationOutcome::Published(operation_id))
    }

    /// Validates and freezes the two publication records for gate activation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] for legacy state, malformed or
    /// substituted prepared bytes, a conflicting prepared-key value, or
    /// corrupt current state. Final successor eligibility is deliberately
    /// rechecked against the live journal immediately before gate activation.
    #[allow(dead_code)]
    pub(crate) fn prepare_gate_activation(
        &self,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<AuthorityPublicationActivationV1, AuthorityPublicationError> {
        if let Some(existing) = self.journal.get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(prepared.digest),
        ) && existing != prepared.bytes
        {
            return Err(AuthorityPublicationError::PreparedConflict);
        }
        self.validate_namespace()?;
        let decoded = decode_prepared(&prepared.bytes, prepared.digest)?;
        if &decoded != prepared || prepared.source_draft_digest != draft.digest {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        Ok(AuthorityPublicationActivationV1 {
            records: [
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest),
                    prepared.bytes.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    current_key(prepared.sandbox),
                    encode_current(prepared),
                ),
            ],
            sandbox: prepared.sandbox,
            assignment_digest: prepared.assignment_digest,
            source_draft_digest: prepared.source_draft_digest,
            ownership_authority: draft.ownership_authority.clone(),
            publication_digest: prepared.digest,
            lease_generation: prepared.lease_generation,
            lease_digest: prepared.lease_digest,
            receipt_action: prepared.receipt_action,
            receipt_request_id: prepared.receipt_request_id,
            receipt_claim_digest: prepared.receipt_claim_digest,
            prepared: prepared.clone(),
        })
    }

    /// Loads and structurally validates a publication by permanent digest.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError::CorruptCurrent`] when the stored
    /// value is not the exact self-contained V3 publication named by `digest`,
    /// or [`AuthorityPublicationError::MigrationRequired`] for legacy state.
    pub fn prepared(
        &self,
        digest: ObjectDigest,
    ) -> Result<Option<PreparedAuthorityPublicationV1>, AuthorityPublicationError> {
        self.validate_namespace()?;
        self.journal
            .get(RecordNamespace::AuthorityPublication, &prepared_key(digest))
            .map(|bytes| decode_prepared(bytes, digest))
            .transpose()
    }

    pub(crate) fn validate_gate_successor(
        &self,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<(), AuthorityPublicationError> {
        self.validate_namespace()?;
        if let Some(current) = self.current(prepared.sandbox)? {
            validate_successor(&current.prepared, prepared)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_durable_gate_publication(
    journal: &Journal,
    publication_digest: ObjectDigest,
    draft: &AuthorityPublicationDraftV1,
    claim: &OwnershipClaimV1,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), AuthorityPublicationError> {
    let prepared = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(publication_digest),
        )
        .map(|bytes| decode_prepared(bytes, publication_digest))
        .transpose()?
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    let manifest = draft.manifest();
    let semantics = manifest.manifest();
    let assignment = claim.assignment();
    if prepared.sandbox != assignment.sandbox()
        || prepared.incarnation != *assignment.incarnation().as_bytes()
        || prepared.epoch != assignment.epoch().get()
        || prepared.desired_generation != claim.desired_generation().get()
        || prepared.assignment_digest != assignment.digest()
        || prepared.node != *claim.node().as_bytes()
        || prepared.source_draft_digest != draft.digest()
        || prepared.lease_generation != lease_generation
        || prepared.lease_digest != lease_digest
        || &prepared.receipt_authority != draft.ownership_authority()
        || prepared.receipt_action != claim.action()
        || prepared.receipt_request_id != *claim.request_id()
        || prepared.receipt_claim_digest != claim.digest()
        || semantics.sandbox() != assignment.sandbox()
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let current = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &current_key(assignment.sandbox()),
        )
        .map(decode_current)
        .transpose()?
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    validate_successor(&prepared, &current.prepared)
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    Ok(())
}

pub(crate) fn validate_publication_namespace(
    journal: &Journal,
) -> Result<(), AuthorityPublicationError> {
    if journal
        .records(RecordNamespace::DesiredState)
        .any(|(key, _)| {
            key.starts_with(LEGACY_CURRENT_KEY_PREFIX)
                || key.starts_with(LEGACY_PREPARED_KEY_PREFIX)
                || key.starts_with(LEGACY_V2_CURRENT_KEY_PREFIX)
                || key.starts_with(LEGACY_V2_PREPARED_KEY_PREFIX)
        })
    {
        return Err(AuthorityPublicationError::MigrationRequired);
    }
    for (key, value) in journal.records(RecordNamespace::AuthorityPublication) {
        if value.starts_with(LEGACY_V1_MAGIC) || value.starts_with(LEGACY_V2_MAGIC) {
            return Err(AuthorityPublicationError::MigrationRequired);
        }
        if let Some(suffix) = key.strip_prefix(CURRENT_KEY_PREFIX) {
            let sandbox_bytes: [u8; 16] = suffix
                .try_into()
                .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
            let sandbox = SandboxId::from_bytes(sandbox_bytes);
            let current = decode_current(value)?;
            if current.prepared.sandbox != sandbox {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
            let permanent = journal
                .get(
                    RecordNamespace::AuthorityPublication,
                    &prepared_key(current.digest()),
                )
                .map(|bytes| decode_prepared(bytes, current.digest()))
                .transpose()?
                .ok_or(AuthorityPublicationError::CorruptCurrent)?;
            if permanent != current.prepared {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
        } else if let Some(suffix) = key.strip_prefix(PREPARED_KEY_PREFIX) {
            let digest_bytes: [u8; 32] = suffix
                .try_into()
                .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
            decode_prepared(value, ObjectDigest::from_bytes(digest_bytes))?;
        } else {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
    }
    Ok(())
}

impl<'a> AuthorityPublicationStore<'a> {
    /// Loads and structurally validates the current bundle for one sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError::CorruptCurrent`] when durable state
    /// is not the exact bounded, cross-linked format emitted by preparation.
    /// Returns [`AuthorityPublicationError::MigrationRequired`] when any V1 or
    /// V2 current or prepared namespace remains in the journal.
    /// This does not cryptographically reverify signatures because the journal
    /// deliberately has no trust-anchor or public-key dependency.
    pub fn current(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError> {
        self.validate_namespace()?;
        let current = self
            .journal
            .get(RecordNamespace::AuthorityPublication, &current_key(sandbox))
            .map(decode_current)
            .transpose()?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.prepared.sandbox != sandbox {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let prepared = self
            .prepared(current.digest())?
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        if prepared != current.prepared {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        Ok(Some(current))
    }

    fn validate_namespace(&self) -> Result<(), AuthorityPublicationError> {
        validate_publication_namespace(self.journal)
    }

    /// Selects one exact current template and attenuates it to a fresh attempt.
    ///
    /// `expected_publication` prevents work compiled against an older bundle
    /// from dispatching after renewal or replacement. Callers supply only
    /// immutable identities and fresh clock/deadline facts, never alternate
    /// authority or request bytes. The result remains non-authorizing broker
    /// input and requires complete protected verification on receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] when current state is absent,
    /// stale, corrupt, lacks the template, assigns it to another audience, or
    /// rejects fresh deadline attenuation.
    #[allow(clippy::too_many_arguments)]
    pub fn select_current_attempt(
        &self,
        sandbox: SandboxId,
        expected_publication: ObjectDigest,
        audience: BrokerAudience,
        template_digest: ObjectDigest,
        deadline_boottime_nanoseconds: u64,
        clock: RawPairedClockSample,
    ) -> Result<BrokerDispatchAttemptV1, AuthorityPublicationError> {
        let current = self
            .current(sandbox)?
            .ok_or(AuthorityPublicationError::CurrentAbsent)?;
        if current.digest() != expected_publication {
            return Err(AuthorityPublicationError::StaleCurrent);
        }
        let template = current
            .templates
            .iter()
            .find(|candidate| candidate.digest == template_digest)
            .ok_or(AuthorityPublicationError::TemplateAbsent)?;
        if template.audience != audience {
            return Err(AuthorityPublicationError::WrongAudience);
        }
        BrokerDispatchAttemptV1::from_recovered_current(
            template,
            &current.lease,
            deadline_boottime_nanoseconds,
            clock,
        )
        .map_err(AuthorityPublicationError::DispatchAttempt)
    }
}

/// Reports rejected proposal, ordering, replay, or durability state.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityPublicationError {
    /// A lease-independent draft is malformed, non-canonical, or substituted.
    #[error("authority publication draft is invalid")]
    InvalidDraft,
    /// Required audiences or templates are empty, unsorted, duplicated, or incomplete.
    #[error("authority publication audience set is invalid or incomplete")]
    IncompleteAudienceSet,
    /// Manifest, lease, plan, node, or ownership signer differs.
    #[error("authority publication contains substituted assignment authority")]
    ContextMismatch,
    /// A permanent digest key is already bound to different bytes.
    #[error("authority publication prepared key conflicts with existing bytes")]
    PreparedConflict,
    /// The complete encoded publication cannot fit its bounded journal records.
    #[error("authority publication exceeds the fixed V3 journal-record bound")]
    PublicationTooLarge,
    /// A generation would roll back.
    #[error("authority publication generation rollback")]
    GenerationRollback,
    /// An equal generation carries different immutable identity.
    #[error("authority publication generation equivocation")]
    GenerationEquivocation,
    /// A durable current record is malformed or internally inconsistent.
    #[error("durable authority publication is corrupt")]
    CorruptCurrent,
    /// Durable publication V1 or V2 state requires an explicit migration.
    #[error("durable authority publication V1 or V2 state requires migration")]
    MigrationRequired,
    /// An idempotency key was previously bound to another publication.
    #[error("authority publication idempotency conflict")]
    IdempotencyConflict,
    /// Journal validation or durability failed.
    #[error("authority publication journal failed: {0}")]
    Journal(#[from] JournalError),
    /// No complete current publication exists for the sandbox.
    #[error("sandbox has no complete current authority publication")]
    CurrentAbsent,
    /// The current publication changed after the caller compiled its work.
    #[error("authority publication is no longer current")]
    StaleCurrent,
    /// The requested template digest is not in the current publication.
    #[error("dispatch template is absent from the current publication")]
    TemplateAbsent,
    /// The selected current template belongs to another broker audience.
    #[error("dispatch template does not belong to the requested broker audience")]
    WrongAudience,
    /// Fresh lease and deadline attenuation rejected the current template.
    #[error("current dispatch attempt is invalid: {0}")]
    DispatchAttempt(#[from] BrokerDispatchAttemptError),
}

fn validate_successor(
    current: &PreparedAuthorityPublicationV1,
    next: &PreparedAuthorityPublicationV1,
) -> Result<(), AuthorityPublicationError> {
    if next.sandbox != current.sandbox || next.receipt_authority != current.receipt_authority {
        return Err(AuthorityPublicationError::ContextMismatch);
    }
    if next.epoch < current.epoch
        || (next.epoch == current.epoch && next.desired_generation < current.desired_generation)
        || next.lease_generation < current.lease_generation
    {
        return Err(AuthorityPublicationError::GenerationRollback);
    }
    if (next.epoch == current.epoch
        && next.desired_generation == current.desired_generation
        && (next.assignment_digest != current.assignment_digest
            || next.source_draft_digest != current.source_draft_digest))
        || (next.lease_generation == current.lease_generation
            && next.lease_digest != current.lease_digest)
        || (next.epoch == current.epoch
            && next.desired_generation == current.desired_generation
            && next.lease_generation == current.lease_generation
            && next.digest != current.digest)
    {
        return Err(AuthorityPublicationError::GenerationEquivocation);
    }
    Ok(())
}

fn publication_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn durable_template_digest(
    plan_digest: ObjectDigest,
    plan_signature: &[u8],
    method: i32,
    body: &[u8],
    roles: &[i32],
    verb: u32,
    target: &[u8],
    commitment: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TEMPLATE_DIGEST_DOMAIN);
    digest.update(plan_digest.as_bytes());
    digest.update(
        u64::try_from(plan_signature.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(plan_signature);
    digest.update(method.to_be_bytes());
    digest.update(verb.to_be_bytes());
    digest.update(target);
    digest.update(commitment.as_bytes());
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    digest.update(u16::try_from(roles.len()).unwrap_or(u16::MAX).to_be_bytes());
    for role in roles {
        digest.update(role.to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn current_key(sandbox: SandboxId) -> Vec<u8> {
    [CURRENT_KEY_PREFIX, sandbox.as_bytes()].concat()
}

fn prepared_key(digest: ObjectDigest) -> Vec<u8> {
    [PREPARED_KEY_PREFIX, digest.as_bytes()].concat()
}

fn strictly_increasing(values: &[BrokerAudience]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

const fn audience_code(audience: BrokerAudience) -> u8 {
    match audience {
        BrokerAudience::Host => 1,
        BrokerAudience::Mount => 2,
        BrokerAudience::Storage => 3,
        BrokerAudience::Network => 4,
    }
}

fn audience_from_code(code: u8) -> Result<BrokerAudience, AuthorityPublicationError> {
    match code {
        1 => Ok(BrokerAudience::Host),
        2 => Ok(BrokerAudience::Mount),
        3 => Ok(BrokerAudience::Storage),
        4 => Ok(BrokerAudience::Network),
        _ => Err(AuthorityPublicationError::CorruptCurrent),
    }
}

fn broker_method_from_code(code: i32) -> Result<BrokerMethod, AuthorityPublicationError> {
    match code {
        1 => Ok(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
        4 => Ok(BrokerMethod::BROKER_METHOD_MOUNT_APPLY),
        7 => Ok(BrokerMethod::BROKER_METHOD_STORAGE_APPLY),
        9 => Ok(BrokerMethod::BROKER_METHOD_NETWORK_APPLY),
        _ => Err(AuthorityPublicationError::CorruptCurrent),
    }
}

fn broker_descriptor_role_from_code(
    code: i32,
) -> Result<BrokerDescriptorRole, AuthorityPublicationError> {
    match code {
        1 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE),
        2 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT),
        3 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE),
        4 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_DETACHED_MOUNT),
        5 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER),
        6 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE),
        7 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT),
        _ => Err(AuthorityPublicationError::CorruptCurrent),
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), AuthorityPublicationError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| AuthorityPublicationError::PublicationTooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthorityPublicationError> {
    put_u32(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], AuthorityPublicationError> {
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], AuthorityPublicationError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<usize, AuthorityPublicationError> {
    usize::try_from(u32::from_be_bytes(take_array(bytes, cursor)?))
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], AuthorityPublicationError> {
    let length = take_u32(bytes, cursor)?;
    take(bytes, cursor, length)
}

#[cfg(test)]
#[path = "publication/tests.rs"]
pub(crate) mod tests;
