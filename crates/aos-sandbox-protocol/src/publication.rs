//! Owns inert complete controller publication history DATA.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, BrokerMethod};
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature, encode_signature,
};
use aos_sandbox_core::model::{SignaturePurpose, KeyReference};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerVerb, CanonicalAssignmentManifestV1,
    DecodeLimits, ObjectDigest, OperationId, OwnershipLease, ProtocolVersion, RawPairedClockSample,
    SandboxId, descriptor_for_bytes,
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_ownership_protocol::{OwnershipClaimAction, OwnershipClaimV1, OwnershipTransactionReceiptV1, SignedOwnershipLease};
use crate::authorization_artifact::SignedBrokerPlan;
use crate::dispatch_template::{BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1};

mod draft;
mod format;
pub use format::{decode_current, decode_prepared, decode_prepared_with_artifacts, encode_current};
use format::validate_encoded_publication;
use draft::{decode_draft, draft_digest, encode_bound_draft, encode_draft, encode_proposal, encode_recovered_draft, encode_target, validate_draft, validate_encoded_size, validate_proposal};

const MAGIC: &[u8; 8] = b"AOSCPUB1";
const VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-publication.v1\0";
const MAXIMUM_TEMPLATES: usize = 256;
const JOURNAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
const CURRENT_HEADER_BYTES: usize = 186;
pub const CURRENT_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.current.v1/";
pub const PREPARED_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.prepared.v1/";
const DRAFT_MAGIC: &[u8; 8] = b"AOSCDRF1";
const DRAFT_VERSION: u16 = 1;
const DRAFT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-authority-draft.v1\0";
const MAXIMUM_PUBLICATION_DRAFT_BYTES: usize = 16 * 1024 * 1024;
/// Bounds complete publications by the existing journal record overhead.
pub const MAXIMUM_PUBLICATION_BYTES: usize = JOURNAL_RECORD_BYTES
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
    /// Returns [`PublicationHistoryError`] unless audiences are canonical
    /// and complete, one to 256 checked templates are canonically ordered,
    /// templates sharing an audience carry one exact plan and signature, every
    /// plan matches the manifest assignment/node/desired generation and one
    /// exact ownership authority, and the canonical encoding is bounded.
    pub fn new(
        manifest: CanonicalAssignmentManifestV1,
        required_audiences: Vec<BrokerAudience>,
        templates: Vec<BrokerDispatchTemplateV1>,
    ) -> Result<Self, PublicationHistoryError> {
        validate_draft(&manifest, &required_audiences, &templates)?;
        let bytes = encode_draft(&manifest, &required_audiences, &templates)?;
        if bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES {
            return Err(PublicationHistoryError::PublicationTooLarge);
        }
        decode_draft(&bytes).map_err(|_| PublicationHistoryError::InvalidDraft)
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
    /// Returns [`PublicationHistoryError::InvalidDraft`] for invalid framing,
    /// bounds, manifest, audience codes, trailing or non-canonical bytes, or
    /// any inconsistent signed-plan or template cross-link.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PublicationHistoryError> {
        if bytes.len() < 18
            || bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES
            || &bytes[..8] != DRAFT_MAGIC
            || bytes[8..10] != DRAFT_VERSION.to_be_bytes()
        {
            return Err(PublicationHistoryError::InvalidDraft);
        }
        decode_draft(bytes).map_err(|_| PublicationHistoryError::InvalidDraft)
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


    /// Binds checked ownership artifacts and prepares the current V1 publication.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationHistoryError`] if the lease does not match the
    /// manifest and common authority or complete publication validation fails.
    pub fn bind_lease(
        self,
        claim: &OwnershipClaimV1,
        lease: SignedOwnershipLease,
    ) -> Result<PublicationHistoryV1, PublicationHistoryError> {
        let assignment = self
            .manifest
            .broker_assignment()
            .map_err(|_| PublicationHistoryError::ContextMismatch)?;
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
            return Err(PublicationHistoryError::ContextMismatch);
        }
        let receipt =
            OwnershipTransactionReceiptV1::from_canonical_bytes(lease.canonical_receipt())
                .map_err(|_| PublicationHistoryError::ContextMismatch)?;
        receipt
            .verify_context(&self.ownership_authority, claim, lease.canonical_lease())
            .map_err(|_| PublicationHistoryError::ContextMismatch)?;
        let bytes = encode_bound_draft(&self, &lease)?;
        if bytes.len() > MAXIMUM_PUBLICATION_BYTES {
            return Err(PublicationHistoryError::PublicationTooLarge);
        }
        let digest = publication_digest(&bytes);
        let prepared = PublicationHistoryV1 {
            manifest: self.manifest.clone(),
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
        .map_err(|_| PublicationHistoryError::InvalidDraft)?;
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
    /// Returns [`PublicationHistoryError`] unless audiences are canonical and
    /// complete, every plan/lease shares the manifest assignment, node, and
    /// ownership signer, and the encoded bundle fits its fixed bound.
    pub fn prepare(self) -> Result<PublicationHistoryV1, PublicationHistoryError> {
        validate_proposal(&self)?;
        validate_encoded_size(&self)?;
        let bytes = encode_proposal(&self)?;
        if bytes.len() > MAXIMUM_PUBLICATION_BYTES {
            return Err(PublicationHistoryError::PublicationTooLarge);
        }
        let digest = publication_digest(&bytes);
        let receipt =
            OwnershipTransactionReceiptV1::from_canonical_bytes(self.lease.canonical_receipt())
                .map_err(|_| PublicationHistoryError::ContextMismatch)?;
        Ok(PublicationHistoryV1 {
            manifest: self.manifest.clone(),
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
pub struct PublicationHistoryV1 {
    manifest: CanonicalAssignmentManifestV1,
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
pub struct RecoveredPublicationArtifactsV1 {
    manifest: CanonicalAssignmentManifestV1,
    lease: RecoveredOwnershipLeaseV1,
    templates: Vec<RecoveredBrokerDispatchTemplateV1>,
}


/// Checks archived publication bytes without constructing current authority.
///
/// # Errors
///
/// Rejects a malformed/mismatched historical publication or an optional exact
/// lease quartet that differs from its canonical retained publication bytes.
pub fn validate_historical_output_publication_v1(
    bytes: &[u8],
    expected_digest: ObjectDigest,
    expected_lease: Option<(&[u8], &[u8])>,
) -> Result<(), PublicationHistoryError> {
    let decoded = decode_historical_output_publication_v1(bytes, expected_digest)?;

    if let Some((lease, signature)) = expected_lease {
        decoded.require_expected_lease(lease, signature)?;
    }

    Ok(())
}

///
/// This structural readback authenticates no signature or current owner. The
/// complete decode precedes any later supported-carrier classification.
///
/// # Errors
///
/// Preserves the decoder's bounds, digest, canonical and cross-link errors.
pub fn decode_historical_output_publication_v1(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<RecoveredOwnershipLeaseV1, PublicationHistoryError> {
    let (_, artifacts) = format::decode_prepared_with_artifacts(bytes, expected_digest)?;

    Ok(artifacts.lease)
}

fn publication_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub fn current_key(sandbox: SandboxId) -> Vec<u8> {
    [CURRENT_KEY_PREFIX, sandbox.as_bytes()].concat()
}

pub fn prepared_key(digest: ObjectDigest) -> Vec<u8> {
    [PREPARED_KEY_PREFIX, digest.as_bytes()].concat()
}

fn strictly_increasing(values: &[BrokerAudience]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

const fn audience_code(audience: BrokerAudience) -> Result<u8, PublicationHistoryError> {
    match audience {
        BrokerAudience::Host => Ok(1),
        BrokerAudience::Mount => Ok(2),
        BrokerAudience::Storage => Ok(3),
        BrokerAudience::Network => Ok(4),
        BrokerAudience::Guardian => Err(PublicationHistoryError::UnsupportedBrokerAudience),
        BrokerAudience::Nix => Err(PublicationHistoryError::UnsupportedBrokerAudience),
    }
}

fn audience_from_code(code: u8) -> Result<BrokerAudience, PublicationHistoryError> {
    match code {
        1 => Ok(BrokerAudience::Host),
        2 => Ok(BrokerAudience::Mount),
        3 => Ok(BrokerAudience::Storage),
        4 => Ok(BrokerAudience::Network),
        _ => Err(PublicationHistoryError::CorruptCurrent),
    }
}

fn broker_method_from_code(code: i32) -> Result<BrokerMethod, PublicationHistoryError> {
    match code {
        1 => Ok(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
        4 => Ok(BrokerMethod::BROKER_METHOD_MOUNT_APPLY),
        7 => Ok(BrokerMethod::BROKER_METHOD_STORAGE_APPLY),
        25 => Ok(BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT),
        9 => Ok(BrokerMethod::BROKER_METHOD_NETWORK_APPLY),
        _ => Err(PublicationHistoryError::CorruptCurrent),
    }
}

fn broker_descriptor_role_from_code(
    code: i32,
) -> Result<BrokerDescriptorRole, PublicationHistoryError> {
    match code {
        1 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE),
        2 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT),
        3 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE),
        4 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_DETACHED_MOUNT),
        5 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER),
        6 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE),
        7 => Ok(BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT),
        _ => Err(PublicationHistoryError::CorruptCurrent),
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), PublicationHistoryError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| PublicationHistoryError::PublicationTooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), PublicationHistoryError> {
    put_u32(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], PublicationHistoryError> {
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(PublicationHistoryError::CorruptCurrent)?;
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], PublicationHistoryError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| PublicationHistoryError::CorruptCurrent)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<usize, PublicationHistoryError> {
    usize::try_from(u32::from_be_bytes(take_array(bytes, cursor)?))
        .map_err(|_| PublicationHistoryError::CorruptCurrent)
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], PublicationHistoryError> {
    let length = take_u32(bytes, cursor)?;
    take(bytes, cursor, length)
}


impl PublicationHistoryV1 {
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }

    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    pub const fn node(&self) -> &[u8; 16] {
        &self.node
    }

    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    pub const fn receipt_authority(&self) -> &KeyReference {
        &self.receipt_authority
    }

    pub const fn receipt_action(&self) -> OwnershipClaimAction {
        self.receipt_action
    }

    pub const fn receipt_request_id(&self) -> &[u8; 16] {
        &self.receipt_request_id
    }

    pub const fn receipt_claim_digest(&self) -> ObjectDigest {
        self.receipt_claim_digest
    }

    pub const fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn require_successor(&self, next: &Self) -> Result<(), PublicationHistoryError> {
        if next.sandbox != self.sandbox || next.receipt_authority != self.receipt_authority {
            return Err(PublicationHistoryError::ContextMismatch);
        }
        if next.epoch < self.epoch
            || (next.epoch == self.epoch && next.desired_generation < self.desired_generation)
            || next.lease_generation < self.lease_generation
        {
            return Err(PublicationHistoryError::GenerationRollback);
        }
        if (next.epoch == self.epoch
            && next.desired_generation == self.desired_generation
            && (next.assignment_digest != self.assignment_digest
                || next.source_draft_digest != self.source_draft_digest))
            || (next.lease_generation == self.lease_generation
                && next.lease_digest != self.lease_digest)
            || (next.epoch == self.epoch
                && next.desired_generation == self.desired_generation
                && next.lease_generation == self.lease_generation
                && next.digest != self.digest)
        {
            return Err(PublicationHistoryError::GenerationEquivocation);
        }
        Ok(())
    }
}

impl RecoveredOwnershipLeaseV1 {
    /// Checks the exact lease preimages without decoding the publication again.
    ///
    /// # Errors
    ///
    /// Returns corruption when either expected canonical preimage differs.
    pub fn require_expected_lease(
        &self,
        lease: &[u8],
        signature: &[u8],
    ) -> Result<(), PublicationHistoryError> {
        if self.canonical_lease() != lease
            || self.canonical_signature() != signature
        {
            return Err(PublicationHistoryError::CorruptCurrent);
        }

        Ok(())
    }
}

impl RecoveredPublicationArtifactsV1 {
    pub fn templates(&self) -> &[RecoveredBrokerDispatchTemplateV1] {
        &self.templates
    }

    pub const fn lease(&self) -> &RecoveredOwnershipLeaseV1 {
        &self.lease
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedPublicationCurrentV1 {
    history: PublicationHistoryV1,
    lease: RecoveredOwnershipLeaseV1,
    templates: Vec<RecoveredBrokerDispatchTemplateV1>,
}

impl DecodedPublicationCurrentV1 {
    pub fn into_parts(self) -> (PublicationHistoryV1, RecoveredOwnershipLeaseV1, Vec<RecoveredBrokerDispatchTemplateV1>) {
        (self.history, self.lease, self.templates)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublicationHistoryError {
    /// A lease-independent draft is malformed, non-canonical, or substituted.
    #[error("authority publication draft is invalid")]
    InvalidDraft,
    /// Required audiences or templates are empty, unsorted, duplicated, or incomplete.
    #[error("authority publication audience set is invalid or incomplete")]
    IncompleteAudienceSet,
    /// Guardian authority cannot use the generic broker publication format.
    #[error("guardian authority is not supported by generic broker publication")]
    UnsupportedBrokerAudience,
    /// Manifest, lease, plan, node, or ownership signer differs.
    #[error("authority publication contains substituted assignment authority")]
    ContextMismatch,
    /// The complete encoded publication cannot fit its bounded journal records.
    #[error("authority publication exceeds the fixed V1 journal-record bound")]
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
}

#[cfg(test)]
mod historical_output_readback_tests {
    use super::*;

    #[test]
    fn historical_readback_preserves_exact_lease_comparison_and_unit_validation() {
        let (_, prepared) = tests::activation_fixture(1);
        let bytes = prepared.canonical_bytes();
        let (_, artifacts) =
            format::decode_prepared_with_artifacts(bytes, prepared.digest()).unwrap();
        let lease = artifacts.lease.canonical_lease();
        let signature = artifacts.lease.canonical_signature();

        let decoded = decode_historical_output_publication_v1(bytes, prepared.digest()).unwrap();

        assert!(decoded.require_expected_lease(lease, signature).is_ok());
        assert!(decoded.require_expected_lease(lease, signature).is_ok());
        assert!(validate_historical_output_publication_v1(bytes, prepared.digest(), None).is_ok());
        assert!(
            validate_historical_output_publication_v1(
                bytes,
                prepared.digest(),
                Some((lease, signature)),
            )
            .is_ok()
        );
    }

    #[test]
    fn historical_readback_and_unit_wrapper_reject_each_changed_lease_preimage() {
        let (_, prepared) = tests::activation_fixture(1);
        let bytes = prepared.canonical_bytes();
        let (_, artifacts) =
            format::decode_prepared_with_artifacts(bytes, prepared.digest()).unwrap();
        let lease = artifacts.lease.canonical_lease();
        let signature = artifacts.lease.canonical_signature();

        let mut changed_lease = lease.to_vec();
        changed_lease[0] ^= 1;
        let mut changed_signature = signature.to_vec();
        changed_signature[0] ^= 1;
        let substitutions: [(&[u8], &[u8]); 4] = [
            (&changed_lease, signature),
            (lease, &changed_signature),
            (b"", signature),
            (lease, b""),
        ];
        let decoded = decode_historical_output_publication_v1(bytes, prepared.digest()).unwrap();

        for (lease, signature) in substitutions {
            assert!(matches!(
                decoded.require_expected_lease(lease, signature),
                Err(PublicationHistoryError::CorruptCurrent),
            ));
            assert!(matches!(
                validate_historical_output_publication_v1(
                    bytes,
                    prepared.digest(),
                    Some((lease, signature)),
                ),
                Err(PublicationHistoryError::CorruptCurrent),
            ));
        }
    }

    #[test]
    fn resealed_malformed_artifacts_still_fail_the_complete_first_decode() {
        let (_, prepared) = tests::activation_fixture(1);
        let bytes = prepared.canonical_bytes();
        let mut cursor = 10;
        let mut offsets = vec![0, 8];
        for _ in 0..5 {
            let field = take_bytes(bytes, &mut cursor).unwrap();
            offsets.push(cursor - field.len());
        }
        let audiences = take_u32(bytes, &mut cursor).unwrap();
        take(bytes, &mut cursor, audiences).unwrap();
        assert!(take_u32(bytes, &mut cursor).unwrap() > 0);
        take(bytes, &mut cursor, 33).unwrap();
        let plan = take_bytes(bytes, &mut cursor).unwrap();
        offsets.push(cursor - plan.len());

        for offset in offsets {
            let mut changed = bytes.to_vec();
            changed[offset] ^= 0xff;
            let digest = publication_digest(&changed);

            assert!(
                matches!(
                    decode_historical_output_publication_v1(&changed, digest),
                    Err(PublicationHistoryError::CorruptCurrent),
                ),
                "decoded malformed artifact at {offset}"
            );
            assert!(
                matches!(
                    validate_historical_output_publication_v1(&changed, digest, None),
                    Err(PublicationHistoryError::CorruptCurrent),
                ),
                "unit wrapper accepted malformed artifact at {offset}"
            );
            assert!(
                matches!(
                    decode_prepared(&changed, digest),
                    Err(PublicationHistoryError::CorruptCurrent),
                ),
                "original decoder accepted malformed artifact at {offset}"
            );
        }
    }

    #[test]
    fn historical_readback_preserves_digest_length_and_trailing_byte_refusals() {
        let (_, prepared) = tests::activation_fixture(1);
        let bytes = prepared.canonical_bytes();
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        let truncated = &bytes[..bytes.len() - 1];
        let oversized = vec![0; MAXIMUM_PUBLICATION_BYTES + 1];
        let malformed = [
            (bytes, ObjectDigest::from_bytes([0; 32])),
            (truncated, publication_digest(truncated)),
            (trailing.as_slice(), publication_digest(&trailing)),
            (oversized.as_slice(), prepared.digest()),
            (b"".as_slice(), prepared.digest()),
        ];

        for (bytes, digest) in malformed {
            assert!(matches!(
                decode_historical_output_publication_v1(bytes, digest),
                Err(PublicationHistoryError::CorruptCurrent),
            ));
            assert!(matches!(
                validate_historical_output_publication_v1(bytes, digest, None),
                Err(PublicationHistoryError::CorruptCurrent),
            ));
        }
    }
}

#[cfg(test)]
mod nix_audience_denial_tests {
    use super::*;

    #[test]
    fn nix_audience_has_no_publication_code_or_decode_path() {
        for audience in [BrokerAudience::Guardian, BrokerAudience::Nix] {
            assert!(matches!(
                audience_code(audience),
                Err(PublicationHistoryError::UnsupportedBrokerAudience)
            ));
        }

        for reserved in [0, 5, 6, u8::MAX] {
            assert!(matches!(
                audience_from_code(reserved),
                Err(PublicationHistoryError::CorruptCurrent)
            ));
        }

        for method_code in [50, 51, 52] {
            assert!(matches!(
                broker_method_from_code(method_code),
                Err(PublicationHistoryError::CorruptCurrent)
            ));
        }
    }

    #[test]
    fn existing_publication_audience_codes_round_trip_unchanged() {
        let audiences = [
            BrokerAudience::Host,
            BrokerAudience::Mount,
            BrokerAudience::Storage,
            BrokerAudience::Network,
        ];

        for (code, audience) in (1..=4).zip(audiences) {
            assert_eq!(audience_code(audience).unwrap(), code);
            assert_eq!(audience_from_code(code).unwrap(), audience);
        }
    }
}


#[cfg(test)]
#[path = "publication/tests.rs"]
pub(crate) mod tests;
