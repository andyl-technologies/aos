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
    JournalRecord, JournalTransaction, RecordNamespace, SignedOwnershipLease,
};

const MAGIC: &[u8; 8] = b"AOSCPUB1";
const VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-publication.v1\0";
const TEMPLATE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.broker-dispatch-template.v1\0";
const MAXIMUM_TEMPLATES: usize = 256;
const MAXIMUM_PUBLICATION_BYTES: usize = 16 * 1024 * 1024;
const CURRENT_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.current.v1/";
const PREPARED_KEY_PREFIX: &[u8] = b"aos.sandbox.publication.prepared.v1/";

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
        Ok(PreparedAuthorityPublicationV1 {
            sandbox: self.manifest.manifest().sandbox(),
            incarnation: *self.manifest.manifest().incarnation().as_bytes(),
            epoch: self.manifest.manifest().epoch().get(),
            desired_generation: self.manifest.manifest().desired_generation().get(),
            assignment_digest: self.manifest.digest(),
            node: *self.manifest.manifest().node().as_bytes(),
            lease_generation: self.lease.generation(),
            lease_digest: self.lease.digest(),
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
    digest: ObjectDigest,
    bytes: Vec<u8>,
}

impl PreparedAuthorityPublicationV1 {
    /// Returns the content digest of the complete frozen publication.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
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
        let request_digest = *prepared.digest.as_bytes();
        match self
            .journal
            .check_idempotency(idempotency_key, request_digest)
        {
            IdempotencyOutcome::Replay(operation) => {
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
                    RecordNamespace::DesiredState,
                    prepared_key(prepared.digest),
                    prepared.bytes.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    current_key(prepared.sandbox),
                    encode_current(prepared),
                ),
                JournalRecord::idempotency(idempotency_key, request_digest, operation_id),
            ],
        )?;
        self.journal.commit(&transaction)?;
        Ok(AuthorityPublicationOutcome::Published(operation_id))
    }

    /// Loads and structurally validates the current bundle for one sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError::CorruptCurrent`] when durable state
    /// is not the exact bounded, cross-linked format emitted by preparation.
    /// This does not cryptographically reverify signatures because the journal
    /// deliberately has no trust-anchor or public-key dependency.
    pub fn current(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError> {
        self.journal
            .get(RecordNamespace::DesiredState, &current_key(sandbox))
            .map(decode_current)
            .transpose()
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
    /// Required audiences or templates are empty, unsorted, duplicated, or incomplete.
    #[error("authority publication audience set is invalid or incomplete")]
    IncompleteAudienceSet,
    /// Manifest, lease, plan, node, or ownership signer differs.
    #[error("authority publication contains substituted assignment authority")]
    ContextMismatch,
    /// The complete encoded publication exceeds 16 MiB.
    #[error("authority publication exceeds the fixed V1 bound")]
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

fn validate_proposal(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<(), AuthorityPublicationError> {
    if proposal.required_audiences.is_empty()
        || proposal.required_audiences.len() > 4
        || proposal.templates.is_empty()
        || proposal.templates.len() > MAXIMUM_TEMPLATES
        || !strictly_increasing(&proposal.required_audiences)
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    let assignment = proposal
        .manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
    let lease_assignment = proposal.lease.assignment();
    if assignment.sandbox() != lease_assignment.sandbox()
        || assignment.incarnation() != lease_assignment.incarnation()
        || assignment.epoch() != lease_assignment.epoch()
        || assignment.digest() != lease_assignment.digest()
        || proposal.manifest.manifest().node() != proposal.lease.node()
    {
        return Err(AuthorityPublicationError::ContextMismatch);
    }

    let mut plans: BTreeMap<BrokerAudience, (ObjectDigest, &[u8])> = BTreeMap::new();
    for template in &proposal.templates {
        let plan = template.signed_plan().plan();
        if !proposal.required_audiences.contains(&plan.audience())
            || plan.assignment() != assignment
            || plan.node() != proposal.manifest.manifest().node()
            || plan.ownership_authority() != proposal.lease.signer()
        {
            return Err(AuthorityPublicationError::ContextMismatch);
        }
        match plans.get(&plan.audience()) {
            Some((digest, signature))
                if *digest != template.signed_plan().digest()
                    || *signature != template.signed_plan().canonical_signature() =>
            {
                return Err(AuthorityPublicationError::ContextMismatch);
            }
            None => {
                plans.insert(
                    plan.audience(),
                    (
                        template.signed_plan().digest(),
                        template.signed_plan().canonical_signature(),
                    ),
                );
            }
            _ => {}
        }
    }
    if plans.len() != proposal.required_audiences.len()
        || proposal
            .required_audiences
            .iter()
            .any(|audience| !plans.contains_key(audience))
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    Ok(())
}

fn encode_proposal(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<Vec<u8>, AuthorityPublicationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    put_bytes(&mut bytes, proposal.manifest.canonical_bytes())?;
    put_bytes(&mut bytes, proposal.lease.canonical_lease())?;
    put_bytes(&mut bytes, proposal.lease.canonical_signature())?;
    put_u32(&mut bytes, proposal.required_audiences.len())?;
    for audience in &proposal.required_audiences {
        bytes.push(audience_code(*audience));
    }
    put_u32(&mut bytes, proposal.templates.len())?;
    for template in &proposal.templates {
        bytes.extend_from_slice(template.digest().as_bytes());
        bytes.push(audience_code(template.signed_plan().plan().audience()));
        put_bytes(&mut bytes, template.signed_plan().canonical_plan())?;
        put_bytes(&mut bytes, template.signed_plan().canonical_signature())?;
        bytes.extend_from_slice(&(template.method() as i32).to_be_bytes());
        put_bytes(&mut bytes, template.body_without_deadline())?;
        put_u32(&mut bytes, template.descriptor_roles().len())?;
        for role in template.descriptor_roles() {
            bytes.extend_from_slice(&(*role as i32).to_be_bytes());
        }
        bytes.extend_from_slice(&template.semantics().verb().get().to_be_bytes());
        encode_target(&mut bytes, template.semantics().target());
        bytes.extend_from_slice(
            template
                .semantics()
                .argument_commitment()
                .digest()
                .as_bytes(),
        );
    }
    Ok(bytes)
}

fn validate_encoded_size(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<(), AuthorityPublicationError> {
    let mut size = 64_usize
        .checked_add(proposal.manifest.canonical_bytes().len())
        .and_then(|value| value.checked_add(proposal.lease.canonical_lease().len()))
        .and_then(|value| value.checked_add(proposal.lease.canonical_signature().len()))
        .ok_or(AuthorityPublicationError::PublicationTooLarge)?;
    for template in &proposal.templates {
        size = size
            .checked_add(128)
            .and_then(|value| value.checked_add(template.signed_plan().canonical_plan().len()))
            .and_then(|value| value.checked_add(template.signed_plan().canonical_signature().len()))
            .and_then(|value| value.checked_add(template.body_without_deadline().len()))
            .and_then(|value| value.checked_add(template.descriptor_roles().len() * 4))
            .ok_or(AuthorityPublicationError::PublicationTooLarge)?;
        if size > MAXIMUM_PUBLICATION_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
    }
    Ok(())
}

fn encode_target(bytes: &mut Vec<u8>, target: aos_sandbox_core::BrokerGrantTarget) {
    match target {
        aos_sandbox_core::BrokerGrantTarget::Assignment => bytes.push(1),
        aos_sandbox_core::BrokerGrantTarget::Resource(handle) => {
            bytes.push(2);
            bytes.extend_from_slice(handle.as_bytes());
        }
        aos_sandbox_core::BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(previous.as_bytes());
            bytes.extend_from_slice(successor.as_bytes());
        }
    }
}

fn encode_current(prepared: &PreparedAuthorityPublicationV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(176 + prepared.bytes.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(prepared.sandbox.as_bytes());
    bytes.extend_from_slice(&prepared.incarnation);
    bytes.extend_from_slice(&prepared.epoch.to_be_bytes());
    bytes.extend_from_slice(&prepared.desired_generation.to_be_bytes());
    bytes.extend_from_slice(prepared.assignment_digest.as_bytes());
    bytes.extend_from_slice(&prepared.node);
    bytes.extend_from_slice(&prepared.lease_generation.to_be_bytes());
    bytes.extend_from_slice(prepared.lease_digest.as_bytes());
    bytes.extend_from_slice(prepared.digest.as_bytes());
    bytes.extend_from_slice(
        &u64::try_from(prepared.bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&prepared.bytes);
    bytes
}

fn decode_current(
    bytes: &[u8],
) -> Result<CurrentAuthorityPublicationV1, AuthorityPublicationError> {
    const HEADER: usize = 186;
    if bytes.len() < HEADER || &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let mut cursor = 10;
    let sandbox = SandboxId::from_bytes(take_array(bytes, &mut cursor)?);
    let incarnation = take_array(bytes, &mut cursor)?;
    let epoch = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let desired_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let assignment_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let node = take_array(bytes, &mut cursor)?;
    let lease_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let length = usize::try_from(u64::from_be_bytes(take_array(bytes, &mut cursor)?))
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if length > MAXIMUM_PUBLICATION_BYTES || cursor.checked_add(length) != Some(bytes.len()) {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let publication = bytes[cursor..].to_vec();
    if publication_digest(&publication) != digest {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let recovered = validate_encoded_publication(
        &publication,
        sandbox,
        incarnation,
        epoch,
        desired_generation,
        assignment_digest,
        node,
        lease_generation,
        lease_digest,
    )?;
    Ok(CurrentAuthorityPublicationV1 {
        prepared: PreparedAuthorityPublicationV1 {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            node,
            lease_generation,
            lease_digest,
            digest,
            bytes: publication,
        },
        lease: recovered.lease,
        templates: recovered.templates,
    })
}

// Keeping every independently persisted summary field visible here makes the
// replay cross-link audit harder to accidentally weaken when the format grows.
#[allow(clippy::too_many_arguments)]
fn validate_encoded_publication(
    bytes: &[u8],
    sandbox: SandboxId,
    incarnation: [u8; 16],
    epoch: u64,
    desired_generation: u64,
    assignment_digest: ObjectDigest,
    node: [u8; 16],
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<RecoveredPublicationArtifactsV1, AuthorityPublicationError> {
    if bytes.len() < 10 || &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let mut cursor = 10;
    let manifest_bytes = take_bytes(bytes, &mut cursor)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if manifest.manifest().sandbox() != sandbox
        || manifest.manifest().incarnation().as_bytes() != &incarnation
        || manifest.manifest().epoch().get() != epoch
        || manifest.manifest().desired_generation().get() != desired_generation
        || manifest.manifest().node().as_bytes() != &node
        || manifest.digest() != assignment_digest
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let lease_bytes = take_bytes(bytes, &mut cursor)?;
    let lease = decode_ownership_lease(lease_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let media = aos_sandbox_core::MediaType::new(
        aos_sandbox_core::PortableMediaType::OwnershipLease
            .as_str()
            .to_owned(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let lease_descriptor = descriptor_for_bytes(media, lease_bytes);
    if lease_descriptor.digest() != lease_digest
        || lease.assignment().digest() != assignment_digest
        || lease.assignment().sandbox() != sandbox
        || lease.assignment().incarnation().as_bytes() != &incarnation
        || lease.assignment().epoch().get() != epoch
        || lease.node().as_bytes() != &node
        || lease.lease_generation() != lease_generation
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let signature_bytes = take_bytes(bytes, &mut cursor)?;
    let signature = decode_signature(signature_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if encode_signature(&signature) != signature_bytes
        || signature.statement().subject() != &lease_descriptor
        || signature.statement().purpose() != SignaturePurpose::OwnershipLease
        || signature.statement().issued_seconds() != lease.authority_issued_seconds()
        || signature.statement().expires_seconds() != Some(lease.authority_expires_seconds())
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let recovered_lease = RecoveredOwnershipLeaseV1 {
        lease,
        canonical_lease: lease_bytes.to_vec(),
        canonical_signature: signature_bytes.to_vec(),
        digest: lease_digest,
    };
    let required = take_u32(bytes, &mut cursor)?;
    if required == 0 || required > 4 {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let audiences = take(bytes, &mut cursor, required)?;
    if audiences.iter().any(|code| !(1..=4).contains(code))
        || audiences.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let templates = take_u32(bytes, &mut cursor)?;
    if templates == 0 || templates > MAXIMUM_TEMPLATES {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let mut plans: BTreeMap<u8, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut recovered_templates = Vec::with_capacity(templates);
    for _ in 0..templates {
        let stored_template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        if !audiences.contains(&audience) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let plan_bytes = take_bytes(bytes, &mut cursor)?;
        let plan = decode_broker_authorization_plan(plan_bytes, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_signature = take_bytes(bytes, &mut cursor)?;
        let decoded = decode_signature(plan_signature, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_media = aos_sandbox_core::MediaType::new(
            aos_sandbox_core::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_descriptor = descriptor_for_bytes(plan_media, plan_bytes);
        if encode_signature(&decoded) != plan_signature
            || decoded.statement().subject() != &plan_descriptor
            || decoded.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || decoded.statement().issued_seconds() != plan.issued_seconds()
            || decoded.statement().expires_seconds() != Some(plan.expires_seconds())
            || audience_code(plan.audience()) != audience
            || plan.assignment() != assignment
            || plan.node().as_bytes() != &node
            || plan.ownership_authority() != signature.statement().signer()
        {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        match plans.get(&audience) {
            Some((prior_plan, prior_signature))
                if prior_plan != plan_bytes || prior_signature != plan_signature =>
            {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
            None => {
                plans.insert(audience, (plan_bytes.to_vec(), plan_signature.to_vec()));
            }
            _ => {}
        }
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        if !matches!((audience, method_code), (1, 1) | (2, 4) | (3, 7) | (4, 9)) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let method = broker_method_from_code(method_code)?;
        let body = take_bytes(bytes, &mut cursor)?;
        if !crate::dispatch::validate_durable_deadline_free_body(body) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let roles = take_u32(bytes, &mut cursor)?;
        if roles > 16 {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let mut role_codes = Vec::with_capacity(roles);
        let mut descriptor_roles = Vec::with_capacity(roles);
        for _ in 0..roles {
            let role = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
            if !(1..=7).contains(&role) || role_codes.contains(&role) {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
            role_codes.push(role);
            descriptor_roles.push(broker_descriptor_role_from_code(role)?);
        }
        let verb = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let target_start = cursor;
        let target = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        take(
            bytes,
            &mut cursor,
            match target {
                1 => 0,
                2 => 32,
                3 => 64,
                _ => return Err(AuthorityPublicationError::CorruptCurrent),
            },
        )?;
        let target_bytes = &bytes[target_start..cursor];
        let commitment = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let maximum_body = body
            .len()
            .checked_add(11)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let descriptor_count =
            u16::try_from(roles).map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let matching_grant = plan.grants().iter().find(|grant| {
            let mut encoded_target = Vec::new();
            encode_target(&mut encoded_target, grant.target());
            grant.verb().get() == verb
                && encoded_target == target_bytes
                && grant.argument_commitment().digest() == commitment
                && maximum_body <= grant.maximum_request_bytes()
                && descriptor_count <= grant.maximum_descriptors()
        });
        if matching_grant.is_none()
            || durable_template_digest(
                plan_descriptor.digest(),
                plan_signature,
                method_code,
                body,
                &role_codes,
                verb,
                target_bytes,
                commitment,
            ) != stored_template_digest
        {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let grant = matching_grant.ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            grant.verb(),
            grant.target(),
            grant.argument_commitment(),
        );
        recovered_templates.push(RecoveredBrokerDispatchTemplateV1 {
            digest: stored_template_digest,
            audience: audience_from_code(audience)?,
            plan,
            canonical_plan: plan_bytes.to_vec(),
            canonical_plan_signature: plan_signature.to_vec(),
            method,
            body_without_deadline: body.to_vec(),
            descriptor_roles,
            semantics,
        });
    }
    if cursor != bytes.len() || plans.len() != audiences.len() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    Ok(RecoveredPublicationArtifactsV1 {
        lease: recovered_lease,
        templates: recovered_templates,
    })
}

fn validate_successor(
    current: &PreparedAuthorityPublicationV1,
    next: &PreparedAuthorityPublicationV1,
) -> Result<(), AuthorityPublicationError> {
    if next.epoch < current.epoch
        || (next.epoch == current.epoch && next.desired_generation < current.desired_generation)
        || next.lease_generation < current.lease_generation
    {
        return Err(AuthorityPublicationError::GenerationRollback);
    }
    if (next.epoch == current.epoch
        && next.desired_generation == current.desired_generation
        && next.assignment_digest != current.assignment_digest)
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
mod tests {
    use std::path::PathBuf;

    use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, BrokerMethod};
    use aos_sandbox_core::format::{encode_signature, encode_trust_policy};
    use aos_sandbox_core::model::{
        AssignmentManifestV1, KeyReference, KeyUsage, SandboxAncestry, Signature, SignatureBytes,
        SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerAuthorizationPlan,
        BrokerGrant, BrokerGrantTarget, BrokerVerb, DesiredGeneration, FeatureRef, IncarnationId,
        LeaseAssignment, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, OwnershipLease,
        PortableMediaType, ProjectId, ProtocolId, ProtocolVersion, ResourceDimension,
        ResourceVector, RevocationScopeId, TrustScopeId, sign_statement,
    };
    use ed25519_dalek::SigningKey;

    use crate::{
        BrokerDispatchSemanticIdentityV1, BrokerPlanPreparation, ReturnedSignature,
        SignedBrokerPlan, SigningAuthority,
    };

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("aos-publication-{}", OperationId::new()));
            std::fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("test directory failed: {error}"));
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("controller.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            u64::from(byte),
        )
    }

    fn manifest_with_node(node: u8) -> CanonicalAssignmentManifestV1 {
        let sandbox = SandboxId::from_bytes([1; 16]);
        let feature = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        let model = AssignmentManifestV1::new(
            sandbox,
            ProjectId::from_bytes([2; 16]),
            SandboxAncestry::new(sandbox, vec![SandboxId::from_bytes([3; 16])])
                .unwrap_or_else(|error| panic!("test ancestry failed: {error}")),
            IncarnationId::from_bytes([4; 16]),
            NodeId::from_bytes([node; 16]),
            AssignmentEpoch::new(6),
            DesiredGeneration::new(7),
            NamespaceGeneration::new(8),
            descriptor(PortableMediaType::SandboxSpec, 9),
            descriptor(PortableMediaType::Policy, 10),
            descriptor(PortableMediaType::Environment, 11),
            descriptor(PortableMediaType::View, 12),
            vec![descriptor(PortableMediaType::Tree, 13)],
            ObjectDigest::from_bytes([14; 32]),
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
            vec![feature],
        )
        .unwrap_or_else(|error| panic!("test manifest failed: {error}"));
        CanonicalAssignmentManifestV1::new(model)
    }

    fn manifest() -> CanonicalAssignmentManifestV1 {
        manifest_with_node(5)
    }

    fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned())
                .unwrap_or_else(|error| panic!("test key failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn authority(key: &SigningKey) -> SigningAuthority {
        let signer = key_reference("controller", KeyUsage::BrokerAuthorization, key);
        let scope = TrustScopeId::from_bytes([20; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::BrokerAuthorization,
            vec![signer.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let bytes = encode_trust_policy(&policy);
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test policy media failed: {error}")),
            &bytes,
        );
        SigningAuthority::new(
            bytes,
            descriptor,
            scope,
            signer,
            key.verifying_key().to_bytes(),
            SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test authority failed: {error}"))
    }

    fn signed_plan(
        manifest: &CanonicalAssignmentManifestV1,
        lease_signer: KeyReference,
    ) -> (SignedBrokerPlan, BrokerDispatchSemanticIdentityV1) {
        let key = SigningKey::from_bytes(&[40; 32]);
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"mount-create"),
        );
        let assignment: BrokerAssignment = manifest
            .broker_assignment()
            .unwrap_or_else(|error| panic!("test broker assignment failed: {error}"));
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            manifest.manifest().node(),
            lease_signer,
            vec![
                BrokerGrant::new(
                    semantics.verb(),
                    semantics.target(),
                    semantics.argument_commitment(),
                    4096,
                    1,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([50; 32]),
            RevocationScopeId::from_bytes([51; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        let preparation = BrokerPlanPreparation::new(plan, authority(&key))
            .unwrap_or_else(|error| panic!("test plan preparation failed: {error}"));
        let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));
        let signed = preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), 150)
            .unwrap_or_else(|error| panic!("test signed plan failed: {error}"));
        (signed, semantics)
    }

    fn proposal(lease_generation: u64, expiry: i64) -> AuthorityPublicationProposalV1 {
        let manifest = manifest();
        let lease_key = SigningKey::from_bytes(&[41; 32]);
        let lease_signer = key_reference("lease", KeyUsage::OwnershipLease, &lease_key);
        let (plan, semantics) = signed_plan(&manifest, lease_signer.clone());
        let broker_assignment = manifest
            .broker_assignment()
            .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let lease_assignment = LeaseAssignment::new(
            broker_assignment.sandbox(),
            broker_assignment.incarnation(),
            broker_assignment.epoch(),
            broker_assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
        let lease = OwnershipLease::new(
            lease_assignment,
            manifest.manifest().node(),
            lease_generation,
            110,
            expiry,
            5,
            [u8::try_from(lease_generation).unwrap_or(u8::MAX); 16],
        )
        .unwrap_or_else(|error| panic!("test lease failed: {error}"));
        let lease_bytes = aos_sandbox_core::format::encode_ownership_lease(&lease);
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test lease media failed: {error}")),
            &lease_bytes,
        );
        let statement = SignatureStatement::new(
            lease_descriptor,
            TrustScopeId::from_bytes([61; 16]),
            lease_signer,
            SignaturePurpose::OwnershipLease,
            110,
            Some(expiry),
            descriptor(PortableMediaType::TrustPolicy, 62),
        )
        .unwrap_or_else(|error| panic!("test lease statement failed: {error}"));
        let signature = encode_signature(&Signature::new(statement, SignatureBytes::new([0; 64])));
        let signed_lease = SignedOwnershipLease::from_test_artifacts(lease, signature);
        let template = BrokerDispatchTemplateV1::new(
            plan,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xaa],
            vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
            semantics,
        )
        .unwrap_or_else(|error| panic!("test template failed: {error}"));
        AuthorityPublicationProposalV1::new(
            manifest,
            signed_lease,
            vec![BrokerAudience::Mount],
            vec![template],
        )
    }

    fn clock(wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            aos_sandbox_core::RawClockProvenance::new_untrusted([91; 16])
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            [92; 16],
            wall,
            boottime,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }

    #[test]
    fn publication_is_atomic_idempotent_and_byte_exact_after_reopen() {
        let directory = TestDirectory::new();
        let prepared = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        let idempotency = IdempotencyKey::new(b"publish-one".to_vec())
            .unwrap_or_else(|error| panic!("test idempotency failed: {error}"));
        let operation = OperationId::from_bytes([70; 16]);
        {
            let (mut journal, _) = Journal::open(directory.journal(), Default::default())
                .unwrap_or_else(|error| panic!("test journal failed: {error}"));
            let mut store = AuthorityPublicationStore::new(&mut journal);
            assert_eq!(
                store
                    .publish(&prepared, &idempotency, operation, [71; 16])
                    .unwrap_or_else(|error| panic!("test publish failed: {error}")),
                AuthorityPublicationOutcome::Published(operation)
            );
            assert_eq!(
                store
                    .publish(&prepared, &idempotency, operation, [72; 16])
                    .unwrap_or_else(|error| panic!("test replay failed: {error}")),
                AuthorityPublicationOutcome::Replay(operation)
            );
            let changed = proposal(2, 195)
                .prepare()
                .unwrap_or_else(|error| panic!("test changed prepare failed: {error}"));
            assert!(matches!(
                store.publish(&changed, &idempotency, operation, [73; 16]),
                Err(AuthorityPublicationError::IdempotencyConflict)
            ));
        }
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test reopen failed: {error}"));
        let store = AuthorityPublicationStore::new(&mut journal);
        let current = store
            .current(SandboxId::from_bytes([1; 16]))
            .unwrap_or_else(|error| panic!("test current failed: {error}"))
            .unwrap_or_else(|| panic!("missing current"));
        assert_eq!(current.canonical_bytes(), prepared.canonical_bytes());
        assert_eq!(current.digest(), prepared.digest());
    }

    #[test]
    fn recovery_retains_exact_typed_lease_plan_and_template_bytes() {
        let directory = TestDirectory::new();
        let proposal = proposal(1, 190);
        let expected_lease = proposal.lease.canonical_lease().to_vec();
        let expected_lease_signature = proposal.lease.canonical_signature().to_vec();
        let expected_template = proposal.templates[0].clone();
        let prepared = proposal
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        {
            let (mut journal, _) = Journal::open(directory.journal(), Default::default())
                .unwrap_or_else(|error| panic!("test journal failed: {error}"));
            AuthorityPublicationStore::new(&mut journal)
                .publish(
                    &prepared,
                    &IdempotencyKey::new(b"typed".to_vec())
                        .unwrap_or_else(|error| panic!("test key failed: {error}")),
                    OperationId::from_bytes([93; 16]),
                    [94; 16],
                )
                .unwrap_or_else(|error| panic!("test publish failed: {error}"));
        }

        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test reopen failed: {error}"));
        let current = AuthorityPublicationStore::new(&mut journal)
            .current(SandboxId::from_bytes([1; 16]))
            .unwrap_or_else(|error| panic!("test current failed: {error}"))
            .unwrap_or_else(|| panic!("missing current"));
        assert_eq!(current.lease().canonical_lease(), expected_lease);
        assert_eq!(
            current.lease().canonical_signature(),
            expected_lease_signature
        );
        assert_eq!(current.templates().len(), 1);
        let recovered = &current.templates()[0];
        assert_eq!(recovered.digest(), expected_template.digest());
        assert_eq!(
            recovered.canonical_plan(),
            expected_template.signed_plan().canonical_plan()
        );
        assert_eq!(
            recovered.canonical_plan_signature(),
            expected_template.signed_plan().canonical_signature()
        );
        assert_eq!(
            recovered.body_without_deadline(),
            expected_template.body_without_deadline()
        );
        assert_eq!(
            recovered.descriptor_roles(),
            expected_template.descriptor_roles()
        );
        assert_eq!(recovered.semantics(), expected_template.semantics());
    }

    #[test]
    fn selection_rejects_substitution_wrong_audience_and_stale_publication() {
        let directory = TestDirectory::new();
        let first_proposal = proposal(1, 190);
        let template_digest = first_proposal.templates[0].digest();
        let first = first_proposal
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal failed: {error}"));
        let mut store = AuthorityPublicationStore::new(&mut journal);
        store
            .publish(
                &first,
                &IdempotencyKey::new(b"first-selection".to_vec())
                    .unwrap_or_else(|error| panic!("test key failed: {error}")),
                OperationId::from_bytes([95; 16]),
                [96; 16],
            )
            .unwrap_or_else(|error| panic!("test publish failed: {error}"));

        let attempt = store
            .select_current_attempt(
                SandboxId::from_bytes([1; 16]),
                first.digest(),
                BrokerAudience::Mount,
                template_digest,
                2_000,
                clock(150, 1_000),
            )
            .unwrap_or_else(|error| panic!("test selection failed: {error}"));
        assert_eq!(attempt.template_digest(), template_digest);
        assert_eq!(attempt.lease_digest(), first.lease_digest);
        assert!(matches!(
            store.select_current_attempt(
                SandboxId::from_bytes([1; 16]),
                first.digest(),
                BrokerAudience::Host,
                template_digest,
                2_000,
                clock(150, 1_000),
            ),
            Err(AuthorityPublicationError::WrongAudience)
        ));
        assert!(matches!(
            store.select_current_attempt(
                SandboxId::from_bytes([1; 16]),
                first.digest(),
                BrokerAudience::Mount,
                ObjectDigest::from_bytes([97; 32]),
                2_000,
                clock(150, 1_000),
            ),
            Err(AuthorityPublicationError::TemplateAbsent)
        ));

        let renewed = proposal(2, 195)
            .prepare()
            .unwrap_or_else(|error| panic!("test renewal prepare failed: {error}"));
        store
            .publish(
                &renewed,
                &IdempotencyKey::new(b"renewed-selection".to_vec())
                    .unwrap_or_else(|error| panic!("test key failed: {error}")),
                OperationId::from_bytes([98; 16]),
                [99; 16],
            )
            .unwrap_or_else(|error| panic!("test renewal publish failed: {error}"));
        assert!(matches!(
            store.select_current_attempt(
                SandboxId::from_bytes([1; 16]),
                first.digest(),
                BrokerAudience::Mount,
                template_digest,
                2_000,
                clock(150, 1_000),
            ),
            Err(AuthorityPublicationError::StaleCurrent)
        ));
    }

    #[test]
    fn incomplete_substituted_and_noncanonical_audience_sets_fail_closed() {
        let mut missing = proposal(1, 190);
        missing.required_audiences = vec![BrokerAudience::Host, BrokerAudience::Mount];
        assert!(matches!(
            missing.prepare(),
            Err(AuthorityPublicationError::IncompleteAudienceSet)
        ));
        let mut duplicate = proposal(1, 190);
        duplicate.required_audiences = vec![BrokerAudience::Mount, BrokerAudience::Mount];
        assert!(matches!(
            duplicate.prepare(),
            Err(AuthorityPublicationError::IncompleteAudienceSet)
        ));
        let mut wrong_lease = proposal(1, 190);
        wrong_lease.manifest = manifest_with_node(99);
        assert!(matches!(
            wrong_lease.prepare(),
            Err(AuthorityPublicationError::ContextMismatch)
        ));
    }

    #[test]
    fn renewal_advances_and_rollback_or_equal_generation_equivocation_fails() {
        let directory = TestDirectory::new();
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal failed: {error}"));
        let mut store = AuthorityPublicationStore::new(&mut journal);
        for (generation, expiry, key, operation, transaction) in [
            (1, 190, b"one".as_slice(), [1; 16], [11; 16]),
            (2, 195, b"two".as_slice(), [2; 16], [12; 16]),
        ] {
            let prepared = proposal(generation, expiry)
                .prepare()
                .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
            let idempotency = IdempotencyKey::new(key.to_vec())
                .unwrap_or_else(|error| panic!("test key failed: {error}"));
            store
                .publish(
                    &prepared,
                    &idempotency,
                    OperationId::from_bytes(operation),
                    transaction,
                )
                .unwrap_or_else(|error| panic!("test renewal failed: {error}"));
        }
        let rollback = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test rollback prepare failed: {error}"));
        let rollback_key = IdempotencyKey::new(b"rollback".to_vec())
            .unwrap_or_else(|error| panic!("test rollback key failed: {error}"));
        assert!(matches!(
            store.publish(
                &rollback,
                &rollback_key,
                OperationId::from_bytes([3; 16]),
                [13; 16],
            ),
            Err(AuthorityPublicationError::GenerationRollback)
        ));
        let equivocation = proposal(2, 196)
            .prepare()
            .unwrap_or_else(|error| panic!("test equivocation prepare failed: {error}"));
        let equivocation_key = IdempotencyKey::new(b"equivocation".to_vec())
            .unwrap_or_else(|error| panic!("test equivocation key failed: {error}"));
        assert!(matches!(
            store.publish(
                &equivocation,
                &equivocation_key,
                OperationId::from_bytes([4; 16]),
                [14; 16],
            ),
            Err(AuthorityPublicationError::GenerationEquivocation)
        ));
    }

    #[test]
    fn a_prepared_record_without_current_is_never_observed_as_current() {
        let directory = TestDirectory::new();
        let prepared = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal failed: {error}"));
        journal
            .commit(
                &JournalTransaction::new(
                    [80; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        prepared_key(prepared.digest()),
                        prepared.canonical_bytes().to_vec(),
                    )],
                )
                .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("test partial commit failed: {error}"));
        let store = AuthorityPublicationStore::new(&mut journal);
        assert!(
            store
                .current(SandboxId::from_bytes([1; 16]))
                .unwrap_or_else(|error| panic!("test current failed: {error}"))
                .is_none()
        );
    }

    #[test]
    fn recomputed_outer_digests_do_not_hide_inner_substitution() {
        let prepared = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));

        let mut semantic_tamper = prepared.clone();
        let last = semantic_tamper
            .bytes
            .last_mut()
            .unwrap_or_else(|| panic!("empty publication"));
        *last ^= 1;
        semantic_tamper.digest = publication_digest(&semantic_tamper.bytes);
        assert!(matches!(
            decode_current(&encode_current(&semantic_tamper)),
            Err(AuthorityPublicationError::CorruptCurrent)
        ));

        let mut summary_tamper = prepared;
        summary_tamper.node = [99; 16];
        summary_tamper.digest = publication_digest(&summary_tamper.bytes);
        assert!(matches!(
            decode_current(&encode_current(&summary_tamper)),
            Err(AuthorityPublicationError::CorruptCurrent)
        ));
    }
}
