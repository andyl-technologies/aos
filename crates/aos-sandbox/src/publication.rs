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
//! Protocol owns the complete canonical history codec and structural recovery.
//! This Native owner retains private accepted identities, Journal selection and
//! atomic activation; raw lower history cannot publicly construct those identities.
//! Durable publication encoding and its isolated journal namespace use one
//! exact V1 schema. Unknown keys and non-V1 values fail closed as corruption.

use aos_sandbox_core::{BrokerAudience, BrokerVerb, CanonicalAssignmentManifestV1, ObjectDigest, OperationId, ProtocolVersion, RawPairedClockSample, SandboxId};
use crate::{AuthorityBoundEffectPlanV1, BrokerDispatchAttemptError, BrokerDispatchAttemptV1, GuardianPlanRequestV1, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalRecord, JournalTransaction, PreparedAuthorityEffectV1, RecordNamespace, SignedOwnershipLease};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;
use aos_sandbox_ownership_protocol::{OwnershipClaimAction, OwnershipClaimV1};

#[cfg(test)]
use aos_sandbox_core::{DecodeLimits, descriptor_for_bytes};
#[cfg(test)]
use crate::BrokerDispatchTemplateV1;

mod format;
use format::{decode_current, decode_prepared};
use aos_sandbox_protocol::publication::{self as publication_data, PublicationHistoryV1, PublicationHistoryError};
use publication_data::{current_key, prepared_key, CURRENT_KEY_PREFIX, PREPARED_KEY_PREFIX};
pub(crate) use publication_data::{MAXIMUM_PUBLICATION_BYTES, decode_historical_output_publication_v1, validate_historical_output_publication_v1};
pub use publication_data::{AuthorityPublicationDraftV1, AuthorityPublicationProposalV1, RecoveredBrokerDispatchTemplateV1, RecoveredOwnershipLeaseV1};

/// Carries one complete validated bundle before its atomic journal commit.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedAuthorityPublicationV1 {
    history: PublicationHistoryV1,
}

impl std::fmt::Debug for PreparedAuthorityPublicationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedAuthorityPublicationV1")
            .field("manifest", self.history.manifest())
            .field("sandbox", &self.history.sandbox())
            .field("incarnation", self.history.incarnation())
            .field("epoch", &self.history.epoch())
            .field("desired_generation", &self.history.desired_generation())
            .field("assignment_digest", &self.history.assignment_digest())
            .field("node", self.history.node())
            .field("lease_generation", &self.history.lease_generation())
            .field("lease_digest", &self.history.lease_digest())
            .field("receipt_authority", self.history.receipt_authority())
            .field("receipt_action", &self.history.receipt_action())
            .field("receipt_request_id", self.history.receipt_request_id())
            .field("receipt_claim_digest", &self.history.receipt_claim_digest())
            .field("source_draft_digest", &self.history.source_draft_digest())
            .field("digest", &self.history.digest())
            .field("bytes", &self.history.canonical_bytes())
            .finish()
    }
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
    /// Returns the complete canonical assignment bound by this publication.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        self.history.manifest()
    }

    /// Returns the digest of the lease-independent source draft.
    #[must_use]
    pub const fn source_draft_digest(&self) -> ObjectDigest {
        self.history.source_draft_digest()
    }

    /// Returns the content digest of the complete frozen publication.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.history.digest()
    }

    /// Returns the bound ownership-lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.history.lease_generation()
    }

    /// Returns the descriptor digest of the bound ownership lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.history.lease_digest()
    }

    /// Returns exact durable publication bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.history.canonical_bytes()
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
    /// Returns the complete structurally recovered assignment manifest.
    ///
    /// This durable record is not proof of current runtime ownership.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        self.prepared.manifest()
    }

    /// Returns the complete publication digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.prepared.history.digest()
    }

    /// Returns exact bytes committed during preparation.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.prepared.history.canonical_bytes()
    }

    /// Returns the current lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.prepared.history.lease_generation()
    }

    /// Returns the current exact lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.prepared.history.lease_digest()
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

/// Reports whether atomic publication committed or replayed a prior decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityPublicationOutcome {
    /// A complete new publication became current.
    Published(OperationId),
    /// The exact idempotent request was already durably accepted.
    Replay(OperationId),
}

/// Publishes and replays authority bundles through an existing journal.
///
/// Reads and idempotent replay reject a poisoned journal until it is dropped
/// and reopened. Its diagnostic materialized values may lag durable state and
/// cannot establish a current publication after an ambiguous I/O failure.
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
        self.journal.ensure_healthy()?;
        if let Some(existing) = self.journal.get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(prepared.history.digest()),
        ) && existing != prepared.history.canonical_bytes()
        {
            return Err(AuthorityPublicationError::PreparedConflict);
        }
        self.validate_namespace()?;
        let request_digest = *prepared.history.digest().as_bytes();
        match self
            .journal
            .check_idempotency(idempotency_key, request_digest)
        {
            IdempotencyOutcome::Replay(operation) => {
                let recovered = self
                    .prepared(prepared.history.digest())?
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

        if let Some(current) = self.current(prepared.history.sandbox())? {
            current.prepared.history.require_successor(&prepared.history).map_err(AuthorityPublicationError::from)?;
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.history.digest()),
                    prepared.history.canonical_bytes().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    current_key(prepared.history.sandbox()),
                    publication_data::encode_current(&prepared.history),
                ),
                JournalRecord::idempotency(idempotency_key, request_digest, operation_id),
            ],
        ).map_err(JournalError::from)?;
        self.journal.commit(&transaction)?;
        Ok(AuthorityPublicationOutcome::Published(operation_id))
    }

    /// Validates and freezes the two publication records for gate activation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] for malformed or substituted
    /// prepared bytes, a conflicting prepared-key value, or corrupt current
    /// state. Final successor eligibility is deliberately rechecked against
    /// the live journal immediately before gate activation.
    pub(crate) fn prepare_gate_activation(
        &self,
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<AuthorityPublicationActivationV1, AuthorityPublicationError> {
        self.journal.ensure_healthy()?;
        if let Some(existing) = self.journal.get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(prepared.history.digest()),
        ) && existing != prepared.history.canonical_bytes()
        {
            return Err(AuthorityPublicationError::PreparedConflict);
        }
        self.validate_namespace()?;
        let decoded = decode_prepared(prepared.history.canonical_bytes(), prepared.history.digest())?;
        if &decoded != prepared || prepared.history.source_draft_digest() != draft.digest() {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        Ok(AuthorityPublicationActivationV1 {
            records: [
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.history.digest()),
                    prepared.history.canonical_bytes().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    current_key(prepared.history.sandbox()),
                    publication_data::encode_current(&prepared.history),
                ),
            ],
            sandbox: prepared.history.sandbox(),
            assignment_digest: prepared.history.assignment_digest(),
            source_draft_digest: prepared.history.source_draft_digest(),
            ownership_authority: draft.ownership_authority().clone(),
            publication_digest: prepared.history.digest(),
            lease_generation: prepared.history.lease_generation(),
            lease_digest: prepared.history.lease_digest(),
            receipt_action: prepared.history.receipt_action(),
            receipt_request_id: *prepared.history.receipt_request_id(),
            receipt_claim_digest: prepared.history.receipt_claim_digest(),
            prepared: prepared.clone(),
        })
    }

    /// Loads and structurally validates a publication by permanent digest.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError::CorruptCurrent`] when the stored
    /// value is not the exact self-contained V1 publication named by `digest`.
    /// Returns a journal error if an earlier I/O failure poisoned the handle.
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
        if let Some(current) = self.current(prepared.history.sandbox())? {
            current.prepared.history.require_successor(&prepared.history).map_err(AuthorityPublicationError::from)?;
        }
        Ok(())
    }
}

/// Checks one exact current/prepared pair after a caller's full namespace scan.
///
/// The caller must retain exclusive journal ownership between that scan and
/// this lookup. This avoids rescanning every publication for each runtime head.
pub(crate) fn current_in_validated_namespace(
    journal: &Journal,
    sandbox: SandboxId,
) -> Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError> {
    journal.ensure_healthy()?;
    let current = journal
        .get(RecordNamespace::AuthorityPublication, &current_key(sandbox))
        .map(decode_current)
        .transpose()?;
    let Some(current) = current else {
        return Ok(None);
    };
    if current.prepared.history.sandbox() != sandbox {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let prepared = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(current.digest()),
        )
        .map(|bytes| decode_prepared(bytes, current.digest()))
        .transpose()?
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    if prepared != current.prepared {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    Ok(Some(current))
}

pub(crate) fn validate_durable_gate_publication(
    journal: &Journal,
    publication_digest: ObjectDigest,
    draft: &AuthorityPublicationDraftV1,
    claim: &OwnershipClaimV1,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), AuthorityPublicationError> {
    journal.ensure_healthy()?;
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
    if prepared.history.sandbox() != assignment.sandbox()
        || *prepared.history.incarnation() != *assignment.incarnation().as_bytes()
        || prepared.history.epoch() != assignment.epoch().get()
        || prepared.history.desired_generation() != claim.desired_generation().get()
        || prepared.history.assignment_digest() != assignment.digest()
        || *prepared.history.node() != *claim.node().as_bytes()
        || prepared.history.source_draft_digest() != draft.digest()
        || prepared.history.lease_generation() != lease_generation
        || prepared.history.lease_digest() != lease_digest
        || prepared.history.receipt_authority() != draft.ownership_authority()
        || prepared.history.receipt_action() != claim.action()
        || *prepared.history.receipt_request_id() != *claim.request_id()
        || prepared.history.receipt_claim_digest() != claim.digest()
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
    prepared.history.require_successor(&current.prepared.history).map_err(AuthorityPublicationError::from)
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_durable_effect_attempt(
    journal: &Journal,
    sandbox: SandboxId,
    activated_publication_digest: ObjectDigest,
    binding_digest: ObjectDigest,
    source_draft_digest: ObjectDigest,
    audience: BrokerAudience,
    template_digest: ObjectDigest,
    body_without_deadline: &[u8],
    prepared_effect: &PreparedAuthorityEffectV1,
    current_host_boot_id: Option<[u8; 16]>,
) -> Result<(), AuthorityPublicationError> {
    validate_publication_namespace(journal)?;
    if prepared_effect.binding_digest() != binding_digest {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    if current_host_boot_id
        .is_some_and(|current| prepared_effect.preparation_host_boot_id() != current)
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let activated = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(activated_publication_digest),
        )
        .map(|bytes| decode_prepared(bytes, activated_publication_digest))
        .transpose()?
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    let digest = prepared_effect.publication_digest();
    let (prepared, artifacts) = journal
        .get(RecordNamespace::AuthorityPublication, &prepared_key(digest))
        .map(|bytes| format::decode_prepared_with_artifacts(bytes, digest))
        .transpose()?
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    if prepared.history.sandbox() != sandbox || prepared.history.source_draft_digest() != source_draft_digest {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    activated.history.require_successor(&prepared.history).map_err(AuthorityPublicationError::from)
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let template = artifacts
        .templates()
        .iter()
        .find(|template| template.digest() == template_digest)
        .ok_or(AuthorityPublicationError::CorruptCurrent)?;
    if template.audience() != audience
        || template.body_without_deadline() != body_without_deadline
        || !template.descriptor_roles().is_empty()
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let reconstructed = if template.plan().protocol_version() == ProtocolVersion::new(1, 0)
        && template.semantics().verb() == BrokerVerb::HostLaunch
    {
        BrokerDispatchAttemptV1::from_recovered_host_launch_with_guardian_at(
            template,
            artifacts.lease(),
            prepared_effect.attempt().body(),
            prepared_effect.preparation_host_boot_id(),
            prepared_effect.attempt().deadline_boottime_nanoseconds(),
            prepared_effect.preparation_wall_seconds(),
            prepared_effect.preparation_boottime_nanoseconds(),
        )
    } else {
        BrokerDispatchAttemptV1::from_recovered_current_at(
            template,
            artifacts.lease(),
            prepared_effect.attempt().deadline_boottime_nanoseconds(),
            prepared_effect.preparation_wall_seconds(),
            prepared_effect.preparation_boottime_nanoseconds(),
        )
    }
    .map_err(AuthorityPublicationError::DispatchAttempt)?;
    if &reconstructed != prepared_effect.attempt() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    Ok(())
}

pub(crate) fn validate_publication_namespace(
    journal: &Journal,
) -> Result<(), AuthorityPublicationError> {
    // Diagnostic materialized values can lag an ambiguously committed successor.
    // Never turn that stale snapshot into current publication or replay evidence.
    journal.ensure_healthy()?;
    for (key, value) in journal.records(RecordNamespace::AuthorityPublication) {
        if let Some(suffix) = key.strip_prefix(CURRENT_KEY_PREFIX) {
            let sandbox_bytes: [u8; 16] = suffix
                .try_into()
                .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
            let sandbox = SandboxId::from_bytes(sandbox_bytes);
            let current = decode_current(value)?;
            if current.prepared.history.sandbox() != sandbox {
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
    /// Returns a journal error if an earlier I/O failure poisoned the handle.
    /// This does not cryptographically reverify signatures because the journal
    /// deliberately has no trust-anchor or public-key dependency.
    pub fn current(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError> {
        self.validate_namespace()?;
        current_in_validated_namespace(self.journal, sandbox)
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
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn select_current_attempt(
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
            .find(|candidate| candidate.digest() == template_digest)
            .ok_or(AuthorityPublicationError::TemplateAbsent)?;
        if template.audience() != audience {
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn select_bound_guardian_plan_request(
        &self,
        sandbox: SandboxId,
        activated_publication: ObjectDigest,
        source_draft_digest: ObjectDigest,
        audience: BrokerAudience,
        template_digest: ObjectDigest,
        host_boot_id: [u8; 16],
    ) -> Result<Option<GuardianPlanRequestV1>, AuthorityPublicationError> {
        let activated = self
            .prepared(activated_publication)?
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let current = self
            .current(sandbox)?
            .ok_or(AuthorityPublicationError::CurrentAbsent)?;
        activated.history.require_successor(&current.prepared.history).map_err(AuthorityPublicationError::from)?;
        if activated.history.source_draft_digest() != source_draft_digest
            || current.prepared.history.source_draft_digest() != source_draft_digest
        {
            return Err(AuthorityPublicationError::StaleCurrent);
        }
        let template = current
            .templates
            .iter()
            .find(|candidate| candidate.digest() == template_digest)
            .ok_or(AuthorityPublicationError::TemplateAbsent)?;
        if template.audience() != audience {
            return Err(AuthorityPublicationError::WrongAudience);
        }
        if template.semantics().verb() != BrokerVerb::HostLaunch {
            return Ok(None);
        }
        if template.audience() != BrokerAudience::Host
            || template.plan().protocol_version() != ProtocolVersion::new(1, 0)
        {
            return Err(AuthorityPublicationError::GuardianRequired);
        }
        GuardianPlanRequestV1::new(
            template.plan(),
            current.lease.lease(),
            current.lease.digest(),
            host_boot_id,
        )
        .map(Some)
        .map_err(AuthorityPublicationError::DispatchAttempt)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn select_bound_current_attempt(
        &self,
        sandbox: SandboxId,
        activated_publication: ObjectDigest,
        source_draft_digest: ObjectDigest,
        audience: BrokerAudience,
        template_digest: ObjectDigest,
        guardian_plan: Option<&SignedBrokerPlan>,
        deadline_boottime_nanoseconds: u64,
        clock: RawPairedClockSample,
    ) -> Result<(ObjectDigest, BrokerDispatchAttemptV1), AuthorityPublicationError> {
        let activated = self
            .prepared(activated_publication)?
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let current = self
            .current(sandbox)?
            .ok_or(AuthorityPublicationError::CurrentAbsent)?;
        activated.history.require_successor(&current.prepared.history).map_err(AuthorityPublicationError::from)?;
        if activated.history.source_draft_digest() != source_draft_digest
            || current.prepared.history.source_draft_digest() != source_draft_digest
        {
            return Err(AuthorityPublicationError::StaleCurrent);
        }
        let template = current
            .templates
            .iter()
            .find(|candidate| candidate.digest() == template_digest)
            .ok_or(AuthorityPublicationError::TemplateAbsent)?;
        if template.audience() != audience {
            return Err(AuthorityPublicationError::WrongAudience);
        }
        if !template.descriptor_roles().is_empty() {
            return Err(AuthorityPublicationError::DescriptorExecutionUnsupported);
        }
        let host_launch = template.semantics().verb() == BrokerVerb::HostLaunch;
        let attempt = match (host_launch, guardian_plan) {
            (true, Some(guardian_plan))
                if template.audience() == BrokerAudience::Host
                    && template.plan().protocol_version() == ProtocolVersion::new(1, 0) =>
            {
                BrokerDispatchAttemptV1::from_recovered_current_with_guardian(
                    template,
                    &current.lease,
                    guardian_plan,
                    clock.host_boot_id(),
                    deadline_boottime_nanoseconds,
                    clock,
                )
            }
            (true, _) => return Err(AuthorityPublicationError::GuardianRequired),
            (false, Some(_)) => return Err(AuthorityPublicationError::UnexpectedGuardianPlan),
            (false, None) => BrokerDispatchAttemptV1::from_recovered_current(
                template,
                &current.lease,
                deadline_boottime_nanoseconds,
                clock,
            ),
        }
        .map_err(AuthorityPublicationError::DispatchAttempt)?;
        Ok((current.digest(), attempt))
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
    /// Guardian authority cannot use the generic broker publication format.
    #[error("guardian authority is not supported by generic broker publication")]
    UnsupportedBrokerAudience,
    /// A Host launch lacks a fresh lease- and boot-bound Guardian plan.
    #[error("Host launch requires a current Guardian arm plan")]
    GuardianRequired,
    /// A non-launch attempt was paired with an unrelated Guardian plan.
    #[error("Guardian arm plan is present for a non-launch attempt")]
    UnexpectedGuardianPlan,
    /// Manifest, lease, plan, node, or ownership signer differs.
    #[error("authority publication contains substituted assignment authority")]
    ContextMismatch,
    /// A permanent digest key is already bound to different bytes.
    #[error("authority publication prepared key conflicts with existing bytes")]
    PreparedConflict,
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
    /// Descriptor-bearing dispatch awaits a durable FD reacquisition contract.
    #[error("descriptor-bearing authority effect execution is unsupported")]
    DescriptorExecutionUnsupported,
    /// Fresh lease and deadline attenuation rejected the current template.
    #[error("current dispatch attempt is invalid: {0}")]
    DispatchAttempt(#[from] BrokerDispatchAttemptError),
}

impl From<PublicationHistoryError> for AuthorityPublicationError {
    fn from(error: PublicationHistoryError) -> Self {
        match error {
            PublicationHistoryError::InvalidDraft => Self::InvalidDraft,
            PublicationHistoryError::IncompleteAudienceSet => Self::IncompleteAudienceSet,
            PublicationHistoryError::UnsupportedBrokerAudience => Self::UnsupportedBrokerAudience,
            PublicationHistoryError::ContextMismatch => Self::ContextMismatch,
            PublicationHistoryError::PublicationTooLarge => Self::PublicationTooLarge,
            PublicationHistoryError::GenerationRollback => Self::GenerationRollback,
            PublicationHistoryError::GenerationEquivocation => Self::GenerationEquivocation,
            PublicationHistoryError::CorruptCurrent => Self::CorruptCurrent,
        }
    }
}

/// Prepares a Native publication identity from one complete typed proposal.
///
/// The fixed preparation path validates structural completeness and bounds before
/// privately enclosing the history. It does not publish a Journal record or replace
/// the privileged broker's signature verification before dispatch.
///
/// # Errors
///
/// Returns [`AuthorityPublicationError`] for invalid or incomplete audiences,
/// unsupported audiences, substituted assignment/ownership context or an oversized
/// canonical publication.
pub fn prepare_authority_publication(proposal: AuthorityPublicationProposalV1) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
    let history = proposal.prepare().map_err(AuthorityPublicationError::from)?;
    Ok(PreparedAuthorityPublicationV1 { history })
}

/// Prepares a Native publication identity by binding a draft to typed ownership artifacts.
///
/// The fixed path checks claim, lease and receipt context before privately enclosing
/// the complete structural history. It neither commits the publication nor
/// establishes present Journal selection.
///
/// # Errors
///
/// Returns [`AuthorityPublicationError::ContextMismatch`] for substituted context,
/// [`AuthorityPublicationError::PublicationTooLarge`] for an oversized encoding, or
/// [`AuthorityPublicationError::InvalidDraft`] for failed complete validation.
pub fn bind_authority_publication_lease(draft: AuthorityPublicationDraftV1, claim: &OwnershipClaimV1, lease: SignedOwnershipLease) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
    let history = draft.bind_lease(claim, lease).map_err(AuthorityPublicationError::from)?;
    Ok(PreparedAuthorityPublicationV1 { history })
}

/// Binds an effect to one exact template selected from a checked publication draft.
///
/// The audience, broker method, deadline-free body, and semantic identity
/// are derived from the selected template and cannot be substituted by the
/// caller.
///
/// # Errors
///
/// Returns [`AuthorityPublicationError::TemplateAbsent`] when the digest
/// is not present, or [`AuthorityPublicationError::InvalidDraft`] if a
/// recovered template cannot produce a bounded effect binding.
pub fn bind_authority_publication_effect(
    draft: &AuthorityPublicationDraftV1,
    template_digest: ObjectDigest,
) -> Result<AuthorityBoundEffectPlanV1, AuthorityPublicationError> {
    let template = draft
        .templates()
        .iter()
        .find(|template| template.digest() == template_digest)
        .ok_or(AuthorityPublicationError::TemplateAbsent)?;
    AuthorityBoundEffectPlanV1::from_template(
        draft.digest(),
        template.audience(),
        template.method(),
        template.digest(),
        template.body_without_deadline(),
        template.semantics(),
        template.descriptor_roles().is_empty(),
    )
    .map_err(|_| AuthorityPublicationError::InvalidDraft)
}

#[cfg(test)]
#[path = "publication/tests.rs"]
pub(crate) mod tests;
