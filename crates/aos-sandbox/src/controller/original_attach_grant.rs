//! Current original-grant authorization under the retained Controller writer.
//!
//! Accepted decisions and tickets are historical inputs, not session factories.
//! This owner joins them to the genuine fixed registration and common current
//! capability evaluator before borrowing a cut through the forward Host consume.
//! It never renews a pending receipt, certificate, capability, or assignment.

use aos_proto::aos::sandbox::v1::ExecutionControlAction;
use aos_sandbox_core::public_attach_grant::{
    PUBLIC_ATTACH_GRANT_BYTES, PublicAttachPendingGrantV1, verify_public_attach_pending_grant_v1,
};
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, CapabilityId, ChannelBinding, NodeId,
    ObjectDigest, Operation, OperationId, ProtocolId, ProtocolVersion, RawPairedClockSample,
    ResourceKind,
};
use aos_sandbox_protocol::semantics::host_attach_gate::canonical_host_attach_consume_semantics_v3;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use super::{
    ActivatedOperationCompiler, ControllerProtectedClockV1, ControllerServiceError, NodeController,
    OperationCompilationError, SingleNodeEffectExecutor,
};
use crate::cli_model::DormantSandboxRequestKindV1;
use crate::cli_model::authorization_adapter::{
    CurrentCapabilityDecisionV1, evaluate_current_protected_capability,
};
use crate::public_api_session::{CurrentOriginalPublicRegistrationV3, PinnedSystemdCredential};
use crate::public_mutation_compiler::ResolvedPublicMutationRequestV1;
use crate::{IdempotencyOutcome, Journal};

/// Borrows one exact currently reauthorized original attach through consumption.
///
/// Construction belongs only to [`NodeController::with_current_original_attach_consume_v3`].
/// The cut cannot be cloned or serialized. It holds the protected Controller
/// writer borrowed, and fixed credential pins and time are rechecked before
/// plan construction, immediately before downstream use, and after the closure.
/// It is not Host/Guest liveness evidence or an independently current grant.
pub struct CurrentOriginalAttachConsumeCutV3<'owner> {
    journal: &'owner Journal,
    registration: CurrentOriginalPublicRegistrationV3,
    grant_key: PinnedSystemdCredential,
    attach_trust: PinnedSystemdCredential,
    original_ticket: &'owner [u8],
    original_grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
    parent: BrokerAuthorizationPlan,
    ownership_lease: Vec<u8>,
    ownership_lease_signature: Vec<u8>,
    original_clock: RawPairedClockSample,
    expires_at: i64,
    deadline_boottime_nanoseconds: u64,
}

/// Keeps unsigned fixed Host consume inputs borrowed from their current owner.
///
/// This is not an independent authorization token: the existing plan signer
/// and authenticated forward transport must use it within the owning closure.
/// The original grant and ticket bytes remain byte-exact.
pub struct CurrentOriginalAttachHostConsumeDraftV3<'cut, 'owner> {
    cut: &'cut CurrentOriginalAttachConsumeCutV3<'owner>,
    plan: BrokerAuthorizationPlan,
}

impl<'owner> CurrentOriginalAttachConsumeCutV3<'owner> {
    /// Returns byte-exact immutable ticket custody, without reconstructing it.
    #[must_use]
    pub const fn original_ticket(&self) -> &[u8] {
        self.original_ticket
    }

    /// Returns the original dedicated-key receipt, without signing a new one.
    #[must_use]
    pub const fn original_grant(&self) -> &[u8; PUBLIC_ATTACH_GRANT_BYTES] {
        &self.original_grant
    }

    /// Rechecks protected custody, current fixed pins, and the same paired clock.
    ///
    /// The transport owner must invoke this immediately before consuming the
    /// forward Host request. A readiness observation alone grants nothing.
    ///
    /// # Errors
    /// Rejects poisoned/replaced custody or credentials, rollback/clock/boot
    /// discontinuity, and original authority or current plan expiry.
    pub fn recheck(&self) -> Result<(), ControllerServiceError> {
        self.journal
            .ensure_protected_authority()
            .map_err(rejected)?;
        self.registration.recheck().map_err(rejected)?;
        self.grant_key.recheck().map_err(rejected)?;
        self.attach_trust.recheck().map_err(rejected)?;
        let later = ControllerProtectedClockV1::open_fixed()
            .map_err(rejected)?
            .sample()
            .map_err(rejected)?;
        require_cut_clock(
            self.original_clock,
            later,
            self.expires_at,
            self.deadline_boottime_nanoseconds,
        )
    }

    /// Prepares only the existing bounded read-only original Host route query.
    ///
    /// The protected parent was derived for this exact accepted operation and
    /// execution. A successful query is an observation, not consume authority.
    ///
    /// # Errors
    /// Rejects stale currentness or invalid original-expiry attenuation.
    pub fn prepare_host_poll_plan_v3(
        &self,
    ) -> Result<CurrentOriginalAttachHostConsumeDraftV3<'_, 'owner>, ControllerServiceError> {
        self.recheck()?;
        let plan = self.narrow_host_plan(self.parent.grants().to_vec())?;
        Ok(CurrentOriginalAttachHostConsumeDraftV3 { cut: self, plan })
    }

    /// Prepares only the fixed original-ticket Host ATTACH consume operation.
    ///
    /// Monitor binding and challenge are fresh nonauthorizing correlation. The
    /// caller cannot choose another verb, target, grant, assignment, or expiry.
    ///
    /// # Errors
    /// Rejects stale currentness, missing correlation, or invalid canonical
    /// consume semantics. No public readiness or I/O authority is minted.
    pub fn prepare_host_consume_plan_v3(
        &self,
        monitor_binding: ObjectDigest,
        observation_challenge: [u8; 32],
    ) -> Result<CurrentOriginalAttachHostConsumeDraftV3<'_, 'owner>, ControllerServiceError> {
        self.recheck()?;
        let semantics = canonical_host_attach_consume_semantics_v3(
            self.parent.assignment(),
            &self.original_grant,
            self.original_ticket,
            monitor_binding,
            observation_challenge,
        )
        .map_err(rejected)?;
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.commitment(),
            u32::try_from(aos_sandbox_protocol::HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES)
                .map_err(rejected)?,
            0,
        )
        .map_err(rejected)?;
        let plan = self.narrow_host_plan(vec![grant])?;
        Ok(CurrentOriginalAttachHostConsumeDraftV3 { cut: self, plan })
    }

    /// Prepares one closed original-session control under current LifecycleControl.
    ///
    /// The original accepted attach already required that exact capability
    /// operation and selector. The same genuine current evaluator and protected
    /// writer stay borrowed; a queued SSH request or read permission cannot
    /// create permission. This never changes the original ticket, holder,
    /// certificate/expiry or chooses another execution or assignment.
    ///
    /// # Errors
    /// Rejects stale current authority, invalid original-session correlation or
    /// malformed signal/resize/PTY data. Host/Guest custody remains independent.
    pub fn prepare_host_control_plan_v5(
        &self,
        monitor_binding: ObjectDigest,
        observation_challenge: [u8; 32],
        request: &[u8],
    ) -> Result<CurrentOriginalAttachHostConsumeDraftV3<'_, 'owner>, ControllerServiceError> {
        self.recheck()?;
        let semantics = aos_sandbox_protocol::semantics::host_attach_gate::canonical_host_attach_control_semantics_v5(
            self.parent.assignment(),
            &self.original_grant,
            self.original_ticket,
            monitor_binding,
            observation_challenge,
            request,
        )
        .map_err(rejected)?;
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.commitment(),
            u32::try_from(aos_sandbox_protocol::HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES)
                .map_err(rejected)?,
            0,
        )
        .map_err(rejected)?;
        let plan = self.narrow_host_plan(vec![grant])?;
        Ok(CurrentOriginalAttachHostConsumeDraftV3 { cut: self, plan })
    }

    fn narrow_host_plan(
        &self,
        grants: Vec<BrokerGrant>,
    ) -> Result<BrokerAuthorizationPlan, ControllerServiceError> {
        BrokerAuthorizationPlan::new(
            BrokerAudience::Host,
            ProtocolId::HostBroker,
            ProtocolVersion::new(1, 0),
            self.parent.assignment(),
            self.parent.node(),
            self.parent.ownership_authority().clone(),
            grants,
            self.parent.policy_commitment(),
            self.parent.revocation_scope(),
            self.parent.issued_seconds(),
            self.expires_at,
            Vec::new(),
        )
        .map_err(rejected)
    }
}

impl CurrentOriginalAttachHostConsumeDraftV3<'_, '_> {
    /// Returns the narrowed unsigned plan for the existing broker-plan signer.
    #[must_use]
    pub const fn plan(&self) -> &BrokerAuthorizationPlan {
        &self.plan
    }

    /// Returns the original exact ticket bytes bound by this plan.
    #[must_use]
    pub fn original_ticket(&self) -> &[u8] {
        self.cut.original_ticket()
    }

    /// Returns the unchanged dedicated-key original receipt.
    #[must_use]
    pub fn original_grant(&self) -> &[u8; PUBLIC_ATTACH_GRANT_BYTES] {
        self.cut.original_grant()
    }

    /// Returns the protected current signed ownership-lease payload.
    #[must_use]
    pub fn ownership_lease(&self) -> &[u8] {
        &self.cut.ownership_lease
    }

    /// Returns the protected current ownership-lease signature.
    #[must_use]
    pub fn ownership_lease_signature(&self) -> &[u8] {
        &self.cut.ownership_lease_signature
    }

    /// Rechecks the owning cut immediately before the authenticated exchange.
    ///
    /// # Errors
    /// Rejects any current credential, clock, expiry, or journal custody failure.
    pub fn recheck(&self) -> Result<(), ControllerServiceError> {
        self.cut.recheck()
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Selects at most 32 currently assigned original accepted attach identities.
    ///
    /// The returned IDs are nonauthorizing data. Every poll and consume still
    /// requires the original-grant cut, genuine current authorization, and the
    /// independent monitor/Host/Guest observations. Selection does not renew or
    /// reconstruct any ticket, peer, grant, or session.
    ///
    /// # Errors
    /// Rejects a zero node or bound outside `1..=32`, malformed protected rows,
    /// unavailable fixed pins/time, or missing accepted operation lineage.
    pub fn current_original_attach_candidates_v3(
        &mut self,
        node: NodeId,
        maximum: usize,
    ) -> Result<Vec<OperationId>, ControllerServiceError> {
        if node.as_bytes() == &[0; 16] || !(1..=32).contains(&maximum) {
            return Err(rejected(()));
        }
        let key = PinnedSystemdCredential::load_attach_grant_public().map_err(rejected)?;
        let key_bytes: [u8; 32] = key.bytes().try_into().map_err(rejected)?;
        let verifier = VerifyingKey::from_bytes(&key_bytes).map_err(rejected)?;
        let now = ControllerProtectedClockV1::open_fixed()
            .map_err(rejected)?
            .sample()
            .map_err(rejected)?
            .wall_seconds();
        let candidates = select_original_candidates(
            self.reconciler.journal_mut(),
            node,
            maximum,
            now,
            &verifier,
        )?;
        for operation in &candidates {
            let accepted = self
                .reconciler
                .public_operation_authorization(*operation)?
                .ok_or_else(|| rejected(()))?;
            let original = crate::attach_decision::original_decision(
                self.reconciler.journal_mut(),
                *operation,
            )
            .map_err(rejected)?;
            let resolved =
                ResolvedPublicMutationRequestV1::decode(&original.request).map_err(rejected)?;
            require_original_request_scope(&original, &resolved, &accepted)?;
        }
        key.recheck().map_err(rejected)?;
        Ok(candidates)
    }

    /// Reauthorizes an original accepted attach while holding the writer through consume.
    ///
    /// No peer is synthesized and no new grant, session, or certificate is
    /// created. The exact accepted request supplies the closed scope. Original
    /// public TLS DER was not retained: current exact registration/trust joins
    /// accepted custody, not a resurrected TLS connection or fresh client proof.
    /// The SSH monitor independently proves current original-holder custody.
    ///
    /// # Errors
    /// Rejects absent/substituted original artifacts, a nonaccepted operation,
    /// changed current policy/revocation/trust/holder/assignment, or expiry.
    /// Closure errors and failed post-consume currentness are propagated.
    pub fn with_current_original_attach_consume_v3<T>(
        &mut self,
        operation: OperationId,
        node: NodeId,
        consume: impl for<'owner> FnOnce(
            &CurrentOriginalAttachConsumeCutV3<'owner>,
        ) -> Result<T, ControllerServiceError>,
    ) -> Result<T, ControllerServiceError> {
        let scope = self.scope;
        let accepted_scope = self
            .reconciler
            .public_operation_authorization(operation)?
            .ok_or_else(|| rejected(()))?;
        let journal = self.reconciler.journal_mut();
        let decision =
            crate::attach_decision::original_decision(journal, operation).map_err(rejected)?;
        let resolved =
            ResolvedPublicMutationRequestV1::decode(&decision.request).map_err(rejected)?;
        let DormantSandboxRequestKindV1::ExecutionControl(request) = resolved.request() else {
            return Err(rejected(()));
        };
        require_original_request_scope(&decision, &resolved, &accepted_scope)?;
        let registration = CurrentOriginalPublicRegistrationV3::load(
            decision.public_tls_trust,
            decision.caller,
            decision.project,
            ChannelBinding::new(decision.coordinates.channel_binding),
        )
        .map_err(rejected)?;
        let current = evaluate_current_protected_capability(
            journal,
            crate::publisher_authority::PublisherAuthorityLimits::default(),
            crate::publisher_policy::PublisherPolicyLimits::default(),
            CapabilityId::from_bytes(decision.coordinates.capability),
            decision.project,
            decision.caller,
            registration.key_binding(),
            &mut ControllerProtectedClockV1::open_fixed().map_err(rejected)?,
            resolved.resource_kind(),
            resolved.operation(),
            resolved.selector().ok_or_else(|| rejected(()))?,
        )
        .map_err(rejected)?;
        require_original_authority(&decision, &current)?;
        let now = current.authorized_wall_seconds();
        let pending = crate::public_attach_pending::load_public_attach_pending_v1(
            journal,
            resolved.idempotency_key(),
        )
        .map_err(rejected)?
        .ok_or_else(|| rejected(()))?;
        let request_digest =
            scope.public_request_digest(decision.caller, decision.project, &decision.request);
        if pending.operation_id() != operation
            || pending.request_digest() != request_digest
            || pending.principal_id() != *decision.caller.as_bytes()
            || request.execution_id.as_slice() != pending.execution_id()
            || journal.check_idempotency(resolved.idempotency_key(), request_digest)
                != IdempotencyOutcome::Replay(operation)
        {
            return Err(rejected(()));
        }
        let query = crate::public_attach_pending::prepare_public_attach_host_query_v1(
            journal,
            decision.project,
            node,
            pending.execution_id(),
            Some(&pending),
            now,
        )
        .map_err(rejected)?;
        let (parent, ownership_lease, ownership_lease_signature) = query.into_parts();
        let claims = current.capability().claims();
        if claims
            .sandbox
            .is_some_and(|sandbox| sandbox != parent.assignment().sandbox())
            || claims
                .incarnation
                .is_some_and(|incarnation| incarnation != parent.assignment().incarnation())
            || claims
                .assignment_epoch
                .is_some_and(|epoch| epoch.get() != parent.assignment().epoch().get())
        {
            return Err(rejected(()));
        }
        let publication = crate::publication::AuthorityPublicationStore::new(journal)
            .current(parent.assignment().sandbox())
            .map_err(rejected)?
            .ok_or_else(|| rejected(()))?;
        let grant_key = PinnedSystemdCredential::load_attach_grant_public().map_err(rejected)?;
        let attach_trust = PinnedSystemdCredential::load_attach_trust().map_err(rejected)?;
        let original_grant =
            crate::attach_decision::original_grant(journal, pending.record_digest())
                .map_err(rejected)?;
        let key_bytes: [u8; 32] = grant_key.bytes().try_into().map_err(rejected)?;
        let grant = verify_public_attach_pending_grant_v1(
            &original_grant,
            &VerifyingKey::from_bytes(&key_bytes).map_err(rejected)?,
        )
        .map_err(rejected)?;
        let original_ticket =
            crate::attach_decision::original_ticket(journal, operation).map_err(rejected)?;
        let ticket = PublicAttachTicketBindingV2::decode(original_ticket).map_err(rejected)?;
        let endpoint = crate::attach_route_issuer::load_public_attach_route_v1(
            journal,
            operation,
            request_digest,
        )
        .map_err(rejected)?;
        require_original_ticket(
            journal,
            operation,
            &decision,
            &ticket,
            &grant,
            &pending,
            &parent,
            &publication,
            &original_grant,
            &endpoint.client_certificate,
            &request.client_public_key,
            Sha256::digest(attach_trust.bytes()).into(),
            now,
        )?;
        let expires_at = parent
            .expires_seconds()
            .min(i64::try_from(ticket.expires_at).map_err(rejected)?)
            .min(decision.coordinates.capability_expires_at)
            .min(decision.coordinates.policy_expires_at);
        if expires_at <= now {
            return Err(rejected(()));
        }
        let deadline_boottime_nanoseconds = cut_deadline(current.clock(), expires_at)?;
        let cut = CurrentOriginalAttachConsumeCutV3 {
            journal,
            registration,
            grant_key,
            attach_trust,
            original_ticket,
            original_grant,
            parent,
            ownership_lease,
            ownership_lease_signature,
            original_clock: current.clock(),
            expires_at,
            deadline_boottime_nanoseconds,
        };
        cut.recheck()?;
        let result = consume(&cut)?;
        cut.recheck()?;
        Ok(result)
    }
}

fn require_original_authority(
    original: &crate::attach_decision::OriginalDecisionV2,
    current: &CurrentCapabilityDecisionV1,
) -> Result<(), ControllerServiceError> {
    if !crate::attach_decision::same_original_scope(
        &original.coordinates,
        &current.original_coordinates(original.coordinates.session_commitment),
    ) || current.authorized_wall_seconds() < original.accepted_wall_seconds
    {
        return Err(rejected(()));
    }
    Ok(())
}

fn require_original_request_scope(
    original: &crate::attach_decision::OriginalDecisionV2,
    resolved: &ResolvedPublicMutationRequestV1,
    accepted: &crate::PublicOperationAuthorizationV1,
) -> Result<(), ControllerServiceError> {
    let DormantSandboxRequestKindV1::ExecutionControl(request) = resolved.request() else {
        return Err(rejected(()));
    };
    if request.action.as_known() != Some(ExecutionControlAction::EXECUTION_CONTROL_ACTION_ATTACH)
        || resolved.resource_kind() != ResourceKind::Execution
        || resolved.operation() != Operation::LifecycleControl
        || accepted.project() != original.project
        || accepted.resource_kind() != resolved.resource_kind()
        || Some(accepted.selector()) != resolved.selector()
    {
        return Err(rejected(()));
    }
    Ok(())
}

fn select_original_candidates(
    journal: &Journal,
    node: NodeId,
    maximum: usize,
    now: i64,
    verifier: &VerifyingKey,
) -> Result<Vec<OperationId>, ControllerServiceError> {
    if node.as_bytes() == &[0; 16] || !(1..=32).contains(&maximum) {
        return Err(rejected(()));
    }
    let unix_seconds = u64::try_from(now).map_err(rejected)?;
    journal.ensure_protected_authority().map_err(rejected)?;
    crate::publication::validate_publication_namespace(journal).map_err(rejected)?;
    let projections =
        crate::controller_service::public_projection::PublicProjectionStoreV1::new(journal);
    let mut candidates = Vec::with_capacity(maximum);
    for item in crate::attach_decision::original_ticket_records(journal).map_err(rejected)? {
        let (operation, ticket) = item.map_err(rejected)?;
        let grant = verify_public_attach_pending_grant_v1(&ticket.pending_grant, verifier)
            .map_err(rejected)?;
        if grant.node_id != *node.as_bytes()
            || unix_seconds >= ticket.expires_at
            || unix_seconds < ticket.valid_after
            || now >= grant.expires_at
        {
            continue;
        }
        let Some(projection) = projections
            .get(
                crate::controller_service::public_projection::PublicProjectionKindV1::Execution,
                ticket.execution_id,
            )
            .map_err(rejected)?
        else {
            continue;
        };
        let crate::controller_service::public_projection::PublicProjectionResourceV1::Execution(
            execution,
        ) = projection.resource()
        else {
            return Err(rejected(()));
        };
        if projection.operation() != operation
            || execution.phase.as_known()
                != Some(aos_proto::aos::sandbox::v1::ExecutionPhase::EXECUTION_PHASE_RUNNING)
            || execution.sandbox_incarnation_id.as_slice() != ticket.incarnation_id
            || execution.assignment_epoch != ticket.assignment_epoch
            || execution.audit_id.as_slice() != ticket.audit_id
        {
            continue;
        }
        let sandbox = aos_sandbox_core::SandboxId::from_bytes(
            execution
                .sandbox_id
                .as_slice()
                .try_into()
                .map_err(rejected)?,
        );
        let Some(publication) =
            crate::publication::current_in_validated_namespace(journal, sandbox)
                .map_err(rejected)?
        else {
            continue;
        };
        let manifest = publication.manifest().manifest();
        if manifest.node() != node
            || manifest.project() != projection.project()
            || manifest.incarnation().as_bytes() != &ticket.incarnation_id
            || manifest.epoch().get() != ticket.assignment_epoch
            || grant.assignment_digest != *publication.manifest().digest().as_bytes()
            || grant.lease_generation != publication.lease_generation()
            || grant.lease_digest != *publication.lease_digest().as_bytes()
            || publication.lease().lease().authority_expires_seconds() <= now
        {
            continue;
        }
        if candidates.len() < maximum {
            candidates.push(operation);
        }
    }
    Ok(candidates)
}

#[allow(clippy::too_many_arguments)]
fn require_original_ticket(
    journal: &Journal,
    operation: OperationId,
    original: &crate::attach_decision::OriginalDecisionV2,
    ticket: &PublicAttachTicketBindingV2,
    grant: &PublicAttachPendingGrantV1,
    pending: &crate::public_attach_pending::PublicAttachPendingV1,
    parent: &BrokerAuthorizationPlan,
    publication: &crate::publication::CurrentAuthorityPublicationV1,
    original_grant: &[u8; PUBLIC_ATTACH_GRANT_BYTES],
    certificate: &[u8],
    request_holder: &[u8],
    current_trust_digest: [u8; 32],
    now: i64,
) -> Result<(), ControllerServiceError> {
    let issued = original.original_ticket.ok_or_else(|| rejected(()))?;
    if ticket.operation_id != *operation.as_bytes()
        || ticket.execution_id != pending.execution_id()
        || ticket.incarnation_id != pending.sandbox_incarnation_id()
        || ticket.principal_id != pending.principal_id()
        || ticket.audit_id != pending.audit_id()
        || ticket.assignment_epoch != pending.assignment_epoch()
        || ticket.request_digest != pending.request_digest()
        || ticket.decision_digest
            != crate::attach_decision::decision_digest(journal, operation).map_err(rejected)?
        || ticket.pending_grant != *original_grant
        || ticket.certificate != certificate
        || ticket.holder_public_key != issued.holder_public_key
        || ticket.valid_after != issued.valid_after
        || ticket.expires_at != issued.expires_at
        || ticket.base_route_digest != issued.base_route_digest
        || Sha256::digest(certificate).as_slice() != issued.certificate_digest
        || Sha256::digest(original_grant).as_slice() != issued.pending_grant_digest
        || grant.operation_id != ticket.operation_id
        || grant.execution_id != ticket.execution_id
        || grant.incarnation_id != ticket.incarnation_id
        || grant.principal_id != ticket.principal_id
        || grant.audit_id != ticket.audit_id
        || grant.assignment_epoch != ticket.assignment_epoch
        || grant.request_digest != ticket.request_digest
        || grant.pending_digest != pending.record_digest()
        || grant.expires_at != pending.expires_at()
        || grant.node_id != *parent.node().as_bytes()
        || grant.sandbox_id != *parent.assignment().sandbox().as_bytes()
        || grant.assignment_digest != *parent.assignment().digest().as_bytes()
        || grant.desired_generation != publication.manifest().manifest().desired_generation().get()
        || grant.namespace_generation
            != publication
                .manifest()
                .manifest()
                .namespace_generation()
                .get()
        || grant.lease_generation != publication.lease_generation()
        || grant.lease_digest != *publication.lease_digest().as_bytes()
        || grant.trust_digest != current_trust_digest
        || now >= grant.expires_at
    {
        return Err(rejected(()));
    }
    let cert =
        ssh_key::Certificate::from_openssh(std::str::from_utf8(certificate).map_err(rejected)?)
            .map_err(rejected)?;
    let holder =
        ssh_key::PublicKey::from_openssh(std::str::from_utf8(request_holder).map_err(rejected)?)
            .map_err(rejected)?;
    let now = u64::try_from(now).map_err(rejected)?;
    if cert.to_openssh().map_err(rejected)?.as_bytes() != certificate
        || cert.public_key().ed25519().map(|key| key.0) != Some(ticket.holder_public_key)
        || cert.public_key() != holder.key_data()
        || cert.cert_type() != ssh_key::certificate::CertType::User
        || cert.valid_after() != ticket.valid_after
        || cert.valid_before() != ticket.expires_at
        || now < ticket.valid_after
        || now >= ticket.expires_at
    {
        return Err(rejected(()));
    }
    // The original issuer was authenticated at admission. Exact accepted bytes
    // and unchanged signed deployment trust prevent substituting its CA here;
    // this signature check does not treat a supplied CA as independent authority.
    cert.validate_at(now, [&cert.signature_key().fingerprint(Default::default())])
        .map_err(rejected)?;
    Ok(())
}

fn rejected<T>(_: T) -> ControllerServiceError {
    OperationCompilationError::Rejected.into()
}

fn cut_deadline(
    original: RawPairedClockSample,
    expiry: i64,
) -> Result<u64, ControllerServiceError> {
    let remaining = expiry
        .checked_sub(original.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(|| rejected(()))?;
    remaining
        .checked_mul(1_000_000_000)
        .and_then(|nanoseconds| original.boottime_nanoseconds().checked_add(nanoseconds))
        .filter(|deadline| *deadline > original.boottime_nanoseconds())
        .ok_or_else(|| rejected(()))
}

fn require_cut_clock(
    original: RawPairedClockSample,
    later: RawPairedClockSample,
    expiry: i64,
    deadline: u64,
) -> Result<(), ControllerServiceError> {
    original.validate_later_sample(later).map_err(rejected)?;
    if later.wall_seconds() >= expiry || later.boottime_nanoseconds() >= deadline {
        return Err(rejected(()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "original_attach_grant_tests.rs"]
mod tests;
