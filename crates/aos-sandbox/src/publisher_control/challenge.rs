//! Live-execution-bound registration of immutable, pending publisher challenges.
//!
//! A pending receipt proves neither holder possession nor capability authority,
//! source authorization, root-registry currentness, admission, reservation, or
//! signing eligibility. The root-registry generation remains an unverified
//! request precondition. No challenge is consumed by this module.

use aos_sandbox_core::format::decode_publisher_admission_request_v1;
use aos_sandbox_core::{DecodeLimits, PublisherAdmissionRequestV1};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::publisher_ingress::{
    PublisherChallengeDraftV1, PublisherChallengeRegistrationV1, PublisherIngressWriteOutcome,
};
use crate::publisher_sessions::AuthenticatedPublisherRecord;

/// Returns owned pending audit facts without granting publication authority.
///
/// The request's holder, capability, source, reservation, and root-registry
/// generation remain unverified. Neither insertion nor exact replay consumes
/// the challenge or creates an admission decision or completion permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPublisherChallengeReceipt {
    /// Exact retained request and its original trusted registration timestamps.
    pub registration: PublisherChallengeRegistrationV1,
    /// Distinguishes a durable insertion from replay of identical retained facts.
    pub outcome: PublisherIngressWriteOutcome,
}

pub(crate) fn register_challenge<T>(
    journal: &mut Journal,
    sessions: &mut PublisherSessionRegistry,
    instance: PublisherInstanceId,
    config: PublisherControlPolicy,
    clock: &mut T,
) -> Result<PendingPublisherChallengeReceipt, PublisherControlError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config)?;
    if let Err(error) = journal.ensure_protected_authority() {
        // Storage failure cannot justify continued use of an already-installed
        // execution, but an unknown lookup handle needs no local cleanup.
        let _ = sessions.retire(instance);
        return Err(error.into());
    }
    let record = sessions.receive(instance)?;
    let result = register_record(journal, &record, config, clock);
    // An authenticated record exclusively borrows the live registry. Release
    // that borrow before closing the socket, while retaining its execution pin.
    drop(record);
    if result.as_ref().is_err_and(retires_session) {
        sessions.retire(instance)?;
    }
    result
}

fn register_record<T>(
    journal: &mut Journal,
    record: &AuthenticatedPublisherRecord<'_>,
    config: PublisherControlPolicy,
    clock: &mut T,
) -> Result<PendingPublisherChallengeReceipt, PublisherControlError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let request = decode_publisher_admission_request_v1(record.payload(), request_limits())?;
    let boot = KernelBootId::current()?.into_bytes();
    let observed = clock().map_err(|_| PublisherControlError::Clock)?;
    validate_clock(observed, boot, config.clock_provenance)?;

    let (execution, existing) = {
        let store = PublisherIngressStore::load(journal, config.ingress_limits)?;
        let execution = store
            .execution(record.instance())?
            .ok_or(PublisherIngressError::UnknownExecution)?;
        let existing = store.challenge(record.instance(), request.challenge())?;
        (execution, existing)
    };
    bind_execution(record, &execution, boot, config.clock_provenance)?;
    validate_execution_time(&execution, observed)?;
    bind_request(&request, &execution)?;
    let policy = resolve_policy(
        journal,
        *record.scope(),
        config.policy_limits,
        observed.wall_seconds(),
    )?;
    validate_current_request(journal, &request, &policy, config, observed.wall_seconds())?;

    // A used key is immutable even after expiry. Exact retries reuse the whole
    // original record rather than refreshing either wall or boottime deadlines.
    let registration = match existing {
        Some(existing) => {
            if existing.fields().request != request {
                return Err(PublisherIngressError::IdentityConflict.into());
            }
            existing
        }
        None => {
            let maximum_expiry = observed
                .wall_seconds()
                .checked_add(i64::from(config.maximum_challenge_seconds))
                .ok_or(PublisherControlError::Clock)?;
            let expiry = request
                .plan()
                .fields()
                .expires_seconds
                .min(policy.revision.expires_at())
                .min(maximum_expiry);
            PublisherChallengeRegistrationV1::new(PublisherChallengeDraftV1 {
                request,
                boot_id: boot,
                clock_provenance: config.clock_provenance,
                registered_wall_seconds: observed.wall_seconds(),
                registered_boottime_nanoseconds: observed.boottime_nanoseconds(),
                expires_wall_seconds: expiry,
            })?
        }
    };
    validate_registration_clock(&registration, observed, boot, config)?;
    if registration.fields().expires_wall_seconds > policy.revision.expires_at() {
        return Err(PublisherControlError::PolicyDenied);
    }

    bind_execution(record, &execution, boot, config.clock_provenance)?;
    let transaction_id = transaction_id(&registration);
    let outcome = PublisherIngressStore::load(journal, config.ingress_limits)?
        .register_challenge(transaction_id, registration.clone())?;

    // A postcommit failure leaves immutable inert facts available for audit.
    // It cannot turn this pending registration into an admission or a permit.
    bind_execution(record, &execution, boot, config.clock_provenance)?;
    let fresh = clock().map_err(|_| PublisherControlError::Clock)?;
    validate_clock(fresh, boot, config.clock_provenance)?;
    validate_elapsed(
        observed,
        fresh,
        registration.fields().expires_wall_seconds,
        u64::from(config.maximum_challenge_seconds),
    )?;
    validate_registration_clock(&registration, fresh, boot, config)?;
    bind_execution(record, &execution, boot, config.clock_provenance)?;
    Ok(PendingPublisherChallengeReceipt {
        registration,
        outcome,
    })
}

fn request_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: 32 * 1024,
        maximum_collection_items: 64,
        maximum_total_items: 1024,
        maximum_byte_string_bytes: 32,
        maximum_text_bytes: 255,
        maximum_depth: 16,
    }
}

fn bind_execution(
    record: &AuthenticatedPublisherRecord<'_>,
    execution: &PublisherExecutionRegistrationV1,
    boot: [u8; 16],
    provenance: [u8; 16],
) -> Result<(), PublisherControlError> {
    let fields = execution.fields();
    let scope = record.scope();
    let peer = record.recheck()?;
    if fields.instance != record.instance()
        || fields.principal != scope.principal
        || fields.node != scope.node
        || fields.project != scope.project
        || fields.cache_resource != scope.cache_resource
        || fields.channel_binding != record.channel_binding()
        || fields.boot_id != boot
        || fields.clock_provenance != provenance
        || fields.peer_pid != peer.pid()
        || fields.peer_tgid != peer.thread_group_id()
        || Some(fields.peer_cgroup_id) != peer.cgroup_id()
    {
        return Err(PublisherIngressError::ExecutionMismatch.into());
    }
    Ok(())
}

fn bind_request(
    request: &PublisherAdmissionRequestV1,
    execution: &PublisherExecutionRegistrationV1,
) -> Result<(), PublisherControlError> {
    let target = &request.plan().fields().target;
    let fields = execution.fields();
    if target.instance != fields.instance
        || target.principal != fields.principal
        || target.node != fields.node
        || target.project != fields.project
        || target.cache_domain != fields.cache_domain
        || target.isolation_policy != fields.isolation_policy
        || request.cache_resource() != fields.cache_resource
    {
        return Err(PublisherIngressError::ExecutionMismatch.into());
    }
    // The request's channel names the separately authenticated holder, not this
    // publisher connection. It remains an unverified admission precondition.
    Ok(())
}

fn validate_current_request(
    journal: &mut Journal,
    request: &PublisherAdmissionRequestV1,
    policy: &ResolvedPolicy,
    config: PublisherControlPolicy,
    now: i64,
) -> Result<(), PublisherControlError> {
    let fields = request.plan().fields();
    let authority = &fields.authority;
    let store = PublisherPolicyStore::load(journal, config.policy_limits)?;
    let revocation = store
        .revocation_head(authority.revocation_scope)?
        .ok_or(PublisherControlError::PolicyDenied)?;
    if authority.policy != policy.revision.descriptor().digest()
        || authority.policy_generation != policy.revision.generation()
        || authority.controller_generation != policy.controller.generation
        || authority.revocation_generation != revocation.generation
        || fields.target.cache_domain != policy.resource.cache_domain()
        || fields.target.isolation_policy != policy.resource.isolation_policy()
    {
        return Err(PublisherControlError::PolicyDenied);
    }
    if now < fields.issued_seconds || now >= fields.expires_seconds {
        return Err(PublisherControlError::Clock);
    }
    // No protected root-registry authority exists on this path. In particular,
    // equality to a request-supplied root generation would prove nothing.
    Ok(())
}

fn validate_execution_time(
    execution: &PublisherExecutionRegistrationV1,
    now: RawPairedClockSample,
) -> Result<(), PublisherControlError> {
    let fields = execution.fields();
    if now.wall_seconds() < fields.registered_wall_seconds
        || now.boottime_nanoseconds() < fields.registered_boottime_nanoseconds
    {
        return Err(PublisherControlError::Clock);
    }
    Ok(())
}

fn validate_registration_clock(
    registration: &PublisherChallengeRegistrationV1,
    now: RawPairedClockSample,
    boot: [u8; 16],
    config: PublisherControlPolicy,
) -> Result<(), PublisherControlError> {
    let fields = registration.fields();
    let lifetime = fields
        .expires_wall_seconds
        .checked_sub(fields.registered_wall_seconds)
        .and_then(|duration| u64::try_from(duration).ok())
        .ok_or(PublisherControlError::Clock)?;
    let elapsed = now
        .boottime_nanoseconds()
        .checked_sub(fields.registered_boottime_nanoseconds)
        .ok_or(PublisherControlError::Clock)?;
    let deadline = lifetime
        .checked_mul(1_000_000_000)
        .ok_or(PublisherControlError::Clock)?;
    if fields.boot_id != boot
        || fields.clock_provenance != config.clock_provenance
        || lifetime == 0
        || lifetime > u64::from(config.maximum_challenge_seconds)
        || now.wall_seconds() < fields.registered_wall_seconds
        || now.wall_seconds() >= fields.expires_wall_seconds
        || elapsed >= deadline
    {
        return Err(PublisherControlError::Clock);
    }
    Ok(())
}

fn transaction_id(registration: &PublisherChallengeRegistrationV1) -> [u8; 16] {
    let request = &registration.fields().request;
    let mut hash = Sha256::new();
    hash.update(b"aos-pending-publisher-challenge-transaction-v1\0");
    hash.update(request.plan().fields().target.instance.as_bytes());
    hash.update(request.challenge().as_bytes());
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hash.finalize()[..16]);
    id
}

fn retires_session(error: &PublisherControlError) -> bool {
    matches!(
        error,
        PublisherControlError::Request(_)
            | PublisherControlError::Kernel(_)
            | PublisherControlError::Session(_)
            | PublisherControlError::Journal(_)
            | PublisherControlError::Ingress(
                PublisherIngressError::ExecutionMismatch
                    | PublisherIngressError::UnknownExecution
                    | PublisherIngressError::Journal(_)
            )
            | PublisherControlError::Policy(PublisherPolicyError::Journal(_))
    )
}
