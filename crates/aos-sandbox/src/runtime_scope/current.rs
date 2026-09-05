//! Protected holder/publication selection joined to a fresh Host observation.
//!
//! The journal remains exclusively borrowed across selection, cryptographic
//! verification, Host exchange, and post-exchange checks. No caller can attach
//! arbitrary holder claims to an independently acquired observation. Retained
//! proofs are short-lived, exact-revision evidence, not endpoint grants.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, ObservePayloadScopeRequest, RequestHeader,
};
use aos_sandbox_core::format::{DecodeLimits, decode_signature};
use aos_sandbox_core::{
    BrokerAudience, BrokerPlanExpectation, BrokerPlanRequest, BrokerPlanTrustAnchor, NodeId,
    PrincipalId, RawPairedClockSample, SandboxId, verify_broker_plan,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_ownership_protocol::{
    OwnershipAuthorityVerifier, SignedOwnershipLease, UnverifiedOwnershipLeaseResponse,
};
use rand::{TryRngCore as _, rngs::OsRng};

use super::*;
use crate::Journal;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::publication::{
    AuthorityPublicationStore, CurrentAuthorityPublicationV1, RecoveredBrokerDispatchTemplateV1,
};
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
    RuntimeAuthorityStore,
};

mod validity;
use validity::ObservationValidity;
#[cfg(test)]
mod tests;

/// Selects an already authenticated holder without supplying assignment facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeScopeHolder {
    /// Sandbox whose protected current binding is required.
    pub sandbox: SandboxId,
    /// Authenticated principal that must match the protected holder decision.
    pub holder: PrincipalId,
}

/// Pins trusted deployment authority and bounds one current-runtime observation.
pub struct CurrentRuntimeScopePolicy {
    /// Exact local node identity, independent of request and journal contents.
    pub node: NodeId,
    /// Protected paired-clock adapter identity, never supplied by an RPC peer.
    pub clock_provenance: [u8; 16],
    /// Maximum observation lifetime in seconds, within `1..=30`.
    pub maximum_validity_seconds: u32,
    /// Bounds complete protected runtime-authority replay.
    pub runtime_limits: RuntimeAuthorityLimits,
    /// Pinned ownership authority used to reverify the lease and transaction receipt.
    pub ownership_verifier: OwnershipAuthorityVerifier,
    /// Pinned controller-plan trust anchor, independent of returned artifacts.
    pub broker_anchor: BrokerPlanTrustAnchor,
}

/// Reports failure to join protected current state with live runtime evidence.
#[derive(Debug, thiserror::Error)]
pub enum CurrentRuntimeScopeError {
    /// The selector, node, clock provenance, or lifetime bound is invalid.
    #[error("invalid current-runtime configuration or selector")]
    Configuration,
    /// Kernel randomness for a fresh request identity is unavailable.
    #[error("current runtime request entropy is unavailable")]
    EntropyUnavailable,
    /// The selected holder is absent, revoked, replaced, or belongs to another node.
    #[error("current runtime holder or publication does not match")]
    CurrentMismatch,
    /// No current Host 1.2 plan grants this exact payload-scope query.
    #[error("current publication does not grant payload-scope observation")]
    MissingGrant,
    /// Clock provenance, boot, ordering, expiry, or deadline arithmetic failed.
    #[error("current runtime observation clock or validity failed")]
    Clock,
    /// Protected runtime-authority replay failed.
    #[error(transparent)]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// Protected publication replay failed.
    #[error(transparent)]
    Publication(#[from] crate::publication::AuthorityPublicationError),
    /// The activated ownership-claim cross-links failed.
    #[error(transparent)]
    Reconciler(#[from] crate::ReconcilerError),
    /// Cryptographic ownership-lease or transaction-receipt verification failed.
    #[error(transparent)]
    Ownership(#[from] aos_sandbox_ownership_protocol::OwnershipLeaseAcquisitionError),
    /// Signed Host plan verification or exact grant matching failed.
    #[error(transparent)]
    Plan(#[from] aos_sandbox_core::BrokerPlanVerificationError),
    /// The Host exchange or retained kernel execution observation failed.
    #[error(transparent)]
    Observation(#[from] RuntimeScopeError),
}

/// Owns short-lived evidence for one exact protected holder revision and runtime.
///
/// Acquisition authenticates the Host and independently verifies current plan
/// and ownership signatures. This object grants no endpoint or publication
/// permission. Every later use must recheck protected current state and clocks;
/// even a successful recheck cannot fence subsequent exit or state changes.
/// Renewal or rebind requires reacquisition, including same-holder ABA changes.
/// Restart cannot reconstruct the retained executions from journal bytes.
///
/// ```compile_fail
/// use aos_sandbox::runtime_scope::CurrentRuntimeScope;
/// fn copy(proof: &CurrentRuntimeScope) -> CurrentRuntimeScope { proof.clone() }
/// ```
pub struct CurrentRuntimeScope {
    selection: RuntimeScopeHolder,
    policy: CurrentRuntimeScopePolicy,
    binding: RuntimeAuthorityBindingV1,
    observed: ObservedPayloadScope,
    validity: ObservationValidity,
}

impl CurrentRuntimeScope {
    /// Borrows the exact protected holder decision selected during acquisition.
    #[must_use]
    pub const fn binding(&self) -> &RuntimeAuthorityBindingV1 {
        &self.binding
    }

    /// Borrows the complete retained Host and payload observation.
    #[must_use]
    pub const fn observed(&self) -> &ObservedPayloadScope {
        &self.observed
    }

    /// Returns the fixed, exclusive BOOTTIME validity bound, never renewed by rechecks.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.validity.deadline()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), CurrentRuntimeScopeError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        transport::check_deadline(self.validity.deadline())?;
        let fresh = read_clock(&self.policy, clock)?;
        self.validity.check(fresh)?;
        let publication =
            select_exact_current(journal, self.selection, &self.policy, &self.binding)?;
        let lease = verify_lease(journal, &self.binding, &publication, &self.policy, fresh)?;
        let artifacts = self.observed.authorization();
        let template = publication
            .templates()
            .iter()
            .find(|template| {
                template.canonical_plan() == artifacts.broker_plan()
                    && template.canonical_plan_signature() == artifacts.broker_plan_signature()
            })
            .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
        if lease.canonical_lease() != artifacts.ownership_lease()
            || lease.canonical_signature() != artifacts.ownership_lease_signature()
        {
            return Err(CurrentRuntimeScopeError::CurrentMismatch);
        }
        verify_plan(template, &self.binding, &self.policy, &lease, fresh)?;
        self.observed.recheck()?;
        self.validity.check(read_clock(&self.policy, clock)?)?;
        transport::check_deadline(self.validity.deadline())?;
        Ok(())
    }
}

pub(crate) fn acquire<T>(
    journal: &mut Journal,
    selection: RuntimeScopeHolder,
    client: RuntimeScopeClient,
    policy: CurrentRuntimeScopePolicy,
    clock: &mut T,
) -> Result<CurrentRuntimeScope, CurrentRuntimeScopeError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if selection.sandbox.as_bytes() == &[0; 16]
        || selection.holder.as_bytes() == &[0; 16]
        || policy.node.as_bytes() == &[0; 16]
        || policy.clock_provenance == [0; 16]
        || !(1..=30).contains(&policy.maximum_validity_seconds)
    {
        return Err(CurrentRuntimeScopeError::Configuration);
    }
    let initial = read_clock(&policy, clock)?;
    let prepared = prepare(journal, selection, &policy, initial)?;
    let observed = client.observe(
        &prepared.body,
        AuthorizationArtifactBytes {
            broker_plan: prepared.template.canonical_plan(),
            broker_plan_signature: prepared.template.canonical_plan_signature(),
            ownership_lease: prepared.lease.canonical_lease(),
            ownership_lease_signature: prepared.lease.canonical_signature(),
        },
    )?;
    let result = CurrentRuntimeScope {
        selection,
        policy,
        binding: prepared.binding,
        observed,
        validity: prepared.validity,
    };
    result.recheck(journal, clock)?;
    Ok(result)
}

/// Holds non-authorizing request inputs; only the real exchange constructs a scope.
struct PreparedCurrentObservation {
    binding: RuntimeAuthorityBindingV1,
    template: RecoveredBrokerDispatchTemplateV1,
    lease: SignedOwnershipLease,
    body: Vec<u8>,
    validity: ObservationValidity,
}

fn prepare(
    journal: &mut Journal,
    selection: RuntimeScopeHolder,
    policy: &CurrentRuntimeScopePolicy,
    initial: RawPairedClockSample,
) -> Result<PreparedCurrentObservation, CurrentRuntimeScopeError> {
    let (binding, publication) = select_current(journal, selection, policy)?;
    let lease = verify_lease(journal, &binding, &publication, policy, initial)?;
    let provisional_deadline = initial
        .boottime_nanoseconds()
        .checked_add(u64::from(policy.maximum_validity_seconds) * 1_000_000_000)
        .ok_or(CurrentRuntimeScopeError::Clock)?;
    let mut body = request_body(&binding, provisional_deadline)?;
    let decoded = decode_local_body(&body.encode_to_vec(), initial.boottime_nanoseconds())?;
    let semantics =
        aos_sandbox_protocol::semantics::payload_scope::canonical_payload_scope_semantics_v1(
            &decoded,
        )
        .map_err(|_| CurrentRuntimeScopeError::MissingGrant)?;
    let template = publication
        .templates()
        .iter()
        .find(|template| {
            template.audience() == BrokerAudience::Host
                && template.plan().protocol_version() == VERSION
                && template.plan().grants().iter().any(|grant| {
                    grant.verb() == semantics.verb()
                        && grant.target() == semantics.target()
                        && grant.argument_commitment() == semantics.commitment()
                })
        })
        .ok_or(CurrentRuntimeScopeError::MissingGrant)?;
    let verified = verify_plan(template, &binding, policy, &lease, initial)?;
    let validity = ObservationValidity::new(
        initial,
        &lease,
        verified.plan().expires_seconds(),
        policy.maximum_validity_seconds,
    )?;
    body.header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = validity.deadline();
    let body = body.encode_to_vec();
    verified.match_request(BrokerPlanRequest {
        verb: semantics.verb(),
        target: semantics.target(),
        argument_commitment: semantics.commitment(),
        request_bytes: u32::try_from(body.len())
            .map_err(|_| CurrentRuntimeScopeError::MissingGrant)?,
        descriptor_count: 0,
    })?;
    Ok(PreparedCurrentObservation {
        binding,
        template: template.clone(),
        lease,
        body,
        validity,
    })
}

fn select_current(
    journal: &mut Journal,
    selection: RuntimeScopeHolder,
    policy: &CurrentRuntimeScopePolicy,
) -> Result<(RuntimeAuthorityBindingV1, CurrentAuthorityPublicationV1), CurrentRuntimeScopeError> {
    let binding = RuntimeAuthorityStore::load(journal, policy.runtime_limits)?
        .current(selection.sandbox)?
        .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || binding.holder() != Some(selection.holder)
        || binding.manifest().manifest().node() != policy.node
    {
        return Err(CurrentRuntimeScopeError::CurrentMismatch);
    }
    let publication = AuthorityPublicationStore::new(journal)
        .current(selection.sandbox)?
        .ok_or(CurrentRuntimeScopeError::CurrentMismatch)?;
    if publication.digest() != binding.publication_digest()
        || publication.manifest() != binding.manifest()
        || publication.lease_generation() != binding.lease_generation()
        || publication.lease_digest() != binding.lease_digest()
    {
        return Err(CurrentRuntimeScopeError::CurrentMismatch);
    }
    Ok((binding, publication))
}

/// Requires the full immutable revision, so renewal and holder ABA cannot reuse a proof.
fn select_exact_current(
    journal: &mut Journal,
    selection: RuntimeScopeHolder,
    policy: &CurrentRuntimeScopePolicy,
    expected: &RuntimeAuthorityBindingV1,
) -> Result<CurrentAuthorityPublicationV1, CurrentRuntimeScopeError> {
    let (binding, publication) = select_current(journal, selection, policy)?;
    if &binding != expected {
        return Err(CurrentRuntimeScopeError::CurrentMismatch);
    }
    Ok(publication)
}

fn verify_lease(
    journal: &Journal,
    binding: &RuntimeAuthorityBindingV1,
    publication: &CurrentAuthorityPublicationV1,
    policy: &CurrentRuntimeScopePolicy,
    clock: RawPairedClockSample,
) -> Result<SignedOwnershipLease, CurrentRuntimeScopeError> {
    let claim = crate::reconciler::runtime_authority_claim(journal, binding)?;
    let lease = publication.lease();
    Ok(policy.ownership_verifier.verify_response(
        &claim,
        UnverifiedOwnershipLeaseResponse::from_transport(
            lease.canonical_lease().to_vec(),
            lease.canonical_signature().to_vec(),
            lease.canonical_receipt().to_vec(),
            lease.canonical_receipt_signature().to_vec(),
        )?,
        &clock,
    )?)
}

fn verify_plan(
    template: &RecoveredBrokerDispatchTemplateV1,
    binding: &RuntimeAuthorityBindingV1,
    policy: &CurrentRuntimeScopePolicy,
    lease: &SignedOwnershipLease,
    clock: RawPairedClockSample,
) -> Result<aos_sandbox_core::VerifiedBrokerPlan, CurrentRuntimeScopeError> {
    let signature = decode_signature(template.canonical_plan_signature(), DecodeLimits::default())
        .map_err(aos_sandbox_core::BrokerPlanVerificationError::from)?;
    let verified = verify_broker_plan(
        template.canonical_plan(),
        &signature,
        &policy.broker_anchor,
        BrokerPlanExpectation {
            audience: BrokerAudience::Host,
            protocol: ProtocolId::HostBroker,
            protocol_version: VERSION,
            assignment: binding
                .manifest()
                .broker_assignment()
                .map_err(|_| CurrentRuntimeScopeError::CurrentMismatch)?,
            node: policy.node,
            now_seconds: clock.wall_seconds(),
        },
        DecodeLimits::default(),
    )?;
    if verified.plan().ownership_authority() != lease.signer() {
        return Err(CurrentRuntimeScopeError::CurrentMismatch);
    }
    Ok(verified)
}

fn request_body(
    binding: &RuntimeAuthorityBindingV1,
    deadline: u64,
) -> Result<ObservePayloadScopeRequest, CurrentRuntimeScopeError> {
    let mut request_id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| CurrentRuntimeScopeError::EntropyUnavailable)?;
    request_id[6] = (request_id[6] & 0x0f) | 0x40;
    request_id[8] = (request_id[8] & 0x3f) | 0x80;
    let manifest = binding.manifest().manifest();
    Ok(ObservePayloadScopeRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 2,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: manifest.sandbox().as_bytes().to_vec(),
            incarnation_id: manifest.incarnation().as_bytes().to_vec(),
            assignment_epoch: manifest.epoch().get(),
            desired_generation: manifest.desired_generation().get(),
            assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        runtime_handle: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            manifest.incarnation().as_bytes(),
            manifest.epoch().get(),
            binding.assignment_digest().as_bytes(),
        )
        .to_vec(),
        ..Default::default()
    })
}

fn decode_local_body(
    body: &[u8],
    now: u64,
) -> Result<
    aos_sandbox_protocol::payload_scope::ValidatedPayloadScopeRequest,
    CurrentRuntimeScopeError,
> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    decode_payload_scope_request(
        body,
        PeerCredentials {
            uid,
            gid,
            pid: Some(std::process::id()),
        },
        PeerPolicy {
            uid,
            gid: Some(gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )
    .map_err(RuntimeScopeError::from)
    .map_err(CurrentRuntimeScopeError::from)
}

fn read_clock<T>(
    policy: &CurrentRuntimeScopePolicy,
    clock: &mut T,
) -> Result<RawPairedClockSample, CurrentRuntimeScopeError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let boot = KernelBootId::current()
        .map_err(RuntimeScopeError::from)?
        .into_bytes();
    let sample = clock().map_err(|_| CurrentRuntimeScopeError::Clock)?;
    // Provenance labels alone cannot make a frozen or replayed adapter sample
    // fresh. Independently bound it to the kernel clock used by the transport.
    if sample.host_boot_id() != boot
        || sample.provenance().as_bytes() != policy.clock_provenance
        || sample
            .boottime_nanoseconds()
            .abs_diff(transport::boottime()?)
            > aos_sandbox_core::ownership_lease::CLOCK_PAIR_TOLERANCE_NANOSECONDS
    {
        return Err(CurrentRuntimeScopeError::Clock);
    }
    Ok(sample)
}
