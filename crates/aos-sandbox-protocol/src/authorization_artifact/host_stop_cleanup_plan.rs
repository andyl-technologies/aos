//! Shares the exact nonissuing Stop cleanup request and unsigned plan recipe.
//!
//! Root and Controller independently authenticate the current Recover, Source
//! dispatch, Host inventory, assignment, live lease and policy before entry.
//! These functions normalize DATA only. They supply neither a signature nor a
//! native signing loan, receiving interval, old Stop owner or effect permission.

use std::error::Error;

use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, Audience, RuntimeAction};
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, CanonicalAssignmentManifestV1, DecodeLimits, DesiredGeneration, FeatureRef,
    ObjectDigest, ProtocolId, ProtocolVersion, RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use buffa::Message as _;

use super::{BrokerPlanPreparation, SigningAuthority};
use crate::host_stop_cleanup::HostStopCleanupSubjectDataV1;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, thiserror::Error)]
#[error("the current Stop cleanup request, scope or original validity changed")]
struct Changed;

/// Retains the ordinary unsigned HostStop plan and its exact live request body.
pub struct StopCleanupPlanPreparationDataV1 {
    /// Holds the canonical plan and ordinary general-authority signing request.
    pub preparation: BrokerPlanPreparation,
    /// Holds only the canonical template with its admitted deadline inserted.
    pub request_body: Vec<u8>,
}

/// Encodes one deadline-free Stop cleanup from current assignment DATA.
///
/// The desired-Stopped generation remains distinct from the binding's observed
/// generation. Only the namespace identity and assignment digest come from the
/// binding. The signed subject retains the original Launch/Stop fence unchanged.
///
/// # Errors
/// Refuses a foreign namespace, regressed generation, reused request identity,
/// or any canonical runtime-template validation failure.
pub fn host_stop_cleanup_request_body_data_v1(
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    subject: HostStopCleanupSubjectDataV1,
) -> Result<Vec<u8>> {
    let original = manifest.broker_assignment()?;
    let assignment = BrokerAssignment::new(
        original.sandbox(),
        original.incarnation(),
        original.epoch(),
        DesiredGeneration::new(desired_generation),
        original.digest(),
    )?;
    request_body(assignment, subject)
}

fn request_body(
    assignment: BrokerAssignment,
    subject: HostStopCleanupSubjectDataV1,
) -> Result<Vec<u8>> {
    let mut request = ApplyRuntimeRequest::default();
    let header = request.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 0;
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.request_id = subject.cleanup_request_v1().to_vec();
    header.maximum_response_bytes = crate::MINIMUM_RESPONSE_BYTES;

    let fence = request.fence.get_or_insert_default();
    fence.sandbox_id = assignment.sandbox().as_bytes().to_vec();
    fence.incarnation_id = assignment.incarnation().as_bytes().to_vec();
    fence.assignment_epoch = assignment.epoch().get();
    fence.desired_generation = assignment.desired_generation().get();
    fence.assignment_digest = assignment.digest().as_bytes().to_vec();
    request.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
    request.host_stop_cleanup_v1 = subject.encode_v1().to_vec();

    let body = request.encode_to_vec();
    let (template, _) =
        crate::runtime_template::decode_runtime_template_with_header_data_v2(&body)?;
    subject.require_request_data_v1(subject.cleanup_request_v1(), template.fence(), 0)?;
    Ok(body)
}

/// Prepares the exact ordinary HostStop grant for a fresh cleanup interval.
///
/// # Errors
/// Refuses changed canonical body/subject/current scope, a foreign lease,
/// exhausted original D or expired current capability, policy or lease.
#[allow(clippy::too_many_arguments)]
pub fn prepare_host_stop_cleanup_plan_v1(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    subject: HostStopCleanupSubjectDataV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    cap_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StopCleanupPlanPreparationDataV1> {
    let expires = super::storage_create_plan::plan_expiry_v1(
        sample,
        cutoff,
        policy_expires.min(cap_expires),
        lease.authority_expires_seconds(),
    )?;
    prepare_at(
        deadline_free_body,
        manifest,
        desired_generation,
        subject,
        policy_digest,
        lease,
        sample,
        cutoff,
        sample.wall_seconds(),
        expires,
        authority,
        revocation_scope,
    )
}

/// Rebuilds the admitted Stop plan before borrowing the actual general signer.
///
/// Root and Controller share this recipe. A parsed plan/statement supplies no
/// signing authority; the enclosing native purpose must independently retain
/// current Recover/Source/C/Host/ownership and finance every representation.
///
/// # Errors
/// Refuses different canonical plan/statement bytes, changed inputs or any
/// validity outside the original finite current authority intersection.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_host_stop_cleanup_plan_v1(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    subject: HostStopCleanupSubjectDataV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    cap_expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_plan: &[u8],
    canonical_statement: &[u8],
) -> Result<StopCleanupPlanPreparationDataV1> {
    let admitted = aos_sandbox_core::format::decode_broker_authorization_plan(
        canonical_plan,
        DecodeLimits::default(),
    )?;
    let maximum = super::storage_create_plan::plan_expiry_v1(
        sample,
        cutoff,
        policy_expires.min(cap_expires),
        lease.authority_expires_seconds(),
    )?;
    if admitted.expires_seconds() > maximum {
        return Err(Box::new(Changed));
    }
    let prepared = prepare_at(
        deadline_free_body,
        manifest,
        desired_generation,
        subject,
        policy_digest,
        lease,
        sample,
        cutoff,
        admitted.issued_seconds(),
        admitted.expires_seconds(),
        authority,
        revocation_scope,
    )?;
    if prepared.preparation.canonical_plan() != canonical_plan
        || prepared.preparation.signing_request().canonical_statement() != canonical_statement
    {
        return Err(Box::new(Changed));
    }
    Ok(prepared)
}

#[allow(clippy::too_many_arguments)]
fn prepare_at(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    subject: HostStopCleanupSubjectDataV1,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    issued: i64,
    expires: i64,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<StopCleanupPlanPreparationDataV1> {
    if deadline_free_body
        != host_stop_cleanup_request_body_data_v1(manifest, desired_generation, subject)?
        || subject.current_boot_v1() != &sample.host_boot_id()
        || cutoff > subject.original_cutoff_v1()
        || cutoff == 0
    {
        return Err(Box::new(Changed));
    }
    super::storage_create_plan::require_admitted_clock_v1(
        sample,
        cutoff,
        issued,
        expires,
        lease.authority_issued_seconds(),
        lease.authority_expires_seconds(),
    )?;
    let (template, _) =
        crate::runtime_template::decode_runtime_template_with_header_data_v2(deadline_free_body)?;
    let assignment = template.fence().broker_assignment()?;
    let owned = lease.assignment();
    if assignment.sandbox() != owned.sandbox()
        || assignment.incarnation() != owned.incarnation()
        || assignment.epoch() != owned.epoch()
        || assignment.digest() != owned.digest()
        || lease.node() != manifest.manifest().node()
    {
        return Err(Box::new(Changed));
    }
    let semantics = crate::semantics::host::canonical_host_template_semantics_v1(&template)?;
    if semantics.verb() != BrokerVerb::HostStop
        || !matches!(semantics.target(), BrokerGrantTarget::Resource(_))
        || template.host_stop_cleanup_v1() != Some(&subject)
    {
        return Err(Box::new(Changed));
    }
    let request_body = crate::dispatch_template::inject_deadline(deadline_free_body, cutoff)?;
    let grant = BrokerGrant::new(
        BrokerVerb::HostStop,
        semantics.target(),
        semantics.commitment(),
        crate::dispatch_template::deadline_free_template_request_bytes_v1(deadline_free_body)?,
        0,
    )?;
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 0),
        assignment,
        lease.node(),
        lease.signer().clone(),
        vec![grant],
        policy_digest,
        revocation_scope,
        issued,
        expires,
        vec![FeatureRef::new(
            "aos.sandbox.authorization.signed-plan-lease",
            1,
            0,
        )?],
    )?;
    Ok(StopCleanupPlanPreparationDataV1 {
        preparation: BrokerPlanPreparation::new(plan, authority)?,
        request_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_stopped_namespace::HostStoppedNamespaceDataV4;
    use aos_sandbox_core::{AssignmentEpoch, IncarnationId, SandboxId};

    fn assignment(generation: u64) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(generation),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap()
    }

    fn subject(dispatched: bool) -> HostStopCleanupSubjectDataV1 {
        let old = HostStoppedNamespaceDataV4::from_data_v4(
            [6; 16],
            crate::ValidatedAssignmentFence {
                sandbox_id: [1; 16],
                incarnation_id: [2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: [5; 32],
            },
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        if dispatched {
            HostStopCleanupSubjectDataV1::from_dispatched_data_v2(
                old.launch_scope_v1(),
                old.stop_v4(),
                [14; 16],
                [15; 16],
                [16; 32],
                [17; 16],
                [18; 32],
                40_000_000_000,
            )
            .unwrap()
        } else {
            HostStopCleanupSubjectDataV1::from_data_v1(
                old,
                [14; 16],
                [15; 16],
                [16; 32],
                [17; 16],
                [18; 32],
                40_000_000_000,
            )
            .unwrap()
        }
    }

    #[test]
    fn canonical_cleanup_preserves_source_tuple_and_distinct_desired_generation() {
        let subject = subject(false);
        let body = request_body(assignment(7), subject).unwrap();
        let (template, header) =
            crate::runtime_template::decode_runtime_template_with_header_data_v2(&body).unwrap();

        assert_eq!(header.request_id, *subject.cleanup_request_v1());
        assert_eq!(header.deadline_boottime_nanoseconds, 0);
        assert_eq!(template.action(), RuntimeAction::RUNTIME_ACTION_STOP);
        assert!(template.launch_plan().is_none());
        assert!(template.guardian_arm().is_none());
        assert_eq!(template.fence().desired_generation(), 7);
        assert_eq!(template.host_stop_cleanup_v1(), Some(&subject));
        assert_eq!(
            subject
                .historical_scope_v1()
                .fence_v4()
                .desired_generation(),
            4
        );
        assert_eq!(
            subject.historical_scope_v1().stop_v4(),
            ([11; 16], [12; 32], [13; 32])
        );
        assert_ne!(subject.historical_scope_v1().stop_v4().0, header.request_id);

        assert!(request_body(assignment(3), subject).is_err());
        let foreign = BrokerAssignment::new(
            SandboxId::from_bytes([99; 16]),
            assignment(7).incarnation(),
            assignment(7).epoch(),
            assignment(7).desired_generation(),
            assignment(7).digest(),
        )
        .unwrap();
        assert!(request_body(foreign, subject).is_err());
    }

    #[test]
    fn source_dispatch_origin_is_part_of_the_actual_signed_host_semantics() {
        let pending = request_body(assignment(7), subject(false)).unwrap();
        let dispatched = request_body(assignment(7), subject(true)).unwrap();
        let pending = crate::decode_runtime_template_v1(&pending).unwrap();
        let dispatched = crate::decode_runtime_template_v1(&dispatched).unwrap();
        let pending =
            crate::semantics::host::canonical_host_template_semantics_v1(&pending).unwrap();
        let dispatched =
            crate::semantics::host::canonical_host_template_semantics_v1(&dispatched).unwrap();

        assert_eq!(pending.verb(), BrokerVerb::HostStop);
        assert_eq!(dispatched.verb(), BrokerVerb::HostStop);
        assert_ne!(pending.commitment(), dispatched.commitment());
    }
}
