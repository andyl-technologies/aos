//! Normalizes unsigned Host launch and Guardian plans from original inputs.
//!
//! These are pure comparison and encoding recipes. Native Root and Controller
//! consumers must independently authenticate their policy, assignment, lease,
//! inventories, original accepted Start and unchanged clocks before calling.
//! No signed artifact, payer, currentness token or dispatch permit is produced.

use std::error::Error;
use std::mem::size_of;

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope, RuntimeAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerGrantTarget, BrokerVerb, CanonicalAssignmentManifestV1, FeatureRef,
    GuardianPlanBinding, NodeId, ObjectDigest, ProtocolId,
    ProtocolVersion, RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_core::format::{decode_broker_authorization_plan, encode_signature};
use aos_sandbox_core::model::{KeyReference, ResourceProfile, Signature, SignatureBytes};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use buffa::Message as _;

use super::{BrokerPlanPreparation, SigningAuthority};
use crate::host_resource_projection::HostPortableResourceProjectionV1;
use crate::semantics::host::canonical_host_template_semantics_v1;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug, thiserror::Error)]
#[error("the original Host launch, Guardian or unchanged validity differs")]
struct Changed;

/// Retains both unsigned plans and their exact nonissuing wire shapes.
pub struct HostLaunchPlanPreparationDataV2 {
    /// Holds the Host launch plan with the original intersected validity.
    pub host: BrokerPlanPreparation,
    /// Holds the boot-and-lease-bound Guardian arm plan with that same validity.
    pub guardian: BrokerPlanPreparation,
    /// Holds a zero Host signature envelope used only for sizing.
    pub host_signature_shape: Vec<u8>,
    /// Holds a zero Guardian signature envelope used only for sizing.
    pub guardian_signature_shape: Vec<u8>,
    /// Holds the complete zero-authentication Host request used only for sizing.
    pub request_shape: Vec<u8>,
    /// Retains exact request coordinates from the sole runtime-template decoder.
    pub request_header: super::start_resource_plan::StartResourceRequestHeaderDataV2,
}

/// Constructs the sole Guardian arm plan from already compared binding DATA.
///
/// The ordinary dispatch planner and fresh Root normalizer share this exact
/// grant/plan recipe. The inputs do not prove a current lease, boot or policy.
///
/// # Errors
/// Returns the canonical grant or plan model refusal for invalid fields.
#[allow(clippy::too_many_arguments)]
pub fn guardian_arm_plan_data_v1(
    assignment: aos_sandbox_core::BrokerAssignment,
    node: NodeId,
    ownership_authority: KeyReference,
    commitment: BrokerArgumentCommitment,
    request_bytes: u32,
    policy_digest: ObjectDigest,
    revocation_scope: RevocationScopeId,
    issued: i64,
    expires: i64,
) -> Result<BrokerAuthorizationPlan> {
    let grant = BrokerGrant::new(BrokerVerb::GuardianArm, BrokerGrantTarget::Assignment,
        commitment, request_bytes, 0)?;
    Ok(BrokerAuthorizationPlan::new(BrokerAudience::Guardian, ProtocolId::Guardian,
        ProtocolVersion::new(1, 0), assignment, node, ownership_authority,
        vec![grant], policy_digest, revocation_scope, issued, expires, Vec::new())?)
}

/// Bounds the exact finite Host request model and canonical body construction.
///
/// The catalog's native and encoded representations remain separately owned.
/// Only existing selected handles, the exact root descriptor, six implemented
/// limit rows, four fixed backend features and one current-publication record
/// enter this request. No field or Vec carrier creates a namespace entry.
///
/// # Errors
/// Refuses an unsupported portable resource projection or checked overflow.
pub fn start_host_launch_request_receiving_demand_v2(
    manifest: &CanonicalAssignmentManifestV1,
    resources: &ResourceProfile,
) -> Result<aos_sandbox_core::ResourceVector> {
    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, AssignmentFence, Descriptor, Feature, RequestHeader,
        ResourceLimit, RuntimePlan,
    };
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

    HostPortableResourceProjectionV1::from_profile_v1(resources)?;
    let media = manifest.manifest().root_view().media_type().as_str().len();
    let features = crate::host_resource_projection::HOST_IMPLEMENTED_FEATURES_V1;
    let feature_names = features.iter().try_fold(0_usize, |total, feature| {
        total.checked_add(feature.0.len())
    }).ok_or(Changed)?;
    let checked = || -> Option<usize> {
        // Every field number in this recipe fits one tag byte. Eleven bytes
        // conservatively cover that tag and any length or u64 varint prefix.
        let header = 16_usize.checked_add(6_usize.checked_mul(11)?)?;
        let fence = (16_usize.checked_mul(2)?.checked_add(32)?)
            .checked_add(5_usize.checked_mul(11)?)?;
        let descriptor = media.checked_add(32)?.checked_add(3_usize.checked_mul(11)?)?;
        let limits = 6_usize.checked_mul(3_usize.checked_mul(11)?)?;
        let feature_wire = feature_names.checked_add(features.len().checked_mul(4_usize.checked_mul(11)?)?)?;
        let current = crate::semantics::storage_guest_root::STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2;
        let plan = descriptor.checked_add(96)?.checked_add(current)?
            .checked_add(limits)?.checked_add(feature_wire)?
            .checked_add(10_usize.checked_mul(11)?)?;
        let encoded = header.checked_add(fence)?.checked_add(plan)?
            .checked_add(4_usize.checked_mul(11)?)?;
        let rows = size_of::<ResourceLimit>().checked_mul(6)?
            .checked_add(size_of::<Feature>().checked_mul(features.len())?)?;
        let models = size_of::<ApplyRuntimeRequest>()
            .checked_add(size_of::<RequestHeader>())?
            .checked_add(size_of::<AssignmentFence>())?
            .checked_add(size_of::<RuntimePlan>())?
            .checked_add(size_of::<Descriptor>())?
            .checked_add(size_of::<crate::ValidatedRuntimeRequest>())?
            .checked_add(size_of::<crate::ValidatedRuntimePlan>())?
            .checked_add(rows)?.checked_add(feature_names)?.checked_add(media)?;
        models.checked_add(encoded.checked_mul(2)?)?.checked_mul(3)
    };
    let bytes = checked().and_then(|bytes| u64::try_from(bytes).ok()).ok_or(Changed)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

/// Encodes one successor Host template from its exact projected catalog rows.
///
/// The catalog is comparison DATA. Actual Controller and Root owners must
/// independently establish its complete inventory/assignment provenance and
/// installed publication before dispatch. This recipe neither allocates a UID
/// range nor fabricates opaque resource handles. The current guest-root binding
/// remains distinct from the workspace's immutable physical creation proof.
///
/// # Errors
/// Refuses missing or duplicate assignment rows, nonempty attachments, an
/// altered root/current publication, invalid resource projection or request
/// identity, and canonical runtime-template validation failure.
pub fn start_host_launch_request_body_data_v2(
    manifest: &CanonicalAssignmentManifestV1,
    resources: &ResourceProfile,
    catalog: &crate::host_catalog_snapshot::HostCatalogSnapshot,
    request_id: [u8; 16],
) -> Result<Vec<u8>> {
    use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, Audience, Descriptor};
    use crate::host_catalog_snapshot::CatalogAssignment;

    let model = manifest.manifest();
    let assignment = CatalogAssignment::new(
        model.sandbox().into_bytes(), model.incarnation().into_bytes(),
        model.epoch().get(), model.desired_generation().get(),
        *manifest.digest().as_bytes(),
    )?;
    let mut workspaces = catalog.workspaces().iter()
        .filter(|workspace| workspace.assignment() == assignment);
    let workspace = workspaces.next().ok_or(Changed)?;
    if workspaces.next().is_some() || !workspace.attachment_handles().is_empty()
        || workspace.root_image() != model.root_view()
    {
        return Err(Box::new(Changed));
    }

    let mut networks = catalog.networks().iter()
        .filter(|network| network.assignment() == assignment);
    let network = networks.next().ok_or(Changed)?;
    if networks.next().is_some() {
        return Err(Box::new(Changed));
    }
    let mut anchors = catalog.attachment_anchors().iter().filter(|anchor| {
        anchor.assignment() == assignment
            && anchor.namespace_generation() == model.namespace_generation().get()
    });
    let anchor = anchors.next().ok_or(Changed)?;
    if anchors.next().is_some() {
        return Err(Box::new(Changed));
    }
    let current = workspace.guest_root_publication().ok_or(Changed)?
        .current_publication_v2()?.ok_or(Changed)?;
    if current.current_assignment_v2()? != manifest.broker_assignment()?
        || workspace.guest_root_publication().ok_or(Changed)?.proof()?.workspace_handle != *workspace.handle()
    {
        return Err(Box::new(Changed));
    }

    let projection = HostPortableResourceProjectionV1::from_profile_v1(resources)?;
    let mut request = ApplyRuntimeRequest::default();
    let header = request.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 0;
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.request_id = request_id.to_vec();
    header.maximum_response_bytes = crate::MINIMUM_RESPONSE_BYTES;

    let fence = request.fence.get_or_insert_default();
    fence.sandbox_id = model.sandbox().as_bytes().to_vec();
    fence.incarnation_id = model.incarnation().as_bytes().to_vec();
    fence.assignment_epoch = model.epoch().get();
    fence.desired_generation = model.desired_generation().get();
    fence.assignment_digest = manifest.digest().as_bytes().to_vec();
    request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();

    let plan = request.launch_plan.get_or_insert_default();
    let descriptor = model.root_view();
    plan.root_image = Some(Descriptor {
        media_type: descriptor.media_type().as_str().to_owned(),
        sha256: descriptor.digest().as_bytes().to_vec(),
        encoded_size: descriptor.encoded_size(),
        ..Default::default()
    }).into();
    plan.workspace_handle = workspace.handle().to_vec();
    plan.network_handle = network.handle().to_vec();
    plan.uid_range_start = workspace.identity().range_start();
    plan.uid_range_size = workspace.identity().range_size();
    plan.limits = projection.wire_limits_v1();
    plan.required_features = projection.wire_features_v1();
    plan.attachment_anchor_handle = anchor.handle().to_vec();
    plan.current_guest_root_publication_v2 = current.encode_v2().to_vec();

    let bytes = request.encode_to_vec();
    crate::decode_runtime_template_v1(&bytes)?;
    Ok(bytes)
}

/// Prepares the exact Host launch and Guardian signing statements as inert DATA.
///
/// The body is the real deadline-free template with actual broker-minted
/// selectors. Its full portable resource profile remains independently owned;
/// this helper compares only implemented Host properties and rejects finite
/// unsupported I/O bandwidth. It never invents a UID range or opaque handle.
///
/// # Errors
/// The initial Host and Guardian resident scope derives from the same protected
/// accepted capability/policy ceilings, fresh verified lease and Host policy.
/// The injected request/header deadline still uses the unchanged short Start
/// acquisition cutoff. This never extends a previously issued signed scope.
///
/// Refuses a changed assignment/root image, resource recipe, nonlaunch body,
/// Guardian already embedded in a template, expired original bound or any
/// canonical model/encoding refusal. Every allocation must be prepaid.
#[allow(clippy::too_many_arguments)]
pub fn prepare_host_launch_plan_v2(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    resources: &ResourceProfile,
    catalog: &crate::host_catalog_snapshot::HostCatalogSnapshot,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    accepted_start: crate::domain_ledger::operation::AcceptedStartOriginDataV1,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
) -> Result<HostLaunchPlanPreparationDataV2> {
    let (_, header) = crate::runtime_template::decode_runtime_template_with_header_data_v2(deadline_free_body)?;
    let expected = start_host_launch_request_body_data_v2(
        manifest, resources, catalog, header.request_id,
    )?;
    if expected != deadline_free_body {
        return Err(Box::new(Changed));
    }
    let expires = initial_resident_expiry_v1(accepted_start, sample, cutoff,
        policy_expires, lease.authority_expires_seconds())?;
    super::storage_create_plan::require_admitted_clock_v1(sample, cutoff,
        sample.wall_seconds(), expires, lease.authority_issued_seconds(),
        lease.authority_expires_seconds())?;
    prepare_at_v1(deadline_free_body, manifest, resources, policy_digest, lease,
        sample.host_boot_id(), sample.wall_seconds(), expires, cutoff, authority, revocation_scope)
}

/// Reconstructs both exact plans from the original Root-admitted Host plan.
///
/// Root and Controller use their independently authenticated manifest, resource
/// profile, fresh lease, original accepted Start and actual boot. The returned
/// Guardian preparation is fixed by those same original inputs and the Host
/// plan's admitted validity; a parsed Host plan alone supplies no such authority.
/// Actual native Host-purpose lenders must guard both signing borrows and Root
/// must independently verify the final embedded Guardian plan and signature.
///
/// # Errors
/// Refuses a changed Host plan/statement, body, resource projection, assignment,
/// lease, policy, boot or validity outside the original accepted ceilings.
#[allow(clippy::too_many_arguments)]
pub fn prepare_admitted_host_launch_plan_v2(
    deadline_free_body: &[u8],
    manifest: &CanonicalAssignmentManifestV1,
    resources: &ResourceProfile,
    catalog: &crate::host_catalog_snapshot::HostCatalogSnapshot,
    policy_digest: ObjectDigest,
    lease: &SignedOwnershipLease,
    sample: RawPairedClockSample,
    cutoff: u64,
    policy_expires: i64,
    accepted_start: crate::domain_ledger::operation::AcceptedStartOriginDataV1,
    authority: SigningAuthority,
    revocation_scope: RevocationScopeId,
    canonical_host_plan: &[u8],
    canonical_host_statement: &[u8],
) -> Result<HostLaunchPlanPreparationDataV2> {
    let (_, header) = crate::runtime_template::decode_runtime_template_with_header_data_v2(deadline_free_body)?;
    let expected = start_host_launch_request_body_data_v2(
        manifest, resources, catalog, header.request_id,
    )?;
    if expected != deadline_free_body {
        return Err(Box::new(Changed));
    }
    let maximum_resident_expiry = initial_resident_expiry_v1(accepted_start,
        sample, cutoff, policy_expires, lease.authority_expires_seconds())?;
    let host = decode_broker_authorization_plan(canonical_host_plan,
        aos_sandbox_core::DecodeLimits::default())?;
    if host.expires_seconds() > maximum_resident_expiry {
        return Err(Box::new(Changed));
    }
    super::storage_create_plan::require_admitted_clock_v1(sample, cutoff,
        host.issued_seconds(), host.expires_seconds(), lease.authority_issued_seconds(),
        lease.authority_expires_seconds())?;
    let prepared = prepare_at_v1(deadline_free_body, manifest, resources, policy_digest,
        lease, sample.host_boot_id(), host.issued_seconds(), host.expires_seconds(),
        cutoff, authority, revocation_scope)?;
    if prepared.host.canonical_plan() != canonical_host_plan
        || prepared.host.signing_request().canonical_statement() != canonical_host_statement
    {
        return Err(Box::new(Changed));
    }
    Ok(prepared)
}

// This is an initial-grant calculation over authenticated accepted DATA. It
// never changes the signed expiry of an existing Host or Guardian owner.
fn initial_resident_expiry_v1(
    accepted: crate::domain_ledger::operation::AcceptedStartOriginDataV1,
    sample: RawPairedClockSample,
    acquisition_cutoff: u64,
    host_policy_expires: i64,
    lease_expires: i64,
) -> Result<i64> {
    let original_acquisition = accepted.cutoff_for_sample_data_v1(sample).ok_or(Changed)?;
    let resident = accepted.original_resident_authority_expiry_v1()
        .min(host_policy_expires).min(lease_expires);
    if acquisition_cutoff > original_acquisition
        || sample.boottime_nanoseconds() >= acquisition_cutoff
        || sample.wall_seconds() >= resident {
        return Err(Box::new(Changed));
    }
    Ok(resident)
}

#[allow(clippy::too_many_arguments)]
fn prepare_at_v1(
    deadline_free_body: &[u8], manifest: &CanonicalAssignmentManifestV1,
    resources: &ResourceProfile, policy_digest: ObjectDigest, lease: &SignedOwnershipLease,
    boot: [u8; 16], issued: i64, expires: i64, cutoff: u64,
    authority: SigningAuthority, revocation_scope: RevocationScopeId,
) -> Result<HostLaunchPlanPreparationDataV2> {
    let (template, mut request_header) = crate::runtime_template::decode_runtime_template_with_header_data_v2(deadline_free_body)?;
    let launch = template.launch_plan().ok_or(Changed)?;
    let semantics = canonical_host_template_semantics_v1(&template)?;
    let assignment = manifest.broker_assignment()?;
    crate::semantics::host::require_start_host_current_publication_v2(
        launch, assignment, lease.digest(),
    )?;
    let projection = HostPortableResourceProjectionV1::from_profile_v1(resources)?;
    if template.action() != RuntimeAction::RUNTIME_ACTION_LAUNCH
        || template.guardian_arm().is_some()
        || template.fence().broker_assignment()? != assignment
        || lease.assignment().sandbox() != assignment.sandbox()
        || lease.assignment().incarnation() != assignment.incarnation()
        || lease.assignment().epoch() != assignment.epoch()
        || lease.assignment().digest() != assignment.digest()
        || lease.desired_generation() != assignment.desired_generation()
        || lease.node() != manifest.manifest().node()
        || launch.root_image() != manifest.manifest().root_view()
        || semantics.verb() != BrokerVerb::HostLaunch
        || semantics.target() != BrokerGrantTarget::Assignment
        || launch.limits().iter().map(|limit| (u32::from(limit.dimension()), limit.value()))
            .ne(projection.wire_limits_v1().iter().map(|limit| (limit.dimension, limit.value)))
        || launch.required_features().iter().map(|feature| (feature.namespace(), feature.major(), feature.minor()))
            .ne(projection.wire_features_v1().iter().map(|feature|
                (feature.namespace.as_str(), feature.major, feature.minor)))
    {
        return Err(Box::new(Changed));
    }
    let binding = GuardianPlanBinding::new(assignment, lease.node(), boot,
        lease.generation(), lease.digest())?;
    let guardian_plan = guardian_arm_plan_data_v1(assignment, lease.node(), lease.signer().clone(),
        binding.commitment(), binding.encoded_len(), policy_digest, revocation_scope, issued, expires)?;
    let guardian = BrokerPlanPreparation::new(guardian_plan, authority.clone())?;
    let guardian_signature_shape = signature_shape_v1(&guardian);
    let deadline_body = crate::dispatch_template::inject_deadline(deadline_free_body, cutoff)?;
    let live = crate::encode_host_guardian_companion_v1(&deadline_body,
        guardian.canonical_plan(), &guardian_signature_shape)?;
    let request_bytes = u32::try_from(live.len())?;
    let grant = BrokerGrant::new(BrokerVerb::HostLaunch, BrokerGrantTarget::Assignment,
        semantics.commitment(), request_bytes, 0)?;
    let plan = BrokerAuthorizationPlan::new(BrokerAudience::Host, ProtocolId::HostBroker,
        ProtocolVersion::new(1, 0), assignment, lease.node(), lease.signer().clone(),
        vec![grant], policy_digest, revocation_scope, issued, expires,
        vec![FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)?])?;
    let host = BrokerPlanPreparation::new(plan, authority)?;
    let host_signature_shape = signature_shape_v1(&host);
    let envelope = crate::encode_authorized_request_envelope(ProtocolId::HostBroker,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME, &live, &[], crate::AuthorizationArtifactBytes {
            broker_plan: host.canonical_plan(), broker_plan_signature: &host_signature_shape,
            ownership_lease: lease.canonical_lease(), ownership_lease_signature: lease.canonical_signature(),
        })?;
    let mut envelope = BrokerRequestEnvelope::decode_from_slice(&envelope)?;
    envelope.signed_session_request = vec![0;
        aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES];
    let request_shape = envelope.encode_to_vec();
    if request_shape.len() > aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(Box::new(Changed));
    }
    request_header.deadline_boottime_nanoseconds = cutoff;
    Ok(HostLaunchPlanPreparationDataV2 {
        host, guardian, host_signature_shape, guardian_signature_shape,
        request_shape, request_header,
    })
}

fn signature_shape_v1(prepared: &BrokerPlanPreparation) -> Vec<u8> {
    encode_signature(&Signature::new(prepared.signing_request().statement().clone(),
        SignatureBytes::new([0; 64])))
}

#[cfg(test)]
mod initial_scope_tests {
    use super::*;
    use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
    use crate::domain_ledger::operation::AcceptedStartOriginDataV1;

    fn sample(wall: i64, seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16], wall, seconds * 1_000_000_000,
        ).unwrap()
    }

    fn accepted(capability: i64, policy: i64) -> AcceptedStartOriginDataV1 {
        AcceptedStartOriginDataV1::from_data_v1(sample(100, 10), 90_000_000_000,
            capability, policy, 30_000_000_000).unwrap()
    }

    #[test]
    fn short_rpc_timeout_does_not_relabel_the_initial_resident_authority() {
        let accepted = accepted(300, 250);
        assert_eq!(accepted.original_wall_expiry_v1(), Some(130));
        assert_eq!(accepted.original_resident_authority_expiry_v1(), 250);
        assert_eq!(initial_resident_expiry_v1(accepted, sample(101, 11),
            38_000_000_000, 240, 220).unwrap(), 220);
    }

    #[test]
    fn each_original_or_current_authority_ceiling_can_tighten_initial_scope() {
        let current = sample(101, 11);
        assert_eq!(initial_resident_expiry_v1(accepted(210, 250), current,
            38_000_000_000, 240, 220).unwrap(), 210);
        assert_eq!(initial_resident_expiry_v1(accepted(300, 205), current,
            38_000_000_000, 240, 220).unwrap(), 205);
        assert_eq!(initial_resident_expiry_v1(accepted(300, 250), current,
            38_000_000_000, 200, 220).unwrap(), 200);
        assert!(initial_resident_expiry_v1(accepted(300, 250), current,
            38_000_000_000, 240, 101).is_err());
    }

    #[test]
    fn long_resident_scope_cannot_authorize_late_or_renewed_acquisition() {
        let accepted = accepted(300, 250);
        assert!(initial_resident_expiry_v1(accepted, sample(130, 40),
            38_000_000_000, 240, 220).is_err());
        assert!(initial_resident_expiry_v1(accepted, sample(101, 11),
            80_000_000_000, 240, 220).is_err());
        let rebooted = RawPairedClockSample::new_untrusted(
            accepted.accepted_clock_v1().provenance(), [9; 16], 101, 11_000_000_000,
        ).unwrap();
        assert!(initial_resident_expiry_v1(accepted, rebooted,
            38_000_000_000, 240, 220).is_err());
    }
}
