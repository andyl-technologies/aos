//! Real compiler/protected-publisher/accepted-Create association fixtures.
//!
//! Synthetic input verifiers exist only here. UID-owned temporary journals
//! exercise actual owner writes/replay; they do not qualify installed fixed
//! Root custody, Source genesis/floor, or positive Create/worker authority.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_proto::aos::sandbox::v1::{
    CreateSandboxRequest, DesiredLifecycle, Duration, ObjectDescriptor as ProtoDescriptor, Sandbox,
    SandboxDesiredState, SandboxObservedState, SandboxPhase, Timestamp,
};
use aos_sandbox_core::{
    CacheDomainId, Grant, GrantId, ObjectDescriptor, Operation, OperationSet, PrincipalId,
    ResourceId, ResourceKind, RevocationScopeId, SandboxId, Selector,
    model::{CacheDomain, CacheDomainKind, RevocationMode, RevocationPolicy},
};
use buffa::Message as _;

use super::*;
use crate::IdempotencyKey;
use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionPlanV1, PublicProjectionResourceV1,
};
use crate::policy_compiler::deployment_head::{
    admit_policy_signer_pins_in_journal_v1, admit_test_held_deployment_profile_v2,
    signed_test_deployment_input_fixture_v1, verify_test_held_deployment_profile_v2,
};
use crate::policy_compiler::{
    AdvisoryActionV1, AdvisoryDegradationV1, AdvisoryKindV1, AuthenticatedCacheDomainV1,
    AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1,
    AuthenticatedSandboxProjectRelationV1, CacheDomainBindingV1, CacheDomainInputV1,
    CacheDomainVerifierV1, EndpointCatalogVerifierV1, HardLimitRequestV1, HardLimitValueV1,
    HardResourceProfileV1, LogicalSourceV1, NamespaceCatalogVerifierV1, NamespaceRuleV1,
    NamespaceSourceClassV1, PolicyCompilerLimitsV1, PolicyDeploymentCatalogDeclarationsV2,
    PolicyLayerV1, RevocationInputV1, SandboxProjectRelationVerifierV1,
    compile_publisher_policy_revision_v2, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1,
};
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherPolicyError, PublisherRevocationHeadV1,
};
use crate::reconciler::{
    EffectFailure, EffectObservation, EffectReceipt, OperationPlan, PublicMutationEffectV1,
    PublicOperationAdmissionV1, PublicOperationAuthorizationV1, Reconciler,
    SingleNodeEffectExecutor,
};

struct SyntheticInputVerifier;

impl CacheDomainVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl SandboxProjectRelationVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl EndpointCatalogVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl NamespaceCatalogVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

fn views(bytes: &[Vec<u8>; 4]) -> PolicyDeploymentInputsV1<'_> {
    PolicyDeploymentInputsV1 {
        node: &bytes[0],
        site: &bytes[1],
        backend: &bytes[2],
        catalogs: &bytes[3],
    }
}

pub(in crate::policy_compiler) fn original_input(
    target: SandboxId,
    request: Option<PolicyLayerV1>,
) -> PolicyCompilerInputV1 {
    let project = ProjectId::from_bytes([1; 16]);
    let key = SigningKey::from_bytes(&[21; 32]);
    let (packet, bytes) = signed_test_deployment_input_fixture_v1(&key);
    let head = verify_policy_deployment_head_v1(&packet, &views(&bytes), &key.verifying_key(), 20)
        .expect("reused complete legacy limit fixture");
    let legacy =
        decode_policy_deployment_sources_v1(&views(&bytes), head).expect("typed limit fixture");
    let domain = AuthenticatedCacheDomainV1::authenticate(
        CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*project.as_bytes()),
        ),
        CacheDomainBindingV1::Project(project),
        &SyntheticInputVerifier,
    )
    .expect("synthetic domain");
    let inherited = legacy.site().layer().clone();
    let project_layer = PolicyLayerV1::new(
        Vec::new(),
        inherited.resources().clone(),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Exact(domain),
        RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
    )
    .expect("explicit typed project choices");
    PolicyCompilerInputV1::new(
        AuthenticatedSandboxProjectRelationV1::authenticate(
            target,
            project,
            &SyntheticInputVerifier,
        )
        .expect("synthetic original relation"),
        legacy.node().clone(),
        legacy.site().clone(),
        ProjectPolicyInputV1::new(project, project_layer).expect("project input"),
        Vec::new(),
        RequestPolicyInputV1::new(request.unwrap_or(inherited)).expect("request input"),
        AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &SyntheticInputVerifier)
            .expect("synthetic empty endpoints"),
        AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &SyntheticInputVerifier)
            .expect("synthetic empty destinations"),
        legacy.backend().clone(),
        PolicyCompilerLimitsV1::DEFAULT,
    )
    .expect("complete original input")
}

fn profile(input: &PolicyCompilerInputV1) -> PolicyDeploymentInputProfileV2 {
    PolicyDeploymentInputProfileV2::new(
        1,
        3,
        input.node().clone(),
        input.site().clone(),
        input.backend().clone(),
        PolicyDeploymentCatalogDeclarationsV2::new(Vec::new(), Vec::new()).expect("declarations"),
    )
    .expect("typed deployment profile")
}

fn signed_deployment(
    profile: &PolicyDeploymentInputProfileV2,
    key: &SigningKey,
) -> (Vec<u8>, [Vec<u8>; 4]) {
    let bytes = profile.canonical_inputs().expect("typed input bytes");
    let mut packet = b"AOSPDH01".to_vec();
    packet.extend_from_slice(&1_u64.to_be_bytes());
    packet.extend_from_slice(&10_i64.to_be_bytes());
    packet.extend_from_slice(&30_i64.to_be_bytes());
    for input in &bytes {
        packet.extend_from_slice(&Sha256::digest(input));
    }
    let mut signed = b"aos.sandbox.policy-deployment-head.v1\0".to_vec();
    signed.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&signed).to_bytes());
    (packet, bytes)
}

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("private fixture directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("0700 fixture");
    directory
}

fn open_controller(directory: &Path) -> Journal {
    let uid = fs::metadata(directory).expect("fixture UID").uid();
    Journal::open_protected_at_uid(
        directory,
        "controller.journal",
        production_journal_limits(),
        uid,
    )
    .expect("actual protected Controller journal")
    .0
}

fn open_root(directory: &Path) -> Journal {
    let uid = fs::metadata(directory).expect("fixture UID").uid();
    Journal::open_protected_at_uid(
        directory,
        "authority.journal",
        crate::JournalLimits::default(),
        uid,
    )
    .expect("actual protected Root fixture")
    .0
}

fn prepared(input: &PolicyCompilerInputV1) -> CompiledPublisherPolicyRevisionV2 {
    compile_publisher_policy_revision_v2(input, 1, 1, 253_402_300_799)
        .expect("actual full compiler producer")
}

fn publish(journal: &mut Journal, prepared: &CompiledPublisherPolicyRevisionV2) {
    let project = prepared.revision().project();
    let scope = RevocationScopeId::from_bytes([4; 16]);
    let mut store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .expect("actual owner replay");
    store
        .publish_compiled_policy_from_trusted_controller_v2([10; 16], None, prepared)
        .expect("atomic revision and current head");
    store
        .advance_revocation_from_trusted_controller(
            [11; 16],
            None,
            PublisherRevocationHeadV1 {
                scope,
                generation: 1,
            },
        )
        .expect("actual revocation head");
    store
        .bind_project_revocation_scope_from_trusted_controller([12; 16], project, scope)
        .expect("actual project scope binding");
}

struct NeverExecute;

impl SingleNodeEffectExecutor for NeverExecute {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("association fixture cannot observe a positive effect");
    }
    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("association fixture cannot apply a positive effect");
    }
}

fn admit_create(
    journal: Journal,
    policy: &ObjectDescriptor,
) -> (
    Reconciler<NeverExecute>,
    OperationPlan,
    ControllerRequestScopeV1,
    EffectPlan,
) {
    let project = ProjectId::from_bytes([1; 16]);
    let operation = OperationId::from_bytes([5; 16]);
    let child = SandboxId::from_bytes([6; 16]);
    let caller = PrincipalId::from_bytes([7; 16]);
    let key = b"project-v3-original-input".to_vec();
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes([8; 32])).expect("scope");
    let policy = ProtoDescriptor {
        media_type: policy.media_type().as_str().to_owned(),
        sha256: policy.digest().as_bytes().to_vec(),
        encoded_size: policy.encoded_size(),
        ..Default::default()
    };
    let specification = ProtoDescriptor {
        media_type: "application/vnd.aos.sandbox.spec.v1+cbor".to_owned(),
        sha256: vec![9; 32],
        encoded_size: 1,
        ..Default::default()
    };
    let request = CreateSandboxRequest {
        project_id: project.as_bytes().to_vec(),
        expected_project_resource_version: vec![10; 32],
        specification: Some(specification.clone()).into(),
        requested_policy: Some(policy.clone()).into(),
        idempotency_key: key.clone(),
        operation_timeout: Some(Duration {
            nanoseconds: 1_000_000_000,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let envelope = PublicMutationRequestV1::new(
        PublicApiAuditMethodV1::CreateSandbox,
        &request.encode_to_vec(),
    )
    .expect("exact original public envelope")
    .encode();
    let request_digest = scope.public_request_digest(caller, project, &envelope);
    let effect = EffectPlan::authorized_public_mutation(
        PublicOperationMethodV1::CreateSandbox,
        PublicMutationEffectV1::new(caller, project, 100, envelope)
            .expect("original effect context"),
    )
    .expect("exact Create effect");
    let timestamp = Timestamp {
        seconds: 100,
        ..Default::default()
    };
    let resource = Sandbox {
        sandbox_id: child.as_bytes().to_vec(),
        project_id: project.as_bytes().to_vec(),
        resource_version: crate::production_operation_compiler::admitted_public_resource_version_v1(
            operation,
            PublicOperationMethodV1::CreateSandbox,
            1,
            request_digest,
        ),
        desired: Some(SandboxDesiredState {
            specification: Some(specification).into(),
            requested_policy: Some(policy.clone()).into(),
            lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
            generation: 1,
            ..Default::default()
        })
        .into(),
        observed: Some(SandboxObservedState {
            phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
            desired_generation: 1,
            observation_sequence: 1,
            last_successful_reconciliation_time: Some(timestamp.clone()).into(),
            ..Default::default()
        })
        .into(),
        effective_policy: Some(policy).into(),
        created_at: Some(timestamp.clone()).into(),
        updated_at: Some(timestamp).into(),
        ..Default::default()
    };
    let projection = PublicProjectionPlanV1::new(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(resource),
    )
    .expect("original child projection");
    let authorization = PublicOperationAuthorizationV1::new(
        project,
        ResourceKind::ChildDelegation,
        Selector::Resource {
            resource: ResourceId::from_bytes(*project.as_bytes()),
        },
    )
    .expect("test admission scope");
    let plan = OperationPlan::new(
        operation,
        IdempotencyKey::new(key).expect("idempotency"),
        request_digest,
        projection.desired_key().to_vec(),
        projection.desired_value().to_vec(),
        vec![effect.clone()],
    )
    .expect("actual desired/effect plan")
    .with_public_operation(
        PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::CreateSandbox,
            1,
            [11; 16],
            100,
            authorization,
        )
        .expect("public admission metadata"),
    )
    .expect("immutable admission plan");
    let mut reconciler = Reconciler::new(journal, NeverExecute);
    reconciler
        .accept(&plan)
        .expect("genuine atomic Reconciler admission");
    (reconciler, plan, scope, effect)
}

#[test]
fn project_v3_real_compiler_publisher_record_and_cold_exact_derivation() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let origin = prepared
        .revision()
        .compiler_origin()
        .expect("real retained origin");
    assert_eq!(origin.original_target(), input.sandbox());
    assert_eq!(
        origin.project_input_bytes(),
        input.project().canonical_bytes()
    );
    assert_eq!(
        origin.request_input_bytes(),
        input.request().canonical_bytes()
    );
    assert_eq!(input.request().layer().resources().portable().len(), 16);
    assert_eq!(input.request().layer().resources().accounting().len(), 22);
    let directory = directory();
    let mut journal = open_controller(directory.path());
    publish(&mut journal, &prepared);
    let sequence = journal.snapshot_sequence();
    drop(journal);

    let mut cold = open_controller(directory.path());
    let store = PublisherPolicyStore::load(&mut cold, PublisherPolicyLimits::default())
        .expect("cold namespace replay");
    let revision = store
        .current_policy(input.project().project())
        .expect("cold current head")
        .expect("current revision");
    assert_eq!(&revision, prepared.revision());
    revision
        .compiler_origin()
        .expect("V2 provenance")
        .verify_original_derivation(&input)
        .expect("actual cold recompile");
    assert_eq!(cold.snapshot_sequence(), sequence);
    let mut store = PublisherPolicyStore::load(&mut cold, PublisherPolicyLimits::default())
        .expect("same exact protected publisher");
    assert!(
        store
            .publish_compiled_policy_from_trusted_controller_v2([10; 16], None, &prepared)
            .is_err()
    );
    assert_eq!(cold.snapshot_sequence(), sequence);
    let changed_target = original_input(SandboxId::from_bytes([12; 16]), None);
    assert!(
        revision
            .compiler_origin()
            .expect("origin")
            .verify_original_derivation(&changed_target)
            .is_err()
    );
}

#[test]
fn project_v3_legacy_policy_cannot_brand_origin_or_default_request_layer() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let legacy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        input.project().project(),
        1,
        1,
        253_402_300_799,
        prepared.revision().canonical_policy(),
        aos_sandbox_core::DecodeLimits::default(),
    )
    .expect("unchanged resolved Policy constructor");
    assert!(legacy.compiler_origin().is_none());
    let directory = directory();
    let mut journal = open_controller(directory.path());
    {
        let mut store = PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .expect("publisher");
        store
            .publish_policy_from_trusted_controller([10; 16], None, &legacy)
            .expect("old V1 publication");
        let scope = RevocationScopeId::from_bytes([4; 16]);
        store
            .advance_revocation_from_trusted_controller(
                [11; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope,
                    generation: 1,
                },
            )
            .expect("scope head");
        store
            .bind_project_revocation_scope_from_trusted_controller(
                [12; 16],
                input.project().project(),
                scope,
            )
            .expect("scope");
    }
    let (mut reconciler, plan, scope, effect) = admit_create(journal, legacy.descriptor());
    assert!(
        with_current_inputs_at(
            reconciler.journal_mut(),
            directory.path(),
            plan.operation_id(),
            input.project().project(),
            scope,
            &effect,
            &input,
            |_| panic!("legacy must not mint typed origin")
        )
        .is_err()
    );
}

#[test]
fn project_v3_held_accepted_create_and_independently_pinned_role_association() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let profile = profile(&input);
    let deployment_key = SigningKey::from_bytes(&[21; 32]);
    let project_key = SigningKey::from_bytes(&[22; 32]);
    let (deployment_packet, bytes) = signed_deployment(&profile, &deployment_key);
    let root_directory = directory();
    let mut root = open_root(root_directory.path());
    admit_policy_signer_pins_in_journal_v1(
        &mut root,
        3,
        &deployment_key.verifying_key(),
        5,
        &project_key.verifying_key(),
    )
    .expect("actual immutable role pins");
    admit_test_held_deployment_profile_v2(
        &mut root,
        &deployment_packet,
        &views(&bytes),
        &profile,
        &deployment_key.verifying_key(),
        20,
    )
    .expect("actual protected deployment CAS");
    drop(root);
    let directory = directory();
    let mut controller = open_controller(directory.path());
    publish(&mut controller, &prepared);
    let (mut reconciler, plan, scope, effect) =
        admit_create(controller, prepared.revision().descriptor());
    let association = ProjectPolicyAssociationV3::from_compiled_revision(&prepared, &input, 1)
        .expect("actual typed association");
    let sequence = reconciler.journal_mut().snapshot_sequence();
    let original_packet = with_current_inputs_at(
        reconciler.journal_mut(),
        directory.path(),
        plan.operation_id(),
        input.project().project(),
        scope,
        &effect,
        &input,
        |held| {
            // Live joins open Root only inside the retained Controller cut.
            let mut root = open_root(root_directory.path());
            assert_ne!(held.source().sandbox(), held.origin().original_target());
            assert_eq!(held.project_input(), input.project());
            assert_eq!(held.request_input(), input.request());
            let head = verify_test_held_deployment_profile_v2(
                &mut root,
                &deployment_packet,
                &views(&bytes),
                &profile,
                20,
            )
            .expect("independent held deployment key/head/typed bytes");
            let claims = [
                ObjectDigest::from_bytes([24; 32]),
                head.packet_digest(),
                held.source().cache_domain_head(),
                held.source().revocation_head(),
            ];
            let packet = association
                .sign(10, 30, claims, 3, 5, &project_key)
                .expect("existing project role signature");
            verify_association_at_held_cut(
                &mut root,
                held,
                &packet,
                &profile,
                head.packet_digest(),
                20,
            )
            .expect("actual held exact signature/provenance join, not Source authority");
            let foreign = association
                .sign(10, 30, claims, 3, 5, &deployment_key)
                .expect("wrong role signed packet");
            assert!(
                verify_association_at_held_cut(
                    &mut root,
                    held,
                    &foreign,
                    &profile,
                    head.packet_digest(),
                    20
                )
                .is_err()
            );
            let rotated_generation = association
                .sign(10, 30, claims, 3, 6, &project_key)
                .expect("validly signed changed role-generation claim");
            verify_packet(
                &rotated_generation,
                association.canonical_bytes(),
                &project_key.verifying_key(),
                20,
            )
            .expect("signature alone is valid");
            assert!(
                verify_association_at_held_cut(
                    &mut root,
                    held,
                    &rotated_generation,
                    &profile,
                    head.packet_digest(),
                    20
                )
                .is_err()
            );
            for now in [9, 30] {
                assert!(
                    verify_association_at_held_cut(
                        &mut root,
                        held,
                        &packet,
                        &profile,
                        head.packet_digest(),
                        now
                    )
                    .is_err()
                );
            }
            let mut legacy = packet;
            legacy[..8].copy_from_slice(b"AOSPPH02");
            assert!(
                verify_packet(
                    &legacy,
                    association.canonical_bytes(),
                    &project_key.verifying_key(),
                    20
                )
                .is_err()
            );
            packet
        },
    )
    .expect("real protected live Create and exact original inputs");
    assert_eq!(reconciler.journal_mut().snapshot_sequence(), sequence);
    drop(reconciler);

    let mut cold = open_controller(directory.path());
    with_current_inputs_at(
        &mut cold,
        directory.path(),
        plan.operation_id(),
        input.project().project(),
        scope,
        &effect,
        &input,
        |held| {
            let mut root = open_root(root_directory.path());
            let deployment = verify_test_held_deployment_profile_v2(
                &mut root,
                &deployment_packet,
                &views(&bytes),
                &profile,
                20,
            )
            .expect("cold protected deployment role/head");
            verify_association_at_held_cut(
                &mut root,
                held,
                &original_packet,
                &profile,
                deployment.packet_digest(),
                20,
            )
            .expect("exact cold original input/role association");
        },
    )
    .expect("cold real operation/effect/projection/publisher joins");
    assert_eq!(cold.snapshot_sequence(), sequence);

    let successor = compile_publisher_policy_revision_v2(&input, 2, 1, 253_402_300_799)
        .expect("explicit successor");
    PublisherPolicyStore::load(&mut cold, PublisherPolicyLimits::default())
        .expect("current owner")
        .publish_compiled_policy_from_trusted_controller_v2([40; 16], Some(1), &successor)
        .expect("exact successor CAS");
    with_current_inputs_at(
        &mut cold,
        directory.path(),
        plan.operation_id(),
        input.project().project(),
        scope,
        &effect,
        &input,
        |held| {
            let mut root = open_root(root_directory.path());
            let deployment = verify_test_held_deployment_profile_v2(
                &mut root,
                &deployment_packet,
                &views(&bytes),
                &profile,
                20,
            )
            .expect("deployment rejoin");
            assert_eq!(held.source().policy_generation(), 2);
            assert!(
                verify_association_at_held_cut(
                    &mut root,
                    held,
                    &original_packet,
                    &profile,
                    deployment.packet_digest(),
                    20
                )
                .is_err()
            );
        },
    )
    .expect("old resolved descriptor still independently selected, old V3 generation rejected");
}

#[test]
fn project_v3_actual_publisher_rejects_underbound_record_without_advancing_head() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let origin_length = prepared
        .revision()
        .compiler_origin()
        .expect("origin")
        .to_record_bytes()
        .expect("bounded data")
        .len();
    let encoded = 88 + prepared.revision().canonical_policy().len() + origin_length;
    let directory = directory();
    let mut journal = open_controller(directory.path());
    let sequence = journal.snapshot_sequence();
    let limits =
        PublisherPolicyLimits::new(10, encoded - 1, 1024 * 1024).expect("exact underbound");
    let mut store = PublisherPolicyStore::load(&mut journal, limits).expect("empty owner");
    assert!(matches!(
        store.publish_compiled_policy_from_trusted_controller_v2([10; 16], None, &prepared),
        Err(PublisherPolicyError::LimitExceeded("policy revision bytes"))
    ));
    assert!(
        store
            .current_policy(input.project().project())
            .expect("head read")
            .is_none()
    );
    assert_eq!(journal.snapshot_sequence(), sequence);
}

#[test]
fn project_v3_six_layer_fields_are_exact_not_recovered_from_equal_output() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let origin = prepared
        .revision()
        .compiler_origin()
        .expect("original provenance");
    let request = input.request().layer();
    let grant = Grant::new(
        GrantId::from_bytes([30; 16]),
        ResourceKind::Tree,
        OperationSet::one(Operation::ContentRead),
        Selector::Tree {
            tree: ObjectDescriptor::new(
                aos_sandbox_core::MediaType::new(
                    aos_sandbox_core::PortableMediaType::Tree.as_str(),
                )
                .expect("Tree media"),
                ObjectDigest::from_bytes([31; 32]),
                1,
            ),
        },
        false,
    )
    .expect("explicit logical selector");
    let changed_grants = PolicyLayerV1::new(
        vec![grant],
        request.resources().clone(),
        request.namespace_rules().to_vec(),
        request.advisory_actions().to_vec(),
        request.cache_domain().clone(),
        request.revocation(),
    )
    .expect("typed narrower request");
    let changed = original_input(input.sandbox(), Some(changed_grants));
    assert!(origin.verify_original_derivation(&changed).is_err());
    assert_ne!(
        origin.request_input_bytes(),
        changed.request().canonical_bytes()
    );

    let mut portable = request.resources().portable().to_vec();
    let first = portable[0];
    portable[0] = HardLimitRequestV1::new(
        first.key(),
        HardLimitValueV1::Bounded(4095),
        first.enforcement(),
    )
    .expect("explicit narrowed portable ceiling");
    let resources = HardResourceProfileV1::new(portable, request.resources().accounting().to_vec())
        .expect("still all 16+22 dimensions");
    let selector = Selector::Tree {
        tree: ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new(aos_sandbox_core::PortableMediaType::Tree.as_str())
                .expect("Tree media"),
            ObjectDigest::from_bytes([31; 32]),
            1,
        ),
    };
    let namespace = NamespaceRuleV1::Source(
        LogicalSourceV1::new(
            ResourceId::from_bytes([32; 16]),
            ResourceKind::Tree,
            selector.clone(),
            NamespaceSourceClassV1::Immutable,
            None,
        )
        .expect("explicit namespace input"),
    );
    let advisory = AdvisoryActionV1::new(
        AdvisoryKindV1::Readahead,
        ResourceId::from_bytes([32; 16]),
        ResourceKind::Tree,
        selector,
        1024,
        1,
        AdvisoryDegradationV1::Omit,
    );
    let domain = AuthenticatedCacheDomainV1::authenticate(
        CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*input.project().project().as_bytes()),
        ),
        CacheDomainBindingV1::Project(input.project().project()),
        &SyntheticInputVerifier,
    )
    .expect("synthetic explicit request domain");
    let changed_layers = [
        PolicyLayerV1::new(
            Vec::new(),
            resources,
            Vec::new(),
            Vec::new(),
            request.cache_domain().clone(),
            request.revocation(),
        ),
        PolicyLayerV1::new(
            Vec::new(),
            request.resources().clone(),
            vec![namespace],
            Vec::new(),
            request.cache_domain().clone(),
            request.revocation(),
        ),
        PolicyLayerV1::new(
            Vec::new(),
            request.resources().clone(),
            Vec::new(),
            vec![advisory],
            request.cache_domain().clone(),
            request.revocation(),
        ),
        PolicyLayerV1::new(
            Vec::new(),
            request.resources().clone(),
            Vec::new(),
            Vec::new(),
            CacheDomainInputV1::Exact(domain),
            request.revocation(),
        ),
        PolicyLayerV1::new(
            Vec::new(),
            request.resources().clone(),
            Vec::new(),
            Vec::new(),
            request.cache_domain().clone(),
            RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
        ),
    ];
    for layer in changed_layers {
        let layer = layer.expect("constructor-normalized changed layer field");
        let changed = original_input(input.sandbox(), Some(layer));
        assert_ne!(
            origin.request_input_bytes(),
            changed.request().canonical_bytes()
        );
        assert!(origin.verify_original_derivation(&changed).is_err());
    }
    assert!(
        HardResourceProfileV1::new(
            request.resources().portable()[1..].to_vec(),
            request.resources().accounting().to_vec()
        )
        .is_err()
    );
    assert!(
        HardResourceProfileV1::new(
            request.resources().portable().to_vec(),
            request.resources().accounting()[1..].to_vec()
        )
        .is_err()
    );

    // Equal resolved output is insufficient: declared inputs and all frozen
    // layer fields are part of the retained full original serialization.
    let retained = origin.to_record_bytes().expect("original data");
    let mut untrusted_input = retained.clone();
    untrusted_input[268] ^= 1;
    let untrusted_input = RetainedPublisherCompilerOriginV3::from_record_bytes(&untrusted_input)
        .expect("raw input bytes are retained DATA, never decoded into authenticated models");
    assert!(untrusted_input.verify_original_derivation(&input).is_err());
    for offset in [40, 72, 104, 136, 168, 200, 232] {
        let mut changed = retained.clone();
        changed[offset] ^= 1;
        if let Ok(changed) = RetainedPublisherCompilerOriginV3::from_record_bytes(&changed) {
            assert!(changed.verify_original_derivation(&input).is_err());
        }
    }
    assert!(
        RetainedPublisherCompilerOriginV3::from_record_bytes(&retained[..retained.len() - 1])
            .is_err()
    );
}

#[test]
fn project_v3_full_outputs_generation_and_role_rotation_do_not_rebind_original() {
    let input = original_input(SandboxId::from_bytes([2; 16]), None);
    let prepared = prepared(&input);
    let origin = prepared
        .revision()
        .compiler_origin()
        .expect("original origin");
    let encoded = origin.to_record_bytes().expect("bounded canonical record");
    let mut offset = 264;
    for index in 0..7 {
        let length = u32::from_be_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .expect("field length"),
        ) as usize;
        offset += 4;
        if index >= 3 {
            let mut substituted = encoded.clone();
            substituted[offset] ^= 1;
            match RetainedPublisherCompilerOriginV3::from_record_bytes(&substituted) {
                Ok(changed) => assert!(changed.verify_original_derivation(&input).is_err()),
                Err(_) => {}
            }
        }
        offset += length;
    }
    let candidate = crate::policy_compiler::PolicyCompilerV1::compile(input.clone())
        .expect("fresh actual candidate");
    origin
        .compare_compiled_derivation(&input, &candidate)
        .expect("compile-once exact comparison");
    let wrong_target = original_input(SandboxId::from_bytes([33; 16]), None);
    assert!(
        origin
            .compare_compiled_derivation(&wrong_target, &candidate)
            .is_err()
    );
    let association = ProjectPolicyAssociationV3::from_compiled_revision(&prepared, &input, 1)
        .expect("typed association");
    let key = SigningKey::from_bytes(&[22; 32]);
    let claims = [ObjectDigest::from_bytes([34; 32]); 4];
    let packet = association
        .sign(10, 30, claims, 3, 5, &key)
        .expect("valid signed profile");
    verify_packet(
        &packet,
        association.canonical_bytes(),
        &key.verifying_key(),
        20,
    )
    .expect("signature provenance");
    assert!(
        verify_packet(
            &packet,
            association.canonical_bytes(),
            &SigningKey::from_bytes(&[35; 32]).verifying_key(),
            20
        )
        .is_err()
    );
    for offset in [8, 24, 48, 56, 88, 120, 152, 184, 216, 248, 256] {
        let mut changed = packet;
        changed[offset] ^= 1;
        assert!(
            verify_packet(
                &changed,
                association.canonical_bytes(),
                &key.verifying_key(),
                20
            )
            .is_err()
        );
    }
    let successor = compile_publisher_policy_revision_v2(&input, 2, 1, 253_402_300_799)
        .expect("new producer generation");
    let successor_association =
        ProjectPolicyAssociationV3::from_compiled_revision(&successor, &input, 1)
            .expect("explicit successor association");
    assert!(
        verify_packet(
            &packet,
            successor_association.canonical_bytes(),
            &key.verifying_key(),
            20
        )
        .is_err()
    );
}
