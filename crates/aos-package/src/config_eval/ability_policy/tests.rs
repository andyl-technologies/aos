//! Tests for protected current-authority publication and admission.

use std::sync::{Arc, Barrier};

use aos_ability_model::{
    AbilityValue, AccessMode, IncarnationId, LocalKey, MethodReference, ResourceAccess, ResourceId,
    RevisionId, TeardownBindingAuthorization,
};
use aos_ability_runtime::adapter::ResourceRevisionObservation;
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::checked_systemd_manager_effect_plan;
use tempfile::TempDir;

use super::storage::publish_authority_file;
use super::*;

#[test]
fn system_authority_paths_are_scoped_by_plan_and_transaction() {
    let first = CurrentAuthorityScope {
        plan: PlanId(Sha256Digest::of_bytes("first-plan")),
        transaction: TransactionId(LocalKey::new("activation-1").expect("valid transaction")),
    };
    let same_plan = CurrentAuthorityScope {
        plan: first.plan,
        transaction: TransactionId(LocalKey::new("activation-2").expect("valid transaction")),
    };
    let other_plan = CurrentAuthorityScope {
        plan: PlanId(Sha256Digest::of_bytes("second-plan")),
        transaction: first.transaction.clone(),
    };

    assert_ne!(first.system_path(), same_plan.system_path());
    assert_ne!(first.system_path(), other_plan.system_path());
    assert!(
        first
            .system_path()
            .starts_with(CURRENT_ABILITY_AUTHORITY_ROOT)
    );
}

struct AuthorityFixture {
    _root: TempDir,
    path: PathBuf,
    trust_anchor: PathBuf,
    policy: ResolutionPolicyDocument,
    platform_policy: CurrentPlatformPolicyDocument,
    plan: CheckedEffectPlan,
    assignment: ProviderAssignment,
    resource: ResourceId,
    revision: RevisionId,
    owner: u32,
}

impl AuthorityFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary authority root");
        let trust_anchor = root.path().to_path_buf();
        let authority_dir = trust_anchor.join("run").join("apm");
        std::fs::create_dir_all(&authority_dir).expect("authority directory");
        let path = authority_dir.join("ability-authority.json");
        let plan = checked_systemd_manager_effect_plan();
        let binding_document = plan.binding_plan().document();
        let policy = ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: binding_document.desired_state,
            environment: binding_document.environment,
            policy_revision: binding_document.policy_revision,
            candidates: Vec::new(),
            explicit_bindings: Vec::new(),
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers: Vec::new(),
            obligations: Vec::new(),
        };
        let platform_policy = CurrentPlatformPolicyDocument {
            schema: CurrentPlatformPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            policy_revision: binding_document.policy_revision,
            bindings: plan.binding_plan().bindings().to_vec(),
        };
        let binding = &plan.binding_plan().bindings()[0];
        let inventory = plan
            .binding_plan()
            .environment()
            .providers
            .iter()
            .find(|provider| provider.provider == binding.provider)
            .expect("fixture provider inventory");
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: inventory
                .incarnation
                .clone()
                .expect("fixture available provider incarnation"),
        };
        let resource = plan.operations()[0].accesses[0].resource.clone();
        let revision = plan
            .document()
            .current_revisions
            .iter()
            .find(|candidate| candidate.resource == resource)
            .expect("fixture current resource revision")
            .revision;
        Self {
            _root: root,
            path,
            trust_anchor,
            policy,
            platform_policy,
            plan,
            assignment,
            resource,
            revision,
            owner: rustix::process::geteuid().as_raw(),
        }
    }

    fn publish(
        &self,
        sequence: u64,
        observed_at: u64,
        state: CurrentResourceState,
    ) -> CurrentAbilityAuthorityDocument {
        CurrentAbilityAuthorityPublisher::for_test(
            self.path.clone(),
            self.trust_anchor.clone(),
            self.owner,
        )
        .publish(CurrentAuthorityPublication {
            policy_fence: policy_fence(),
            resolution_policy: &self.policy,
            platform_policy: Some(&self.platform_policy),
            transition_authority: None,
            plan: &self.plan,
            observations: CurrentAuthorityObservations {
                sequence,
                observed_at_restart_millis: observed_at,
                max_age_millis: 100,
                provider_assignments: vec![self.assignment.clone()],
                resource_observations: vec![CurrentResourceObservation {
                    resource: self.resource.clone(),
                    state,
                }],
            },
        })
        .expect("fixture authority publication")
    }

    fn admission_policy(
        &self,
        document: &CurrentAbilityAuthorityDocument,
    ) -> NativeCurrentAdmissionPolicy<RootOwnedCurrentAuthoritySource, TestClock> {
        NativeCurrentAdmissionPolicy::new(
            RootOwnedCurrentAuthoritySource::for_test(
                self.path.clone(),
                self.trust_anchor.clone(),
                self.owner,
            ),
            TestClock(document.observed_at_restart_millis),
            CurrentAuthorityCommitment {
                plan: document.plan,
                policy_fence: document.policy_fence,
                policy_revision: document.policy_revision,
                resolution_policy: document.resolution_policy,
                platform_policy: document.platform_policy,
                transition_authority: document.transition_authority,
                minimum_sequence: document.sequence,
            },
            BTreeSet::new(),
        )
    }

    fn authorize_resources(
        &self,
        policy: &mut NativeCurrentAdmissionPolicy<RootOwnedCurrentAuthoritySource, TestClock>,
        revision: ResourceRevisionObservation,
    ) -> Result<(), CurrentAuthorityError> {
        let operation = &self.plan.operations()[0];
        let binding = self
            .plan
            .binding_plan()
            .binding(&operation.binding)
            .expect("fixture binding");
        let observation =
            AbilityValue::new(serde_json::json!({"probe": "test"})).expect("bounded observation");
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            self.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision,
            observation,
        );
        policy.authorize_resources(
            &self.plan,
            binding,
            operation,
            Some(&self.assignment),
            &[evidence],
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct TestClock(u64);

impl MonotonicClock for TestClock {
    fn now_millis(&self) -> u64 {
        self.0
    }

    fn restart_stable_millis(&self) -> u64 {
        self.0
    }
}

#[test]
fn publisher_rederives_binding_and_policy_authorizes_exact_method() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(
        1,
        1_000,
        CurrentResourceState::Present {
            revision: fixture.revision,
        },
    );
    assert_eq!(document.bindings, fixture.plan.binding_plan().bindings());

    let operation = &fixture.plan.operations()[0];
    let binding = fixture
        .plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture binding");
    let method = MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    };
    fixture
        .admission_policy(&document)
        .authorize(
            &fixture.plan,
            binding,
            operation,
            &method,
            InvocationPurpose::Effect,
        )
        .expect("fresh exact policy admission");
}

#[test]
fn same_policy_instance_rejects_a_newly_revoked_fence() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(
        1,
        1_000,
        CurrentResourceState::Present {
            revision: fixture.revision,
        },
    );
    let operation = &fixture.plan.operations()[0];
    let binding = fixture
        .plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture binding");
    let method = MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    };
    let mut admission = fixture.admission_policy(&document);
    admission
        .authorize(
            &fixture.plan,
            binding,
            operation,
            &method,
            InvocationPurpose::Effect,
        )
        .expect("initial current fence must authorize");

    let mut revoked = document;
    revoked.sequence = 2;
    revoked.observed_at_restart_millis = 1_001;
    revoked.policy_fence = RevisionId(Sha256Digest::of_bytes("revoked policy fence"));
    publish_authority_file(
        &fixture.path,
        &fixture.trust_anchor,
        fixture.owner,
        &revoked,
    )
    .expect("publish revoked fence");

    let error = admission
        .authorize(
            &fixture.plan,
            binding,
            operation,
            &method,
            InvocationPurpose::Effect,
        )
        .expect_err("the next authorization must observe the revoked fence");
    assert!(error.to_string().contains("plan-policy commitment"));
}

#[test]
fn expired_current_observations_fail_closed() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(1, 1_000, CurrentResourceState::Absent);
    let mut admission = NativeCurrentAdmissionPolicy::new(
        RootOwnedCurrentAuthoritySource::for_test(
            fixture.path.clone(),
            fixture.trust_anchor.clone(),
            fixture.owner,
        ),
        TestClock(1_101),
        CurrentAuthorityCommitment {
            plan: document.plan,
            policy_fence: document.policy_fence,
            policy_revision: document.policy_revision,
            resolution_policy: document.resolution_policy,
            platform_policy: document.platform_policy,
            transition_authority: document.transition_authority,
            minimum_sequence: document.sequence,
        },
        BTreeSet::new(),
    );
    let operation = &fixture.plan.operations()[0];
    let binding = fixture
        .plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture binding");
    let method = MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    };

    let error = admission
        .authorize(
            &fixture.plan,
            binding,
            operation,
            &method,
            InvocationPurpose::Effect,
        )
        .expect_err("expired live observations must not authorize dispatch");
    assert!(error.to_string().contains("expired"));
}

#[test]
fn publisher_rejects_cross_policy_binding_shadowing() {
    let fixture = AuthorityFixture::new();
    let binding = fixture.plan.binding_plan().bindings()[0].clone();
    let request = fixture
        .plan
        .binding_plan()
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
        .expect("fixture binding request")
        .clone();
    let transition = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: Sha256Digest::of_bytes("desired planning"),
        current_planning: Sha256Digest::of_bytes("current planning"),
        desired_policy_revision: binding.policy_revision,
        prior_policy_revision: binding.policy_revision,
        authorization_policy_revision: binding.policy_revision,
        teardown_bindings: vec![TeardownBindingAuthorization {
            source_binding: binding.id.clone(),
            request,
            binding,
        }],
        teardown_providers: Vec::new(),
    };
    let error = CurrentAbilityAuthorityPublisher::for_test(
        fixture.path.clone(),
        fixture.trust_anchor.clone(),
        fixture.owner,
    )
    .publish(CurrentAuthorityPublication {
        policy_fence: policy_fence(),
        resolution_policy: &fixture.policy,
        platform_policy: Some(&fixture.platform_policy),
        transition_authority: Some(&transition),
        plan: &fixture.plan,
        observations: CurrentAuthorityObservations {
            sequence: 1,
            observed_at_restart_millis: 1_000,
            max_age_millis: 100,
            provider_assignments: vec![fixture.assignment.clone()],
            resource_observations: vec![CurrentResourceObservation {
                resource: fixture.resource.clone(),
                state: CurrentResourceState::Absent,
            }],
        },
    })
    .expect_err("one binding must not be shadowed across authority sources");

    assert!(error.to_string().contains("ambiguously issued"));
}

#[test]
fn first_activation_accepts_only_explicit_authoritative_absence() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(1, 1_000, CurrentResourceState::Absent);
    let mut policy = fixture.admission_policy(&document);

    fixture
        .authorize_resources(&mut policy, ResourceRevisionObservation::Absent)
        .expect("matching authoritative absence must be admitted");
}

#[test]
fn unknown_resource_observation_fails_closed() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(1, 1_000, CurrentResourceState::Absent);
    let error = fixture
        .authorize_resources(
            &mut fixture.admission_policy(&document),
            ResourceRevisionObservation::Unknown,
        )
        .expect_err("unknown state must not be treated as absence");

    assert!(error.to_string().contains("unknown observation"));
}

#[test]
fn observed_existing_revision_mismatch_fails_closed() {
    let fixture = AuthorityFixture::new();
    let document = fixture.publish(
        1,
        1_000,
        CurrentResourceState::Present {
            revision: fixture.revision,
        },
    );
    let different = RevisionId(Sha256Digest::of_bytes("different resource revision"));
    let error = fixture
        .authorize_resources(
            &mut fixture.admission_policy(&document),
            ResourceRevisionObservation::Present(different),
        )
        .expect_err("stale present revision must fail");

    assert!(error.to_string().contains("authoritative current state"));
}

#[test]
fn foreign_resource_is_checked_against_its_own_provider_incarnation() {
    let fixture = AuthorityFixture::new();
    let mut document = fixture.publish(
        1,
        1_000,
        CurrentResourceState::Present {
            revision: fixture.revision,
        },
    );
    let mut foreign_assignment = fixture.assignment.clone();
    foreign_assignment.provider.key =
        LocalKey::new("foreign-provider").expect("valid provider key");
    foreign_assignment.incarnation =
        IncarnationId::new("foreign-incarnation").expect("valid incarnation");
    let foreign_resource = ResourceId {
        provider: foreign_assignment.provider.clone(),
        key: LocalKey::new("foreign-resource").expect("valid resource key"),
    };
    document
        .provider_assignments
        .push(foreign_assignment.clone());
    document
        .provider_assignments
        .sort_by(|left, right| left.provider.cmp(&right.provider));
    document
        .resource_observations
        .push(CurrentResourceObservation {
            resource: foreign_resource.clone(),
            state: CurrentResourceState::Absent,
        });
    document
        .resource_observations
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    let access = ResourceAccess {
        resource: foreign_resource.clone(),
        mode: AccessMode::Read,
    };
    let observation =
        AbilityValue::new(serde_json::json!({"probe": "foreign"})).expect("bounded observation");
    let current = ResourceAdmissionEvidence::new_with_revision_observation(
        foreign_resource.clone(),
        Some(foreign_assignment.incarnation.clone()),
        ResourceRevisionObservation::Absent,
        observation.clone(),
    );

    require_current_resource_evidence(&document, &access, &current)
        .expect("foreign resource must use its own provider assignment");

    let stale = ResourceAdmissionEvidence::new_with_revision_observation(
        foreign_resource,
        Some(IncarnationId::new("stale-foreign-incarnation").expect("valid incarnation")),
        ResourceRevisionObservation::Absent,
        observation,
    );
    let error = require_current_resource_evidence(&document, &access, &stale)
        .expect_err("stale foreign provider incarnation must fail closed");
    assert!(error.to_string().contains("own current provider"));
}

#[test]
fn source_rejects_a_symlink_in_the_descriptor_relative_parent_walk() {
    use std::os::unix::fs::symlink;

    let fixture = AuthorityFixture::new();
    let real = fixture.trust_anchor.join("real");
    std::fs::create_dir(&real).expect("real authority directory");
    let alias = fixture.trust_anchor.join("alias");
    symlink(&real, &alias).expect("authority directory symlink");
    let mut source = RootOwnedCurrentAuthoritySource::for_test(
        alias.join("authority.json"),
        fixture.trust_anchor.clone(),
        fixture.owner,
    );

    assert!(source.load_current().is_err());
}

#[test]
fn source_exercises_trusted_owner_mismatch_without_a_test_bypass() {
    let fixture = AuthorityFixture::new();
    fixture.publish(1, 1_000, CurrentResourceState::Absent);
    let wrong_owner = fixture.owner.checked_add(1).unwrap_or(fixture.owner - 1);
    let mut source = RootOwnedCurrentAuthoritySource::for_test(
        fixture.path.clone(),
        fixture.trust_anchor.clone(),
        wrong_owner,
    );

    assert!(source.load_current().is_err());
}

#[test]
fn publisher_rejects_a_lower_sequence_replay() {
    let fixture = AuthorityFixture::new();
    let mut document = fixture.publish(3, 1_003, CurrentResourceState::Absent);
    document.sequence = 2;
    document.observed_at_restart_millis = 1_002;

    let error = publish_authority_file(
        &fixture.path,
        &fixture.trust_anchor,
        fixture.owner,
        &document,
    )
    .expect_err("a lower sequence must not replace current authority");
    assert!(error.to_string().contains("advance its sequence"));
}

#[test]
fn publisher_rejects_a_regressed_observation_timestamp() {
    let fixture = AuthorityFixture::new();
    let mut document = fixture.publish(2, 1_002, CurrentResourceState::Absent);
    document.sequence = 3;
    document.observed_at_restart_millis = 1_001;

    let error = publish_authority_file(
        &fixture.path,
        &fixture.trust_anchor,
        fixture.owner,
        &document,
    )
    .expect_err("a newer sequence must not regress its observation time");
    assert!(error.to_string().contains("observation timestamp"));
}

#[test]
fn competing_publishers_leave_the_highest_sequence_selected() {
    let fixture = AuthorityFixture::new();
    let mut lower = fixture.publish(1, 1_001, CurrentResourceState::Absent);
    lower.sequence = 2;
    lower.observed_at_restart_millis = 1_002;
    let mut higher = lower.clone();
    higher.sequence = 3;
    higher.observed_at_restart_millis = 1_003;
    let barrier = Arc::new(Barrier::new(3));
    let workers = [lower, higher].map(|document| {
        let path = fixture.path.clone();
        let anchor = fixture.trust_anchor.clone();
        let barrier = Arc::clone(&barrier);
        let owner = fixture.owner;
        std::thread::spawn(move || {
            barrier.wait();
            publish_authority_file(&path, &anchor, owner, &document)
        })
    });
    barrier.wait();
    let results = workers.map(|worker| worker.join().expect("publisher thread"));
    assert!(results[1].is_ok());

    let selected = RootOwnedCurrentAuthoritySource::for_test(
        fixture.path.clone(),
        fixture.trust_anchor.clone(),
        fixture.owner,
    )
    .load_current()
    .expect("selected current authority");
    assert_eq!(selected.sequence, 3);
}

fn policy_fence() -> RevisionId {
    RevisionId(Sha256Digest::of_bytes("test policy fence"))
}
