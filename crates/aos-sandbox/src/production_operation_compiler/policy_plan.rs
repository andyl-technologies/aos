//! Pure production policy planning over current protected policy inputs.
//!
//! V1 accepts only an already resolved policy descriptor that exactly matches
//! the project's current protected revision. The public request carries no
//! policy bytes, so accepting a different descriptor would claim an
//! intersection that the controller could not actually verify.

use aos_proto::aos::sandbox::v1::{
    Feature, ObjectDescriptor, PolicyPlan, PolicyReason, PolicyReasonCode,
};
use aos_sandbox_core::{ObjectDescriptor as CoreObjectDescriptor, ProjectId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::cli_model::DormantSandboxRequestKindV1 as Request;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::public_policy_planner::{
    AuthorizedPublicPolicyPlanRequestV1, PublicPolicyPlanningErrorV1,
};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

const POLICY_PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-policy-plan.v1\0";

pub(super) fn compile_public_policy_plan(
    journal: &mut Journal,
    authorized: &AuthorizedPublicPolicyPlanRequestV1,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let authorized_at = authorized.authorized_wall_seconds();
    let policy_generation = authorized.policy_generation();
    match authorized.request().typed_request() {
        Request::PlanCreate(request) => {
            plan_create(journal, request, authorized_at, policy_generation)
        }
        Request::PlanPolicy(request) => {
            plan_update(journal, request, authorized_at, policy_generation)
        }
        _ => Err(PublicPolicyPlanningErrorV1::Malformed),
    }
}

pub(super) fn expected_update_plan_digest(
    journal: &mut Journal,
    sandbox_id: [u8; 16],
    expected_resource_version: &[u8],
    requested_policy: &ObjectDescriptor,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<Vec<u8>, PublicPolicyPlanningErrorV1> {
    let sandbox = load_sandbox(journal, sandbox_id)?;
    if sandbox.resource_version != expected_resource_version {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }
    let project = project_id(&sandbox.project_id)?;
    policy_plan(
        journal,
        project,
        requested_policy,
        &[],
        None,
        authorized_at,
        policy_generation,
    )
    .map(|plan| plan.plan_digest)
}

pub(super) fn validate_current_requested_policy(
    journal: &mut Journal,
    project: ProjectId,
    requested_policy: &ObjectDescriptor,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<(), PublicPolicyPlanningErrorV1> {
    let current = current_policy(journal, project, authorized_at, policy_generation)?;
    if proto_descriptor(current.descriptor()) == *requested_policy {
        Ok(())
    } else {
        Err(PublicPolicyPlanningErrorV1::Rejected)
    }
}

fn plan_create(
    journal: &mut Journal,
    request: &aos_proto::aos::sandbox::v1::PlanCreateSandboxRequest,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let project = project_id(&request.project_id)?;
    let policy = current_policy(journal, project, authorized_at, policy_generation)?;
    if request.expected_project_resource_version != policy.descriptor().digest().as_bytes() {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }
    let requested_policy = request
        .requested_policy
        .as_option()
        .ok_or(PublicPolicyPlanningErrorV1::Malformed)?;
    if proto_descriptor(policy.descriptor()) != *requested_policy {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }

    let mut extra_input = request.specification.as_option().cloned();
    if !request.parent_sandbox_id.is_empty() {
        let parent = load_sandbox(journal, exact_id(&request.parent_sandbox_id)?)?;
        if parent.project_id.as_slice() != project.as_bytes()
            || parent.resource_version != request.expected_parent_resource_version
            || parent.effective_policy.as_option() != Some(requested_policy)
        {
            return Err(PublicPolicyPlanningErrorV1::Rejected);
        }
        if extra_input.is_none() {
            extra_input = parent.effective_policy.as_option().cloned();
        }
    }

    policy_plan(
        journal,
        project,
        requested_policy,
        &request.required_features,
        extra_input,
        authorized_at,
        policy_generation,
    )
}

fn plan_update(
    journal: &mut Journal,
    request: &aos_proto::aos::sandbox::v1::PlanSandboxPolicyRequest,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let sandbox = load_sandbox(journal, exact_id(&request.sandbox_id)?)?;
    if sandbox.resource_version != request.expected_resource_version {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }
    let project = project_id(&sandbox.project_id)?;
    let requested_policy = request
        .requested_policy
        .as_option()
        .ok_or(PublicPolicyPlanningErrorV1::Malformed)?;
    let specification = sandbox
        .desired
        .as_option()
        .and_then(|desired| desired.specification.as_option())
        .cloned();

    policy_plan(
        journal,
        project,
        requested_policy,
        &[],
        specification,
        authorized_at,
        policy_generation,
    )
}

fn policy_plan(
    journal: &mut Journal,
    project: ProjectId,
    requested_policy: &ObjectDescriptor,
    request_features: &[Feature],
    extra_input: Option<ObjectDescriptor>,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let current = current_policy(journal, project, authorized_at, policy_generation)?;
    let effective_policy = proto_descriptor(current.descriptor());
    if effective_policy != *requested_policy {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }

    let mut input_commitments = vec![effective_policy.clone()];
    if let Some(input) = extra_input {
        push_unique(&mut input_commitments, input);
    }
    for input in current.policy().input_commitments() {
        push_unique(&mut input_commitments, proto_descriptor(input));
    }

    let mut required_features = request_features.to_vec();
    required_features.extend(
        current
            .policy()
            .required_features()
            .iter()
            .map(|feature| Feature {
                namespace: feature.namespace().to_owned(),
                major: feature.major(),
                minor: feature.minor(),
                ..Default::default()
            }),
    );
    required_features.sort_by(|left, right| {
        (&left.namespace, left.major, left.minor).cmp(&(&right.namespace, right.major, right.minor))
    });
    required_features.dedup();

    let reason = PolicyReason {
        code: "request-accepted".to_owned(),
        source: Some(effective_policy.clone()).into(),
        safe_message: "The requested policy is the current resolved project policy.".to_owned(),
        reason_code: PolicyReasonCode::POLICY_REASON_CODE_REQUEST_ACCEPTED.into(),
        ..Default::default()
    };
    let mut plan = PolicyPlan {
        requested_policy: Some(requested_policy.clone()).into(),
        effective_policy: Some(effective_policy).into(),
        input_commitments,
        required_features,
        reasons: vec![reason],
        ..Default::default()
    };
    plan.plan_digest = policy_plan_digest(&plan);
    Ok(plan)
}

fn policy_plan_digest(plan: &PolicyPlan) -> Vec<u8> {
    let mut canonical = plan.clone();
    canonical.plan_digest.clear();
    Sha256::new()
        .chain_update(POLICY_PLAN_DIGEST_DOMAIN)
        .chain_update(canonical.encode_to_vec())
        .finalize()
        .to_vec()
}

fn current_policy(
    journal: &mut Journal,
    project: ProjectId,
    authorized_at: i64,
    policy_generation: u64,
) -> Result<crate::publisher_policy::PreparedPublisherPolicyRevisionV1, PublicPolicyPlanningErrorV1>
{
    let current = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
        .current_policy(project)
        .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
        .ok_or(PublicPolicyPlanningErrorV1::Rejected)?;
    // Authorization sampled protected time and policy generation before
    // compilation. Both must still describe the reloaded head, even when a
    // successor publishes identical policy bytes.
    if current.generation() != policy_generation
        || authorized_at < current.not_before()
        || authorized_at >= current.expires_at()
    {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }
    Ok(current)
}

fn load_sandbox(
    journal: &Journal,
    id: [u8; 16],
) -> Result<aos_proto::aos::sandbox::v1::Sandbox, PublicPolicyPlanningErrorV1> {
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Sandbox, id)
        .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
        .ok_or(PublicPolicyPlanningErrorV1::Rejected)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = record.resource() else {
        return Err(PublicPolicyPlanningErrorV1::Unavailable);
    };
    Ok(sandbox.clone())
}

fn project_id(bytes: &[u8]) -> Result<ProjectId, PublicPolicyPlanningErrorV1> {
    Ok(ProjectId::from_bytes(exact_id(bytes)?))
}

fn exact_id(bytes: &[u8]) -> Result<[u8; 16], PublicPolicyPlanningErrorV1> {
    let id = bytes
        .try_into()
        .map_err(|_| PublicPolicyPlanningErrorV1::Malformed)?;
    if id == [0; 16] {
        Err(PublicPolicyPlanningErrorV1::Malformed)
    } else {
        Ok(id)
    }
}

fn proto_descriptor(value: &CoreObjectDescriptor) -> ObjectDescriptor {
    ObjectDescriptor {
        media_type: value.media_type().as_str().to_owned(),
        sha256: value.digest().as_bytes().to_vec(),
        encoded_size: value.encoded_size(),
        ..Default::default()
    }
}

fn push_unique(values: &mut Vec<ObjectDescriptor>, value: ObjectDescriptor) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::format::encode_policy;
    use aos_sandbox_core::model::{
        CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
    };
    use aos_sandbox_core::{CacheDomainId, DecodeLimits};

    use super::*;
    use crate::JournalLimits;
    use crate::publisher_policy::PreparedPublisherPolicyRevisionV1;

    #[test]
    fn current_policy_rechecks_the_exact_authorization_interval_after_head_change() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "create-policy.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();

        let project = ProjectId::from_bytes([1; 16]);
        let domain = CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([2; 16]));
        let policy = Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResourceProfile::new(Vec::new()).unwrap(),
            Vec::new(),
            domain,
            RevocationPolicy::new(RevocationMode::DenyNew, 0),
            None,
            Vec::new(),
        )
        .unwrap();
        let canonical = encode_policy(&policy);
        let revision = |generation, not_before, expires_at| {
            PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
                project,
                generation,
                not_before,
                expires_at,
                &canonical,
                DecodeLimits::default(),
            )
            .unwrap()
        };
        let first = revision(1, 100, 200);
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .unwrap()
            .publish_policy_from_trusted_controller([3; 16], None, &first)
            .unwrap();

        let descriptor = proto_descriptor(first.descriptor());
        assert_eq!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 99, 1),
            Err(PublicPolicyPlanningErrorV1::Rejected)
        );
        assert!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 100, 1).is_ok()
        );
        assert!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 199, 1).is_ok()
        );
        assert_eq!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 200, 1),
            Err(PublicPolicyPlanningErrorV1::Rejected)
        );

        let replacement = revision(2, 150, 400);
        assert_eq!(replacement.descriptor(), first.descriptor());
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .unwrap()
            .publish_policy_from_trusted_controller([4; 16], Some(1), &replacement)
            .unwrap();
        assert_eq!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 150, 1),
            Err(PublicPolicyPlanningErrorV1::Rejected)
        );
        assert!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 150, 2).is_ok()
        );

        let later = revision(3, 500, 600);
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .unwrap()
            .publish_policy_from_trusted_controller([5; 16], Some(2), &later)
            .unwrap();
        assert_eq!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 350, 3),
            Err(PublicPolicyPlanningErrorV1::Rejected)
        );
        assert!(
            validate_current_requested_policy(&mut journal, project, &descriptor, 500, 3).is_ok()
        );
    }
}
