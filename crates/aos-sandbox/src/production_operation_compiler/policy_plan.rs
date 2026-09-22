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
    PublicPolicyPlanningErrorV1, ResolvedPublicPolicyPlanRequestV1,
};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

const POLICY_PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-policy-plan.v1\0";

pub(super) fn compile_public_policy_plan(
    journal: &mut Journal,
    resolved: &ResolvedPublicPolicyPlanRequestV1,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    match resolved.typed_request() {
        Request::PlanCreate(request) => plan_create(journal, request),
        Request::PlanPolicy(request) => plan_update(journal, request),
        _ => Err(PublicPolicyPlanningErrorV1::Malformed),
    }
}

pub(super) fn expected_update_plan_digest(
    journal: &mut Journal,
    sandbox_id: [u8; 16],
    expected_resource_version: &[u8],
    requested_policy: &ObjectDescriptor,
) -> Result<Vec<u8>, PublicPolicyPlanningErrorV1> {
    let sandbox = load_sandbox(journal, sandbox_id)?;
    if sandbox.resource_version != expected_resource_version {
        return Err(PublicPolicyPlanningErrorV1::Rejected);
    }
    let project = project_id(&sandbox.project_id)?;
    policy_plan(journal, project, requested_policy, &[], None).map(|plan| plan.plan_digest)
}

pub(super) fn validate_current_requested_policy(
    journal: &mut Journal,
    project: ProjectId,
    requested_policy: &ObjectDescriptor,
) -> Result<(), PublicPolicyPlanningErrorV1> {
    let current = current_policy(journal, project)?;
    if proto_descriptor(current.descriptor()) == *requested_policy {
        Ok(())
    } else {
        Err(PublicPolicyPlanningErrorV1::Rejected)
    }
}

fn plan_create(
    journal: &mut Journal,
    request: &aos_proto::aos::sandbox::v1::PlanCreateSandboxRequest,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let project = project_id(&request.project_id)?;
    let policy = current_policy(journal, project)?;
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
    )
}

fn plan_update(
    journal: &mut Journal,
    request: &aos_proto::aos::sandbox::v1::PlanSandboxPolicyRequest,
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

    policy_plan(journal, project, requested_policy, &[], specification)
}

fn policy_plan(
    journal: &mut Journal,
    project: ProjectId,
    requested_policy: &ObjectDescriptor,
    request_features: &[Feature],
    extra_input: Option<ObjectDescriptor>,
) -> Result<PolicyPlan, PublicPolicyPlanningErrorV1> {
    let current = current_policy(journal, project)?;
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
) -> Result<crate::publisher_policy::PreparedPublisherPolicyRevisionV1, PublicPolicyPlanningErrorV1>
{
    PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
        .current_policy(project)
        .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
        .ok_or(PublicPolicyPlanningErrorV1::Rejected)
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
