//! Provider domain isolation, exact projections, positional paging and quota fences.

use anyhow::Result;
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::observation::{
    PROVIDER_OBSERVATION_V1, ProviderCoverage, ProviderObservationV1, SourceEvidenceRef,
};
use aos_assessment::time::Timestamp;
use aos_assessment_providers::osv::Query;
use aos_assessment_runtime::provider::*;
use aos_assessment_runtime::scan::*;
use aos_contract::Sha256Digest;

fn now() -> Result<Timestamp> {
    Timestamp::parse("2026-10-09T12:00:00Z")
}

fn plan() -> Result<ProviderWorkPlanV1> {
    let issued = now()?;
    let expires = Timestamp::from_unix_seconds(issued.unix_seconds() + 60)?;
    let operation = ProviderOperation::QueryOsv {
        queries: vec![Query::Ecosystem {
            ecosystem: "crates.io".into(),
            name: "fixture".into(),
            version: "1.2.0".into(),
        }],
        projects: vec!["fixture-query".into()],
        continuations: vec![],
    };
    Ok(ProviderWorkPlanV1 {
        schema: PROVIDER_WORK_PLAN_V1.into(),
        deployment_id: "fixture-deployment".into(),
        issuer: "coordinator".into(),
        audience: "provider-executor".into(),
        plan_id: "fixture-plan".into(),
        claim: TaskClaim {
            scan_id: "fixture-scan".into(),
            task_id: "fixture-task".into(),
            request_digest: Sha256Digest::of_bytes("request"),
            generation: 1,
            inventory_revision: 1,
            claim_token: "00000000000000000000000000000001".into(),
            expires_at: expires.clone(),
            attempt: 1,
        },
        issued_at: issued,
        expires_at: expires.clone(),
        nonce: "00000000000000000000000000000002".into(),
        inventory_digest: Sha256Digest::of_bytes("inventory"),
        policy_digest: Sha256Digest::of_bytes("policy"),
        authorization_partition: "tenant-fixture".into(),
        credential_ref: None,
        budget_reservation: BudgetReservation {
            source_budget: "public-osv".into(),
            reservation_id: "reservation-one".into(),
            requests: 10,
            deadline: expires,
        },
        cache_ref: None,
        continuation: None,
        adapter_version: operation.adapter_version().into(),
        operation,
        limits: ProviderLimits::default(),
    })
}

fn result(plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
    let raw = b"retained complete empty query answer";
    let source = Sha256Digest::of_bytes(raw);
    let observation = ProviderObservationV1 {
        schema: PROVIDER_OBSERVATION_V1.into(),
        provider: "osv".into(),
        project: "fixture-query".into(),
        adapter_version: plan.adapter_version.clone(),
        request_identity_digest: plan.operation.digest()?,
        retrieved_at: now()?,
        validated_at: now()?,
        expires_at: Timestamp::from_unix_seconds(now()?.unix_seconds() + 86400)?,
        response_digest: source,
        payload_digest: Sha256Digest::of_canonical(
            "aos.advisory-record-set/v1",
            &Vec::<Sha256Digest>::new(),
        )?,
        validators: None,
        coverage: ProviderCoverage::Complete {
            proof: "query-pagination-exhausted".into(),
        },
        source_refs: vec![SourceEvidenceRef {
            digest: source,
            byte_length: raw.len() as u64,
            origin: "osv".into(),
        }],
    };
    let digest = observation.digest()?;
    Ok(ProviderWorkResultV1 {
        schema: PROVIDER_WORK_RESULT_V1.into(),
        plan_digest: plan.digest()?,
        claim: plan.claim.clone(),
        executor_build: "fixture-build".into(),
        adapter_version: plan.adapter_version.clone(),
        outcome: WorkOutcome::Observed,
        normalized_objects: vec![ObjectProjection {
            digest,
            object: NormalizedObject::Observation(observation),
        }],
        observation_refs: vec![digest],
        coverage: ProviderCoverage::Complete {
            proof: "query-pagination-exhausted".into(),
        },
        continuation: None,
        usage: ProviderUsage {
            requests: 1,
            compressed_bytes: raw.len() as u64,
            decompressed_bytes: raw.len() as u64,
            duration_milliseconds: 10,
        },
        completed_at: now()?,
        diagnostics: vec![],
    })
}

fn auth() -> Result<ProviderWorkAuth> {
    ProviderWorkAuth::new(
        vec![17; 32],
        "fixture-deployment".into(),
        "coordinator".into(),
        "provider-executor".into(),
    )
}

#[test]
fn exact_plan_and_result_signatures_are_independent_and_body_bound() -> Result<()> {
    let plan = plan()?;
    let auth = auth()?;
    let (bytes, signature) = auth.sign_plan(&plan, &now()?)?;
    assert_eq!(auth.verify_plan(&bytes, &signature, &now()?)?, plan);
    let result = result(&plan)?;
    let (result_bytes, result_signature) = auth.sign_result(&result, &plan, &now()?)?;
    assert_eq!(
        auth.verify_result(&result_bytes, &result_signature, &plan, &now()?)?,
        result
    );
    assert!(
        auth.verify_plan(&result_bytes, &result_signature, &now()?)
            .is_err()
    );
    assert!(
        auth.verify_result(&bytes, &signature, &plan, &now()?)
            .is_err()
    );
    let mut tampered = bytes;
    tampered.push(b' ');
    assert!(auth.verify_plan(&tampered, &signature, &now()?).is_err());
    Ok(())
}

#[test]
fn wrong_deployment_expiry_lease_or_adapter_fails_before_effects() -> Result<()> {
    let mut work = plan()?;
    let auth = auth()?;
    work.deployment_id = "other-deployment".into();
    assert!(auth.sign_plan(&work, &now()?).is_err());
    work = plan()?;
    assert!(work.validate_at(&work.expires_at).is_err());
    work.expires_at = Timestamp::from_unix_seconds(now()?.unix_seconds() + 61)?;
    assert!(work.validate_at(&now()?).is_err());
    work = plan()?;
    work.claim.claim_token = "guessable".into();
    assert!(work.validate_at(&now()?).is_err());
    work = plan()?;
    work.adapter_version = "future-unnegotiated".into();
    assert!(work.validate_at(&now()?).is_err());
    Ok(())
}

#[test]
fn arbitrary_source_paths_optional_nulls_and_unknown_operations_are_rejected() -> Result<()> {
    for repository in [
        "https://private.invalid/path",
        "owner/repo/extra",
        "owner/..",
        "owner/repo?secret=x",
    ] {
        assert!(
            ProviderOperation::ObserveTags {
                repository: repository.into(),
                tag_prefix: "v".into(),
                page: 1
            }
            .validate()
            .is_err()
        );
    }
    let mut body = serde_json::to_value(plan()?)?;
    body["credentialRef"] = serde_json::Value::Null;
    let bytes = aos_contract::canonical::to_vec(&body)?;
    assert!(ProviderWorkPlanV1::from_slice(&bytes, &now()?).is_err());
    let mut request = request()?;
    request.subjects.push("other".into());
    assert!(request.digest().is_err());
    body["operation"]["kind"] = serde_json::json!("fetch-arbitrary-url");
    assert!(serde_json::from_value::<ProviderWorkPlanV1>(body).is_err());
    Ok(())
}

#[test]
fn positional_osv_continuation_does_not_move_another_querys_token() -> Result<()> {
    let query = |name: &str| Query::Ecosystem {
        ecosystem: "crates.io".into(),
        name: name.into(),
        version: "1.2.0".into(),
    };
    let mut work = ProviderOperation::QueryOsv {
        queries: vec![query("first"), query("second")],
        projects: vec!["first-scope".into(), "second-scope".into()],
        continuations: vec![QueryContinuation {
            position: 1,
            token: "second-page-token".into(),
        }],
    };
    work.validate()?;
    if let ProviderOperation::QueryOsv { continuations, .. } = &mut work {
        continuations[0].position = 2;
    }
    assert!(work.validate().is_err());
    Ok(())
}

#[test]
fn changed_projection_query_scope_claim_or_budget_cannot_be_admitted() -> Result<()> {
    let plan = plan()?;
    let mut result = result(&plan)?;
    result.validate_for(&plan, &now()?)?;
    result.normalized_objects[0].digest = Sha256Digest::of_bytes("changed projection");
    assert!(result.validate_for(&plan, &now()?).is_err());
    result = self::result(&plan)?;
    if let NormalizedObject::Observation(observation) = &mut result.normalized_objects[0].object {
        observation.project = "other-tenant-query".into();
    }
    result.normalized_objects[0].digest = result.normalized_objects[0].object.digest()?;
    result.observation_refs = vec![result.normalized_objects[0].digest];
    assert!(result.validate_for(&plan, &now()?).is_err());
    result = self::result(&plan)?;
    result.claim.attempt = 2;
    assert!(result.validate_for(&plan, &now()?).is_err());
    result = self::result(&plan)?;
    result.usage.requests = 11;
    assert!(result.validate_for(&plan, &now()?).is_err());
    Ok(())
}

#[test]
fn not_modified_without_exact_cached_response_is_not_a_fresh_answer() -> Result<()> {
    let plan = plan()?;
    let mut result = result(&plan)?;
    result.outcome = WorkOutcome::NotModified;
    assert!(result.validate_for(&plan, &now()?).is_err());
    Ok(())
}

fn request() -> Result<ScanRequestV1> {
    let plan = plan()?;
    Ok(ScanRequestV1 {
        schema: SCAN_REQUEST_V1.into(),
        resource_scope: "registry-incarnation".into(),
        authorization_partition: plan.authorization_partition,
        inventory_revision: 1,
        inventory_digest: plan.inventory_digest,
        policy_digest: plan.policy_digest,
        subjects: vec!["subject".into()],
        profiles: vec![Profile::Updates, Profile::Vulnerabilities],
        freshness: FreshnessMode::RefreshStale,
        trigger: "manual".into(),
        actor_ref: "fixture-user".into(),
        idempotency_key: "request-one".into(),
        limits: ScanLimits::default(),
    })
}

#[test]
fn immutable_terminal_states_and_cancellation_fence_every_success_transition() -> Result<()> {
    for terminal in [
        ScanState::Succeeded,
        ScanState::Partial,
        ScanState::Failed,
        ScanState::Cancelled,
        ScanState::Superseded,
    ] {
        assert!(terminal.is_terminal());
        assert!(terminal.transition(ScanState::Running).is_err());
        assert!(terminal.transition(terminal).is_err());
    }
    ScanState::Queued
        .transition(ScanState::Running)?
        .transition(ScanState::Cancelling)?
        .transition(ScanState::Cancelled)?;
    assert!(
        ScanState::Cancelling
            .transition(ScanState::Succeeded)
            .is_err()
    );
    assert!(ScanState::Queued.transition(ScanState::Succeeded).is_err());
    Ok(())
}

#[test]
fn scan_request_scope_is_closed_and_attempt_usage_is_monotonic() -> Result<()> {
    let request = request()?;
    let bytes = aos_contract::canonical::to_vec(&request)?;
    assert_eq!(ScanRequestV1::from_slice(&bytes)?, request);
    let mut value = serde_json::to_value(request.clone())?;
    value["token"] = serde_json::json!("must-not-enter-request");
    assert!(ScanRequestV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = serde_json::to_value(request.clone())?;
    value["actorRef"] = serde_json::Value::Null;
    assert!(ScanRequestV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    let mut limits = request.limits;
    limits.provider_requests = 1;
    let consumed = ScanUsage::default().consume(
        &ScanUsage {
            provider_requests: 1,
            tasks: 1,
            normalized_bytes: 10,
        },
        &limits,
    )?;
    assert!(
        consumed
            .consume(
                &ScanUsage {
                    provider_requests: 1,
                    ..ScanUsage::default()
                },
                &limits
            )
            .is_err()
    );
    assert_eq!(consumed.provider_requests, 1);
    assert!(
        ScanUsage {
            normalized_bytes: u64::MAX,
            ..ScanUsage::default()
        }
        .consume(
            &ScanUsage {
                normalized_bytes: 1,
                ..ScanUsage::default()
            },
            &limits
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn capabilities_are_fresh_paired_authenticated_and_bound_to_exact_profiles() -> Result<()> {
    let plan = plan()?;
    let challenge = CapabilityChallenge {
        schema: "aos.provider-capability-challenge/v1".into(),
        deployment_id: plan.deployment_id.clone(),
        issuer: plan.issuer.clone(),
        audience: plan.audience.clone(),
        nonce: plan.nonce.clone(),
        issued_at: now()?,
        expires_at: plan.expires_at.clone(),
    };
    let auth = auth()?;
    let (body, signature) = auth.sign_challenge(&challenge, &now()?)?;
    assert_eq!(
        auth.verify_challenge(&body, &signature, &now()?)?,
        challenge
    );
    assert!(auth.verify_plan(&body, &signature, &now()?).is_err());
    let capabilities = ProviderCapabilitiesV1 {
        schema: "aos.provider-capabilities/v1".into(),
        challenge: challenge.clone(),
        executor_build: "fixture-executor".into(),
        adapters: vec![plan.adapter_version.clone()],
        limits: ProviderLimits::default(),
    };
    let (body, signature) = auth.sign_capabilities(&capabilities, &now()?)?;
    auth.verify_capabilities(&body, &signature, &challenge, &now()?)?
        .require(&plan.operation)?;
    let mut different = challenge.clone();
    different.nonce = "00000000000000000000000000000003".into();
    assert!(
        auth.verify_capabilities(&body, &signature, &different, &now()?)
            .is_err()
    );
    assert!(
        auth.verify_capabilities(&body, &signature, &challenge, &challenge.expires_at)
            .is_err()
    );
    assert!(
        capabilities
            .require(&ProviderOperation::RefreshKev { offset: 0 })
            .is_err()
    );
    let mut tighter = capabilities.limits;
    tighter.result_bytes = 128 * 1024;
    assert!(plan.limits.require_within(&tighter).is_err());
    Ok(())
}
