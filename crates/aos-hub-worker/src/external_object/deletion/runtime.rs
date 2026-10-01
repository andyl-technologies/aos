//! Worker-local exact precondition observation and conditional provider DELETE.

use anyhow::{ensure, Result};
use aos_hub_core::{
    s3surface::{Method as S3Method, S3Surface},
    storage_authority::{
        external_object::{
            deletion::ExternalDeletePrecondition, ExternalObjectOutcome, ExternalObjectRequest,
        },
        lease::{EpochLeaseFloor, LeaseEffect},
    },
    storage_work::{StorageBindingPublication, StorageCredentialSelector},
};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use super::super::{config::Config, delete_config, protocol::Intent};

/// Executes the exact leased versioned DELETE and bounded metadata preconditions.
///
/// # Errors
/// Returns an error for changed authority, expiry, unavailable material, provider
/// I/O, or an ambiguous response that leaves the permanent turn unresolved.
pub(in crate::external_object) async fn execute(
    env: &Env,
    object: &Config,
    publication: &StorageBindingPublication,
    work: &ExternalObjectRequest,
    intent: &Intent,
    floor: &EpochLeaseFloor,
    expected: &ExternalDeletePrecondition,
    path: &str,
) -> Result<ExternalObjectOutcome> {
    let cohort = object.cohort(&intent.cohort_digest)?;
    let domains = delete_config::configured(env, object)?;
    let domain = domains.domain(cohort)?;
    // HEAD is the metadata precondition phase of this exact delete turn. It
    // uses only the retained delete credential, as the frozen cleanup contract
    // requires, and grants neither object-body reads nor another effect.
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let now = object.clock().observed_at;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, now)?;
    let condition_selector = StorageCredentialSelector {
        purpose: "delete".into(),
        generation: domain.delete_cohort.credential.generation.get(),
    };
    ensure!(
        work.plan
            .credential_references
            .contains(&condition_selector),
        "delete condition generation differs"
    );
    let secret = publication.credential_text(&condition_selector, &deployment, now)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &work.plan.placement_prefix,
        Some(secret.as_str()),
        now,
    )?;
    let url = surface.object_url(S3Method::Head, path, now)?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let headers = Headers::new();
    let probe = aos_hub_core::storage_work::admitted_probe_path(path)
        && expected.bytes.parse::<u64>()? <= 4096;
    if !probe {
        headers.set("if-match", &expected.etag)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Head)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(&url, &init)?;
    let validated = object.verifier()?.validate_lease(
        work.lease.as_bytes(),
        &domain.delete_cohort,
        &object.timing_profile,
        floor,
        &intent.scope.full_key,
        LeaseEffect::ConditionalDelete,
        object.clock(),
    )?;
    work.check_dispatch_time(&publication.snapshot, &validated, floor, object.clock())?;
    let response = Fetch::Request(request).send().await?;
    match response.status_code() {
        404 => {
            // Latest-key absence can hide an older version behind a marker.
            // It cannot settle the reviewed physical incarnation by itself.
            let url = surface.versioned_head_url(
                path,
                &expected.provider_version,
                object.clock().observed_at,
                30,
            )?;
            aos_hub_core::url_guard::is_safe_remote_url(&url)?;
            let mut init = RequestInit::new();
            init.with_method(Method::Head)
                .with_redirect(RequestRedirect::Manual);
            let request = Request::new_with_init(&url, &init)?;
            let validated = object.verifier()?.validate_lease(
                work.lease.as_bytes(),
                cohort,
                &object.timing_profile,
                floor,
                &intent.scope.full_key,
                LeaseEffect::ConditionalDelete,
                object.clock(),
            )?;
            work.check_dispatch_time(&publication.snapshot, &validated, floor, object.clock())?;
            let exact = Fetch::Request(request).send().await?;
            return match exact.status_code() {
                404 => Ok(ExternalObjectOutcome::DeleteAbsent),
                200 | 405 => Ok(ExternalObjectOutcome::DeletePreconditionFailed),
                _ => anyhow::bail!("exact-version absence was not positively observed"),
            };
        }
        412 => return Ok(ExternalObjectOutcome::DeletePreconditionFailed),
        200 => {}
        _ => anyhow::bail!("conditional delete HEAD was not positively acknowledged"),
    }
    let size = response.headers().get("content-length")?;
    let etag = response.headers().get("etag")?;
    let version = response.headers().get("x-amz-version-id")?;
    if !super::condition_matches(
        expected,
        path,
        size.as_deref(),
        etag.as_deref(),
        version.as_deref(),
    )? {
        return Ok(ExternalObjectOutcome::DeletePreconditionFailed);
    }
    // Reserved probes intentionally send a wrong If-Match to the *current*
    // version so the provider must enforce the condition. Ordinary objects
    // never reach DELETE after an ETag mismatch.

    let now = object.clock().observed_at;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, now)?;
    let selector = StorageCredentialSelector {
        purpose: "delete".into(),
        generation: cohort.credential.generation.get(),
    };
    ensure!(
        work.plan.credential_references.contains(&selector),
        "delete generation differs"
    );
    let secret = publication.credential_text(&selector, &deployment, now)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &work.plan.placement_prefix,
        Some(secret.as_str()),
        now,
    )?;
    let url = surface.versioned_conditional_delete_url(
        path,
        &expected.provider_version,
        &expected.etag,
        now,
        30,
    )?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let headers = Headers::new();
    headers.set("if-match", &expected.etag)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Delete)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(&url, &init)?;
    let validated = object.verifier()?.validate_lease(
        work.lease.as_bytes(),
        cohort,
        &object.timing_profile,
        floor,
        &intent.scope.full_key,
        LeaseEffect::ConditionalDelete,
        object.clock(),
    )?;
    work.check_dispatch_time(&publication.snapshot, &validated, floor, object.clock())?;
    // No await follows the final lease check before this single provider effect.
    let response = Fetch::Request(request).send().await?;
    super::acknowledgement(
        expected,
        response.status_code(),
        response.headers().get("x-amz-version-id")?.as_deref(),
        response.headers().get("x-amz-delete-marker")?.as_deref(),
    )
}
