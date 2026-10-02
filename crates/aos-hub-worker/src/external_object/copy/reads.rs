//! Independently leased, bounded scan reads for external copies.
//!
//! Listings describe keys; they never establish a source incarnation. Hash
//! inspection pins either a real provider version or a previously closed
//! permanent guard receipt. Protected ranges hold that source gate through EOF
//! or cancellation. Provider bytes stay beside the store, with 64 KiB buffers.
//! Cross-request OCI hash continuations require a real provider version; their
//! wire state has no permanent closure pin for the protected versionless form.

use anyhow::{Result, ensure};
use aos_hub_core::{
    db::OciSha256State,
    s3surface::{Method as S3Method, S3Surface},
    storage_authority::{
        external_object::copy::CopySourceObject,
        lease::{LeaseEffect, LeaseInteger},
    },
    storage_work::{
        StorageBindingPublication, StorageObjectIdentity, StorageWorkOperation, StorageWorkPlan,
        StorageWorkResult,
    },
};
use rand::TryRngCore as _;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use super::super::{
    config::{Config as ObjectConfig, configured},
    protocol::{GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER, digest},
    storage,
};
use super::{config, read_control, stream, window::DispatchWindow};

/// Executes configured HEAD, LIST, protected inspection or versioned OCI hashing.
///
/// # Errors
/// Refuses missing installed cohorts, active owners, changed publications,
/// unsupported version metadata, stale permission or any failed provider I/O.
pub(crate) async fn execute(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
    signal: &worker::web_sys::AbortSignal,
) -> Result<Option<StorageWorkResult>> {
    use aos_hub_core::storage_work::StorageWorkOutcome as Outcome;
    if !matches!(
        plan.operation,
        StorageWorkOperation::Head { .. }
            | StorageWorkOperation::ListPage { .. }
            | StorageWorkOperation::InspectSha256 { .. }
            | StorageWorkOperation::HashOciRange { .. }
    ) {
        return Ok(None);
    }
    let Some(object) = configured(env)? else {
        return Ok(None);
    };
    let Some(config) = config::configured(env, &object)? else {
        return Ok(None);
    };
    let domain = config
        .domains
        .iter()
        .find(|domain| domain.write_cohort.association.binding_id.get() == plan.binding_id)
        .ok_or_else(|| anyhow::anyhow!("external scan copy domain absent"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    // Validate the signed inventory continuation before acquiring a lease or
    // touching the provider. Its selected version cannot be renewed by HEAD.
    let hash_range = if matches!(plan.operation, StorageWorkOperation::HashOciRange { .. }) {
        Some(super::hash_range::Selection::from_operation(
            &plan.operation,
        )?)
    } else {
        None
    };
    let (purpose, effect, relative) = match &plan.operation {
        StorageWorkOperation::ListPage { prefix, limit, .. } => {
            ensure!(*limit > 0, "external scan page is empty");
            ("list", LeaseEffect::List, prefix.as_str())
        }
        StorageWorkOperation::Head { path } => ("read", LeaseEffect::Head, path.as_str()),
        StorageWorkOperation::InspectSha256 { path, .. } => {
            ("read", LeaseEffect::Read, path.as_str())
        }
        StorageWorkOperation::HashOciRange { path, .. } => {
            ("read", LeaseEffect::Read, path.as_str())
        }
        _ => anyhow::bail!("external scan operation differs"),
    };
    let cohort = if effect == LeaseEffect::List {
        &domain.list_cohort
    } else {
        &domain.read_cohort
    };
    let association = &cohort.association;
    let full_key = aos_hub_core::keymap::r2_key(
        &association.binding_prefix,
        &aos_hub_core::keymap::r2_key(&plan.placement_prefix, relative),
    );
    // A listing prefix may end at a directory boundary, including the empty
    // relative prefix for a whole placement. Its read-only floor uses the
    // canonical nonempty boundary; the signed provider query and cursor retain
    // the exact requested prefix. Object HEAD/read keys are never normalized.
    let full_key = if effect == LeaseEffect::List {
        full_key.trim_end_matches('/').to_owned()
    } else {
        full_key
    };
    let scope = object.scope(cohort, full_key)?;
    let fresh_publication = || -> Result<()> {
        publication
            .snapshot
            .authorizes(plan, &deployment, object.clock().observed_at)?;
        ensure!(
            association.binding_stable_id == publication.snapshot.binding_stable_id
                && association.binding_resource_version.get() == plan.binding_resource_version
                && association.binding_prefix == publication.snapshot.object_prefix
                && super::super::executor::select_cohort(
                    &object,
                    publication,
                    purpose,
                    association.binding_write_revision.get()
                )? == cohort,
            "external scan publication or cohort differs"
        );
        Ok(())
    };
    fresh_publication()?;
    let lease = super::super::stage::planning::acquire_configured_lease(
        env,
        &object,
        &domain.issuer_installation,
        cohort,
        &cohort.admitted_prefix,
    )
    .await?;
    fresh_publication()?;
    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow::anyhow!("external read correlation unavailable"))?;
    let request = read_control::Request {
        domain: read_control::DOMAIN.into(),
        nonce: hex::encode(nonce),
        profile_digest: domain.commitment()?,
        scope: scope.clone(),
        cohort_digest: digest(cohort)?,
        effect,
        lease: lease.clone(),
        expires_at: LeaseInteger::new(plan.expires_at)?,
    };
    let floor = admit(env, &request).await?;
    let fresh = || -> Result<()> {
        fresh_publication()?;
        object.verifier()?.validate_lease(
            lease.as_bytes(),
            cohort,
            &object.timing_profile,
            &floor,
            &scope.full_key,
            effect,
            object.clock(),
        )?;
        Ok(())
    };
    let window = DispatchWindow {
        expires_at: plan.expires_at,
        uncertainty: object.clock_uncertainty,
        client_signal: signal,
        fresh: &fresh,
        lifetime: super::lifetime::Lifetime::new(signal.clone())?,
    };
    window.check()?;
    crate::direct_upload::provider_capacity::configure(u32::from(domain.provider_concurrency))?;
    let permit = crate::direct_upload::provider_capacity::acquire_class_checked(
        1,
        if matches!(
            plan.operation,
            StorageWorkOperation::InspectSha256 { .. } | StorageWorkOperation::HashOciRange { .. }
        ) {
            crate::direct_upload::provider_capacity::Class::Bulk
        } else {
            crate::direct_upload::provider_capacity::Class::Metadata
        },
        &|| window.check(),
    )
    .await?;
    window.lifetime.retain_capacity(permit)?;
    let selector = plan
        .credential_references
        .iter()
        .find(|selector| selector.purpose == purpose)
        .ok_or_else(|| anyhow::anyhow!("external scan credential absent"))?;
    let credential =
        publication.credential_text(selector, &deployment, object.clock().observed_at)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &plan.placement_prefix,
        Some(credential.as_str()),
        object.clock().observed_at,
    )?;

    let (outcome, source_bytes) = match &plan.operation {
        StorageWorkOperation::Head { path } => {
            let result = head(
                &surface,
                path,
                plan,
                &object,
                &window,
                domain.provider_contract.protected_versionless.is_some(),
            )
            .await?;
            (
                result.map_or(Outcome::NotFound, |object| Outcome::Head { object }),
                0,
            )
        }
        StorageWorkOperation::ListPage {
            prefix,
            cursor,
            limit,
        } => {
            // A signed requested limit is an upper bound. The independently
            // installed provider page budget can narrow it further.
            let provider_limit = (*limit).min(domain.maximum_list_page_objects as usize);
            let key = storage::key(env)?;
            let selector = digest(&(
                domain.commitment()?,
                &scope,
                &plan.placement_prefix,
                prefix,
                limit,
            ))?;
            let (page, provider_cursor) = super::list_cursor::open(
                &key,
                cursor.as_deref(),
                &selector,
                domain.maximum_list_pages,
            )?;
            let url = surface.list_url_with_prefix(
                prefix,
                provider_cursor.as_deref(),
                provider_limit,
                object.clock().observed_at,
            )?;
            let (response, _registration) = metadata_request(&url, Method::Get, &window).await?;
            ensure!(
                response.status_code() == 200,
                "external scan listing unacknowledged"
            );
            let body = window
                .run(async {
                    Ok(crate::direct_digest::read_bounded_native(
                        response,
                        usize::try_from(aos_hub_core::s3surface::WORKER_MAX_S3_LIST_PAGE_BYTES)?,
                    )
                    .await?)
                })
                .await?;
            let (listed, next, truncated) =
                aos_hub_core::s3surface::parse_list_objects_v2_evidence(std::str::from_utf8(
                    &body,
                )?)?;
            ensure!(
                listed.len() <= provider_limit,
                "external scan provider page exceeds limit"
            );
            let mut objects = Vec::with_capacity(listed.len());
            for listed in listed {
                let relative = surface
                    .relative_from_key(&listed.key)
                    .ok_or_else(|| anyhow::anyhow!("external listing escaped placement"))?;
                ensure!(
                    relative.starts_with(prefix),
                    "external listing escaped signed prefix"
                );
                if relative.is_empty() {
                    continue;
                }
                objects.push(StorageObjectIdentity {
                    key: plan.object_key(&relative)?,
                    size: listed.size,
                    etag: listed.strong_etag,
                    provider_version: None,
                });
            }
            // A LIST ETag is evidence for the scan, never an immutable version.
            let cursor = if truncated {
                Some(super::list_cursor::seal(
                    &key,
                    next.ok_or_else(|| anyhow::anyhow!("external listing cursor absent"))?,
                    &selector,
                    page,
                    domain.maximum_list_pages,
                )?)
            } else {
                None
            };
            (Outcome::ListPage { objects, cursor }, 0)
        }
        StorageWorkOperation::InspectSha256 {
            path,
            expected_sha256,
            max_source_bytes,
        } => {
            let Some(identity) = head(
                &surface,
                path,
                plan,
                &object,
                &window,
                domain.provider_contract.protected_versionless.is_some(),
            )
            .await?
            else {
                return Ok(Some(crate::surface::storage_work_result(
                    plan,
                    Outcome::NotFound,
                    0,
                )));
            };
            ensure!(
                identity.size > 0 && identity.size <= *max_source_bytes,
                "external hash source exceeds bound or empty-read contract"
            );
            let protected = if domain.provider_contract.protected_versionless.is_some() {
                let message = super::source::request(
                    plan,
                    domain.commitment()?,
                    scope.clone(),
                    None,
                    super::source_protocol::Operation::Lookup,
                )?;
                let closure = super::source::lookup(env, &message).await?;
                ensure!(
                    closure.bytes.get() as u64 == identity.size
                        && closure
                            .etag
                            .as_ref()
                            .is_none_or(|etag| etag == &identity.etag),
                    "protected scan HEAD differs from retained source closure"
                );
                Some(closure)
            } else {
                None
            };
            let source = CopySourceObject {
                provider_version: identity.provider_version.clone(),
                etag: identity.etag.clone(),
                bytes: LeaseInteger::new(i64::try_from(identity.size)?)?,
                guard_stamp: protected
                    .as_ref()
                    .map(|closure| closure.guard_stamp.clone()),
            };
            source.validate()?;
            let mut state = OciSha256State::initial();
            while state.total_bytes < identity.size {
                window.check()?;
                let offset = state.total_bytes;
                let bytes = (identity.size - offset)
                    .min(aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES);
                let signed = if protected.is_none() {
                    Some(surface.versioned_conditional_range_request(
                        path,
                        &source,
                        offset,
                        bytes,
                        object.clock().observed_at,
                        30,
                    )?)
                } else {
                    None
                };
                let request = if let Some(closure) = &protected {
                    Some(super::source::request(
                        plan,
                        domain.commitment()?,
                        scope.clone(),
                        None,
                        super::source_protocol::Operation::InspectRange {
                            closure: closure.clone(),
                            read_lease: lease.clone(),
                            etag: identity.etag.clone(),
                            offset,
                            bytes,
                        },
                    )?)
                } else {
                    None
                };
                let read = match (&signed, &request) {
                    (Some(signed), None) => stream::SourceRequest::Provider(signed),
                    (None, Some(request)) => stream::SourceRequest::Protected { env, request },
                    _ => anyhow::bail!("scan source incarnation selection differs"),
                };
                state = stream::hash_range(
                    &read,
                    &stream::SourceRange {
                        source: &source,
                        offset,
                        bytes,
                    },
                    state,
                    &window,
                )
                .await?
                .source_state;
            }
            let sha256 = state.final_digest()?.encoded();
            ensure!(
                protected
                    .as_ref()
                    .is_none_or(|closure| closure.sha256 == sha256),
                "protected scan body differs from its retained positive source SHA-256"
            );
            ensure!(
                expected_sha256
                    .as_ref()
                    .is_none_or(|expected| expected.eq_ignore_ascii_case(&sha256)),
                "external hash differs from selected source"
            );
            (
                Outcome::Sha256Evidence {
                    object: identity.clone(),
                    sha256,
                },
                identity.size,
            )
        }
        StorageWorkOperation::HashOciRange { .. } => {
            let selection = hash_range
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("external inventory range absent"))?;
            let Some(identity) =
                head(&surface, selection.path, plan, &object, &window, false).await?
            else {
                return Ok(Some(crate::surface::storage_work_result(
                    plan,
                    Outcome::NotFound,
                    0,
                )));
            };
            selection.validate_identity(&plan.object_key(selection.path)?, &identity)?;
            let signed = surface.versioned_conditional_range_request(
                selection.path,
                &selection.source,
                selection.start,
                selection.bytes,
                object.clock().observed_at,
                30,
            )?;
            let result = stream::hash_range(
                &stream::SourceRequest::Provider(&signed),
                &stream::SourceRange {
                    source: &selection.source,
                    offset: selection.start,
                    bytes: selection.bytes,
                },
                selection.continuation.clone(),
                &window,
            )
            .await?;
            (
                Outcome::OciRangeHashed {
                    source: identity,
                    start: selection.start,
                    end: selection.end,
                    sha256_state: result.source_state,
                },
                selection.bytes,
            )
        }
        _ => anyhow::bail!("external scan operation differs"),
    };
    window.check()?;
    Ok(Some(crate::surface::storage_work_result(
        plan,
        outcome,
        source_bytes,
    )))
}

async fn head(
    surface: &S3Surface,
    path: &str,
    plan: &StorageWorkPlan,
    object: &ObjectConfig,
    window: &DispatchWindow<'_>,
    protected_versionless: bool,
) -> Result<Option<StorageObjectIdentity>> {
    let url = surface.object_url(S3Method::Head, path, object.clock().observed_at)?;
    let (response, _registration) = metadata_request(&url, Method::Head, window).await?;
    if response.status_code() == 404 {
        return Ok(None);
    }
    ensure!(
        response.status_code() == 200,
        "external scan HEAD unacknowledged"
    );
    let headers = response.headers();
    let size = headers
        .get("content-length")?
        .ok_or_else(|| anyhow::anyhow!("external HEAD size absent"))?
        .parse()?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(
        &headers
            .get("etag")?
            .ok_or_else(|| anyhow::anyhow!("external HEAD ETag absent"))?,
    )?;
    let provider_version = headers.get("x-amz-version-id")?;
    let provider_version = if protected_versionless {
        ensure!(
            provider_version
                .as_deref()
                .is_none_or(|version| version == "null"),
            "protected HEAD returned an unselected immutable provider version"
        );
        None
    } else {
        let version = provider_version
            .ok_or_else(|| anyhow::anyhow!("external HEAD immutable version absent"))?;
        CopySourceObject {
            provider_version: Some(version.clone()),
            etag: etag.clone(),
            bytes: LeaseInteger::new(i64::try_from(size)?)?,
            guard_stamp: None,
        }
        .validate()?;
        Some(version)
    };
    window.check()?;
    Ok(Some(StorageObjectIdentity {
        key: plan.object_key(path)?,
        size,
        etag,
        provider_version,
    }))
}

async fn metadata_request(
    url: &str,
    method: Method,
    window: &DispatchWindow<'_>,
) -> Result<(worker::Response, super::lifetime::Registration)> {
    aos_hub_core::url_guard::is_safe_remote_url(url)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(url, &init)?;
    let controller = worker::web_sys::AbortController::new()
        .map_err(|_| anyhow::anyhow!("external read cancellation unavailable"))?;
    let registration = window
        .lifetime
        .register(controller.clone().into(), "abort")?;
    let response = window
        .run(async {
            crate::direct_upload::provider_capacity::record_dispatch();
            Ok(Fetch::Request(request)
                .send_with_signal(&worker::AbortSignal::from(controller.signal()))
                .await?)
        })
        .await?;
    Ok((response, registration))
}

async fn admit(
    env: &Env,
    request: &read_control::Request,
) -> Result<aos_hub_core::storage_authority::lease::EpochLeaseFloor> {
    request.validate()?;
    let key = storage::key(env)?;
    let body = serde_json::to_vec(request)?;
    let name = request.scope.guard_name()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &key.sign_body(&body)?)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request_http = Request::new_with_init(
        &format!("https://external-object{}", read_control::PATH),
        &init,
    )?;
    let response = env
        .durable_object(storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request_http)
        .await?;
    ensure!(response.status_code() == 200, "external read floor refused");
    let signature = response
        .headers()
        .get(GUARD_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("external read floor signature absent"))?;
    let body = crate::direct_digest::read_bounded_native(response, MAX_MESSAGE).await?;
    read_control::verify_reply(&key, request, &signature, &body)
}
