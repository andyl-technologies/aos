//! Hybrid Worker ingress for Native-owned control requests.
//!
//! This adapter forwards bounded control bodies with a signed public request
//! context. Storage-work and byte-delivery routes have no generic origin
//! fallback: they must be implemented by the Worker storage data plane.

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use aos_hub_core::hybrid_ingress::{
    oci_chunk_range_matches, HybridCachePartAdmission, HybridCachePartAdmissionRequest,
    HybridCachePartCompletionRequest, HybridCachePartPreflight, HybridCacheUploadAdmission,
    HybridCacheUploadAdmissionRequest, HybridCacheUploadCompletionRequest,
    HybridCacheUploadPreflight, HybridDeliveryTarget, HybridIngressAssertion, HybridIngressKey,
    HybridOciChunkAdmission, HybridOciChunkCompletionRequest, HybridPublicationPartAdmission,
    HybridPublicationPartAdmissionRequest, HybridPublicationPartCompletionRequest,
    HybridPublicationPartPreflight, HybridPublicationPartTag, HybridPublicationUploadAdmission,
    HybridPublicationUploadCompletionRequest, HYBRID_DELIVERY_HEADER, HYBRID_INGRESS_HEADER,
    HYBRID_UPLOAD_PHASE_HEADER, MAX_HYBRID_OCI_CHUNK_BYTES, MAX_HYBRID_PUBLICATION_PLACEMENTS,
};
use aos_hub_core::storage_work::{
    StorageCapabilities, StorageWorkKey, MAX_PLAN_BYTES, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES,
    STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH, STORAGE_WORK_PATH,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use base64::Engine as _;
use futures_util::lock::{Mutex, OwnedMutexGuard};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{
    Env, Fetch, Headers, Request, RequestInit, RequestRedirect, Response, ResponseBody, Result,
};

const MAX_CONTROL_BODY_BYTES: usize = aos_hub_core::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES;
const MAX_CONTROL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

thread_local! {
    // Buffered upload bodies share one isolate's memory. Cloudflare can run
    // other isolates in parallel, while a local workerd cannot absorb an
    // unbounded burst of large bodies in one instance.
    static UPLOAD_GATES: [Arc<Mutex<()>>; 2] = [
        Arc::new(Mutex::new(())),
        Arc::new(Mutex::new(())),
    ];
    static NEXT_UPLOAD_GATE: Cell<usize> = const { Cell::new(0) };
}

async fn acquire_upload_permit() -> OwnedMutexGuard<()> {
    let gate = UPLOAD_GATES.with(|gates| {
        NEXT_UPLOAD_GATE.with(|next| {
            let index = next.get();
            next.set((index + 1) % gates.len());
            Arc::clone(&gates[index])
        })
    });
    loop {
        if let Some(permit) = gate.try_lock_owned() {
            return permit;
        }
        // Workerd cancels a request that only waits on an in-isolate future.
        // A runtime timer keeps the queued request alive until a slot opens.
        worker::Delay::from(Duration::from_millis(50)).await;
    }
}

/// Dispatches hybrid control and authenticated storage-work requests.
///
/// # Errors
///
/// Returns an error for missing deployment bindings or a failed origin or
/// object-store operation.
pub async fn fetch(request: Request, env: &Env) -> Result<Response> {
    let path = request.url()?.path().to_owned();
    if let Some(response) = serve_static_asset(&request, &path).await? {
        return Ok(response);
    }
    if path == STORAGE_WORK_PATH {
        return execute_storage_work(request, env).await;
    }
    if path == STORAGE_CAPABILITIES_PATH {
        return storage_capabilities(request, env).await;
    }
    if path.starts_with("/_internal/storage/") {
        return Response::error("not found", 404);
    }
    if path.starts_with("/aos.hub.v1.BinaryCacheService/UploadObject/") {
        return upload_cache_object(request, env).await;
    }
    if path.starts_with("/aos.hub.v1.BinaryCacheService/UploadPart/") {
        return upload_cache_part(request, env).await;
    }
    if path.starts_with("/aos.hub.v1.PublishService/UploadObject/") {
        return upload_registry_object(request, env).await;
    }
    if path.starts_with("/aos.hub.v1.PublishService/UploadPart/") {
        return upload_registry_part(request, env).await;
    }
    if request.method() == worker::Method::Post && is_oci_upload_collection(&path) {
        return begin_oci_upload(request, env).await;
    }
    if request.method() == worker::Method::Patch && is_oci_upload_session(&path) {
        return append_oci_upload_chunk(request, env).await;
    }
    if request.method() == worker::Method::Put && is_oci_upload_session(&path) {
        return finalize_oci_upload(request, env).await;
    }
    if is_unrouted_oci_upload(&request.method(), &path) {
        return Response::error("hybrid storage upload is unavailable", 503);
    }
    proxy(request, env).await
}

async fn serve_static_asset(request: &Request, path: &str) -> Result<Option<Response>> {
    use aos_hub_core::web::assets;
    use axum::body::Body;
    use axum::extract::Path;

    if !matches!(request.method(), worker::Method::Get | worker::Method::Head) {
        return Ok(None);
    }

    let response = match path {
        "/_assets/style.css" => assets::stylesheet().await,
        "/_assets/app.js" => assets::app_js().await,
        "/_assets/theme.js" => assets::theme_js().await,
        "/_assets/geist-sans-variable.woff2" => assets::font_sans().await,
        "/_assets/geist-mono-variable.woff2" => assets::font_mono().await,
        "/_assets/OFL.txt" => assets::font_license().await,
        _ => {
            let Some(asset) = path.strip_prefix("/_assets/") else {
                return Ok(None);
            };
            if asset.is_empty() || asset.contains('/') || asset.contains('%') {
                return Ok(None);
            }
            assets::console_asset(Path(asset.to_owned())).await
        }
    };
    let response = if request.method() == worker::Method::Head {
        let (parts, _) = response.into_parts();
        http::Response::from_parts(parts, Body::empty())
    } else {
        response
    };
    crate::bridge::to_worker(response).await.map(Some)
}

fn is_oci_upload_collection(path: &str) -> bool {
    path.split_once("/v2/")
        .is_some_and(|(_, route_path)| route_path.ends_with("/blobs/uploads/"))
}

fn is_oci_upload_session(path: &str) -> bool {
    path.split_once("/v2/")
        .and_then(|(_, route_path)| route_path.rsplit_once("/blobs/uploads/"))
        .is_some_and(|(repository, upload_id)| {
            !repository.is_empty() && !upload_id.is_empty() && !upload_id.contains('/')
        })
}

async fn append_oci_upload_chunk(mut request: Request, env: &Env) -> Result<Response> {
    let _permit = acquire_upload_permit().await;
    let preflight_request = upload_phase_request_with_method(&request, &[], worker::Method::Patch)?;
    let preflight_response =
        match proxy_with_upload_phase(preflight_request, env, Some("preflight")).await {
            Ok(response) => response,
            Err(error) => {
                worker::console_error!("hybrid_oci_preflight_failed: {error:#}");
                return Response::error("OCI upload origin is unavailable", 503);
            }
        };
    if preflight_response.status_code() != 200 {
        return Ok(preflight_response);
    }
    let Some(preflight_body) = read_bounded_response(preflight_response, 4096).await? else {
        return Response::error("OCI chunk admission is too large", 502);
    };
    let admission: HybridOciChunkAdmission = match serde_json::from_slice(&preflight_body) {
        Ok(admission) => admission,
        Err(_) => return Response::error("OCI chunk admission is invalid", 502),
    };
    let request_url = request.url()?;
    let Some((_, upload_id)) = request_url.path().rsplit_once("/blobs/uploads/") else {
        return Response::error("OCI upload path is invalid", 400);
    };
    let staging_prefix = format!("oci/uploads/{upload_id}/chunks/{}-", admission.ordinal);
    let valid_staging_key = admission
        .staging_object_key
        .strip_prefix(&staging_prefix)
        .is_some_and(|attempt| {
            attempt.len() == 32
                && attempt
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if admission.maximum_chunk_bytes == 0
        || admission.maximum_chunk_bytes > MAX_HYBRID_OCI_CHUNK_BYTES as u64
        || admission.sha256_state.validate().is_err()
        || admission.sha256_state.total_bytes != admission.offset
        || !valid_staging_key
    {
        return Response::error("OCI chunk admission identity is invalid", 502);
    }
    let object_key =
        aos_hub_core::keymap::r2_key(&admission.placement_prefix, &admission.staging_object_key);
    if !valid_r2_key(&object_key) {
        return Response::error("OCI chunk placement key is invalid", 502);
    }

    let Some(bytes) =
        read_bounded_body(&mut request, admission.maximum_chunk_bytes as usize).await?
    else {
        return Response::error("OCI chunk body is too large", 413);
    };
    if bytes.is_empty() {
        return Response::error("OCI chunk body is empty", 400);
    }
    let requested_range = request.headers().get("content-range")?;
    if !oci_chunk_range_matches(requested_range.as_deref(), admission.offset, bytes.len()) {
        return Response::error("OCI chunk content range is not contiguous", 416);
    }
    let mut next_sha256_state = admission.sha256_state.clone();
    if next_sha256_state.update(&bytes).is_err() {
        return Response::error("OCI chunk digest state is invalid", 502);
    }
    let chunk_sha256 = hex::encode(Sha256::digest(&bytes));
    let byte_size = bytes.len() as u64;
    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    if let Err(error) = crate::surface::hybrid_r2_put(bucket, &object_key, &bytes).await {
        worker::console_error!("hybrid_oci_chunk_put_failed: {error:#}");
        return Response::error("OCI chunk storage write failed", 503);
    }

    let completion = HybridOciChunkCompletionRequest {
        admission,
        byte_size,
        chunk_sha256,
        next_sha256_state,
    };
    let completion_body = serde_json::to_vec(&completion)
        .map_err(|error| worker::Error::RustError(format!("OCI chunk completion JSON: {error}")))?;
    let completion_request =
        upload_phase_request_with_method(&request, &completion_body, worker::Method::Patch)?;
    match proxy_with_upload_phase(completion_request, env, Some("complete")).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("hybrid_oci_completion_failed: {error:#}");
            Response::error("OCI upload completion is unavailable", 503)
        }
    }
}

async fn finalize_oci_upload(mut request: Request, env: &Env) -> Result<Response> {
    let Some(final_bytes) = read_bounded_body(&mut request, MAX_HYBRID_OCI_CHUNK_BYTES).await?
    else {
        return Response::error("final OCI chunk body is too large", 413);
    };
    if !final_bytes.is_empty() {
        let patch =
            upload_phase_request_with_method(&request, &final_bytes, worker::Method::Patch)?;
        let appended = append_oci_upload_chunk(patch, env).await?;
        if appended.status_code() != 202 {
            return Ok(appended);
        }
    }

    let completion = upload_phase_request_with_method(&request, &[], worker::Method::Put)?;
    match proxy(completion, env).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("hybrid_oci_finalization_failed: {error:#}");
            Response::error("OCI upload finalization is unavailable", 503)
        }
    }
}

async fn begin_oci_upload(mut request: Request, env: &Env) -> Result<Response> {
    if read_bounded_body(&mut request, 0).await?.is_none() {
        return Response::error("OCI upload creation body must be empty", 400);
    }

    let headers = Headers::new();
    for (name, value) in request.headers().entries() {
        if is_forwarded_header(&name) && name != "cf-connecting-ip" {
            continue;
        }
        headers.append(&name, &value)?;
    }
    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let control = Request::new_with_init(request.url()?.as_str(), &init)?;
    proxy(control, env).await
}

fn is_unrouted_oci_upload(method: &worker::Method, path: &str) -> bool {
    if *method != worker::Method::Put
        && *method != worker::Method::Post
        && *method != worker::Method::Patch
    {
        return false;
    }

    // Unhandled OCI upload variants must not relay object bytes to Native.
    path.split_once("/v2/")
        .is_some_and(|(_, route_path)| route_path.contains("/blobs/uploads"))
}

async fn upload_registry_part(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Put {
        return Response::error("method not allowed", 405);
    }
    let _permit = acquire_upload_permit().await;
    let url = request.url()?;
    let Some((upload_id, part_number)) = url
        .path()
        .strip_prefix("/aos.hub.v1.PublishService/UploadPart/")
        .and_then(|suffix| suffix.split_once('/'))
    else {
        return Response::error("invalid publication multipart path", 400);
    };
    if upload_id.is_empty() || upload_id.len() > 64 || part_number.contains('/') {
        return Response::error("invalid publication multipart identity", 400);
    }
    let Ok(part_number) = part_number.parse::<u32>() else {
        return Response::error("invalid publication multipart part number", 400);
    };
    if part_number == 0 {
        return Response::error("invalid publication multipart part number", 400);
    }

    let preflight_request = upload_phase_request(&request, &[])?;
    let preflight_response = proxy_upload_phase(preflight_request, env, "preflight").await?;
    if preflight_response.status_code() != 200 {
        return Ok(preflight_response);
    }
    let Some(preflight_body) = read_bounded_response(preflight_response, 4096).await? else {
        return Response::error("publication multipart preflight is too large", 502);
    };
    let preflight: HybridPublicationPartPreflight = match serde_json::from_slice(&preflight_body) {
        Ok(preflight) => preflight,
        Err(_) => return Response::error("publication multipart preflight is invalid", 502),
    };
    let valid_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if preflight.expected_part_size == 0
        || preflight.expected_part_size > MAX_CONTROL_BODY_BYTES as u64
        || !valid_digest(&preflight.sha256_state)
        || !valid_digest(&preflight.expected_sha256)
    {
        return Response::error("publication multipart part shape is invalid", 502);
    }
    let Some(bytes) =
        read_bounded_body(&mut request, preflight.expected_part_size as usize).await?
    else {
        return Response::error("publication multipart part is too large", 413);
    };
    if bytes.len() as u64 != preflight.expected_part_size {
        return Response::error("publication multipart part has the wrong size", 400);
    }
    let Some(hashed_size) = preflight.prior_hashed_size.checked_add(bytes.len() as u64) else {
        return Response::error("publication multipart hash length overflowed", 502);
    };
    let next_sha256_state = match aos_hub_core::service::advance_multipart_sha256(
        &preflight.sha256_state,
        &bytes,
        hashed_size,
        preflight.final_part,
    ) {
        Ok(state) => state,
        Err(_) => return Response::error("publication multipart hash state is invalid", 502),
    };
    if preflight.final_part && next_sha256_state != preflight.expected_sha256 {
        return Response::error("publication multipart bytes have the wrong digest", 400);
    }
    let body_sha256 = hex::encode(Sha256::digest(&bytes));
    let admission_body = serde_json::to_vec(&HybridPublicationPartAdmissionRequest {
        size: bytes.len() as u64,
        body_sha256: body_sha256.clone(),
        prior_hashed_size: preflight.prior_hashed_size,
        next_sha256_state: next_sha256_state.clone(),
    })
    .map_err(|error| {
        worker::Error::RustError(format!("publication part admission JSON: {error}"))
    })?;
    let admission_request = upload_phase_request(&request, &admission_body)?;
    let admission_response = proxy_upload_phase(admission_request, env, "admit").await?;
    if admission_response.status_code() != 200 {
        return Ok(admission_response);
    }
    let Some(admission_body) = read_bounded_response(admission_response, 128 * 1024).await? else {
        return Response::error("publication multipart admission is too large", 502);
    };
    let admission: HybridPublicationPartAdmission = match serde_json::from_slice(&admission_body) {
        Ok(admission) => admission,
        Err(_) => return Response::error("publication multipart admission is invalid", 502),
    };
    if admission.claim_token.len() != 32
        || !admission
            .claim_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || admission.destinations.is_empty()
        || admission.destinations.len() > MAX_HYBRID_PUBLICATION_PLACEMENTS
        || admission
            .destinations
            .windows(2)
            .any(|pair| pair[0].placement_id >= pair[1].placement_id)
        || admission.destinations.iter().any(|destination| {
            destination.placement_id <= 0
                || !valid_r2_key(&destination.object_key)
                || destination.backend_upload_id.is_empty()
                || destination.backend_upload_id.len() > 1024
        })
    {
        return Response::error("publication multipart destinations are invalid", 502);
    }
    let mut placements = Vec::with_capacity(admission.destinations.len());
    for destination in &admission.destinations {
        let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
        let etag = match crate::surface::hybrid_r2_upload_part(
            bucket,
            &destination.object_key,
            &destination.backend_upload_id,
            part_number,
            &bytes,
        )
        .await
        {
            Ok(etag) => etag,
            Err(error) => {
                worker::console_error!("hybrid_publication_part_put_failed: {error:#}");
                return Response::error("publication multipart storage write failed", 503);
            }
        };
        placements.push(HybridPublicationPartTag {
            placement_id: destination.placement_id,
            etag,
        });
    }
    let completion_body = serde_json::to_vec(&HybridPublicationPartCompletionRequest {
        admission,
        size: bytes.len() as u64,
        body_sha256,
        prior_hashed_size: preflight.prior_hashed_size,
        next_sha256_state,
        placements,
    })
    .map_err(|error| {
        worker::Error::RustError(format!("publication part completion JSON: {error}"))
    })?;
    let completion_request = upload_phase_request(&request, &completion_body)?;
    proxy_upload_phase(completion_request, env, "complete").await
}

async fn upload_cache_part(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Put {
        return Response::error("method not allowed", 405);
    }
    let _permit = acquire_upload_permit().await;
    let url = request.url()?;
    let Some((upload_id, part_number)) = url
        .path()
        .strip_prefix("/aos.hub.v1.BinaryCacheService/UploadPart/")
        .and_then(|suffix| suffix.split_once('/'))
    else {
        return Response::error("invalid cache multipart path", 400);
    };
    if upload_id.is_empty() || upload_id.len() > 128 || part_number.contains('/') {
        return Response::error("invalid cache multipart identity", 400);
    }
    let Ok(part_number) = part_number.parse::<u32>() else {
        return Response::error("invalid cache multipart part number", 400);
    };
    if part_number == 0 {
        return Response::error("invalid cache multipart part number", 400);
    }

    let preflight_request = upload_phase_request(&request, &[])?;
    let preflight_response = proxy_upload_phase(preflight_request, env, "preflight").await?;
    if preflight_response.status_code() != 200 {
        return Ok(preflight_response);
    }
    let Some(preflight_body) = read_bounded_response(preflight_response, 1024).await? else {
        return Response::error("cache multipart preflight is too large", 502);
    };
    let preflight: HybridCachePartPreflight = match serde_json::from_slice(&preflight_body) {
        Ok(preflight) => preflight,
        Err(_) => return Response::error("cache multipart preflight is invalid", 502),
    };
    if preflight.maximum_part_bytes == 0
        || preflight.maximum_part_bytes > MAX_CONTROL_BODY_BYTES as u64
    {
        return Response::error("cache multipart body limit is invalid", 502);
    }
    let Some(bytes) =
        read_bounded_body(&mut request, preflight.maximum_part_bytes as usize).await?
    else {
        return Response::error("cache multipart part is too large", 413);
    };
    if bytes.is_empty() {
        return Response::error("cache multipart part is empty", 400);
    }
    let size = bytes.len() as u64;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let admission_body = serde_json::to_vec(&HybridCachePartAdmissionRequest {
        size,
        sha256: sha256.clone(),
    })
    .map_err(|error| worker::Error::RustError(format!("cache part admission JSON: {error}")))?;
    let admission_request = upload_phase_request(&request, &admission_body)?;
    let admission_response = proxy_upload_phase(admission_request, env, "admit").await?;
    if admission_response.status_code() != 200 {
        return Ok(admission_response);
    }
    let Some(admission_body) = read_bounded_response(admission_response, 4096).await? else {
        return Response::error("cache multipart admission is too large", 502);
    };
    let admission: HybridCachePartAdmission = match serde_json::from_slice(&admission_body) {
        Ok(admission) => admission,
        Err(_) => return Response::error("cache multipart admission is invalid", 502),
    };
    if !valid_r2_key(&admission.object_key)
        || admission.backend_upload_id.is_empty()
        || admission.backend_upload_id.len() > 1024
    {
        return Response::error("cache multipart target is invalid", 502);
    }
    let etag = match admission.confirmed_etag {
        Some(etag) => etag,
        None => {
            let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
            match crate::surface::hybrid_r2_upload_part(
                bucket,
                &admission.object_key,
                &admission.backend_upload_id,
                part_number,
                &bytes,
            )
            .await
            {
                Ok(etag) => etag,
                Err(error) => {
                    worker::console_error!("hybrid_cache_part_put_failed: {error:#}");
                    return Response::error("cache multipart storage write failed", 503);
                }
            }
        }
    };
    let completion_body =
        serde_json::to_vec(&HybridCachePartCompletionRequest { size, sha256, etag }).map_err(
            |error| worker::Error::RustError(format!("cache part completion JSON: {error}")),
        )?;
    let completion_request = upload_phase_request(&request, &completion_body)?;
    proxy_upload_phase(completion_request, env, "complete").await
}

async fn upload_registry_object(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Put {
        return Response::error("method not allowed", 405);
    }
    let _permit = acquire_upload_permit().await;
    // Authenticate and freeze the SQL destinations before consuming client bytes.
    let admission_request = upload_phase_request(&request, &[])?;
    let admission_response = proxy_upload_phase(admission_request, env, "admit").await?;
    if admission_response.status_code() != 200 {
        return Ok(admission_response);
    }
    let Some(admission_body) = read_bounded_response(admission_response, 64 * 1024).await? else {
        return Response::error("publication admission is too large", 502);
    };
    let admission: HybridPublicationUploadAdmission = match serde_json::from_slice(&admission_body)
    {
        Ok(admission) => admission,
        Err(_) => return Response::error("publication admission is invalid", 502),
    };
    if admission.size < 0
        || admission.size > MAX_CONTROL_BODY_BYTES as i64
        || admission.placements.is_empty()
        || admission.placements.len() > MAX_HYBRID_PUBLICATION_PLACEMENTS
        || admission
            .placements
            .windows(2)
            .any(|pair| pair[0].placement_id >= pair[1].placement_id)
    {
        return Response::error("publication admission identity is invalid", 502);
    }
    let Some(bytes) = read_bounded_body(&mut request, MAX_CONTROL_BODY_BYTES).await? else {
        return Response::error("publication upload body is too large", 413);
    };
    let size = bytes.len() as u64;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if aos_hub_core::service::verify_registry_publication_object_bytes(
        &admission.path,
        admission.size,
        &admission.sha256,
        &bytes,
    )
    .is_err()
    {
        return Response::error("publication object bytes are invalid", 400);
    }

    let needs_companion = aos_hub_core::keymap::is_git_pack_index_path(&admission.path);
    for placement in &admission.placements {
        if placement.placement_id <= 0
            || placement.placement_resource_version <= 0
            || placement.binding_id <= 0
            || placement.binding_resource_version <= 0
            || placement.companion_pack_key.is_some() != needs_companion
            || !valid_r2_key(&placement.object_key)
            || placement
                .companion_pack_key
                .as_ref()
                .is_some_and(|key| !valid_r2_key(key))
        {
            return Response::error("publication placement key is invalid", 502);
        }
        if let Some(companion_key) = &placement.companion_pack_key {
            let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
            let pack = match crate::surface::hybrid_publication_companion_pack(
                bucket,
                companion_key,
            )
            .await
            {
                Ok(pack) => pack,
                Err(error) => {
                    worker::console_error!("publication_companion_read_failed: {error:#}");
                    return Response::error("publication companion pack is unavailable", 503);
                }
            };
            if aos_registry_surface::pack_index::validate_against_pack(
                &admission.path,
                &bytes,
                &pack,
            )
            .is_err()
            {
                return Response::error("publication pack index is invalid", 400);
            }
        }
    }
    for placement in &admission.placements {
        let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
        if let Err(error) =
            crate::surface::hybrid_r2_put(bucket, &placement.object_key, &bytes).await
        {
            worker::console_error!("publication_r2_put_failed: {error:#}");
            return Response::error("publication storage write failed", 503);
        }
    }

    let completion_body = serde_json::to_vec(&HybridPublicationUploadCompletionRequest {
        size,
        sha256,
        placements: admission.placements,
    })
    .map_err(|error| worker::Error::RustError(format!("publication completion JSON: {error}")))?;
    let completion_request = upload_phase_request(&request, &completion_body)?;
    proxy_upload_phase(completion_request, env, "complete").await
}

fn valid_r2_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('/')
        && key.len() <= 1024
        && key
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

async fn upload_cache_object(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Put {
        return Response::error("method not allowed", 405);
    }
    let _permit = acquire_upload_permit().await;
    let url = request.url()?;
    let Some(encoded_path) = url.path().rsplit('/').next() else {
        return Response::error("invalid cache upload path", 400);
    };
    let path = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_path)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let Some(path) = path else {
        return Response::error("invalid cache upload path", 400);
    };
    let preflight_request = upload_phase_request(&request, &[])?;
    let preflight_response = proxy_upload_phase(preflight_request, env, "preflight").await?;
    if preflight_response.status_code() != 200 {
        return Ok(preflight_response);
    }
    let Some(preflight_body) = read_bounded_response(preflight_response, 1024).await? else {
        return Response::error("cache upload preflight is too large", 502);
    };
    let preflight: HybridCacheUploadPreflight = match serde_json::from_slice(&preflight_body) {
        Ok(preflight) => preflight,
        Err(_) => return Response::error("cache upload preflight is invalid", 502),
    };
    if preflight.expected_size > MAX_CONTROL_BODY_BYTES as u64 {
        return Response::error("cache upload preflight size is invalid", 502);
    }
    let Some(bytes) = read_bounded_body(&mut request, preflight.expected_size as usize).await?
    else {
        return Response::error("cache upload body is too large", 413);
    };
    if bytes.len() as u64 != preflight.expected_size {
        return Response::error("cache upload body size differs from its ticket", 400);
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let size = bytes.len() as u64;
    let narinfo = if path.ends_with(".narinfo") {
        if bytes.len() > aos_hub_core::fetch::MAX_CACHE_NARINFO_BYTES {
            return Response::error("narinfo body is too large", 413);
        }
        match String::from_utf8(bytes.clone()) {
            Ok(body) => Some(body),
            Err(_) => return Response::error("narinfo is not UTF-8", 400),
        }
    } else {
        None
    };
    let admission_request = HybridCacheUploadAdmissionRequest {
        size,
        sha256: sha256.clone(),
        narinfo,
    };
    let admission_body = serde_json::to_vec(&admission_request)
        .map_err(|error| worker::Error::RustError(format!("cache admission JSON: {error}")))?;
    let admission_request = upload_phase_request(&request, &admission_body)?;
    let admission_response = proxy_upload_phase(admission_request, env, "admit").await?;
    if admission_response.status_code() != 200 {
        return Ok(admission_response);
    }
    let Some(admission_body) = read_bounded_response(admission_response, 4096).await? else {
        return Response::error("cache upload admission is too large", 502);
    };
    let admission: HybridCacheUploadAdmission = match serde_json::from_slice(&admission_body) {
        Ok(admission) => admission,
        Err(_) => return Response::error("cache upload admission is invalid", 502),
    };
    if admission.completed && admission.object_key.is_none() {
        return Response::empty().map(|response| response.with_status(201));
    }
    let Some(object_key) = admission.object_key.filter(|_| !admission.completed) else {
        return Response::error("cache upload admission is invalid", 502);
    };
    if object_key.is_empty()
        || object_key.starts_with('/')
        || object_key
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Response::error("cache upload key is invalid", 502);
    }
    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    if let Err(error) = crate::surface::hybrid_r2_put(bucket, &object_key, &bytes).await {
        worker::console_error!("hybrid_cache_upload_put_failed: {error:#}");
        return Response::error("cache upload storage write failed", 503);
    }

    let completion = HybridCacheUploadCompletionRequest { size, sha256 };
    let completion_body = serde_json::to_vec(&completion)
        .map_err(|error| worker::Error::RustError(format!("cache completion JSON: {error}")))?;
    let completion_request = upload_phase_request(&request, &completion_body)?;
    proxy_upload_phase(completion_request, env, "complete").await
}

fn upload_phase_request(original: &Request, body: &[u8]) -> Result<Request> {
    upload_phase_request_with_method(original, body, worker::Method::Put)
}

fn upload_phase_request_with_method(
    original: &Request,
    body: &[u8],
    method: worker::Method,
) -> Result<Request> {
    let headers = Headers::new();
    for (name, value) in original.headers().entries() {
        if is_forwarded_header(&name) && name != "cf-connecting-ip" {
            continue;
        }
        headers.append(&name, &value)?;
    }
    headers.set("content-type", "application/json")?;
    headers.delete("content-length")?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let js_body: JsValue = js_sys::Uint8Array::from(body).into();
    init.with_body(Some(js_body));
    Request::new_with_init(original.url()?.as_str(), &init)
}

async fn storage_capabilities(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Post {
        return Response::error("method not allowed", 405);
    }
    // Workerd reserves getAll for Set-Cookie; hex decoding rejects joined duplicates.
    let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
        return Response::error("storage work signature is required", 401);
    };
    let Some(body) = read_bounded_body(&mut request, STORAGE_CAPABILITIES_CHALLENGE.len()).await?
    else {
        return Response::error("storage capability challenge is invalid", 401);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if body != STORAGE_CAPABILITIES_CHALLENGE || key.verify_body(&signature, &body).is_err() {
        return Response::error("storage capability challenge is invalid", 401);
    }
    let _bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let capabilities = StorageCapabilities {
        version: 1,
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        binding_kind: "deployment_r2".into(),
        operations: vec![
            "head".into(),
            "list_page".into(),
            "inspect_sha256".into(),
            "inspect_git_object".into(),
            "inspect_git_objects".into(),
            "inspect_metadata".into(),
            "inspect_documentation".into(),
            "inspect_oci_range".into(),
            "hash_oci_range".into(),
            "copy_object".into(),
            "compose_oci_blob".into(),
            "delete_oci_staging".into(),
            "create_multipart".into(),
            "complete_multipart".into(),
            "abort_multipart".into(),
        ],
        max_result_bytes: MAX_RESULT_BYTES,
        max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
    };
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_json(&capabilities)?.with_headers(headers))
}

async fn execute_storage_work(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Post {
        return Response::error("method not allowed", 405);
    }
    let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
        return Response::error("storage work signature is required", 401);
    };
    let Some(body) = read_bounded_body(&mut request, MAX_PLAN_BYTES).await? else {
        return Response::error("storage work plan is too large", 413);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let plan = match key.verify_plan(
        &signature,
        &body,
        &deployment_id,
        aos_hub_core::clock::now_unix_secs(),
    ) {
        Ok(plan) => plan,
        Err(_) => return Response::error("storage work plan is not authorized", 401),
    };
    let operation_kind = plan.operation.kind();

    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let result = match crate::surface::execute_r2_storage_work(bucket, &plan).await {
        Ok(result) => result,
        Err(_error) => {
            worker::console_error!(
                "storage_work_failed plan={} operation={}",
                plan.plan_id,
                operation_kind,
            );
            return Response::error("storage work failed", 503);
        }
    };
    let bytes = serde_json::to_vec(&result)
        .map_err(|error| worker::Error::RustError(format!("storage result encoding: {error}")))?;
    if bytes.len() > MAX_RESULT_BYTES {
        return Response::error("storage work result exceeds its limit", 413);
    }
    worker::console_log!(
        "storage_work_complete plan={} operation={} plan_bytes={} source_bytes={} result_bytes={}",
        plan.plan_id,
        operation_kind,
        body.len(),
        result.source_bytes,
        bytes.len(),
    );
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

/// Proxies one bounded control request to the signed Native origin.
///
/// # Errors
///
/// Returns an error for invalid deployment configuration or a failed origin
/// request. Unauthorized or oversized requests receive an HTTP response.
pub async fn proxy(request: Request, env: &Env) -> Result<Response> {
    proxy_with_upload_phase(request, env, None).await
}

async fn proxy_upload_phase(request: Request, env: &Env, phase: &str) -> Result<Response> {
    match proxy_with_upload_phase(request, env, Some(phase)).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("hybrid_upload_origin_failed phase={phase}: {error:#}");
            Response::error("hybrid upload origin is unavailable", 503)
        }
    }
}

async fn proxy_with_upload_phase(
    mut request: Request,
    env: &Env,
    upload_phase: Option<&str>,
) -> Result<Response> {
    let public_url = request.url()?;
    if public_url.path().starts_with("/_internal/storage/") {
        return Response::error("storage executor unavailable", 503);
    }
    if public_url.scheme() != "https" {
        return Response::error("hybrid ingress requires HTTPS", 400);
    }

    let origin = env.var("HUB_HYBRID_ORIGIN_URL")?.to_string();
    let origin = url::Url::parse(&origin)
        .map_err(|error| worker::Error::RustError(format!("invalid hybrid origin URL: {error}")))?;
    if origin.scheme() != "https"
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(worker::Error::RustError(
            "HUB_HYBRID_ORIGIN_URL must be an HTTPS origin".into(),
        ));
    }
    if origin.origin() == public_url.origin() {
        return Err(worker::Error::RustError(
            "hybrid origin must differ from the public Worker origin".into(),
        ));
    }

    // Local workerd may omit Cloudflare's client-IP header. A single
    // shared rate-limit identity keeps local clients usable without trusting
    // a caller-controlled forwarding header.
    let client_ip = request
        .headers()
        .get("cf-connecting-ip")?
        .unwrap_or_else(|| "0.0.0.0".into());
    let requested_range = request.headers().get("range")?;
    let Some(body) = read_bounded_body(&mut request, MAX_CONTROL_BODY_BYTES).await? else {
        return Response::error("control request body is too large", 413);
    };
    if !body.is_empty()
        && matches!(
            request.method(),
            worker::Method::Get | worker::Method::Head | worker::Method::Delete
        )
    {
        return Response::error("control request method does not accept a body", 400);
    }

    let path_and_query = match public_url.query() {
        Some(query) => format!("{}?{query}", public_url.path()),
        None => public_url.path().to_owned(),
    };
    let public_origin = public_url.origin().ascii_serialization();
    let authority = public_origin
        .split_once("://")
        .map(|(_, authority)| authority)
        .ok_or_else(|| worker::Error::RustError("public authority is missing".into()))?;
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = HybridIngressKey::new(env.secret("HUB_HYBRID_INGRESS_KEY")?.to_string())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let now = aos_hub_core::clock::now_unix_secs();
    let assertion = HybridIngressAssertion {
        version: 1,
        deployment_id,
        issued_at: now,
        expires_at: now.saturating_add(30),
        request_id: uuid::Uuid::new_v4().to_string(),
        scheme: "https".into(),
        authority: authority.to_owned(),
        method: request.method().as_ref().to_owned(),
        path_and_query: path_and_query.clone(),
        body_sha256: hex::encode(Sha256::digest(&body)),
        client_ip,
    };
    let compact = key
        .sign(&assertion)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;

    let headers = Headers::new();
    for (name, value) in request.headers().entries() {
        if is_forwarded_header(&name) {
            continue;
        }
        headers.append(&name, &value)?;
    }
    headers.set(HYBRID_INGRESS_HEADER, &compact)?;
    if let Some(phase) = upload_phase {
        headers.set(HYBRID_UPLOAD_PHASE_HEADER, phase)?;
    }

    let target = format!(
        "{}{}",
        origin.origin().ascii_serialization(),
        path_and_query
    );
    let request_body_bytes = body.len();
    let mut init = RequestInit::new();
    init.with_method(request.method())
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    if !body.is_empty() {
        let js_body: JsValue = js_sys::Uint8Array::from(body.as_slice()).into();
        init.with_body(Some(js_body));
    }
    let upstream = Request::new_with_init(&target, &init)?;
    let origin_started_ms = js_sys::Date::now();
    let response = Fetch::Request(upstream).send().await?;
    let origin_elapsed_ms = (js_sys::Date::now() - origin_started_ms).max(0.0) as u64;
    let headers = response.headers().clone();
    if headers.get("x-aos-hybrid-origin")?.as_deref() != Some("1") {
        worker::console_error!(
            "hybrid_origin_identity_missing id={} method={} phase={:?} status={} elapsed_ms={}",
            assertion.request_id,
            assertion.method,
            upload_phase,
            response.status_code(),
            origin_elapsed_ms,
        );
        return Response::error("hybrid origin identity is missing", 502);
    }
    headers.delete("x-aos-hybrid-origin")?;
    let status = response.status_code();
    if let Some(compact) = headers.get(HYBRID_DELIVERY_HEADER)? {
        if status != 200 || !matches!(request.method(), worker::Method::Get | worker::Method::Head)
        {
            return Response::error("invalid hybrid delivery response", 502);
        }
        let target =
            match key.verify_delivery(&compact, &assertion, aos_hub_core::clock::now_unix_secs()) {
                Ok(target) => target,
                Err(_) => return Response::error("hybrid delivery grant is invalid", 502),
            };
        worker::console_log!(
            "hybrid_origin_delivery_grant id={} method={} request_bytes={} elapsed_ms={}",
            assertion.request_id,
            assertion.method,
            request_body_bytes,
            origin_elapsed_ms,
        );
        return deliver_from_r2(env, request.method(), requested_range.as_deref(), target).await;
    }
    let Some(body) = read_bounded_response(response, MAX_CONTROL_RESPONSE_BYTES).await? else {
        return Response::error("hybrid control response is too large", 502);
    };
    worker::console_log!(
        "hybrid_origin_request id={} method={} status={} request_bytes={} response_bytes={} elapsed_ms={}",
        assertion.request_id,
        assertion.method,
        status,
        request_body_bytes,
        body.len(),
        origin_elapsed_ms,
    );
    headers.delete("content-length")?;
    Ok(Response::from_body(if body.is_empty() {
        ResponseBody::Empty
    } else {
        ResponseBody::Body(body)
    })?
    .with_status(status)
    .with_headers(headers))
}

async fn deliver_from_r2(
    env: &Env,
    method: worker::Method,
    range_header: Option<&str>,
    target: HybridDeliveryTarget,
) -> Result<Response> {
    let planned = target.planned_response.as_ref();
    if planned.is_some() && method == worker::Method::Head {
        return Response::error("invalid planned delivery method", 502);
    }
    // HEAD reports the complete representation even when a client sends Range.
    let served = if let Some(planned) = planned {
        (planned.status == 206).then_some((planned.start, planned.end))
    } else {
        let requested = (method != worker::Method::Head)
            .then(|| aos_hub_core::service::parse_byte_range(range_header))
            .flatten();
        requested.and_then(|(start, end)| {
            (start < target.object_size).then_some((start, end.min(target.object_size - 1)))
        })
    };
    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let body = if method == worker::Method::Head {
        if let Err(error) = crate::surface::hybrid_delivery_head(bucket, &target).await {
            worker::console_error!("hybrid_delivery_head_failed: {error:#}");
            return Response::error("hybrid delivery unavailable", 503);
        }
        axum::body::Body::empty()
    } else {
        let read = match crate::surface::hybrid_delivery_read(bucket, &target, served).await {
            Ok(read) => read,
            Err(error) => {
                worker::console_error!("hybrid_delivery_read_failed: {error:#}");
                return Response::error("hybrid delivery unavailable", 503);
            }
        };
        if read.range != served {
            return Response::error("hybrid delivery range changed", 503);
        }
        read.body
    };

    let mut response = axum::response::Response::builder().status(
        planned.map_or(if served.is_some() { 206 } else { 200 }, |planned| {
            planned.status
        }),
    );
    if let Some(planned) = planned {
        for (name, value) in &planned.headers {
            response = response.header(name.as_str(), value.as_str());
        }
    } else {
        response = response
            .header("content-type", &target.content_type)
            .header("cache-control", &target.cache_control)
            .header("accept-ranges", "bytes");
        if target.cache_control == "private, no-store" {
            response = response.header("vary", "Authorization, Cookie");
        }
        if target.producer_document {
            response = response
                .header("content-security-policy", "sandbox")
                .header("content-disposition", "attachment");
        }
        response = match served {
            Some((start, end)) => response
                .header(
                    "content-range",
                    format!("bytes {start}-{end}/{}", target.object_size),
                )
                .header("content-length", end - start + 1),
            None => response.header("content-length", target.object_size),
        };
    }
    let response = response
        .body(body)
        .map_err(|error| worker::Error::RustError(format!("hybrid delivery response: {error}")))?;
    crate::bridge::to_worker(response).await
}

async fn read_bounded_response(mut response: Response, maximum: usize) -> Result<Option<Vec<u8>>> {
    if response
        .headers()
        .get("content-length")?
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum)
    {
        return Ok(None);
    }
    match response.body() {
        ResponseBody::Empty => return Ok(Some(Vec::new())),
        ResponseBody::Body(body) => return Ok((body.len() <= maximum).then(|| body.clone())),
        ResponseBody::Stream(_) => {}
    }
    let mut stream = response.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let Some(length) = body.len().checked_add(chunk.len()) else {
            return Ok(None);
        };
        if length > maximum {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

async fn read_bounded_body(request: &mut Request, maximum: usize) -> Result<Option<Vec<u8>>> {
    if request.inner().body().is_none() {
        return Ok(Some(Vec::new()));
    }
    let mut stream = request.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let Some(length) = body.len().checked_add(chunk.len()) else {
            return Ok(None);
        };
        if length > maximum {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

fn is_forwarded_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "host"
        || name == "connection"
        || name == "transfer-encoding"
        || name == "content-length"
        || name == "expect"
        || name == "keep-alive"
        || name == "proxy-connection"
        || name == "te"
        || name == "trailer"
        || name == "upgrade"
        || name == "forwarded"
        || name == "cf-connecting-ip"
        || name.starts_with("x-forwarded-")
        || matches!(
            name.as_str(),
            "x-aos-hybrid-ingress"
                | "x-aos-hybrid-delivery"
                | "x-aos-hybrid-upload-phase"
                | "x-aos-delivery-attestation"
                | "x-aos-client-ip"
                | "x-aos-console-route"
        )
}
