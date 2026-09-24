//! Hybrid Worker ingress for Native-owned control requests.
//!
//! This adapter forwards bounded control bodies with a signed public request
//! context. Storage-work and byte-delivery routes have no generic origin
//! fallback: they must be implemented by the Worker storage data plane.

use aos_hub_core::hybrid_ingress::{
    HybridIngressAssertion, HybridIngressKey, HYBRID_INGRESS_HEADER,
};
use aos_hub_core::storage_work::{
    StorageCapabilities, StorageWorkKey, MAX_PLAN_BYTES, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES,
    STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH, STORAGE_WORK_PATH,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{
    Env, Fetch, Headers, Request, RequestInit, RequestRedirect, Response, ResponseBody, Result,
};

const MAX_CONTROL_BODY_BYTES: usize = aos_hub_core::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES;
const MAX_CONTROL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Dispatches hybrid control and authenticated storage-work requests.
///
/// # Errors
///
/// Returns an error for missing deployment bindings or a failed origin or
/// object-store operation.
pub async fn fetch(request: Request, env: &Env) -> Result<Response> {
    let path = request.url()?.path().to_owned();
    if path == STORAGE_WORK_PATH {
        return execute_storage_work(request, env).await;
    }
    if path == STORAGE_CAPABILITIES_PATH {
        return storage_capabilities(request, env).await;
    }
    if path.starts_with("/_internal/storage/") {
        return Response::error("not found", 404);
    }
    proxy(request, env).await
}

async fn storage_capabilities(mut request: Request, env: &Env) -> Result<Response> {
    if request.method() != worker::Method::Post {
        return Response::error("method not allowed", 405);
    }
    let signatures = request.headers().get_all(STORAGE_WORK_SIGNATURE_HEADER)?;
    if signatures.len() != 1 {
        return Response::error("storage work signature is required", 401);
    }
    let Some(body) = read_bounded_body(&mut request, STORAGE_CAPABILITIES_CHALLENGE.len()).await?
    else {
        return Response::error("storage capability challenge is invalid", 401);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if body != STORAGE_CAPABILITIES_CHALLENGE || key.verify_body(&signatures[0], &body).is_err() {
        return Response::error("storage capability challenge is invalid", 401);
    }
    let _bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let capabilities = StorageCapabilities {
        version: 1,
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        binding_kind: "deployment_r2".into(),
        operations: vec!["head".into(), "list_page".into(), "inspect_sha256".into()],
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
    let signatures = request.headers().get_all(STORAGE_WORK_SIGNATURE_HEADER)?;
    if signatures.len() != 1 {
        return Response::error("storage work signature is required", 401);
    }
    let Some(body) = read_bounded_body(&mut request, MAX_PLAN_BYTES).await? else {
        return Response::error("storage work plan is too large", 413);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let plan = match key.verify_plan(
        &signatures[0],
        &body,
        &deployment_id,
        aos_hub_core::clock::now_unix_secs(),
    ) {
        Ok(plan) => plan,
        Err(_) => return Response::error("storage work plan is not authorized", 401),
    };
    let operation_kind = match &plan.operation {
        aos_hub_core::storage_work::StorageWorkOperation::Head { .. } => "head",
        aos_hub_core::storage_work::StorageWorkOperation::ListPage { .. } => "list_page",
        aos_hub_core::storage_work::StorageWorkOperation::InspectSha256 { .. } => "inspect_sha256",
    };

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
        "storage_work_complete plan={} source_bytes={} result_bytes={}",
        plan.plan_id,
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
pub async fn proxy(mut request: Request, env: &Env) -> Result<Response> {
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

    let client_ip = request
        .headers()
        .get("cf-connecting-ip")?
        .ok_or_else(|| worker::Error::RustError("Cloudflare client IP is missing".into()))?;
    let Some(body) = read_bounded_body(&mut request, MAX_CONTROL_BODY_BYTES).await? else {
        return Response::error("control request body is too large", 413);
    };

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

    let target = format!(
        "{}{}",
        origin.origin().ascii_serialization(),
        path_and_query
    );
    let mut init = RequestInit::new();
    init.with_method(request.method())
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    if !body.is_empty() {
        let js_body: JsValue = js_sys::Uint8Array::from(body.as_slice()).into();
        init.with_body(Some(js_body));
    }
    let upstream = Request::new_with_init(&target, &init)?;
    let response = Fetch::Request(upstream).send().await?;
    let headers = response.headers().clone();
    if headers.get("x-aos-hybrid-origin")?.as_deref() != Some("1") {
        return Response::error("hybrid origin identity is missing", 502);
    }
    headers.delete("x-aos-hybrid-origin")?;
    let status = response.status_code();
    let Some(body) = read_bounded_response(response, MAX_CONTROL_RESPONSE_BYTES).await? else {
        return Response::error("hybrid control response is too large", 502);
    };
    headers.delete("content-length")?;
    Ok(Response::from_body(if body.is_empty() {
        ResponseBody::Empty
    } else {
        ResponseBody::Body(body)
    })?
    .with_status(status)
    .with_headers(headers))
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
        || name == "forwarded"
        || name == "cf-connecting-ip"
        || name.starts_with("x-forwarded-")
        || matches!(
            name.as_str(),
            "x-aos-hybrid-ingress"
                | "x-aos-delivery-attestation"
                | "x-aos-client-ip"
                | "x-aos-console-route"
        )
}
