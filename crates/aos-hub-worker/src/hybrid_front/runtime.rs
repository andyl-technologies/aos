//! Cloudflare Cache API and signed-origin transport for the hybrid front door.

use std::cell::RefCell;

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use sha2::{Digest as _, Sha256};
use worker::{Cache, Env, Request, Response, ResponseBody, Result};

use super::policy::{MAX_CACHE_AGE_SECS, MAX_CACHE_BODY_BYTES};
use super::{FrontTransport, OriginShield, Refusal, ShieldLimits};

const CACHE_EXPIRY_HEADER: &str = "x-aos-front-cache-expires";

thread_local! {
    static ORIGIN_SHIELD: RefCell<OriginShield> = RefCell::new(OriginShield::new(ShieldLimits::default()));
}

pub(crate) async fn proxy(request: Request, env: &Env, phase: Option<&str>) -> Result<Response> {
    let url = request.url()?;
    let method = Method::from_bytes(request.method().as_ref().as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let headers = header_map(request.headers())?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = if phase.is_none() && request.inner().body().is_none() {
        super::request_key(
            &deployment,
            aos_hub_core::web::assets::asset_version(),
            &method,
            &url,
            &headers,
        )
    } else {
        None
    };
    let class = super::origin_class(&method, &url, &headers);
    // The platform supplies this header. Local emulators without it share one
    // conservative bucket; caller-supplied forwarding headers are never used.
    let client_ip = request
        .headers()
        .get("cf-connecting-ip")?
        .unwrap_or_else(|| "0.0.0.0".to_owned());
    let client = hex::encode(Sha256::digest(client_ip.as_bytes()));
    let shield = ORIGIN_SHIELD.with(|shield| shield.borrow().clone());
    let mut transport = WorkerFront {
        request: Some(request),
        env,
        phase,
    };
    super::dispatch(
        &mut transport,
        &shield,
        class,
        &client,
        key.as_deref(),
        aos_hub_core::clock::now_unix_secs(),
    )
    .await
}

struct WorkerFront<'a> {
    request: Option<Request>,
    env: &'a Env,
    phase: Option<&'a str>,
}

#[async_trait::async_trait(?Send)]
impl FrontTransport for WorkerFront<'_> {
    type Response = Response;
    type Error = worker::Error;

    async fn cached(&mut self, key: &str) -> Result<Option<Response>> {
        cached_response(key).await
    }

    async fn origin(&mut self) -> Result<Response> {
        let request = self.request.take().ok_or_else(|| {
            worker::Error::RustError("hybrid origin request was already dispatched".into())
        })?;
        crate::hybrid::proxy_origin(request, self.env, self.phase).await
    }

    async fn store(&mut self, key: &str, response: &mut Response) -> Result<()> {
        store_response(key, response).await
    }

    fn refused(&self, refusal: Refusal) -> Result<Response> {
        let (message, status, retry) = match refusal {
            Refusal::RateLimited => ("hybrid origin rate limit exceeded", 429, "60"),
            Refusal::Busy => ("hybrid origin capacity exhausted", 503, "1"),
            Refusal::Unavailable => ("hybrid origin admission unavailable", 503, "1"),
        };
        let mut response = Response::error(message, status)?;
        response
            .headers_mut()
            .set("cache-control", "private, no-store")?;
        response.headers_mut().set("retry-after", retry)?;
        Ok(response)
    }
}

pub(crate) async fn cached_response(key: &str) -> Result<Option<Response>> {
    match read_cache(key).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("hybrid_public_cache_read_failed: {error}");
            Ok(None)
        }
    }
}

async fn read_cache(key: &str) -> Result<Option<Response>> {
    let response = match Cache::default().get(key, false).await {
        Ok(Some(response)) => response,
        Ok(None) => return Ok(None),
        Err(error) => {
            worker::console_error!("hybrid_public_cache_read_failed: {error}");
            return Ok(None);
        }
    };
    let now = aos_hub_core::clock::now_unix_secs();
    let headers = response.headers().clone();
    let expiry = headers
        .get(CACHE_EXPIRY_HEADER)?
        .and_then(|value| value.parse::<i64>().ok());
    if expiry.is_none_or(|expiry| expiry <= now || expiry > now.saturating_add(MAX_CACHE_AGE_SECS))
    {
        return Ok(None);
    }
    let status = response.status_code();
    let Some(body) = crate::hybrid::read_bounded_response(response, MAX_CACHE_BODY_BYTES).await?
    else {
        return Ok(None);
    };
    if super::response_age(status, &header_map(&headers)?, body.len()).is_none() {
        return Ok(None);
    }
    headers.delete(CACHE_EXPIRY_HEADER)?;
    headers.set("x-aos-front-cache", "hit")?;
    Ok(Some(
        Response::from_bytes(body)?
            .with_status(status)
            .with_headers(headers),
    ))
}

pub(crate) async fn store_response(key: &str, response: &mut Response) -> Result<()> {
    if let Err(error) = write_cache(key, response).await {
        worker::console_error!("hybrid_public_cache_write_failed: {error}");
    }
    Ok(())
}

async fn write_cache(key: &str, response: &mut Response) -> Result<()> {
    let body_size = match response.body() {
        ResponseBody::Empty => 0,
        ResponseBody::Body(bytes) => bytes.len(),
        // Streamed storage delivery has its own post-authorization cache.
        ResponseBody::Stream(_) => return Ok(()),
    };
    let Some(age) = super::response_age(
        response.status_code(),
        &header_map(response.headers())?,
        body_size,
    ) else {
        return Ok(());
    };
    let cached = response.cloned()?;
    let headers = cached.headers().clone();
    headers.set(
        CACHE_EXPIRY_HEADER,
        &aos_hub_core::clock::now_unix_secs()
            .saturating_add(age)
            .to_string(),
    )?;
    let cached = cached.with_headers(headers);
    if let Err(error) = Cache::default().put(key, cached).await {
        worker::console_error!("hybrid_public_cache_write_failed: {error}");
    }
    Ok(())
}

pub(crate) fn header_map(headers: &worker::Headers) -> Result<HeaderMap> {
    let mut output = HeaderMap::new();
    for (name, value) in headers.entries() {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        output.append(name, value);
    }
    Ok(output)
}
