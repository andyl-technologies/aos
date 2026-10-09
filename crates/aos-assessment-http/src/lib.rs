//! Bounded native source effects for local and Native Hub package assessments.
//!
//! [`NativeSourceTransport`] executes only typed installed source requests with
//! bounded streaming, TLS, explicit timeouts and no redirects. [`SourceCredentials`]
//! resolves immutable scoped secret references at invocation time. Parsing and
//! continuation semantics remain in [`aos_assessment_runtime::provider`], which
//! Worker adapters reuse without this native HTTP dependency.

#![forbid(unsafe_code)]

pub mod executor;
pub mod remote;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use aos_assessment::observation::HttpValidators;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::ports::Clock;
use aos_assessment_runtime::provider::{
    ProviderOperation, ProviderWorkPlanV1, SourceMethod, SourceRequest, SourceResponse,
    SourceTransport,
};
use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::Zeroizing;

/// Reads the native physical clock exclusively at the runtime effect boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PhysicalClock;

impl Clock for PhysicalClock {
    /// Returns the native whole-second UTC time.
    ///
    /// # Errors
    /// Returns an error for a clock before the epoch or outside the timestamp profile.
    #[allow(clippy::disallowed_methods)] // Physical I/O adapter; pure policy receives explicit time.
    fn now(&self) -> Result<Timestamp> {
        Timestamp::from_unix_seconds(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }
}

/// Preserves secret bytes until one exact installed source header is constructed.
pub enum SourceCredential {
    /// Sends no source credential.
    Anonymous,
    /// Sends an immutable GitHub token only to the fixed GitHub API profile.
    Github(Zeroizing<String>),
    /// Sends an immutable NVD API key only to the fixed NVD API profile.
    Nvd(Zeroizing<String>),
}

/// Resolves current scoped secret custody without putting bytes into work plans.
#[async_trait::async_trait]
pub trait SourceCredentials: Send + Sync {
    /// Resolves the plan's exact immutable credential reference under current grants.
    ///
    /// Implementations check the partition, provider, secret version and current
    /// credential authority. A removed reference never falls back to ambient tokens.
    ///
    /// # Errors
    /// Returns an error for unknown, revoked, unavailable or incompatible credentials.
    async fn resolve(&self, plan: &ProviderWorkPlanV1) -> Result<SourceCredential>;
}

/// Supplies anonymous requests and rejects every referenced secret.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnonymousCredentials;

#[async_trait::async_trait]
impl SourceCredentials for AnonymousCredentials {
    async fn resolve(&self, plan: &ProviderWorkPlanV1) -> Result<SourceCredential> {
        if plan.credential_ref.is_some() {
            bail!("source credential reference is unavailable");
        }
        Ok(SourceCredential::Anonymous)
    }
}

/// Executes exact source-profile HTTP requests with independent physical limits.
pub struct NativeSourceTransport {
    credentials: Arc<dyn SourceCredentials>,
    clients: Mutex<BTreeMap<u32, reqwest::Client>>,
}

impl NativeSourceTransport {
    /// Creates a transport with an explicitly scoped credential resolver.
    #[must_use]
    pub fn new(credentials: Arc<dyn SourceCredentials>) -> Self {
        Self {
            credentials,
            clients: Mutex::new(BTreeMap::new()),
        }
    }

    fn client(&self, connect_seconds: u32) -> Result<reqwest::Client> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| anyhow::anyhow!("source client pool is unavailable"))?;
        if let Some(client) = clients.get(&connect_seconds) {
            return Ok(client.clone());
        }
        // Identity encoding makes encoded and decoded limits independently
        // enforceable without hidden automatic decompression inside reqwest.
        let client = source_client_builder(connect_seconds)
            .build()
            .map_err(|_| anyhow::anyhow!("source TLS client could not be initialized"))?;
        clients.insert(connect_seconds, client.clone());
        Ok(client)
    }
}

fn source_client_builder(connect_seconds: u32) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(u64::from(connect_seconds)))
        .timeout(Duration::from_secs(45))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .user_agent("aos-package-assessment/v1")
}

#[async_trait::async_trait]
impl SourceTransport for NativeSourceTransport {
    async fn fetch(
        &self,
        plan: &ProviderWorkPlanV1,
        request: &SourceRequest,
    ) -> Result<SourceResponse> {
        let now = PhysicalClock.now()?;
        plan.validate_at(&now)?;
        if !plan.operation.source_requests()?.contains(request) {
            bail!("HTTP request differs from the exact admitted source operation");
        }
        let credential = self.credentials.resolve(plan).await?;
        plan.validate_at(&PhysicalClock.now()?)?;
        let remaining = plan
            .expires_at
            .unix_seconds()
            .checked_sub(PhysicalClock.now()?.unix_seconds())
            .filter(|seconds| *seconds > 0)
            .context("source work expired before HTTP execution")?;
        let timeout = Duration::from_secs(remaining.min(u64::from(plan.limits.request_seconds)));
        let client = self.client(plan.limits.connect_seconds)?;
        let mut builder = match request.method {
            SourceMethod::Get => client.get(request.url.clone()),
            SourceMethod::Post => client.post(request.url.clone()),
        }
        .timeout(timeout)
        .header("accept", "application/json")
        .header("accept-encoding", "identity");
        builder = source_headers(builder, &plan.operation, credential)?;
        if let Some(cache) = &plan.cache_ref {
            if let Some(etag) = &cache.validators.etag {
                builder = builder.header("if-none-match", safe_header(etag)?);
            }
            if let Some(modified) = &cache.validators.last_modified {
                builder = builder.header("if-modified-since", safe_header(modified)?);
            }
        }
        if let Some(body) = &request.body {
            builder = builder
                .header("content-type", "application/json")
                .body(body.clone());
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("source HTTP request failed"))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > plan.limits.response_bytes)
        {
            bail!("source content length exceeds the response byte ceiling");
        }
        if response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
        {
            bail!("source ignored the installed identity encoding profile");
        }
        let validators = response_validators(response.headers())?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("source HTTP stream failed"))?
        {
            let size = body
                .len()
                .checked_add(chunk.len())
                .context("source response size overflow")?;
            if size as u64 > plan.limits.response_bytes {
                bail!("source stream exceeds the response byte ceiling");
            }
            body.try_reserve(chunk.len())
                .context("source response allocation failed")?;
            body.extend_from_slice(&chunk);
        }
        plan.validate_at(&PhysicalClock.now()?)?;
        Ok(SourceResponse {
            status,
            transferred_bytes: body.len() as u64,
            body,
            validators,
        })
    }
}

fn source_headers(
    mut builder: reqwest::RequestBuilder,
    operation: &ProviderOperation,
    credential: SourceCredential,
) -> Result<reqwest::RequestBuilder> {
    match credential {
        SourceCredential::Anonymous => {}
        SourceCredential::Github(token)
            if matches!(
                operation,
                ProviderOperation::ObserveReleases { .. } | ProviderOperation::ObserveTags { .. }
            ) =>
        {
            let value = Zeroizing::new(format!("Bearer {}", token.as_str()));
            let mut header = safe_header(&value)?;
            header.set_sensitive(true);
            builder = builder.header("authorization", header);
        }
        SourceCredential::Nvd(token)
            if matches!(
                operation,
                ProviderOperation::QueryNvd { .. } | ProviderOperation::RefreshNvd { .. }
            ) =>
        {
            let mut header = safe_header(&token)?;
            header.set_sensitive(true);
            builder = builder.header("apiKey", header);
        }
        _ => bail!("source credential is incompatible with the installed provider"),
    }
    if matches!(
        operation,
        ProviderOperation::ObserveReleases { .. } | ProviderOperation::ObserveTags { .. }
    ) {
        builder = builder.header("x-github-api-version", "2022-11-28");
    }
    Ok(builder)
}

fn safe_header(value: &str) -> Result<HeaderValue> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        bail!("source header exceeds the installed value profile");
    }
    HeaderValue::from_str(value).map_err(|_| anyhow::anyhow!("source header is invalid"))
}

fn response_validators(headers: &HeaderMap) -> Result<Option<HttpValidators>> {
    let value = |name: &str| -> Result<Option<String>> {
        headers
            .get(name)
            .map(|value| {
                let text = value
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("source validator is not text"))?;
                safe_header(text)?;
                Ok(text.to_owned())
            })
            .transpose()
    };
    let validators = HttpValidators {
        etag: value("etag")?,
        last_modified: value("last-modified")?,
    };
    Ok((validators.etag.is_some() || validators.last_modified.is_some()).then_some(validators))
}
