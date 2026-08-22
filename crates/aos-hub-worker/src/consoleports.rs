//! The Worker's adapters from Cloudflare bindings to the shared console ports.
//!
//! Retained browser identity handlers live in `aos_hub_core::web::console` and
//! run unchanged on both runtimes. This module supplies the Worker's outbound
//! capabilities:
//!
//! - [`WorkerMailer`] — the transactional [`Mailer`] (an `async` port). When the
//!   Cloudflare Email Service binding (`EMAIL`) and a `HUB_EMAIL_FROM` address are
//!   present it sends through `EMAIL.send({ from, to, subject, html, text })`; else
//!   when `HUB_EMAIL_API_URL` is configured it `POST`s the structured message to
//!   that email relay through the configured egress transport (optional
//!   `HUB_EMAIL_API_TOKEN` bearer);
//!   otherwise it logs the message via [`worker::console_log!`] (the
//!   dev/unconfigured path).
//! - [`WorkerHttpClient`] — the OIDC/domain-probe outbound [`HttpClient`], over
//!   Worker Fetch by default or an optional authenticated native router. Both
//!   transports enforce a closed request contract; the router additionally
//!   returns signed connect-time peer evidence.
//! - [`WorkerReindexer`] — the [`Reindexer`] the shared facade-write handler
//!   runs when a publish-completing pointer lands after its signed partitions
//!   are written through the
//!   [`SurfaceWriteProvider`](aos_hub_core::surface_write::SurfaceWriteProvider).
//!   It re-indexes that one registry inline through the shared core indexer, so
//!   a Worker publish is browse-visible the instant its final `PUT` returns;
//!   the `*/15` Cron indexer is the backstop for non-publish surface changes.
//!
//! The at-rest [`SecretSealer`](aos_hub_core::auth::seal::SecretSealer) the
//! console's OIDC token exchange needs is the shared pure-Rust AES-256-GCM
//! [`AesGcmSealer`](aos_hub_core::auth::seal::AesGcmSealer), built from a
//! Worker secret by [`sealer_from_secret`]. The *crypto* is shared; only the
//! Worker's key *sourcing* (a Wrangler secret) is platform-specific.

use anyhow::{bail, Context, Result};
use aos_hub_core::auth::magic::Mailer;
use aos_hub_core::auth::seal::{parse_key, AesGcmSealer, SecretSealer};
use aos_hub_core::db::{Database, RegistryRecord};
use aos_hub_core::email::EmailContent;
use aos_hub_core::fetch::SurfaceProvider as _;
use aos_hub_core::reindex::Reindexer;
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::secret_version::{verify_secret_fingerprint, SecretVersionResolver};
use aos_hub_core::url_guard;
use aos_hub_core::web::console::ports::HttpClient;
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::StreamExt;
use rand::Rng as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wasm_bindgen::{JsCast, JsValue};
use worker::{Bucket, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

/// Maximum response-body size for an OIDC outbound call: 1 MiB.
///
/// A token-endpoint response and a JWKS document are KB-scale by nature, so a
/// 1 MiB cap leaves ample headroom while bounding a hostile IdP endpoint, matching
/// the native hub's `MAX_OIDC_BODY_BYTES`.
const MAX_OIDC_BODY_BYTES: usize = 1024 * 1024;

/// Worker storage-credential probe adapter over the selected egress transport.
pub struct WorkerStorageCredentialProbeProvider {
    egress: Arc<WorkerEgressClient>,
    secrets: Arc<dyn SecretVersionResolver>,
}

impl WorkerStorageCredentialProbeProvider {
    /// Creates a Worker probe adapter with controller-owned secret resolution.
    #[must_use]
    pub fn new(egress: Arc<WorkerEgressClient>, secrets: Arc<dyn SecretVersionResolver>) -> Self {
        Self { egress, secrets }
    }
}

#[async_trait(?Send)]
impl aos_hub_core::topology_probe::StorageCredentialProbeProvider
    for WorkerStorageCredentialProbeProvider
{
    async fn probe(
        &self,
        binding: &aos_hub_core::db::BindingRecord,
        credential: &aos_hub_core::db::BindingCredentialRevisionRecord,
        probe_token: &str,
    ) -> Result<aos_hub_core::topology_probe::StorageCredentialProbeEvidence> {
        anyhow::ensure!(
            credential.binding_id == binding.id,
            "credential probe binding identity is inconsistent"
        );
        let secret = self
            .secrets
            .resolve(&credential.secret_version_ref)
            .await
            .context("resolving immutable credential version for probe")?;
        verify_secret_fingerprint(&secret, &credential.credential_fingerprint)?;
        let surface = S3Surface::from_binding(binding, "", Some(secret.expose_utf8()?))?
            .context("credential probe requires an external S3-compatible binding")?;
        let now = aos_hub_core::clock::now_unix_secs();
        let path = format!(
            ".aos/credential-probes/{}/{}/{}",
            credential.purpose, credential.generation, probe_token
        );
        let mut statuses = serde_json::Map::new();
        let valid = match credential.purpose.as_str() {
            "read" | "presign" => {
                let url = surface.object_url(S3Method::Get, &path, now)?;
                let response = self
                    .egress
                    .send(&url, "GET", None, None, None, None, None)
                    .await?;
                let status = response.status_code();
                statuses.insert("getStatus".into(), status.into());
                status == 404 || (200..300).contains(&status)
            }
            "list" => {
                let url = surface.list_url(None, 1, now)?;
                let response = self
                    .egress
                    .send(&url, "GET", None, None, None, None, None)
                    .await?;
                let status = response.status_code();
                statuses.insert("listStatus".into(), status.into());
                (200..300).contains(&status)
            }
            "delete" => {
                let url = surface.object_url(S3Method::Delete, &path, now)?;
                let response = self
                    .egress
                    .send(&url, "DELETE", None, None, None, None, None)
                    .await?;
                let status = response.status_code();
                statuses.insert("deleteStatus".into(), status.into());
                (200..300).contains(&status)
            }
            "write" => {
                let recovery_url = surface.list_multipart_uploads_url(&path, now)?;
                let mut recovery = self
                    .egress
                    .send(&recovery_url, "GET", None, None, None, None, None)
                    .await?;
                let recovery_status = recovery.status_code();
                statuses.insert("multipartRecoveryListStatus".into(), recovery_status.into());
                anyhow::ensure!(
                    (200..300).contains(&recovery_status),
                    "multipart recovery listing was rejected"
                );
                let recovery_body = read_response_capped(
                    &mut recovery,
                    1024 * 1024,
                    "credential multipart recovery listing",
                )
                .await?;
                let recovery_xml = std::str::from_utf8(&recovery_body)
                    .context("credential multipart recovery listing is not UTF-8")?;
                let abandoned = surface.parse_exact_multipart_uploads(&path, recovery_xml)?;
                statuses.insert("recoveredMultipartUploads".into(), abandoned.len().into());
                for upload_id in abandoned {
                    let abort_url = surface.multipart_url(
                        "abort",
                        &path,
                        Some(&upload_id),
                        None,
                        aos_hub_core::clock::now_unix_secs(),
                    )?;
                    let abort = self
                        .egress
                        .send(&abort_url, "DELETE", None, None, None, None, None)
                        .await?;
                    anyhow::ensure!(
                        (200..300).contains(&abort.status_code()),
                        "multipart recovery abort was rejected"
                    );
                }
                let create_url = surface.multipart_url("create", &path, None, None, now)?;
                let mut response = self
                    .egress
                    .send(
                        &create_url,
                        "POST",
                        Some(Vec::new()),
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                let create_status = response.status_code();
                statuses.insert("multipartCreateStatus".into(), create_status.into());
                if (200..300).contains(&create_status) {
                    let body = read_response_capped(
                        &mut response,
                        1024 * 1024,
                        "credential multipart-create probe",
                    )
                    .await?;
                    let upload_id = aos_hub_core::s3surface::parse_multipart_upload_id(
                        std::str::from_utf8(&body)
                            .context("credential multipart-create response is not UTF-8")?,
                    )?;
                    let abort_url = surface.multipart_url(
                        "abort",
                        &path,
                        Some(&upload_id),
                        None,
                        aos_hub_core::clock::now_unix_secs(),
                    )?;
                    let abort = self
                        .egress
                        .send(&abort_url, "DELETE", None, None, None, None, None)
                        .await?;
                    let abort_status = abort.status_code();
                    statuses.insert("multipartAbortStatus".into(), abort_status.into());
                    (200..300).contains(&abort_status)
                } else {
                    false
                }
            }
            _ => anyhow::bail!("credential probe purpose is not supported"),
        };
        let error = (!valid).then(|| {
            format!(
                "{} capability probe was rejected by origin",
                credential.purpose
            )
        });
        Ok(
            aos_hub_core::topology_probe::StorageCredentialProbeEvidence {
                valid,
                conditional_writes_supported: false,
                error,
                evidence: serde_json::Value::Object(statuses),
            },
        )
    }
}

/// Drains one gateway response with both declared-length and streaming caps.
///
/// The gateway may forward a chunked upstream response, so `Content-Length` is
/// only an early rejection. The running total is the authoritative bound and
/// stops reading as soon as the operation-specific cap is crossed.
///
/// # Errors
///
/// Returns an error for an invalid or over-cap declared length, a stream
/// failure, arithmetic overflow, or accumulated bytes beyond `cap`.
pub async fn read_response_capped(
    response: &mut worker::Response,
    cap: u64,
    operation: &str,
) -> Result<Vec<u8>> {
    if let Some(declared) = response
        .headers()
        .get("content-length")?
        .map(|value| value.parse::<u64>())
        .transpose()
        .context("gateway Content-Length is invalid")?
    {
        validate_declared_length(declared, cap, operation)?;
    }
    let mut stream = response
        .stream()
        .map_err(|error| anyhow::anyhow!("{operation} response stream: {error}"))?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| anyhow::anyhow!("{operation} response stream: {error}"))?;
        append_capped(&mut body, &chunk, cap, operation)?;
    }
    Ok(body)
}

fn validate_declared_length(declared: u64, cap: u64, operation: &str) -> Result<()> {
    anyhow::ensure!(
        declared <= cap,
        "{operation} response exceeds its {cap}-byte cap"
    );
    Ok(())
}

fn append_capped(body: &mut Vec<u8>, chunk: &[u8], cap: u64, operation: &str) -> Result<()> {
    let next = body
        .len()
        .checked_add(chunk.len())
        .context("gateway response length overflow")?;
    anyhow::ensure!(
        next as u64 <= cap,
        "{operation} response exceeds its {cap}-byte cap"
    );
    body.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod capped_response_tests {
    use super::{append_capped, require_fresh_gateway_timestamp, validate_declared_length};

    #[test]
    fn rejects_lying_declared_length_before_reading() {
        assert!(validate_declared_length(1025, 1024, "S3 list").is_err());
    }

    #[test]
    fn rejects_chunked_body_when_running_total_crosses_cap() {
        let mut body = Vec::new();
        append_capped(&mut body, &[1; 700], 1024, "S3 object").unwrap();
        assert!(append_capped(&mut body, &[2; 400], 1024, "S3 object").is_err());
        assert_eq!(body.len(), 700);
    }

    #[test]
    fn rejects_future_gateway_evidence() {
        assert!(require_fresh_gateway_timestamp(101, 100).is_err());
        assert!(require_fresh_gateway_timestamp(100, 100).is_ok());
    }
}

/// Build the shared [`AesGcmSealer`] from a Worker secret string.
///
/// The console's OIDC token exchange unseals a tenant's client secret with a
/// [`SecretSealer`]; production uses AES-256-GCM with a 256-bit instance key.
/// The key is sourced from the `HUB_SEAL_KEY` Wrangler secret two ways:
///
/// 1. if the secret parses as a literal key (32 raw bytes or 64 hex
///    characters), it is used verbatim — the *same* form the native hub reads
///    from its `secret.key` file ([`parse_key`]), so an operator can configure
///    both targets with identical key material;
/// 2. otherwise the secret is hashed with SHA-256 to a 256-bit key, so a
///    free-form Wrangler secret still yields a valid AES-256 key. A value
///    derived this way is **not** interchangeable with a hub key file.
///
/// # Errors
///
/// Returns an error only if [`AesGcmSealer::new`] rejects the derived key, which
/// cannot happen here (both paths yield exactly 32 bytes).
pub fn sealer_from_secret(secret: &str) -> Result<Arc<dyn SecretSealer>> {
    let key =
        parse_key(secret.as_bytes()).unwrap_or_else(|_| Sha256::digest(secret.as_bytes()).to_vec());
    Ok(Arc::new(AesGcmSealer::new(&key)?))
}

/// The Worker's transactional [`Mailer`], with three delivery tiers.
///
/// [`send_email`](Mailer::send_email) renders nothing itself — it receives a
/// fully-rendered [`EmailContent`] from the shared [`aos_hub_core::email`]
/// helpers — and routes it through the first available transport:
///
/// 1. **Cloudflare Email Service** — when the `EMAIL` `[[send_email]]` binding is
///    present *and* a `HUB_EMAIL_FROM` sender address is set, it calls the
///    binding's JS API `EMAIL.send({ from, to, subject, html, text })` over
///    wasm-bindgen interop. workers-rs 0.8's typed `worker::SendEmail` binding is
///    *not* a fit here: it wraps the `cloudflare:email` (Email Routing) product,
///    whose `EmailMessage::new(from, to, raw)` takes a full raw-MIME message,
///    whereas this binding is the structured Email Sending API
///    (`send({subject, html, text})`) — a different shape — so the raw interop is
///    retained deliberately. The sender domain must be onboarded in the
///    Cloudflare dashboard first.
/// 2. **HTTP relay** — else when `HUB_EMAIL_API_URL` is set, it `POST`s
///    `{from,to,subject,html,text}` JSON to it (optional `Bearer` token from
///    `HUB_EMAIL_API_TOKEN`) through the fixed authenticated gateway, for an operator who
///    fronts their own provider (Resend, SendGrid, a Routing worker, …). The
///    endpoint is operator-controlled but still passes the same URL and
///    connect-time egress checks as every other remote origin.
/// 3. **Log** — else it emits the subject + recipient via [`worker::console_log!`]
///    (the dev/unconfigured path), so a magic-link login still works from the
///    Worker's tail logs.
pub struct WorkerMailer {
    /// The Cloudflare Email Service binding (`EMAIL`), as the raw JS object
    /// exposing a `send` method; `None` when the binding is absent.
    email_binding: Option<js_sys::Object>,
    /// The verified sender address (`HUB_EMAIL_FROM`) the Email Service requires;
    /// `None` disables tier 1 even when the binding is present.
    from: Option<String>,
    /// The email-relay endpoint (`HUB_EMAIL_API_URL`) for tier 2; `None` skips it.
    api_url: Option<String>,
    /// An optional `Bearer` token (`HUB_EMAIL_API_TOKEN`) for the relay.
    api_token: Option<String>,
    /// Fixed authenticated gateway used for the optional HTTP relay.
    egress: Arc<WorkerEgressClient>,
}

impl WorkerMailer {
    /// Build a mailer from the Email Service binding, sender address, relay
    /// endpoint, and optional bearer token.
    ///
    /// Empty strings are treated as absent, so an unset Wrangler var/secret
    /// falls back to the next tier (ultimately the logging path).
    #[must_use]
    pub fn new(
        email_binding: Option<js_sys::Object>,
        from: Option<String>,
        api_url: Option<String>,
        api_token: Option<String>,
        egress: Arc<WorkerEgressClient>,
    ) -> WorkerMailer {
        let clean = |v: Option<String>| v.filter(|s| !s.is_empty());
        WorkerMailer {
            email_binding,
            from: clean(from),
            api_url: clean(api_url),
            api_token: clean(api_token),
            egress,
        }
    }

    /// Sends `content` to `to` via the Cloudflare Email Service binding.
    ///
    /// Builds the structured payload and awaits the promise returned by the
    /// binding's `send` method. `from` is the verified sender address.
    ///
    /// # Errors
    ///
    /// Returns an error if any field cannot be set on the JS payload, the
    /// binding has no callable `send`, or the `EMAIL.send` promise rejects.
    async fn send_via_binding(
        binding: &js_sys::Object,
        from: &str,
        to: &str,
        content: &EmailContent,
    ) -> Result<()> {
        let payload = js_sys::Object::new();
        let set = |key: &str, value: &str| -> Result<()> {
            js_sys::Reflect::set(&payload, &JsValue::from_str(key), &JsValue::from_str(value))
                .map_err(|e| anyhow::anyhow!("EMAIL payload set {key}: {e:?}"))?;
            Ok(())
        };
        set("from", from)?;
        set("to", to)?;
        set("subject", &content.subject)?;
        set("html", &content.html)?;
        set("text", &content.text)?;
        let send = js_sys::Reflect::get(binding, &JsValue::from_str("send"))
            .map_err(|e| anyhow::anyhow!("EMAIL binding has no send: {e:?}"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|e| anyhow::anyhow!("EMAIL.send is not callable: {e:?}"))?;
        let promise = send
            .call1(binding, &payload)
            .map_err(|e| anyhow::anyhow!("EMAIL.send call failed: {e:?}"))?
            .dyn_into::<js_sys::Promise>()
            .map_err(|e| anyhow::anyhow!("EMAIL.send did not return a promise: {e:?}"))?;
        wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("EMAIL.send failed: {e:?}"))?;
        Ok(())
    }

    /// Sends `content` to `to` by `POST`ing structured JSON to the HTTP relay.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be built/sent or the relay returns
    /// a non-2xx status.
    async fn send_via_relay(&self, url: &str, to: &str, content: &EmailContent) -> Result<()> {
        let body = serde_json::json!({
            "from": self.from,
            "to": to,
            "subject": content.subject,
            "html": content.html,
            "text": content.text,
        })
        .to_string();
        let authorization = self
            .api_token
            .as_ref()
            .map(|token| format!("Bearer {token}"));
        let response = self
            .egress
            .send(
                url,
                "POST",
                Some(body.into_bytes()),
                Some("application/json"),
                None,
                None,
                authorization.as_deref(),
            )
            .await
            .context("email relay gateway request")?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            bail!("email relay returned HTTP {status}");
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl Mailer for WorkerMailer {
    async fn send_email(&self, to: &str, content: &EmailContent) -> Result<()> {
        // Tier 1: Cloudflare Email Service binding (requires a verified sender).
        if let (Some(binding), Some(from)) = (&self.email_binding, &self.from) {
            return WorkerMailer::send_via_binding(binding, from, to, content).await;
        }
        // Tier 2: operator-fronted HTTP relay.
        if let Some(url) = self.api_url.as_deref() {
            return self.send_via_relay(url, to, content).await;
        }
        // Tier 3: nothing configured — log so a dev can still follow the link.
        worker::console_log!(
            "email for {to}: {} (no EMAIL binding / HUB_EMAIL_API_URL; not sent)",
            content.subject
        );
        Ok(())
    }
}

/// The Worker's OIDC outbound [`HttpClient`].
///
/// Both methods reject literal-IP internal hosts and non-http(s) schemes up
/// front ([`url_guard::is_safe_remote_url`]) and bound the response at 1 MiB:
/// a `Content-Length` pre-check rejects an honestly-declared oversized body
/// before reading, and the body is then drained from the `Response` stream with
/// a running cap that aborts the instant the accumulated total exceeds the
/// limit — so a chunked response that declares no `Content-Length` cannot stream
/// an unbounded body into the isolate. This matches the native hub's streaming
/// abort.
///
/// Worker-direct mode relies on Cloudflare's mediated outbound network. The
/// optional native router adds connect-time DNS pinning and signed peer evidence
/// where an installation needs that stronger boundary.
#[derive(Debug, Clone)]
pub struct WorkerHttpClient {
    egress: Arc<WorkerEgressClient>,
}

/// Authenticated Cloudflare control-plane client exposed by Worker egress.
#[derive(Debug, Clone)]
pub struct WorkerCloudflareControlPlaneClient {
    egress: Arc<WorkerEgressClient>,
    api_token: String,
}

/// Closed outbound transport used by the Worker adapters.
#[derive(Debug, Clone)]
pub struct WorkerEgressClient {
    transport: WorkerEgressTransport,
}

#[derive(Debug, Clone)]
enum WorkerEgressTransport {
    Direct,
    Gateway {
        gateway_url: String,
        key_id: String,
        key: Arc<Vec<u8>>,
    },
}

impl WorkerEgressClient {
    /// Builds a client that uses Cloudflare's native Worker Fetch transport.
    #[must_use]
    pub fn direct() -> Self {
        Self {
            transport: WorkerEgressTransport::Direct,
        }
    }

    /// Builds a client using an authenticated repository-owned native router.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe gateway URL or malformed shared key.
    pub fn gateway(gateway_url: String, shared_key: &str) -> Result<Self> {
        let parsed =
            url::Url::parse(&gateway_url).context("invalid hardened-egress gateway URL")?;
        anyhow::ensure!(
            parsed.scheme() == "https"
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.path() == "/v1/fetch",
            "hardened-egress gateway must be an exact HTTPS /v1/fetch URL"
        );
        let (key_id, key_text) = shared_key
            .split_once(':')
            .context("hardened-egress secret must be KEY_ID:KEY")?;
        anyhow::ensure!(
            !key_id.is_empty()
                && key_id.len() <= 64
                && key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "invalid hardened-egress key id"
        );
        let key = parse_key(key_text.as_bytes()).context("invalid hardened-egress shared key")?;
        Ok(Self {
            transport: WorkerEgressTransport::Gateway {
                gateway_url,
                key_id: key_id.to_string(),
                key: Arc::new(key),
            },
        })
    }

    /// Sends one request through the selected Worker egress transport.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe target, request construction or transport
    /// failure, a forbidden redirect, or invalid gateway evidence when the
    /// optional router transport is selected.
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        target: &str,
        method: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        range: Option<&str>,
        if_match: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<worker::Response> {
        self.send_with_webhook(
            target,
            method,
            body,
            content_type,
            range,
            if_match,
            authorization,
            None,
        )
        .await
    }

    /// Sends one signed webhook JSON POST through the closed egress contract.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed closed headers or any ordinary hardened
    /// egress validation, transport, or evidence failure.
    pub async fn send_webhook(
        &self,
        target: &str,
        body: Vec<u8>,
        event: &str,
        signature: &str,
        delivery_id: &str,
    ) -> Result<worker::Response> {
        self.send_with_webhook(
            target,
            "POST",
            Some(body),
            Some("application/json"),
            None,
            None,
            None,
            Some((event, signature, delivery_id)),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_with_webhook(
        &self,
        target: &str,
        method: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        range: Option<&str>,
        if_match: Option<&str>,
        authorization: Option<&str>,
        webhook: Option<(&str, &str, &str)>,
    ) -> Result<worker::Response> {
        url_guard::is_safe_remote_url(target)?;
        match &self.transport {
            WorkerEgressTransport::Direct => {
                self.send_direct(
                    target,
                    method,
                    body,
                    content_type,
                    range,
                    if_match,
                    authorization,
                    webhook,
                )
                .await
            }
            WorkerEgressTransport::Gateway {
                gateway_url,
                key_id,
                key,
            } => {
                self.send_gateway(
                    gateway_url,
                    key_id,
                    key,
                    target,
                    method,
                    body,
                    content_type,
                    range,
                    if_match,
                    authorization,
                    webhook,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_direct(
        &self,
        target: &str,
        method: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        range: Option<&str>,
        if_match: Option<&str>,
        authorization: Option<&str>,
        webhook: Option<(&str, &str, &str)>,
    ) -> Result<worker::Response> {
        let request_method = match method {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            _ => bail!("unsupported Worker egress method {method}"),
        };
        let redirectable = matches!(&request_method, Method::Get | Method::Head);
        let headers = Headers::new();
        for (name, value) in [
            ("content-type", content_type),
            ("range", range),
            ("if-match", if_match),
            ("authorization", authorization),
            ("x-aos-event", webhook.map(|value| value.0)),
            ("x-aos-signature", webhook.map(|value| value.1)),
            ("x-aos-delivery-id", webhook.map(|value| value.2)),
        ] {
            if let Some(value) = value {
                headers.set(name, value)?;
            }
        }
        let mut current = url::Url::parse(target).context("invalid Worker egress target")?;
        anyhow::ensure!(
            current.scheme() == "https",
            "Worker-direct egress requires HTTPS"
        );
        let initial_origin = current.origin().ascii_serialization();
        for redirects in 0..=5 {
            url_guard::is_safe_remote_url(current.as_str())?;
            let mut init = RequestInit::new();
            init.with_method(request_method.clone())
                .with_redirect(RequestRedirect::Manual)
                .with_headers(headers.clone());
            if let Some(bytes) = body.as_ref().filter(|bytes| !bytes.is_empty()) {
                let js_body: JsValue = js_sys::Uint8Array::from(bytes.as_slice()).into();
                init.with_body(Some(js_body));
            }
            let request = Request::new_with_init(current.as_str(), &init)?;
            let response = Fetch::Request(request).send().await?;
            if !matches!(response.status_code(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            anyhow::ensure!(
                redirectable,
                "Worker egress refuses redirects for mutating requests"
            );
            anyhow::ensure!(redirects < 5, "Worker egress redirect limit exceeded");
            let location = response
                .headers()
                .get("location")?
                .context("Worker egress redirect omitted Location")?;
            let next = current
                .join(&location)
                .context("invalid Worker egress redirect Location")?;
            url_guard::is_safe_remote_url(next.as_str())?;
            anyhow::ensure!(
                next.scheme() == "https",
                "Worker-direct egress refuses an HTTPS downgrade"
            );
            anyhow::ensure!(
                authorization.is_none() || next.origin().ascii_serialization() == initial_origin,
                "Worker egress refuses an authenticated cross-origin redirect"
            );
            current = next;
        }
        unreachable!("redirect loop returns or fails within the bounded iteration")
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_gateway(
        &self,
        gateway_url: &str,
        key_id: &str,
        key: &[u8],
        target: &str,
        method: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        range: Option<&str>,
        if_match: Option<&str>,
        authorization: Option<&str>,
        webhook: Option<(&str, &str, &str)>,
    ) -> Result<worker::Response> {
        let body = body.unwrap_or_default();
        let body_digest = aos_hub_core::egress_protocol::body_sha256(&body);
        let mut nonce_bytes = [0_u8; 32];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
        let timestamp = aos_hub_core::clock::now_unix_secs();
        let evidence = aos_hub_core::egress_protocol::RequestEvidence {
            timestamp,
            nonce: &nonce,
            target_url: target,
            method,
            body_sha256: &body_digest,
            content_type,
            range,
            if_match,
            authorization,
            webhook_event: webhook.map(|value| value.0),
            webhook_signature: webhook.map(|value| value.1),
            webhook_delivery_id: webhook.map(|value| value.2),
        };
        let signature = aos_hub_core::egress_protocol::sign_request(key, &evidence)?;
        let headers = Headers::new();
        for (name, value) in [
            (
                "x-aos-egress-contract",
                aos_hub_core::egress_protocol::CONTRACT,
            ),
            ("x-aos-egress-key-id", key_id),
            ("x-aos-egress-nonce", nonce.as_str()),
            ("x-aos-egress-target-url", target),
            ("x-aos-egress-upstream-method", method),
            ("x-aos-egress-body-sha256", body_digest.as_str()),
            ("x-aos-egress-signature", signature.as_str()),
        ] {
            headers.set(name, value)?;
        }
        headers.set("x-aos-egress-timestamp", &timestamp.to_string())?;
        for (name, value) in [
            ("x-aos-egress-upstream-content-type", content_type),
            ("x-aos-egress-upstream-range", range),
            ("x-aos-egress-upstream-if-match", if_match),
            ("x-aos-egress-upstream-authorization", authorization),
            (
                "x-aos-egress-upstream-webhook-event",
                webhook.map(|value| value.0),
            ),
            (
                "x-aos-egress-upstream-webhook-signature",
                webhook.map(|value| value.1),
            ),
            (
                "x-aos-egress-upstream-webhook-delivery-id",
                webhook.map(|value| value.2),
            ),
        ] {
            if let Some(value) = value {
                headers.set(name, value)?;
            }
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_redirect(RequestRedirect::Error)
            .with_headers(headers);
        if !body.is_empty() {
            let body: JsValue = js_sys::Uint8Array::from(body.as_slice()).into();
            init.with_body(Some(body));
        }
        let request = Request::new_with_init(gateway_url, &init)?;
        let response = Fetch::Request(request).send().await?;
        Self::verify_gateway_response(&response, &nonce, key_id, key)?;
        Ok(response)
    }

    fn verify_gateway_response(
        response: &worker::Response,
        request_nonce: &str,
        key_id: &str,
        key: &[u8],
    ) -> Result<()> {
        let headers = response.headers();
        let required = |name: &str| -> Result<String> {
            headers
                .get(name)?
                .with_context(|| format!("hardened-egress response omitted {name}"))
        };
        anyhow::ensure!(
            required("x-aos-egress-contract")? == aos_hub_core::egress_protocol::CONTRACT,
            "hardened-egress response contract mismatch"
        );
        anyhow::ensure!(
            required("x-aos-egress-key-id")? == key_id,
            "hardened-egress response key id mismatch"
        );
        let timestamp = required("x-aos-egress-timestamp")?.parse::<i64>()?;
        require_fresh_gateway_timestamp(timestamp, aos_hub_core::clock::now_unix_secs())?;
        let nonce = required("x-aos-egress-nonce")?;
        anyhow::ensure!(
            nonce == request_nonce,
            "hardened-egress response nonce mismatch"
        );
        let final_url = required("x-aos-egress-final-url")?;
        url_guard::is_safe_remote_url(&final_url)?;
        let peer_ip = required("x-aos-egress-peer-ip")?;
        let peer = peer_ip.parse::<std::net::IpAddr>()?;
        anyhow::ensure!(
            url_guard::is_global_ip(peer),
            "hardened-egress peer is non-global"
        );
        let status = required("x-aos-egress-upstream-status")?.parse::<u16>()?;
        anyhow::ensure!(
            status == response.status_code(),
            "hardened-egress status mismatch"
        );
        let signature = required("x-aos-egress-signature")?;
        aos_hub_core::egress_protocol::verify_response(
            key,
            &aos_hub_core::egress_protocol::ResponseEvidence {
                timestamp,
                nonce: &nonce,
                final_url: &final_url,
                peer_ip: &peer_ip,
                status,
            },
            &signature,
        )
    }
}

/// Exercises the Worker-direct Fetch contract against the workerd E2E outbound
/// fixture. This is compiled only into the non-production `do-e2e` artifact.
#[cfg(feature = "do-e2e")]
pub async fn e2e_assert_direct_egress() -> Result<()> {
    let client = WorkerEgressClient::direct();

    let mut ranged = client
        .send(
            "https://egress.test/bytes",
            "GET",
            None,
            None,
            Some("bytes=1-3"),
            None,
            Some("Bearer e2e-token"),
        )
        .await?;
    anyhow::ensure!(ranged.status_code() == 206, "direct range status drift");
    anyhow::ensure!(ranged.bytes().await? == b"bcd", "direct range body drift");

    let mut head = client
        .send(
            "https://egress.test/head",
            "HEAD",
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    anyhow::ensure!(head.status_code() == 200, "direct HEAD status drift");
    anyhow::ensure!(
        head.headers().get("x-egress-fixture")?.as_deref() == Some("head"),
        "direct HEAD response header drift"
    );
    anyhow::ensure!(
        head.bytes().await?.is_empty(),
        "direct HEAD returned a body"
    );

    let mut redirected = client
        .send(
            "https://egress.test/redirect-same",
            "GET",
            None,
            None,
            None,
            None,
            None,
        )
        .await?;
    anyhow::ensure!(
        redirected.bytes().await? == b"redirect-ok",
        "direct same-origin redirect drift"
    );

    anyhow::ensure!(
        client
            .send(
                "https://egress.test/redirect-cross",
                "GET",
                None,
                None,
                None,
                None,
                Some("Bearer e2e-token"),
            )
            .await
            .is_err(),
        "direct egress followed an authenticated cross-origin redirect"
    );
    anyhow::ensure!(
        client
            .send(
                "https://egress.test/redirect-mutating",
                "POST",
                Some(b"mutation".to_vec()),
                Some("text/plain"),
                None,
                None,
                None,
            )
            .await
            .is_err(),
        "direct egress followed a mutating redirect"
    );
    anyhow::ensure!(
        client
            .send(
                "https://egress.test/redirect-downgrade",
                "GET",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .is_err(),
        "direct egress followed an HTTPS downgrade"
    );

    let webhook = client
        .send_webhook(
            "https://egress.test/webhook",
            br#"{"ok":true}"#.to_vec(),
            "release.published",
            "sha256=e2e",
            "delivery-e2e",
        )
        .await?;
    anyhow::ensure!(
        webhook.status_code() == 204,
        "direct webhook contract drift"
    );
    Ok(())
}

fn require_fresh_gateway_timestamp(timestamp: i64, now: i64) -> Result<()> {
    let age = now
        .checked_sub(timestamp)
        .context("hardened-egress response timestamp overflow")?;
    anyhow::ensure!(
        age >= 0,
        "hardened-egress response timestamp is in the future"
    );
    anyhow::ensure!(age <= 60, "hardened-egress response evidence is stale");
    Ok(())
}

impl WorkerCloudflareControlPlaneClient {
    /// Creates the client over the selected Worker egress transport.
    #[must_use]
    pub fn new(egress: Arc<WorkerEgressClient>, api_token: String) -> Self {
        Self { egress, api_token }
    }
}

#[async_trait(?Send)]
impl aos_hub_core::topology_probe::CloudflareControlPlaneClient
    for WorkerCloudflareControlPlaneClient
{
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        anyhow::ensure!(
            path.starts_with("/client/v4/") && !path.contains(['?', '#']),
            "invalid Cloudflare API path"
        );
        let target = format!("https://api.cloudflare.com{path}");
        let authorization = format!("Bearer {}", self.api_token);
        let mut response = self
            .egress
            .send(&target, "GET", None, None, None, None, Some(&authorization))
            .await
            .map_err(|error| anyhow::anyhow!("Cloudflare provider adapter: {error}"))?;
        anyhow::ensure!(
            response.status_code() == 200,
            "Cloudflare provider adapter rejected request"
        );
        let mut stream = response
            .stream()
            .map_err(|error| anyhow::anyhow!("Cloudflare API body: {error}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| anyhow::anyhow!("Cloudflare API body: {error}"))?;
            anyhow::ensure!(
                body.len() + chunk.len() <= MAX_OIDC_BODY_BYTES,
                "Cloudflare API response exceeds 1 MiB"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

impl WorkerHttpClient {
    /// Creates a fail-closed client over the selected egress transport.
    #[must_use]
    pub fn new(egress: Arc<WorkerEgressClient>) -> Self {
        Self { egress }
    }

    /// Send `request`, enforce a 2xx status and the [`MAX_OIDC_BODY_BYTES`] cap,
    /// and return the decoded body bytes.
    async fn send_capped(
        &self,
        target: &str,
        method: Method,
        body: Option<String>,
        content_type: Option<&str>,
        what: &str,
    ) -> Result<Vec<u8>> {
        url_guard::is_safe_remote_url(target).with_context(|| format!("{method:?} {target}"))?;
        let target_url =
            url::Url::parse(target).with_context(|| format!("invalid URL {target}"))?;
        let method = match method {
            Method::Get => "GET",
            Method::Post => "POST",
            _ => bail!("{what}: unsupported Worker egress method"),
        };
        let mut response = self
            .egress
            .send(
                target_url.as_str(),
                method,
                body.map(String::into_bytes),
                content_type,
                None,
                None,
                None,
            )
            .await
            .map_err(|err| anyhow::anyhow!("{what}: Worker egress: {err}"))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            bail!("{what}: endpoint returned HTTP {status}");
        }
        // Reject up front on a declared `Content-Length` over the cap, before
        // reading a byte, so an endpoint that honestly declares an oversized
        // body never makes the isolate buffer it.
        if let Ok(Some(declared)) = response.headers().get("content-length") {
            if let Ok(len) = declared.parse::<usize>() {
                if len > MAX_OIDC_BODY_BYTES {
                    bail!("{what}: declared Content-Length {len} exceeds {MAX_OIDC_BODY_BYTES}-byte cap");
                }
            }
        }
        // Drain the body stream with a running cap, aborting the instant the
        // accumulated total exceeds it — so a chunked response that declares no
        // `Content-Length` cannot stream an unbounded body into the isolate.
        let mut stream = response
            .stream()
            .map_err(|err| anyhow::anyhow!("{what}: opening body stream: {err}"))?;
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| anyhow::anyhow!("{what}: read body: {err}"))?;
            if buf.len() + chunk.len() > MAX_OIDC_BODY_BYTES {
                bail!("{what}: response body exceeds {MAX_OIDC_BODY_BYTES}-byte cap");
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }
}

#[async_trait(?Send)]
impl HttpClient for WorkerHttpClient {
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<Vec<u8>> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        self.send_capped(
            url,
            Method::Post,
            Some(body),
            Some("application/x-www-form-urlencoded"),
            "OIDC token response",
        )
        .await
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.send_capped(url, Method::Get, None, None, "JWKS document")
            .await
    }

    async fn probe_https(&self, url: &str) -> Result<Vec<u8>> {
        url_guard::is_safe_remote_url(url).with_context(|| format!("probe {url}"))?;
        let parsed = url::Url::parse(url).with_context(|| format!("probe {url}"))?;
        if parsed.scheme() != "https" {
            bail!("domain TLS probes require https");
        }
        self.send_capped(url, Method::Get, None, None, "domain TLS proof")
            .await
    }
}

/// The Worker's [`Reindexer`]: re-indexes the published registry inline, the
/// same as the native hub.
///
/// The shared facade-write handler calls this when a publish-completing pointer
/// (`info/refs`/`nix-cache-info`) lands, so the browse pages and release/channel
/// listings are consistent the instant the final `PUT` returns — no
/// up-to-the-Cron-pass lag. It re-walks **one** registry's R2 surface through
/// the *shared* core indexer ([`index_and_record`](aos_hub_core::indexer::index_and_record)),
/// the exact orchestration the native hub and the Cron-trigger indexer
/// ([`crate::indexer::index_all`]) run, so the index is byte-identical across
/// all three.
///
/// **Why inline is safe on the Worker:** this indexes a *single* registry, far
/// less work than the all-public-registry sweep `index_all` already completes in
/// one Cron invocation, so it sits comfortably inside the isolate's per-request
/// budget. A reindex failure is logged by the facade-write caller and does not
/// fail the publish (the bytes are already written); the Cron pass reconciles
/// the index on its next run.
///
/// The `*/15` Cron remains the **backstop** — it still re-walks every public
/// registry, catching surface changes that did not flow through a hub publish
/// (mirror syncs, `stale`/`failed` retries) and running cache GC.
pub struct WorkerReindexer {
    bucket: Bucket,
    db: Arc<Database>,
    secrets: Arc<dyn SecretVersionResolver>,
    egress: Arc<WorkerEgressClient>,
}

impl WorkerReindexer {
    /// Build a reindexer over the hub R2 bucket, the shared HubDb [`Database`], and
    /// the [`SecretVersionResolver`] used to resolve a registry's external storage
    /// binding (matching the surface provider the read path and Cron use).
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        secrets: Arc<dyn SecretVersionResolver>,
        egress: Arc<WorkerEgressClient>,
    ) -> WorkerReindexer {
        WorkerReindexer {
            bucket,
            db,
            secrets,
            egress,
        }
    }
}

#[async_trait(?Send)]
impl Reindexer for WorkerReindexer {
    async fn reindex(&self, registry: &RegistryRecord) -> Result<Option<String>> {
        // Resolve the registry's surface exactly as the Cron indexer does — the
        // hub R2 bucket by prefix, or its external S3/R2 binding — then run the
        // shared single-registry index.
        let provider = crate::surface::R2SurfaceProvider::new(
            self.bucket.clone(),
            Arc::clone(&self.db),
            Arc::clone(&self.secrets),
            Arc::clone(&self.egress),
        );
        let placement = self
            .db
            .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await?;
        let fetch = provider.placement_fetcher(&placement).await?;
        let outcome = aos_hub_core::indexer::index_and_record_from_placement(
            &self.db,
            fetch.as_ref(),
            registry,
            Some(placement.id),
        )
        .await?;
        // Return the indexed commit (when the run wasn't an empty/pending no-op)
        // so the caller can cross-reference the indexed revision in audit state.
        Ok((!outcome.commit.is_empty()).then(|| outcome.commit))
    }
}
