//! The Worker's adapters from Cloudflare bindings to the shared console ports.
//!
//! The producer console's request handlers live in `aos_hub_core::web::console`
//! and run unchanged on both shells; each reaches its platform-specific
//! capabilities through a *port* (RFC-0004 Phase 5, console-dedup stage C). The
//! native hub satisfies those ports from its `coreports` module; this module is
//! the Worker's mirror, satisfying the same ports from the Workers runtime:
//!
//! - [`WorkerMailer`] — the transactional [`Mailer`] (an `async` port). When the
//!   Cloudflare Email Service binding (`EMAIL`) and a `HUB_EMAIL_FROM` address are
//!   present it sends through `EMAIL.send({ from, to, subject, html, text })`; else
//!   when `HUB_EMAIL_API_URL` is configured it `POST`s the structured message to
//!   that email relay over the Fetch API (optional `HUB_EMAIL_API_TOKEN` bearer);
//!   otherwise it logs the message via [`worker::console_log!`] (the
//!   dev/unconfigured path).
//! - [`WorkerHttpClient`] — the OIDC outbound [`HttpClient`], over the Workers
//!   global Fetch API. It applies the literal-IP SSRF rejection
//!   ([`url_guard::is_safe_remote_url`](aos_hub_core::url_guard::is_safe_remote_url))
//!   and a 1 MiB body cap enforced by a `Content-Length` pre-check plus a
//!   running cap over the streamed body (aborting an unbounded chunked
//!   response). Unlike the native hub it cannot run a connect-time validating
//!   resolver, so *hostname*-based SSRF is delegated to Cloudflare's egress
//!   policy rather than blocked in code (see [`WorkerHttpClient`]).
//! - [`WorkerReindexer`] — the [`Reindexer`] the shared facade-write handler
//!   runs when a publish-completing pointer lands (and a hosted-key channel
//!   advance after its signed partitions are written through the
//!   [`SurfaceWriteProvider`](aos_hub_core::surface_write::SurfaceWriteProvider)).
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
use aos_hub_core::url_guard;
use aos_hub_core::web::console::ports::HttpClient;
use async_trait::async_trait;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wasm_bindgen::{JsCast, JsValue};
use worker::{Bucket, Fetch, Headers, Method, Request, RequestInit};

/// Maximum response-body size for an OIDC outbound call: 1 MiB.
///
/// A token-endpoint response and a JWKS document are KB-scale by nature, so a
/// 1 MiB cap leaves ample headroom while bounding a hostile IdP endpoint, matching
/// the native hub's `MAX_OIDC_BODY_BYTES`.
const MAX_OIDC_BODY_BYTES: usize = 1024 * 1024;

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
///    `HUB_EMAIL_API_TOKEN`) over the Workers Fetch API, for an operator who
///    fronts their own provider (Resend, SendGrid, a Routing worker, …). The
///    endpoint is operator-controlled, so the relay URL is not SSRF-guarded here.
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
    ) -> WorkerMailer {
        let clean = |v: Option<String>| v.filter(|s| !s.is_empty());
        WorkerMailer {
            email_binding,
            from: clean(from),
            api_url: clean(api_url),
            api_token: clean(api_token),
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
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|err| anyhow::anyhow!("email relay: set header: {err}"))?;
        if let Some(token) = &self.api_token {
            headers
                .set("Authorization", &format!("Bearer {token}"))
                .map_err(|err| anyhow::anyhow!("email relay: set auth: {err}"))?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into()));
        let request = Request::new_with_init(url, &init)
            .map_err(|err| anyhow::anyhow!("email relay: build request: {err}"))?;
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("email relay POST: {err}"))?;
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

/// The Worker's OIDC outbound [`HttpClient`], over the Workers global Fetch API.
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
/// One property still differs from the native hub's `HubHttpClient`:
///
/// - **Hostname SSRF.** The hub runs a connect-time validating resolver that
///   refuses a domain resolving to an internal address; the Workers runtime
///   exposes no such hook, so a hostile IdP config using a *hostname* (rather
///   than a literal internal IP) is bounded only by Cloudflare's egress policy,
///   not by this guard.
///
/// It holds no state: the Fetch API is global. The client is live: as of the
/// OIDC move into shared `core` (console-dedup stage F), the Worker mounts the
/// OIDC routes, whose token-exchange and JWKS fetch reach this client.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerHttpClient;

impl WorkerHttpClient {
    /// Send `request`, enforce a 2xx status and the [`MAX_OIDC_BODY_BYTES`] cap,
    /// and return the decoded body bytes.
    async fn send_capped(request: Request, what: &str) -> Result<Vec<u8>> {
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("{what}: {err}"))?;
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
        url_guard::is_safe_remote_url(url).with_context(|| format!("POST {url}"))?;
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/x-www-form-urlencoded")
            .map_err(|err| anyhow::anyhow!("POST {url}: set header: {err}"))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into()));
        let request = Request::new_with_init(url, &init)
            .map_err(|err| anyhow::anyhow!("POST {url}: build request: {err}"))?;
        WorkerHttpClient::send_capped(request, "OIDC token response").await
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        url_guard::is_safe_remote_url(url).with_context(|| format!("GET {url}"))?;
        let request = Request::new(url, Method::Get)
            .map_err(|err| anyhow::anyhow!("GET {url}: build request: {err}"))?;
        WorkerHttpClient::send_capped(request, "JWKS document").await
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
    sealer: Arc<dyn SecretSealer>,
}

impl WorkerReindexer {
    /// Build a reindexer over the hub R2 bucket, the shared D1 [`Database`], and
    /// the [`SecretSealer`] used to resolve a registry's external storage
    /// binding (matching the surface provider the read path and Cron use).
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        sealer: Arc<dyn SecretSealer>,
    ) -> WorkerReindexer {
        WorkerReindexer { bucket, db, sealer }
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
            Arc::clone(&self.sealer),
        );
        let fetch = provider.fetcher(registry).await?;
        let outcome =
            aos_hub_core::indexer::index_and_record(&self.db, fetch.as_ref(), registry).await?;
        // Return the indexed commit (when the run wasn't an empty/pending no-op)
        // so a hosted-key channel advance can cross-reference it in its audit row.
        Ok((!outcome.commit.is_empty()).then(|| outcome.commit))
    }
}
