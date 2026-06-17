//! The Worker's adapters from Cloudflare bindings to the shared console ports.
//!
//! The producer console's request handlers live in `aos_registry_core::web::console`
//! and run unchanged on both shells; each reaches its platform-specific
//! capabilities through a *port* (RFC-0004 Phase 5, console-dedup stage C). The
//! native hub satisfies those ports from its `coreports` module; this module is
//! the Worker's mirror, satisfying the same ports from the Workers runtime:
//!
//! - [`WorkerMailer`] — the magic-link [`Mailer`]. The Workers runtime has no
//!   synchronous SMTP, and the port method is synchronous, so this logs the
//!   link via [`worker::console_log!`] (a real email-binding delivery is a
//!   documented TODO).
//! - [`WorkerHttpClient`] — the OIDC outbound [`HttpClient`], over the Workers
//!   global Fetch API. It applies the literal-IP SSRF rejection
//!   ([`url_guard::is_safe_remote_url`](aos_registry_core::url_guard::is_safe_remote_url))
//!   and a 1 MiB body cap (a `Content-Length` pre-check plus a post-read bound).
//!   Unlike the native hub it cannot run a connect-time validating resolver, so
//!   *hostname*-based SSRF is delegated to Cloudflare's egress policy rather than
//!   blocked in code (see [`WorkerHttpClient`]).
//! - [`WorkerChannelAdvancer`] — the hosted-key [`ChannelAdvancer`]. R2-backed
//!   partition signing is not yet implemented on the Worker, so an advance
//!   returns a clear error rather than a false success (a documented TODO).
//!
//! The at-rest [`SecretSealer`](aos_registry_core::auth::seal::SecretSealer) the
//! console's OIDC token exchange needs is the shared pure-Rust AES-256-GCM
//! [`AesGcmSealer`](aos_registry_core::auth::seal::AesGcmSealer), built from a
//! Worker secret by [`sealer_from_secret`]. The *crypto* is shared; only the
//! Worker's key *sourcing* (a Wrangler secret) is platform-specific.

use aos_registry_core::auth::magic::Mailer;
use aos_registry_core::auth::seal::{parse_key, AesGcmSealer, SecretSealer};
use aos_registry_core::db::RegistryRecord;
use aos_registry_core::url_guard;
use aos_registry_core::web::console::ports::{AdvanceOutcome, ChannelAdvancer, HttpClient};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use worker::{Fetch, Headers, Method, Request, RequestInit};

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
    let key = parse_key(secret.as_bytes())
        .unwrap_or_else(|_| Sha256::digest(secret.as_bytes()).to_vec());
    Ok(Arc::new(AesGcmSealer::new(&key)?))
}

/// The Worker's magic-link [`Mailer`]: logs the link to the Worker console.
///
/// The [`Mailer`] port method is synchronous and the Workers runtime offers no
/// synchronous mail transport, so this emits the magic-link URL via
/// [`worker::console_log!`] and reports success. An operator can follow the link
/// from the Worker's tail logs; wiring real delivery through a Cloudflare Email
/// Routing or transactional-email binding is a documented TODO.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerMailer;

impl Mailer for WorkerMailer {
    fn send_magic_link(&self, email: &str, link_url: &str) -> Result<()> {
        // TODO(RFC-0004): deliver via a Cloudflare email binding instead of
        // logging. The link is visible to anyone reading the Worker tail logs.
        worker::console_log!("magic link for {email}: {link_url} (WorkerMailer: not emailed)");
        Ok(())
    }
}

/// The Worker's OIDC outbound [`HttpClient`], over the Workers global Fetch API.
///
/// Both methods reject literal-IP internal hosts and non-http(s) schemes up
/// front ([`url_guard::is_safe_remote_url`]) and bound the response at 1 MiB (a
/// `Content-Length` pre-check before reading plus a post-read length bound).
/// Two properties differ from the native hub's `HubHttpClient` and are *not*
/// closed in code here:
///
/// - **Hostname SSRF.** The hub runs a connect-time validating resolver that
///   refuses a domain resolving to an internal address; the Workers runtime
///   exposes no such hook, so a hostile IdP config using a *hostname* (rather
///   than a literal internal IP) is bounded only by Cloudflare's egress policy,
///   not by this guard.
/// - **Streaming abort.** The hub aborts mid-stream the instant the running
///   body total exceeds the cap; [`worker::Response::bytes`] buffers the whole
///   body, so a chunked response that declares no `Content-Length` is bounded
///   only after the fact. The `Content-Length` pre-check covers the common and
///   the honest-but-oversized cases.
///
/// It holds no state: the Fetch API is global.
///
/// Currently *forward-wiring*: the only callers are the OIDC token-exchange and
/// JWKS fetch, and the OIDC routes stay native-only on the hub (not yet mounted
/// by `console_router`), so no mounted Worker route reaches this client. The
/// streaming-abort gap must be closed before the OIDC routes move to the Worker.
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
        let bytes = response
            .bytes()
            .await
            .map_err(|err| anyhow::anyhow!("{what}: read body: {err}"))?;
        if bytes.len() > MAX_OIDC_BODY_BYTES {
            bail!(
                "{what}: response body {} bytes exceeds {MAX_OIDC_BODY_BYTES}-byte cap",
                bytes.len()
            );
        }
        Ok(bytes)
    }
}

#[async_trait(?Send)]
impl HttpClient for WorkerHttpClient {
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<Vec<u8>> {
        url_guard::is_safe_remote_url(url).with_context(|| format!("POST {url}"))?;
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish();
        let mut headers = Headers::new();
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

/// The Worker's hosted-key [`ChannelAdvancer`] — not yet implemented.
///
/// On the native hub a channel advance signs the next partitions with the
/// hub-held key and writes them to a filesystem/HTTP surface; the Worker's
/// equivalent must sign against its R2 surface, which is not yet built. Rather
/// than fake a success, [`advance`](ChannelAdvancer::advance) returns a clear
/// error so the route is mounted and every other console path works, while a
/// hosted-key advance fails loudly until R2-backed signing lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerChannelAdvancer;

#[async_trait(?Send)]
impl ChannelAdvancer for WorkerChannelAdvancer {
    async fn advance(
        &self,
        _registry: &RegistryRecord,
        _channel_name: &str,
        _target_semver: &str,
        _count: usize,
        _when: i64,
    ) -> Result<AdvanceOutcome> {
        // TODO(RFC-0004): R2-backed partition signing + re-index on the Worker.
        bail!("hosted-key channel advance is not yet supported on the Cloudflare Worker target")
    }
}
