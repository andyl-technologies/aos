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
//!   global Fetch API, with the same SSRF guard
//!   ([`url_guard::is_safe_remote_url`](aos_registry_core::url_guard::is_safe_remote_url))
//!   and 1 MiB body cap the native hub applies.
//! - [`WorkerChannelAdvancer`] — the hosted-key [`ChannelAdvancer`]. R2-backed
//!   partition signing is not yet implemented on the Worker, so an advance
//!   returns a clear error rather than a false success (a documented TODO).
//!
//! The at-rest [`SecretSealer`](aos_registry_core::auth::seal::SecretSealer) the
//! console's OIDC token exchange needs is the shared
//! [`AesGcmSealer`](aos_registry_core::auth::seal::AesGcmSealer), built from a
//! Worker secret by [`sealer_from_secret`]; it is pure-Rust AES-256-GCM and
//! needs no Worker-specific impl.

use aos_registry_core::auth::magic::Mailer;
use aos_registry_core::auth::seal::{AesGcmSealer, SecretSealer};
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
/// [`SecretSealer`]; production uses AES-256-GCM with a per-instance key. The
/// Worker derives that 32-byte key by hashing the configured secret with
/// SHA-256, so an operator can set an arbitrary-length `HUB_SEAL_KEY` secret and
/// always get a valid AES-256 key.
///
/// # Errors
///
/// Returns an error only if [`AesGcmSealer::new`] rejects the derived key, which
/// cannot happen here (SHA-256 always yields exactly 32 bytes).
pub fn sealer_from_secret(secret: &str) -> Result<Arc<dyn SecretSealer>> {
    let key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
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
/// Both methods apply the same hardening the native hub's `HubHttpClient`
/// applies — an SSRF guard that rejects private, loopback, and link-local hosts
/// ([`url_guard::is_safe_remote_url`]) and a 1 MiB body cap — so routing the
/// shared OIDC flow through this port preserves the multi-tenant safety
/// properties on the Worker too. It holds no state: the Fetch API is global.
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
