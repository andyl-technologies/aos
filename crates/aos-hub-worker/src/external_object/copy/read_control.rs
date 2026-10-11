//! Read-only cohort admission on the existing permanent physical-key floor.
//!
//! A permit advances the addressed source or listing-prefix floor under CAS.
//! It exposes no mutation turn, continuation or receipt. Unknown/active physical
//! workflows refuse observation; read failure cannot settle those workflows.
//!
//! ```text
//! request = {domain, nonce, profile_digest, scope, cohort_digest,
//!            effect: head | read | list, lease, expires_at}
//! reply = {request_digest, floor}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::{
        control::StorageAuthorityObjectScope,
        lease::{EpochLeaseFloor, LeaseEffect, LeaseInteger},
    },
    storage_work::StorageWorkKey,
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string, MAX_MESSAGE};

pub(super) const PATH: &str = "/copy-read-floor";
pub(super) const DOMAIN: &str = "aos.external-copy-read-floor.v1";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-read-floor-reply.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub domain: String,
    pub nonce: String,
    pub profile_digest: String,
    pub scope: StorageAuthorityObjectScope,
    pub cohort_digest: String,
    pub effect: LeaseEffect,
    pub lease: String,
    pub expires_at: LeaseInteger,
}

impl Request {
    pub(super) fn validate(&self) -> Result<()> {
        self.scope.guard_name()?;
        ensure!(
            self.domain == DOMAIN
                && digest_string(&self.nonce)
                && digest_string(&self.profile_digest)
                && digest_string(&self.cohort_digest)
                && matches!(
                    self.effect,
                    LeaseEffect::Head | LeaseEffect::Read | LeaseEffect::List
                )
                && !self.lease.is_empty()
                && self.expires_at.get() > 0
                && serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "invalid copy read-floor request"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    request_digest: String,
    floor: EpochLeaseFloor,
}

/// Authenticates a closed read-only floor request before selecting any cohort.
///
/// # Errors
/// Refuses mutation effects, unknown fields, wrong MAC/domain or excessive bytes.
pub(super) fn authenticate(key: &StorageWorkKey, signature: &str, body: &[u8]) -> Result<Request> {
    ensure!(body.len() <= MAX_MESSAGE, "copy read-floor oversized");
    key.verify_body(signature, body)?;
    let request: Request = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&request)? == body,
        "copy read-floor noncanonical"
    );
    request.validate()?;
    Ok(request)
}

/// Authenticates the exact durable physical floor without granting mutation authority.
///
/// # Errors
/// Refuses a wrong key/domain/nonce, different physical scope or excessive reply.
pub(super) fn verify_reply(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<EpochLeaseFloor> {
    request.validate()?;
    ensure!(body.len() <= MAX_MESSAGE, "copy read-floor reply oversized");
    key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
    let reply: Reply = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&reply)? == body
            && reply.request_digest == digest(request)?
            && reply.floor.full_key == request.scope.full_key
            && reply.floor.authority.authority_id == request.scope.physical_authority_id,
        "copy read-floor reply differs"
    );
    Ok(reply.floor)
}

#[cfg(target_arch = "wasm32")]
mod runtime {
    use super::super::super::{
        config::configured,
        protocol::{GUARD_HEADER, SCOPE_HEADER},
        state::Head,
        storage::{
            decode, error, key, load_head, transaction_string, ExternalObjectGuard, BINDING, HEAD,
        },
    };
    use super::*;
    use worker::{Method, Request as HttpRequest, Response};

    impl ExternalObjectGuard {
        /// Advances only an independently configured read/list floor under the existing key CAS.
        ///
        /// # Errors
        /// Refuses stale permission, active physical owners, changed config or storage failure.
        pub(crate) async fn copy_read_floor_fetch(
            &self,
            request: &mut HttpRequest,
        ) -> worker::Result<Response> {
            let result = async {
                ensure!(
                    request.method() == Method::Post,
                    "copy read-floor requires POST"
                );
                let body = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("copy read-floor body oversized"))?;
                let signature = request
                    .headers()
                    .get(GUARD_HEADER)?
                    .ok_or_else(|| anyhow::anyhow!("copy read-floor signature absent"))?;
                let key = key(&self.env)?;
                let message = authenticate(&key, &signature, &body)?;
                let object = configured(&self.env)?
                    .ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
                let config = super::super::config::configured(&self.env, &object)?
                    .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
                let domain = config
                    .domains
                    .iter()
                    .find(|domain| {
                        domain
                            .commitment()
                            .is_ok_and(|digest| digest == message.profile_digest)
                    })
                    .ok_or_else(|| anyhow::anyhow!("copy read profile absent"))?;
                let cohort = if message.effect == LeaseEffect::List {
                    &domain.list_cohort
                } else {
                    &domain.read_cohort
                };
                ensure!(
                    digest(cohort)? == message.cohort_digest
                        && object.scope(cohort, message.scope.full_key.clone())? == message.scope,
                    "copy read scope or cohort changed"
                );
                let name = message.scope.guard_name()?;
                ensure!(
                    request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                        && self
                            .env
                            .durable_object(BINDING)?
                            .id_from_name(&name)?
                            .to_string()
                            == self.state.id().to_string(),
                    "copy read addressed to another guard"
                );

                let _gate = self.gate.lock().await;
                let storage = self.state.storage();
                crate::direct_guard::deny_legacy(&storage).await?;
                let prior = load_head(&storage).await?;
                let mut head = if let Some(head) = &prior {
                    head.validate(&object, &message.scope)?;
                    head.clone()
                } else {
                    Head::initialize_floor(&object, &message.scope, cohort, object.clock())?
                };
                ensure!(
                    head.pending.is_none()
                        && head.observation.is_none()
                        && head.stage.is_none()
                        && head.copy.is_none()
                        && head.oci.is_none()
                        && head.mirror.is_none(),
                    "copy read refuses an active physical workflow"
                );
                ensure!(
                    object.clock().observed_at < message.expires_at.get(),
                    "copy read application cutoff expired"
                );
                head.floor = object
                    .verifier()?
                    .validate_lease(
                        message.lease.as_bytes(),
                        cohort,
                        &object.timing_profile,
                        &head.floor,
                        &head.scope.full_key,
                        message.effect,
                        object.clock(),
                    )?
                    .next_floor;
                let encoded = serde_json::to_string(&head)?;
                storage
                    .transaction(move |transaction| {
                        let prior = prior.clone();
                        let encoded = encoded.clone();
                        async move {
                            let current: Option<Head> =
                                decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                                    .map_err(error)?;
                            if current != prior {
                                return Err(error("copy read-floor CAS refused"));
                            }
                            transaction.put(HEAD, encoded).await
                        }
                    })
                    .await?;
                let body = serde_json::to_vec(&Reply {
                    request_digest: digest(&message)?,
                    floor: head.floor,
                })?;
                ensure!(body.len() <= MAX_MESSAGE, "copy read-floor reply oversized");
                let signature = key.sign_body(&[REPLY_DOMAIN, &body].concat())?;
                let headers = worker::Headers::new();
                headers.set(GUARD_HEADER, &signature)?;
                headers.set("content-type", "application/json")?;
                headers.set("cache-control", "private, no-store")?;
                Ok::<_, anyhow::Error>(Response::from_bytes(body)?.with_headers(headers))
            }
            .await;
            match result {
                Ok(response) => Ok(response),
                Err(_) => Response::error("external copy read floor refused", 409),
            }
        }
    }
}
