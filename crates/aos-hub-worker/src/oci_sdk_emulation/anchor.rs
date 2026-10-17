//! Bounded actual SDK anchor reads under the selected physical key gate.

use std::sync::Arc;

use futures_util::lock::Mutex;
use worker::{Request, Response};

use crate::hybrid_object::HybridObjectGuard;

pub(crate) const PHYSICAL_PATH: &str = aos_hub_core::oci_sdk_emulation::anchor::OCI_SDK_ANCHOR_PATH;

pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
    gate: Arc<Mutex<()>>,
) -> worker::Result<Response> {
    #[cfg(feature = "do-e2e")]
    {
        return match runtime::physical_read(guard, key, request, gate).await {
            Ok(response) => Ok(response),
            Err(_) => Response::error("OCI SDK anchor unavailable", 409),
        };
    }
    #[cfg(not(feature = "do-e2e"))]
    {
        let _ = (guard, key, request, gate);
        Response::error("OCI SDK emulator unavailable", 404)
    }
}

#[cfg(feature = "do-e2e")]
pub(super) use runtime::verify_current;

#[cfg(feature = "do-e2e")]
mod runtime {
    use anyhow::{ensure, Context as _, Result};
    use aos_hub_core::{
        mirror_guard::MirrorGuardIssuer,
        oci_sdk_emulation::{anchor::*, OciSdkEmulationArtifact, OciSdkObjectObservation},
        storage_work::StorageObjectIdentity,
    };
    use js_sys::{Object, Reflect};
    use sha2::{Digest as _, Sha256};
    use std::{future::Future, rc::Rc};
    use wasm_bindgen::{JsCast as _, JsValue};
    use worker::{Env, Headers, Method, RequestInit};

    use super::*;
    use crate::{
        direct_upload::{config, managed, provider_capacity},
        oci_projection::{
            guard_key,
            lifetime::{Owner, Scope},
            sdk_read,
        },
        oci_sdk_emulation::OciProviderConfig,
    };

    pub(crate) async fn verify_current(
        env: &Env,
        artifact: &OciSdkEmulationArtifact,
        deadline: Option<u64>,
    ) -> Result<()> {
        let issued_at = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        let own_deadline = issued_at
            .checked_add(30)
            .context("OCI SDK anchor deadline overflow")?;
        let lookup = OciSdkAnchorLookup {
            version: 1,
            deployment_id: artifact.profile.deployment_id.clone(),
            profile_digest: artifact.profile.digest()?,
            issuer: MirrorGuardIssuer {
                source_digest: artifact.profile.worker_source_digest.clone(),
                script_version: artifact.profile.worker_script_version.clone(),
            },
            clock_uncertainty_seconds: artifact.profile.clock_policy.uncertainty_seconds.get(),
            anchor: artifact.profile.anchor.clone(),
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            issued_at,
            expires_at: own_deadline
                .min(deadline.unwrap_or(own_deadline))
                .min(artifact.expires_at),
        };
        lookup.validate(&lookup.deployment_id, config::guard_latest_now(env)?)?;
        let key = guard_key(env)?;
        let signed = sign_oci_sdk_anchor_lookup(&key, &lookup)?;
        let headers = Headers::new();
        headers.set(OCI_SDK_ANCHOR_SIGNATURE_HEADER, &signed.signature)?;
        headers.set("x-aos-hybrid-object-key", &lookup.anchor.object.key)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(
                js_sys::Uint8Array::from(signed.body.as_slice()).into(),
            ));
        let address = format!(
            "{}:{}",
            lookup.deployment_id,
            hex::encode(Sha256::digest(&lookup.anchor.object.key))
        );
        bounded(env, &lookup, async {
            let response = env
                .durable_object("HYBRID_OBJECT_GUARD")?
                .id_from_name(&address)?
                .get_stub()?
                .fetch_with_request(Request::new_with_init(
                    &format!("https://physical-guard{PHYSICAL_PATH}"),
                    &init,
                )?)
                .await?;
            ensure!(response.status_code() == 200, "OCI SDK anchor refused");
            let signature = response
                .headers()
                .get(OCI_SDK_ANCHOR_SIGNATURE_HEADER)?
                .context("OCI SDK anchor signature absent")?;
            let body =
                crate::hybrid::read_bounded_response(response, MAX_OCI_SDK_ANCHOR_CONTROL_BYTES)
                    .await?
                    .context("OCI SDK anchor reply exceeds bound")?;
            verify_oci_sdk_anchor_reply(
                &key,
                &signature,
                &body,
                &lookup,
                config::guard_latest_now(env)?,
            )
        })
        .await
    }

    pub(super) async fn physical_read(
        guard: &HybridObjectGuard,
        key: &str,
        request: &mut Request,
        gate: Arc<Mutex<()>>,
    ) -> Result<Response> {
        ensure!(
            request.method() == Method::Post,
            "OCI SDK anchor requires POST"
        );
        let signature = request
            .headers()
            .get(OCI_SDK_ANCHOR_SIGNATURE_HEADER)?
            .context("OCI SDK anchor signature absent")?;
        let body = crate::hybrid::read_bounded_body(request, MAX_OCI_SDK_ANCHOR_CONTROL_BYTES)
            .await?
            .context("OCI SDK anchor request exceeds bound")?;
        let lookup = verify_oci_sdk_anchor_lookup(
            &guard_key(&guard.env)?,
            &signature,
            &body,
            &guard.env.var("HUB_DEPLOYMENT_ID")?.to_string(),
            config::guard_latest_now(&guard.env)?,
        )?;
        ensure!(
            key == lookup.anchor.object.key,
            "OCI SDK anchor addressed another key"
        );
        bounded(&guard.env, &lookup, async {
            let qualified = OciProviderConfig::load(&guard.env).await?;
            let artifact = qualified.artifact()?;
            ensure!(
                artifact.profile.digest()? == lookup.profile_digest
                    && artifact.profile.anchor == lookup.anchor
                    && artifact.profile.worker_source_digest == lookup.issuer.source_digest
                    && artifact.profile.worker_script_version == lookup.issuer.script_version
                    && artifact.profile.clock_policy.uncertainty_seconds.get()
                        == lookup.clock_uncertainty_seconds,
                "OCI SDK anchor selected another reviewed installation"
            );
            let before_dispatch = || {
                lookup.validate(&lookup.deployment_id, config::guard_latest_now(&guard.env)?)?;
                qualified.check(&guard.env)
            };
            let gate = crate::hybrid_object::acquire_gate(gate).await;
            let storage = guard.state.storage();
            crate::direct_guard::deny_legacy(&storage).await?;
            crate::mirror_import::runtime::deny_other_owner(&storage).await?;
            let pending = storage
                .get::<crate::hybrid_object_state::Mutation>("pending-mutation")
                .await?;
            let deleting = storage
                .get::<crate::hybrid_object_state::DeleteClaim>("pending-delete")
                .await?;
            crate::hybrid_object_state::ensure_ready(pending.as_ref(), deleting.as_ref())?;
            let buffer = crate::mirror_import::buffers::acquire(true, &before_dispatch).await?;
            let capacity = provider_capacity::acquire_class_checked(
                1,
                provider_capacity::Class::Metadata,
                &before_dispatch,
            )
            .await?;
            let owner = Owner::new((gate, capacity, buffer));
            let _scope = Scope(Rc::clone(&owner));
            let bucket = managed::bucket(&guard.env)?;
            before_dispatch()?;
            let head =
                sdk_read(&guard.state, &bucket, "head", key, None, Rc::clone(&owner)).await?;
            let identity = managed::identity(&head)?;
            ensure!(
                identity.version
                    == lookup
                        .anchor
                        .object
                        .provider_version
                        .as_deref()
                        .unwrap_or("")
                    && identity.etag == lookup.anchor.object.etag
                    && identity.byte_size.get() == lookup.anchor.object.size,
                "OCI SDK anchor incarnation differs"
            );
            let only_if = Object::new();
            Reflect::set(
                &only_if,
                &JsValue::from_str("etagMatches"),
                &JsValue::from_str(identity.etag.trim_matches('"')),
            )
            .map_err(|_| anyhow::anyhow!("OCI SDK conditional anchor read unavailable"))?;
            let options = Object::new();
            Reflect::set(&options, &JsValue::from_str("onlyIf"), &only_if)
                .map_err(|_| anyhow::anyhow!("OCI SDK conditional anchor read unavailable"))?;
            before_dispatch()?;
            let object = sdk_read(
                &guard.state,
                &bucket,
                "get",
                key,
                Some(options.into()),
                Rc::clone(&owner),
            )
            .await?;
            let stream = Reflect::get(&object, &JsValue::from_str("body"))
                .map_err(|_| anyhow::anyhow!("OCI SDK anchor body unavailable"))?
                .dyn_into::<worker::web_sys::ReadableStream>()
                .map_err(|_| anyhow::anyhow!("OCI SDK anchor body unavailable"))?;
            let reader = owner.attach(crate::direct_digest::Reader::new(stream.into())?)?;
            ensure!(
                managed::identity(&object)? == identity,
                "OCI SDK conditional read changed incarnation"
            );
            let mut hash = Sha256::new();
            let mut size = 0_u64;
            loop {
                owner.check_open()?;
                before_dispatch()?;
                let (view, done) = reader.read().await?;
                owner.check_open()?;
                size = size
                    .checked_add(u64::from(view.length()))
                    .context("OCI SDK anchor length overflow")?;
                ensure!(
                    size <= lookup.anchor.object.size && size <= 1024,
                    "OCI SDK anchor exceeds bound"
                );
                hash.update(view.to_vec());
                if done {
                    break;
                }
            }
            ensure!(
                size == lookup.anchor.object.size,
                "OCI SDK anchor body is incomplete"
            );
            let reply = OciSdkAnchorReply {
                request: lookup.clone(),
                observed: OciSdkObjectObservation {
                    object: StorageObjectIdentity {
                        key: key.into(),
                        size,
                        etag: identity.etag,
                        provider_version: Some(identity.version),
                    },
                    sha256: hex::encode(hash.finalize()),
                },
                observed_at: config::guard_latest_now(&guard.env)?,
            };
            let signed = sign_oci_sdk_anchor_reply(&guard_key(&guard.env)?, &reply)?;
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set(OCI_SDK_ANCHOR_SIGNATURE_HEADER, &signed.signature)?;
            Ok(Response::from_bytes(signed.body)?.with_headers(headers))
        })
        .await
    }

    async fn bounded<T>(
        env: &Env,
        lookup: &OciSdkAnchorLookup,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let remaining = lookup
            .expires_at
            .checked_sub(config::guard_latest_now(env)?)
            .filter(|seconds| *seconds > 0)
            .context("OCI SDK original deadline expired")?;
        let timer = worker::Delay::from(std::time::Duration::from_secs(remaining));
        match futures_util::future::select(Box::pin(operation), Box::pin(timer)).await {
            futures_util::future::Either::Left((result, _)) => {
                lookup.validate(&lookup.deployment_id, config::guard_latest_now(env)?)?;
                result
            }
            futures_util::future::Either::Right(_) => {
                anyhow::bail!("OCI SDK original deadline expired")
            }
        }
    }
}
