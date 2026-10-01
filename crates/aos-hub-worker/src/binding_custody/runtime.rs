//! Authenticated custody controls on the existing permanent binding object gate.

use anyhow::{ensure, Result};
use aos_hub_core::{
    s3surface::S3Surface,
    storage_work::{
        binding_custody::*, StorageBindingPublication, StorageBindingSnapshot, StorageWorkKey,
        STORAGE_WORK_SIGNATURE_HEADER,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Headers, Method, Request, RequestInit, Response, Storage};

use super::state::HeldCredential;

/// Prepared result; publication still passes the existing binding replay floor.
pub(crate) enum Outcome {
    Reply(SignedStorageCustodyControl),
    Adoption {
        request: StorageBindingAdoptionRequest,
        publication: StorageBindingPublication,
    },
}

/// Authenticates and forwards one bounded control to its permanent binding object.
///
/// # Errors
/// Returns an error when a bounded refusal response cannot be constructed.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        let body = crate::hybrid::read_bounded_body(&mut request, MAX_BINDING_CUSTODY_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("credential custody control exceeds bound"))?;
        ensure!(
            request.method() == Method::Post,
            "credential custody method differs"
        );
        let signature = request
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("credential custody authentication absent"))?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let now = aos_hub_core::clock::now_unix_secs();
        let key = key(env)?;
        let path = request.url()?.path().to_owned();
        let binding_id = if path == STORAGE_CREDENTIAL_CUSTODY_PATH {
            verify_storage_credential_custody_stage(&key, &signature, &body, &deployment, now)?
                .request
                .snapshot
                .binding_id
        } else if path == STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH {
            verify_storage_credential_custody_probe(&key, &signature, &body, &deployment, now)?
                .snapshot
                .binding_id
        } else if path == STORAGE_BINDING_ADOPTION_PATH {
            verify_storage_binding_adoption(&key, &signature, &body, &deployment, now)?
                .expected
                .binding_id
        } else if path == STORAGE_FROZEN_CLEANUP_CUSTODY_PATH {
            verify_storage_frozen_cleanup_custody(&key, &signature, &body, &deployment, now)?
                .snapshot
                .binding_id
        } else if path == STORAGE_FROZEN_DELETE_CUSTODY_PATH {
            verify_storage_frozen_delete_custody(&key, &signature, &body, &deployment, now)?
                .claim
                .snapshot
                .binding_id
        } else if path == STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH {
            verify_storage_frozen_cleanup_credential_stage(
                &key,
                &signature,
                &body,
                &deployment,
                now,
            )?
            .request
            .snapshot
            .binding_id
        } else {
            anyhow::bail!("credential custody route differs")
        };
        let headers = Headers::new();
        headers.set("x-aos-storage-binding-id", &binding_id.to_string())?;
        headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        let forwarded = Request::new_with_init(&format!("https://hybrid-binding{path}"), &init)?;
        let mut response = env
            .durable_object("HYBRID_BINDING_STATE")?
            .id_from_name(&format!("{deployment}:binding:{binding_id}"))?
            .get_stub()?
            .fetch_with_request(forwarded)
            .await?;
        if path == STORAGE_BINDING_ADOPTION_PATH {
            crate::control_receipt::emit_forwarded_response(&path, &body, &mut response).await;
        }
        Ok::<_, anyhow::Error>(response)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(_) => Response::error("credential custody control refused", 409),
    }
}

/// Encodes an authenticated nonsecret reply with private cache policy.
///
/// # Errors
/// Returns an error when response headers or body cannot be constructed.
pub(crate) fn response(reply: SignedStorageCustodyControl) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &reply.signature)?;
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(reply.body)?.with_headers(headers))
}

/// Executes only while the existing binding object's exclusive gate is held.
///
/// # Errors
/// Returns a value-free refusal for changed originals, stale material or probes.
pub(crate) async fn handle(
    request: &mut Request,
    env: &Env,
    storage: &Storage,
    active: Option<StorageBindingPublication>,
    binding_id: i64,
) -> Result<Outcome> {
    ensure!(
        request.method() == Method::Post,
        "credential custody method differs"
    );
    let body = crate::hybrid::read_bounded_body(request, MAX_BINDING_CUSTODY_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("credential custody control exceeds bound"))?;
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("credential custody authentication absent"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let now = aos_hub_core::clock::now_unix_secs();
    ensure!(
        read::<i64>(storage, "credential-custody/clock/v1")
            .await?
            .is_none_or(|floor| now >= floor),
        "credential custody clock regressed"
    );
    let key = key(env)?;
    match request.url()?.path() {
        STORAGE_CREDENTIAL_CUSTODY_PATH => {
            let staged =
                verify_storage_credential_custody_stage(&key, &signature, &body, &deployment, now)?;
            let original = staged.request.clone();
            ensure!(
                original.snapshot.binding_id == binding_id,
                "credential custody address differs"
            );
            let material_not_after = staged.material_not_after;
            let record_key = credential_key(&original.snapshot, &original.snapshot.credentials[0])?;
            ensure!(
                !read::<bool>(
                    storage,
                    &format!(
                        "credential-custody/revoked/v1/{}",
                        hex::encode(Sha256::digest(&record_key))
                    )
                )
                .await?
                .unwrap_or(false),
                "credential custody revision explicitly revoked"
            );
            let purpose = &original.snapshot.credentials[0].purpose;
            let head_key = format!("credential-custody/head/v1/{purpose}");
            if let Some(prior_key) = read::<String>(storage, &head_key).await? {
                let prior: HeldCredential = read(storage, &prior_key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("credential custody head lost original"))?;
                prior.accept_replacement(&original)?;
            }
            let existing: Option<HeldCredential> = read(storage, &record_key).await?;
            match existing {
                Some(mut old) if old.original.operation_id == original.operation_id => {
                    original.matches_original(&old.original)?;
                    old.expire(now);
                    write(storage, &record_key, &old).await?;
                    ensure!(
                        !old.revoked
                            && old
                                .material
                                .as_ref()
                                .is_some_and(|material| material.selector
                                    == staged.material.selector
                                    && material.value_base64 == staged.material.value_base64)
                            && material_not_after <= old.material_not_after,
                        "credential custody staging retry changed or expired original"
                    );
                }
                old => {
                    if let Some(mut old) = old {
                        old.accept_replacement(&original)?;
                        old.material = None;
                        write(
                            storage,
                            &format!(
                                "credential-custody/history/v1/{}",
                                hex::encode(Sha256::digest(&old.original.operation_id))
                            ),
                            &old,
                        )
                        .await?;
                    }
                    write(storage, &record_key, &HeldCredential::new(staged)).await?;
                }
            }
            write(storage, &head_key, &record_key).await?;
            write(storage, "credential-custody/clock/v1", &now).await?;
            original.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
            Ok(Outcome::Reply(sign_storage_credential_custody_stage_reply(
                &key,
                &StorageCredentialCustodyStageReply {
                    request: original,
                    material_not_after,
                    stage_body_sha256: hex::encode(Sha256::digest(&body)),
                },
            )?))
        }
        STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH => {
            let challenge =
                verify_storage_credential_custody_probe(&key, &signature, &body, &deployment, now)?;
            ensure!(
                challenge.snapshot.binding_id == binding_id,
                "credential custody address differs"
            );
            let record_key =
                current_key(storage, &challenge.snapshot.credentials[0].purpose).await?;
            let mut held: HeldCredential = read(storage, &record_key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("credential custody original absent"))?;
            if held.expire(now) {
                write(storage, &record_key, &held).await?;
            }
            held.require_probe(&challenge, now)?;
            let evidence = if let Some(evidence) = &held.positive {
                evidence.clone()
            } else {
                let purpose = &challenge.snapshot.credentials[0].purpose;
                ensure!(
                    !held.pending || matches!(purpose.as_str(), "read" | "list" | "presign"),
                    "credential custody mutating probe remains unknown"
                );
                held.pending = true;
                write(storage, &record_key, &held).await?;
                write(storage, "credential-custody/clock/v1", &now).await?;
                let publication = held.publication(challenge.snapshot.clone(), now)?;
                let reference = &challenge.snapshot.credentials[0];
                let secret = publication.credential_text(
                    &aos_hub_core::storage_work::StorageCredentialSelector {
                        purpose: reference.purpose.clone(),
                        generation: reference.generation,
                    },
                    &deployment,
                    now,
                )?;
                let surface = S3Surface::from_snapshot(
                    &challenge.snapshot,
                    &deployment,
                    "",
                    Some(&secret),
                    now,
                )?;
                // The retained pending original precedes actual provider Fetch.
                // Failed mutating probes remain unknown, independently of time.
                let measured = super::probe::execute(&surface, &challenge).await?;
                challenge.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
                held.pending = false;
                held.positive = Some(measured.clone());
                write(storage, &record_key, &held).await?;
                measured
            };
            let observed_at = aos_hub_core::clock::now_unix_secs();
            challenge.validate(&deployment, observed_at)?;
            write(storage, "credential-custody/clock/v1", &observed_at).await?;
            Ok(Outcome::Reply(sign_storage_credential_custody_probe_reply(
                &key,
                &StorageCredentialCustodyProbeReply {
                    request: challenge,
                    evidence,
                    observed_at,
                },
            )?))
        }
        STORAGE_BINDING_ADOPTION_PATH => {
            let challenge =
                verify_storage_binding_adoption(&key, &signature, &body, &deployment, now)?;
            ensure!(
                challenge.expected.binding_id == binding_id,
                "credential custody address differs"
            );
            let mut materials = Vec::new();
            for reference in &challenge.expected.credentials {
                let record_key = current_key(storage, &reference.purpose).await?;
                let mut held: HeldCredential =
                    read(storage, &record_key).await?.ok_or_else(|| {
                        anyhow::anyhow!("credential custody adoption original absent")
                    })?;
                if held.expire(now) {
                    write(storage, &record_key, &held).await?;
                }
                held.renew_validated(&challenge.expected, now)?;
                let material = held
                    .material
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("credential custody material absent"))?;
                materials.push(aos_hub_core::storage_work::StorageCredentialMaterial {
                    selector: material.selector.clone(),
                    value_base64: material.value_base64.clone(),
                });
                write(storage, &record_key, &held).await?;
            }
            write(storage, "credential-custody/clock/v1", &now).await?;
            let snapshot = match active {
                Some(publication)
                    if publication.snapshot.expires_at > now.saturating_add(60)
                        && same_snapshot_original(&publication.snapshot, &challenge.expected) =>
                {
                    publication.snapshot
                }
                _ => challenge.expected.clone(),
            };
            let publication = StorageBindingPublication {
                snapshot,
                materials,
            };
            publication.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
            challenge.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
            Ok(Outcome::Adoption {
                request: challenge,
                publication,
            })
        }
        STORAGE_FROZEN_CLEANUP_CUSTODY_PATH
        | STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH
        | STORAGE_FROZEN_DELETE_CUSTODY_PATH => {
            super::frozen::handle(
                request.url()?.path(),
                &body,
                &signature,
                env,
                storage,
                binding_id,
            )
            .await
        }
        _ => anyhow::bail!("credential custody route differs"),
    }
}

/// Signs the exact acknowledged durable snapshot under a still-fresh challenge.
///
/// # Errors
/// Returns an error for expired authority, unavailable signing material or encoding.
pub(crate) fn reply_adoption(
    env: &Env,
    request: StorageBindingAdoptionRequest,
    acknowledged: StorageBindingSnapshot,
) -> Result<SignedStorageCustodyControl> {
    request.validate(
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        aos_hub_core::clock::now_unix_secs(),
    )?;
    sign_storage_binding_adoption_reply(
        &key(env)?,
        &StorageBindingAdoptionReply {
            request,
            acknowledged,
        },
    )
    .map_err(Into::into)
}

/// Permanently revokes exact material revisions while retaining original journals.
///
/// # Errors
/// Returns an error when exact revision identities or durable writes fail.
pub(crate) async fn revoke_material(
    storage: &Storage,
    snapshot: &StorageBindingSnapshot,
) -> Result<()> {
    for reference in &snapshot.credentials {
        let key = credential_key(snapshot, reference)?;
        write(
            storage,
            &format!(
                "credential-custody/revoked/v1/{}",
                hex::encode(Sha256::digest(&key))
            ),
            &true,
        )
        .await?;
        if let Some(mut held) = read::<HeldCredential>(storage, &key).await? {
            held.revoke();
            write(storage, &key, &held).await?;
        }
    }
    Ok(())
}

fn same_snapshot_original(left: &StorageBindingSnapshot, right: &StorageBindingSnapshot) -> bool {
    let mut expected = right.clone();
    expected.issued_at = left.issued_at;
    expected.expires_at = left.expires_at;
    *left == expected
}

async fn current_key(storage: &Storage, purpose: &str) -> Result<String> {
    read(storage, &format!("credential-custody/head/v1/{purpose}"))
        .await?
        .ok_or_else(|| anyhow::anyhow!("credential custody current material missing"))
}

pub(super) fn credential_key(
    snapshot: &StorageBindingSnapshot,
    reference: &aos_hub_core::storage_work::StorageCredentialReference,
) -> Result<String> {
    Ok(format!(
        "credential-custody/material/v1/{}",
        hex::encode(Sha256::digest(serde_json::to_vec(&(
            &snapshot.deployment_id,
            snapshot.binding_id,
            &snapshot.binding_stable_id,
            snapshot.binding_resource_version,
            snapshot.binding_spec_revision()?,
            reference
        ))?))
    ))
}

fn key(env: &Env) -> Result<StorageWorkKey> {
    Ok(StorageWorkKey::new(
        env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
    )?)
}

pub(super) async fn read<T: DeserializeOwned>(storage: &Storage, key: &str) -> Result<Option<T>> {
    storage
        .get::<String>(key)
        .await?
        .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

pub(super) async fn write<T: Serialize>(storage: &Storage, key: &str, value: &T) -> Result<()> {
    let raw = serde_json::to_string(value)?;
    ensure!(
        raw.len() <= MAX_BINDING_CUSTODY_BYTES,
        "credential custody retained record exceeds bound"
    );
    storage.put(key, raw).await?;
    Ok(())
}
