//! Test-provider fault turns on actual permanent physical-object SQLite storage.
//!
//! The fixture exists only in `do-e2e` builds. Separate requests and process
//! restarts reuse the production reservation and effect transitions. The fake
//! provider records dispatch count before failing, and its explicit positive
//! callback settles only the retained original attempt.

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Headers, Method, Request, RequestInit, Response, State};

use super::{
    fixture, runtime,
    state::{authenticate_native_commit, Reservation},
    transport::OWNER,
};
use crate::direct_upload::journal::Effect;

pub(crate) const PATH: &str = "/_e2e/direct-guard";
const EFFECT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct Probe {
    key: String,
    action: Action,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Seed,
    Unknown,
    AfterRestart,
    ProviderAcknowledged,
    LostNativeAcknowledgement,
    NativeAcknowledged,
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        ensure!(
            request.method() == Method::Post,
            "direct fixture method differs"
        );
        let body = crate::hybrid::read_bounded_body(&mut request, 4096)
            .await?
            .ok_or_else(|| anyhow::anyhow!("direct fixture message exceeds bound"))?;
        let probe: Probe = serde_json::from_slice(&body)?;
        ensure!(
            probe.key.starts_with(".aos-direct-guard-fixture/") && valid_direct_path(&probe.key),
            "direct fixture key differs"
        );
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let address = format!("{deployment}:{}", hex::encode(Sha256::digest(&probe.key)));
        let headers = Headers::new();
        headers.set("x-aos-hybrid-object-key", &probe.key)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        Ok::<_, anyhow::Error>(
            env.durable_object("HYBRID_OBJECT_GUARD")?
                .id_from_name(&address)?
                .get_stub()?
                .fetch_with_request(Request::new_with_init(
                    &format!("https://physical-guard{PATH}"),
                    &init,
                )?)
                .await?,
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(_) => Response::error("direct fixture refused", 409),
    }
}

pub(crate) async fn physical_fetch(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    match exercise(request, env, state).await {
        Ok(value) => Response::from_json(&value),
        Err(error) => Response::error(format!("direct fixture refused: {error:#}"), 409),
    }
}

async fn exercise(request: &mut Request, env: &Env, state: &State) -> Result<serde_json::Value> {
    let probe: Probe = request.json().await?;
    let original = fixture::reservation(&env.var("HUB_DEPLOYMENT_ID")?.to_string(), &probe.key);
    original.validate()?;
    let storage = state.storage();
    let expected = Effect::new(
        EFFECT_ID.into(),
        &(&original.binding, &original.source),
        false,
    )?;
    match probe.action {
        Action::Seed => {
            if let Some(retained) = runtime::read::<Reservation>(&storage, OWNER).await? {
                retained.validate_original(&original)?;
            } else {
                runtime::write(&storage, OWNER, &original).await?;
            }
            ensure!(
                runtime::deny_legacy(&storage).await.is_err(),
                "direct fixture legacy guard did not retain reservation"
            );
            let mut changed = fixture::changed_complete(&original);
            ensure!(
                original.validate_original(&changed).is_err(),
                "direct fixture changed Complete accepted"
            );
            changed = original.clone();
            changed.source.incarnation = DirectObjectIncarnation::ProviderVersion {
                version: "changed-source".into(),
            };
            ensure!(
                original.validate_original(&changed).is_err(),
                "direct fixture changed incarnation accepted"
            );
        }
        Action::Unknown => {
            let result: Result<serde_json::Value> = runtime::effect(
                &storage,
                EFFECT_ID.into(),
                &(&original.binding, &original.source),
                || async {
                    let count = runtime::read::<u32>(&storage, "fixture-provider/dispatch-count")
                        .await?
                        .unwrap_or(0);
                    runtime::write(&storage, "fixture-provider/dispatch-count", &(count + 1))
                        .await?;
                    anyhow::bail!("test provider effect outcome unknown")
                },
            )
            .await;
            ensure!(
                result.is_err(),
                "direct fixture unknown provider effect unexpectedly succeeded"
            );
        }
        Action::AfterRestart => {
            let pending: Effect = runtime::read(&storage, "direct-guard/pending/v1")
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct fixture lost unknown effect on restart"))?;
            ensure!(
                pending.begin(&expected, &"bb".repeat(32)).is_err(),
                "direct fixture duplicate unknown attempt was admitted"
            );
            ensure!(
                runtime::read::<u32>(&storage, "fixture-provider/dispatch-count").await? == Some(1),
                "direct fixture duplicate dispatched provider again"
            );
            ensure!(
                runtime::deny_legacy(&storage).await.is_err(),
                "direct fixture restart erased physical reservation"
            );
            let owner: Reservation = runtime::read(&storage, OWNER)
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct fixture lost owner"))?;
            owner.validate_original(&original)?;
            ensure!(
                owner
                    .validate_original(&fixture::changed_complete(&original))
                    .is_err(),
                "direct fixture restart accepted changed Complete"
            );
            let mut replacement_source = original.clone();
            replacement_source.source.incarnation = DirectObjectIncarnation::ProviderVersion {
                version: "changed-after-restart".into(),
            };
            ensure!(
                owner.validate_original(&replacement_source).is_err(),
                "direct fixture restart accepted changed source incarnation"
            );
            ensure!(
                owner.final_record.is_none() && !owner.native_committed,
                "direct fixture timeout manufactured settlement"
            );
        }
        Action::ProviderAcknowledged => {
            let pending: Effect = runtime::read(&storage, "direct-guard/pending/v1")
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("direct fixture original provider attempt absent")
                })?;
            let nonce = pending
                .pending_attempt
                .clone()
                .ok_or_else(|| anyhow::anyhow!("direct fixture dispatch nonce absent"))?;
            let record = fixture::final_record(&original);
            let terminal = serde_json::to_value(&record)?;
            runtime::write(
                &storage,
                &format!("direct-guard/effect/v1/{EFFECT_ID}"),
                &pending.finish(&nonce, terminal)?,
            )
            .await?;
            let replay: DirectFinalGuardRecord = runtime::effect(
                &storage,
                EFFECT_ID.into(),
                &(&original.binding, &original.source),
                || async { anyhow::bail!("test provider replay must not redispatch") },
            )
            .await?;
            ensure!(
                replay == record
                    && runtime::read::<u32>(&storage, "fixture-provider/dispatch-count").await?
                        == Some(1),
                "direct fixture positive receipt did not replay"
            );
            let owner: Reservation = runtime::read(&storage, OWNER)
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct fixture owner absent"))?;
            runtime::write(
                &storage,
                &runtime::final_key(&owner.binding.reservation_operation_id),
                &record,
            )
            .await?;
            runtime::write(&storage, OWNER, &owner.acknowledge_publication(record)?).await?;
        }
        Action::LostNativeAcknowledgement => {
            let owner: Reservation = runtime::read(&storage, OWNER)
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct fixture owner absent"))?;
            ensure!(
                owner.final_record.as_ref() == Some(&fixture::final_record(&original))
                    && !owner.native_committed,
                "direct fixture lost acknowledgement released reservation"
            );
            ensure!(
                runtime::deny_legacy(&storage).await.is_err(),
                "direct fixture publication lost physical fence"
            );
            let mut replacement_final = fixture::final_record(&original);
            replacement_final.final_incarnation = DirectObjectIncarnation::ProviderVersion {
                version: "changed-after-publication-restart".into(),
            };
            ensure!(
                owner
                    .acknowledge_publication(replacement_final.clone())
                    .is_err()
                    && owner.acknowledge_native(&replacement_final).is_err(),
                "direct fixture restart accepted changed final incarnation"
            );
            fresh_lookup_checks(&owner)?;
        }
        Action::NativeAcknowledged => {
            let owner: Reservation = runtime::read(&storage, OWNER)
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct fixture owner absent"))?;
            let record = fixture::final_record(&owner);
            let public_body = encode_direct_control(&DirectBatch {
                operation_id: "cc".repeat(32),
                items: vec![owner.complete.clone()],
            })?;
            let context = context(
                &owner.binding.deployment_id,
                hex::encode(Sha256::digest(&public_body)),
            );
            let reply = DirectUploadLogicalReply {
                admissions: vec![owner.admission.clone()],
                session_summaries: Vec::new(),
                sessions: vec![DirectSessionStatus {
                    session: owner.complete.session.clone(),
                    resource_version: WireInteger::new(8),
                    intent: owner.admission.intent.clone(),
                    placements: owner
                        .complete
                        .manifests
                        .iter()
                        .map(|manifest| manifest.placement.clone())
                        .collect(),
                    state: DirectSessionState::Committed,
                    parts: Vec::new(),
                    next_cursor: None,
                    outstanding_grants: true,
                }],
                authorizations: Vec::new(),
                baseline_permissions: Vec::new(),
                errors: Vec::new(),
            };
            let key = StorageWorkKey::new("fixture-independent-native-key-0003")?;
            let signed = sign_direct_logical_reply(
                &key,
                &DirectLogicalReplyEnvelope {
                    context: context.clone(),
                    reply,
                },
            )?;
            let mut changed = context.clone();
            changed.request_nonce = "dd".repeat(32);
            ensure!(
                authenticate_native_commit(
                    &key,
                    &owner,
                    &record,
                    &changed,
                    &public_body,
                    &signed.body,
                    &signed.signature,
                    110
                )
                .is_err(),
                "direct fixture changed Native nonce accepted"
            );
            let committed = authenticate_native_commit(
                &key,
                &owner,
                &record,
                &context,
                &public_body,
                &signed.body,
                &signed.signature,
                110,
            )?;
            runtime::write(&storage, OWNER, &committed).await?;
            runtime::deny_legacy(&storage).await?;
        }
    }
    Ok(serde_json::json!({ "action": probe.action, "ok": true }))
}

fn fresh_lookup_checks(owner: &Reservation) -> Result<()> {
    let expected = fixture::final_record(owner);
    let key = StorageWorkKey::new("fixture-independent-guard-key-0001")?;
    let lookup = DirectFinalGuardLookup {
        admission: owner.admission.clone(),
        complete: owner.complete.clone(),
        expected: expected.clone(),
        request_nonce: "ee".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    };
    let signed = sign_direct_final_guard_reply(
        &key,
        &DirectFinalGuardReply {
            request: lookup.clone(),
            record: expected,
        },
    )?;
    verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &lookup, 110)?;
    let mut changed = lookup.clone();
    changed.request_nonce = "ff".repeat(32);
    ensure!(
        verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &changed, 110)
            .is_err(),
        "direct fixture stale nonce accepted"
    );
    let mut changed_body = signed.body;
    changed_body.push(b' ');
    ensure!(
        verify_direct_final_guard_reply(&key, &signed.signature, &changed_body, &lookup, 110)
            .is_err(),
        "direct fixture changed lookup body accepted"
    );
    Ok(())
}

fn context(deployment: &str, body_digest: String) -> DirectRequestContext {
    DirectRequestContext {
        deployment_id: deployment.into(),
        executor_public_origin: "https://fixture.example".into(),
        public_authority: "fixture.example".into(),
        foreground: DirectForegroundBudget {
            invocation_id: "ab".repeat(32),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request_nonce: "cd".repeat(32),
        request_body_sha256: body_digest,
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    }
}
