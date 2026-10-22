//! Exercises actual journal RPC durability across Workerd process restarts.
//!
//! This endpoint exists only in `do-e2e` builds. It uses synthetic originals and
//! never dispatches a provider effect or qualifies a production storage profile.

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::*;
use serde::Deserialize;
use worker::{Env, Request, Response};

use super::{call, journal::Effect, journal::PartRecord, Operation, Reply};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    key: String,
    action: Action,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Seed,
    AfterRestart,
    FinishedAfterRestart,
}

/// Exercises one retained journal phase through the production storage RPC.
///
/// # Errors
///
/// Returns an error if the fixture response cannot be constructed.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match exercise(&mut request, env).await {
        Ok(()) => Response::ok("ok"),
        Err(error) => Response::error(format!("direct journal fixture refused: {error:#}"), 409),
    }
}

async fn exercise(request: &mut Request, env: &Env) -> Result<()> {
    let probe: Probe = request.json().await?;
    ensure!(
        probe.key.starts_with(".aos-direct-guard-fixture/") && valid_direct_path(&probe.key),
        "direct journal fixture key differs"
    );
    let original = crate::direct_guard::fixture::reservation(
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        &probe.key,
    );
    let admission = &original.admission;
    let effect = Effect::new("ab".repeat(32), &"journal fixture effect", false)?;
    let nonce = "cd".repeat(32);
    let terminal = serde_json::json!({"fixture": "acknowledged"});

    match probe.action {
        Action::Seed => {
            ensure!(
                matches!(
                    call(env, admission, Operation::Admit).await?,
                    Reply::Acknowledged
                ),
                "direct journal admission was not retained"
            );
            ensure!(
                matches!(
                    call(
                        env,
                        admission,
                        Operation::Begin {
                            effect: effect.clone(),
                            nonce: nonce.clone(),
                        }
                    )
                    .await?,
                    Reply::Begin { terminal: None }
                ),
                "direct journal attempt did not begin"
            );
            let now = u64::try_from(aos_hub_model::clock::now_unix_secs())?;
            let part = PartRecord {
                session: original.complete.session.clone(),
                placement: original.complete.manifests[0].placement.clone(),
                grant_id: "ef".repeat(32),
                grant_revision: WireInteger::new(1),
                part: DirectPart {
                    part_number: 1,
                    offset: WireInteger::new(0),
                    byte_size: WireInteger::new(1),
                    sha256: admission.intent.expected_sha256.clone(),
                    checksum: DirectPartChecksum {
                        algorithm: DirectChecksumAlgorithm::Md5,
                        value: "ndTkYSaMgDT1yFZOFVxnpg==".into(),
                    },
                },
                issued_at: WireInteger::new(now),
                expires_at: WireInteger::new(now + 60),
                observed: None,
            };
            call(env, admission, Operation::Register { part: part.clone() }).await?;
            let report = DirectPartReport {
                session: part.session,
                placement: part.placement,
                operation_id: "12".repeat(32),
                grant_id: part.grant_id,
                grant_revision: part.grant_revision,
                observed: DirectManifestPart {
                    part: part.part,
                    etag: "\"fixture-etag\"".into(),
                },
            };
            call(
                env,
                admission,
                Operation::Report {
                    report: report.clone(),
                },
            )
            .await?;
            call(
                env,
                admission,
                Operation::Freeze {
                    complete: original.complete.clone(),
                },
            )
            .await?;
            ensure!(
                call(env, admission, Operation::Report { report })
                    .await
                    .is_err(),
                "direct journal accepted a report after its original Complete"
            );
        }
        Action::AfterRestart => {
            let Reply::Effect {
                effect: Some(retained),
            } = call(
                env,
                admission,
                Operation::ReadEffect {
                    operation_id: effect.operation_id.clone(),
                },
            )
            .await?
            else {
                anyhow::bail!("direct journal lost pending attempt on restart");
            };
            ensure!(
                retained.pending_attempt.as_deref() == Some(nonce.as_str())
                    && retained.attempt_count == 1
                    && retained.terminal.is_none(),
                "direct journal pending attempt changed"
            );
            ensure!(
                call(
                    env,
                    admission,
                    Operation::Begin {
                        effect: effect.clone(),
                        nonce: "34".repeat(32),
                    }
                )
                .await
                .is_err(),
                "direct journal redispatched an unknown mutation"
            );

            let mut changed = admission.clone();
            // Keep the same addressed business original while changing its bytes.
            changed.intent.expected_sha256 = "78".repeat(32);
            changed.logical_fingerprint =
                changed.fingerprint(&env.var("HUB_DEPLOYMENT_ID")?.to_string())?;
            ensure!(
                call(env, &changed, Operation::Admit).await.is_err(),
                "direct journal replaced its original admission"
            );

            call(
                env,
                admission,
                Operation::Finish {
                    operation_id: effect.operation_id.clone(),
                    nonce,
                    terminal: terminal.clone(),
                },
            )
            .await?;
        }
        Action::FinishedAfterRestart => {
            let Reply::Effect {
                effect: Some(retained),
            } = call(
                env,
                admission,
                Operation::ReadEffect {
                    operation_id: effect.operation_id.clone(),
                },
            )
            .await?
            else {
                anyhow::bail!("direct journal lost terminal receipt on restart");
            };
            ensure!(
                retained.pending_attempt.is_none()
                    && retained.attempt_count == 1
                    && retained.terminal.as_ref() == Some(&terminal),
                "direct journal terminal receipt changed"
            );
            let Reply::Begin { terminal: replayed } = call(
                env,
                admission,
                Operation::Begin {
                    effect,
                    nonce: "90".repeat(32),
                },
            )
            .await?
            else {
                anyhow::bail!("direct journal terminal replay differs");
            };
            ensure!(
                replayed == Some(terminal),
                "direct journal terminal replay changed"
            );
        }
    }

    let Reply::Original {
        admission: retained,
        complete,
    } = call(env, admission, Operation::ReadOriginal).await?
    else {
        anyhow::bail!("direct journal original lookup differs");
    };
    ensure!(
        retained == *admission && complete.as_ref() == Some(&original.complete),
        "direct journal original or frozen Complete changed"
    );
    let Reply::Parts { parts } = call(
        env,
        admission,
        Operation::PartPage {
            placement_id: WireInteger::new(1),
            after: 0,
            maximum: 1,
        },
    )
    .await?
    else {
        anyhow::bail!("direct journal part lookup differs");
    };
    ensure!(
        parts.len() == 1
            && parts[0].observed.as_ref().map(|part| part.etag.as_str())
                == Some("\"fixture-etag\""),
        "direct journal lost acknowledged part or changed its report"
    );
    Ok(())
}
