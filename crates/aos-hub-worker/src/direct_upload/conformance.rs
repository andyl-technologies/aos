//! Hosted ordinary R2 SDK qualification probe with durable unknown-effect fences.
//!
//! The operator supplies a fresh run identity and exact expected private bucket
//! coordinates. Scoped credentials remain protected Worker secrets. Native SDK
//! controls and direct S3 UploadPart interoperability are measured on the actual
//! binding; this probe rejects local/test builds. Its observations are inputs to
//! independent acceptance, and never enable production dispatch by themselves.
//!
//! ```text
//! start -> durable SDK Create -> exact direct UploadPart URL
//! operator checksum rejection + positive PUT -> finish
//! finish -> SDK Complete + streamed identity/hash + range/copy + Abort probes
//! cleanup -> only acknowledged, exactly retained objects; unknowns stay fenced
//! ```

use std::future::Future;

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response, State};

use super::{journal, managed, storage};

pub(crate) const PATH: &str = "/_internal/storage/direct-upload-sdk-conformance";
const HEADER: &str = "x-aos-direct-sdk-probe-signature";
const DOMAIN: &[u8] = b"aos.direct-upload.hosted-sdk-probe.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeRequest {
    version: u32,
    run_id: String,
    phase: String,
    account_id: String,
    bucket_name: String,
    expires_at: WireInteger,
    part_etag: Option<String>,
    checksum_rejection_sha256: Option<String>,
}

type ProbeOriginal = DirectHostedSdkProbeOriginal;
type ProbeDocument = DirectHostedSdkProbeDocument;

#[derive(Serialize, Deserialize)]
struct ProbeFailure {
    step: String,
    cause: String,
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match route(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("hosted SDK probe unavailable or fenced", 409),
    }
}

async fn route(request: &mut Request, env: &Env) -> Result<Response> {
    let (bytes, original, signature) = authenticate(request, env).await?;
    let name = address(env, &original.run_id)?;
    let headers = Headers::new();
    headers.set(HEADER, &signature)?;
    let colo = request
        .cf()
        .map(|cf| cf.colo())
        .filter(|colo| colo.len() == 3 && colo.bytes().all(|byte| byte.is_ascii_uppercase()))
        .ok_or_else(|| anyhow::anyhow!("actual hosted Cloudflare edge metadata absent"))?;
    headers.set("x-aos-direct-sdk-edge-colo", &colo)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from(js_sys::Uint8Array::from(
            bytes.as_slice(),
        ))));
    let stub = env
        .durable_object(storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?;
    Ok(stub
        .fetch_with_request(Request::new_with_init(
            "https://direct-sdk-probe/conformance",
            &init,
        )?)
        .await?)
}

/// Executes ordinary SDK operations inside one durable protected probe owner.
///
/// The caller holds the journal's serialization gate. SDK responses are retained
/// before the fence clears; eviction or a lost reply never repeats unknown Create.
pub(crate) async fn physical(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    let mut inspection_only = false;
    match run(request, env, state, &mut inspection_only).await {
        Ok(value) => Response::from_json(&value),
        Err(error) => {
            let storage = state.storage();
            let step = if inspection_only {
                "status".into()
            } else {
                storage::read::<String>(&storage, "probe/active-step/v1")
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "authentication_or_original".into())
            };
            let failure = ProbeFailure {
                step,
                cause: failure_cause(&error).into(),
            };
            // Diagnostics contain only closed local classifications. Provider
            // exceptions, object keys, URLs and credentials never enter this log.
            if !inspection_only {
                let _ = storage::write(&storage, "probe/last-failure/v1", &failure).await;
            }
            Ok(Response::from_json(&serde_json::json!({
                "version": 1, "state": "refused_or_unknown", "failure": failure
            }))?
            .with_status(409))
        }
    }
}

async fn run(
    request: &mut Request,
    env: &Env,
    state: &State,
    inspection_only: &mut bool,
) -> Result<serde_json::Value> {
    let (_, probe, _) = authenticate(request, env).await?;
    *inspection_only = probe.phase == "status";
    ensure!(
        env.durable_object(storage::BINDING)?
            .id_from_name(&address(env, &probe.run_id)?)?
            .to_string()
            == state.id().to_string(),
        "SDK probe original address differs"
    );
    let storage = state.storage();
    let script_version = current_script_version(env)?;
    let original = if let Some(original) =
        storage::read::<ProbeOriginal>(&storage, "probe/original/v1").await?
    {
        ensure!(
            journal::sdk_probe_original_allows(
                &original,
                &probe.run_id,
                &probe.account_id,
                &probe.bucket_name,
                &script_version,
                &probe.phase
            ),
            "SDK probe original or deployed script changed"
        );
        original
    } else {
        ensure!(probe.phase == "start", "SDK probe original absent");
        // The outer request retains actual hosted edge identity before the DO hop.
        let colo = request
            .headers()
            .get("x-aos-direct-sdk-edge-colo")?
            .filter(|colo| colo.len() == 3 && colo.bytes().all(|byte| byte.is_ascii_uppercase()))
            .ok_or_else(|| anyhow::anyhow!("actual hosted edge evidence absent"))?;
        let original = ProbeOriginal {
            run_id: probe.run_id.clone(),
            account_id: probe.account_id.clone(),
            bucket_name: probe.bucket_name.clone(),
            script_version: script_version.clone(),
            colo,
        };
        storage::write(&storage, "probe/original/v1", &original).await?;
        original
    };
    if probe.phase == "status" {
        let failure = storage::read::<ProbeFailure>(&storage, "probe/last-failure/v1").await?;
        let mut effects = Vec::new();
        for operation in [
            "create-source",
            "complete-source",
            "create-copy",
            "copy-part",
            "complete-copy",
            "create-abort",
            "ordinary-upload-part",
            "abort",
            "late-part-complete",
            "late-part-abort",
            "delete-source",
            "delete-copy",
        ] {
            let terminal = storage::read::<(String, serde_json::Value)>(
                &storage,
                &format!("probe/effect/v1/{operation}"),
            )
            .await?;
            let pending =
                storage::read::<String>(&storage, &format!("probe/pending/v1/{operation}")).await?;
            let state = if let Some((_, value)) = &terminal {
                if value.as_str().is_some_and(|outcome| {
                    outcome.starts_with("unknown") || outcome.starts_with("positive_unexpected")
                }) {
                    "unknown_or_unexpected"
                } else {
                    "acknowledgement_retained"
                }
            } else if pending.is_some() {
                "unknown"
            } else {
                "not_dispatched"
            };
            let terminal_digest = terminal
                .as_ref()
                .map(|value| journal::digest(value))
                .transpose()?;
            effects.push(serde_json::json!({"operation":operation,"state":state,"terminalSha256":terminal_digest}));
        }
        return Ok(
            serde_json::json!({"version":1,"inspectionOnly":true,"original":original,"currentScriptVersion":script_version,"effects":effects,"failure":failure}),
        );
    }
    managed::probe(env)?;
    let prefix = format!(".aos-direct-qualification/{}", probe.run_id);
    let source_key = format!("{prefix}/source");
    let copy_key = format!("{prefix}/copy");
    let abort_key = format!("{prefix}/abort");
    let payload = payload();
    let part = part(&payload)?;
    let intent = intent(&probe.run_id, &part);
    let create: managed::CreateReceipt = effect(
        &storage,
        probe.expires_at.get(),
        "create-source",
        &original,
        || {
            managed::create_checked(env, &source_key, false, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    let upload_id = create
        .upload_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SDK probe Create acknowledgement invalid"))?;
    if probe.phase == "start" {
        let signed = sign_part(env, &original, &source_key, upload_id, &part)?;
        return Ok(
            serde_json::json!({"version":1,"runId":probe.run_id,"scriptVersion":original.script_version,"part":part,"url":signed.url,"requiredHeaders":signed.required_headers,"method":"PUT"}),
        );
    }
    if probe.phase == "cleanup" {
        let document: ProbeDocument = storage::read(&storage, "probe/document/v1")
            .await?
            .ok_or_else(|| anyhow::anyhow!("SDK probe positive document absent"))?;
        ensure!(
            document.late_part_after_complete == "negative"
                && document.late_part_after_abort == "negative",
            "SDK probe unknown effect blocks cleanup"
        );
        for (key, expected, name) in [
            (&source_key, &document.source, "delete-source"),
            (&copy_key, &document.destination, "delete-copy"),
        ] {
            effect(&storage, probe.expires_at.get(), name, expected, || async {
                ensure!(
                    managed::head(env, key).await?.as_ref() == Some(expected),
                    "SDK probe cleanup original incarnation changed"
                );
                managed::invoke_await_checked(
                    &managed::bucket(env)?,
                    "delete",
                    &[JsValue::from_str(key)],
                    || probe_dispatch_time(probe.expires_at.get()),
                )
                .await?;
                Ok(true)
            })
            .await?;
        }
        return Ok(serde_json::json!({"version":1,"runId":probe.run_id,"cleanupState":"positive"}));
    }
    ensure!(probe.phase == "finish", "SDK probe phase invalid");
    let etag = probe
        .part_etag
        .clone()
        .filter(|etag| valid_direct_etag(etag))
        .ok_or_else(|| anyhow::anyhow!("SDK probe direct part acknowledgement absent"))?;
    let reported = vec![DirectManifestPart {
        part: part.clone(),
        etag,
    }];
    let source: managed::ObjectReceipt = effect(
        &storage,
        probe.expires_at.get(),
        "complete-source",
        &reported,
        || {
            managed::complete_checked(env, &source_key, upload_id, &reported, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    active_step(&storage, "source-head").await?;
    ensure!(
        managed::head(env, &source_key).await?.as_ref() == Some(&source),
        "SDK probe HEAD acknowledgement differs"
    );
    active_step(&storage, "source-verify").await?;
    managed::verify(env, &source_key, &source, &intent, &reported).await?;
    let destination_create: managed::CreateReceipt = effect(
        &storage,
        probe.expires_at.get(),
        "create-copy",
        &original,
        || {
            managed::create_checked(env, &copy_key, false, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    let destination_upload = destination_create
        .upload_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SDK probe destination Create absent"))?;
    let copied: DirectManifestPart = effect(
        &storage,
        probe.expires_at.get(),
        "copy-part",
        &source,
        || {
            managed::copy_part_checked(
                env,
                &source_key,
                &source,
                &copy_key,
                destination_upload,
                &intent,
                &part,
                || probe_dispatch_time(probe.expires_at.get()),
            )
        },
    )
    .await?;
    let copied_parts = [copied.clone()];
    let destination: managed::ObjectReceipt = effect(
        &storage,
        probe.expires_at.get(),
        "complete-copy",
        &copied,
        || {
            managed::complete_checked(env, &copy_key, destination_upload, &copied_parts, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    ensure!(
        destination.version != source.version,
        "SDK probe object version not unique"
    );
    active_step(&storage, "copy-verify").await?;
    managed::verify(env, &copy_key, &destination, &intent, &[copied]).await?;
    let abort_create: managed::CreateReceipt = effect(
        &storage,
        probe.expires_at.get(),
        "create-abort",
        &original,
        || {
            managed::create_checked(env, &abort_key, false, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    let abort_upload = abort_create
        .upload_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SDK probe Abort Create absent"))?;
    let _: String = effect(
        &storage,
        probe.expires_at.get(),
        "ordinary-upload-part",
        &part,
        || {
            managed::upload_probe_part_checked(env, &abort_key, abort_upload, 1, &payload, || {
                probe_dispatch_time(probe.expires_at.get())
            })
        },
    )
    .await?;
    effect(
        &storage,
        probe.expires_at.get(),
        "abort",
        abort_upload,
        || async {
            managed::abort_checked(env, &abort_key, abort_upload, || {
                probe_dispatch_time(probe.expires_at.get())
            })
            .await?;
            Ok(true)
        },
    )
    .await?;
    let after_complete: String = effect(
        &storage,
        probe.expires_at.get(),
        "late-part-complete",
        &source,
        || {
            rejection(
                env,
                &source_key,
                upload_id,
                &payload,
                probe.expires_at.get(),
            )
        },
    )
    .await?;
    let after_abort: String = effect(
        &storage,
        probe.expires_at.get(),
        "late-part-abort",
        abort_upload,
        || {
            rejection(
                env,
                &abort_key,
                abort_upload,
                &payload,
                probe.expires_at.get(),
            )
        },
    )
    .await?;
    // Rehash the same acknowledged source after the negative late mutation.
    active_step(&storage, "source-rehash").await?;
    managed::verify(env, &source_key, &source, &intent, &reported).await?;
    let document = ProbeDocument {
        version: 1,
        source_kind: "hosted_ordinary_r2_binding".into(),
        workers_rs_version: "0.8.5".into(),
        source_digest: option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .filter(|digest| valid_direct_digest(digest))
            .ok_or_else(|| anyhow::anyhow!("hermetic Worker source identity missing"))?
            .into(),
        original,
        expected_sha256: part.sha256,
        expected_byte_size: part.byte_size,
        source,
        destination,
        ordinary_create: "positive".into(),
        ordinary_complete: "positive".into(),
        ordinary_head: "positive".into(),
        ordinary_get_streamed_sha_size: "positive".into(),
        ordinary_range_streamed_sha_size: "positive".into(),
        ordinary_upload_part_streamed_copy: "positive".into(),
        ordinary_abort: "positive".into(),
        upload_part_checksum_algorithm: DirectChecksumAlgorithm::Md5,
        late_part_after_complete: after_complete,
        late_part_after_abort: after_abort,
        direct_s3_checksum_rejection_sha256: probe
            .checksum_rejection_sha256
            .filter(|digest| valid_direct_digest(digest))
            .ok_or_else(|| anyhow::anyhow!("SDK probe external checksum observation absent"))?,
        cleanup_state: "retained_known_objects".into(),
    };
    storage::write(&storage, "probe/document/v1", &document).await?;
    Ok(serde_json::to_value(document)?)
}

async fn authenticate(request: &mut Request, env: &Env) -> Result<(Vec<u8>, ProbeRequest, String)> {
    ensure!(
        !cfg!(feature = "do-e2e"),
        "emulated SDK probe cannot produce hosted qualification"
    );
    ensure!(
        env.var("HUB_DIRECT_UPLOAD_CONFORMANCE_ENABLED")?
            .to_string()
            == "true",
        "hosted SDK probe not enabled"
    );
    ensure!(request.method() == Method::Post, "SDK probe method invalid");
    let signature = request
        .headers()
        .get(HEADER)?
        .ok_or_else(|| anyhow::anyhow!("SDK probe authentication absent"))?;
    let body = crate::hybrid::read_bounded_body(request, 4096)
        .await?
        .ok_or_else(|| anyhow::anyhow!("SDK probe request exceeds bound"))?;
    key(env)?.verify_body(&signature, &[DOMAIN, &body].concat())?;
    let probe: ProbeRequest = decode_direct_control(&body)?;
    ensure!(
        matches!(
            probe.phase.as_str(),
            "start" | "finish" | "cleanup" | "status"
        ),
        "SDK probe phase unsupported"
    );
    ensure!(
        encode_direct_control(&probe)? == body
            && probe.version == 1
            && valid_direct_digest(&probe.run_id)
            && probe.account_id == env.var("HUB_DIRECT_UPLOAD_R2_ACCOUNT_ID")?.to_string()
            && probe.bucket_name == env.var("HUB_DIRECT_UPLOAD_R2_BUCKET_NAME")?.to_string(),
        "SDK probe coordinates differ"
    );
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    ensure!(
        now < probe.expires_at.get() && probe.expires_at.get() <= now.saturating_add(30),
        "SDK probe transport expired"
    );
    Ok((body, probe, signature))
}

fn key(env: &Env) -> Result<StorageWorkKey> {
    Ok(StorageWorkKey::new(
        env.secret("HUB_DIRECT_UPLOAD_CONFORMANCE_KEY")?.to_string(),
    )?)
}

fn current_script_version(env: &Env) -> Result<String> {
    let version = js_sys::Reflect::get(env, &JsValue::from_str("CF_VERSION_METADATA"))
        .map_err(|_| anyhow::anyhow!("hosted script metadata unavailable"))?;
    js_sys::Reflect::get(&version, &JsValue::from_str("id"))
        .map_err(|_| anyhow::anyhow!("hosted script metadata unavailable"))?
        .as_string()
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| anyhow::anyhow!("hosted script version absent"))
}

fn address(env: &Env, run_id: &str) -> Result<String> {
    Ok(format!(
        "direct-sdk-probe:{}:{run_id}",
        env.var("HUB_DEPLOYMENT_ID")?
    ))
}

async fn effect<T, F, Fut>(
    storage: &worker::Storage,
    expires_at: u64,
    operation: &str,
    original: &impl Serialize,
    dispatch: F,
) -> Result<T>
where
    T: Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    active_step(storage, operation).await?;
    let key = format!("probe/effect/v1/{operation}");
    let intent = journal::digest(original)?;
    if let Some((retained, terminal)) =
        storage::read::<(String, serde_json::Value)>(storage, &key).await?
    {
        ensure!(retained == intent, "SDK probe original effect changed");
        return serde_json::from_value(terminal)
            .map_err(|_| anyhow::anyhow!("SDK probe terminal receipt malformed"));
    }
    let fence = format!("probe/pending/v1/{operation}");
    ensure!(
        storage::read::<String>(storage, &fence).await?.is_none(),
        "SDK probe effect outcome unknown"
    );
    probe_dispatch_time(expires_at)?;
    storage::write(storage, &fence, &intent).await?;
    probe_dispatch_time(expires_at)?;
    let result = dispatch().await?;
    storage::write(storage, &key, &(intent, serde_json::to_value(&result)?)).await?;
    Ok(result)
}

async fn active_step(storage: &worker::Storage, operation: &str) -> Result<()> {
    storage::write(storage, "probe/active-step/v1", &operation).await
}

fn failure_cause(error: &anyhow::Error) -> &'static str {
    let causes = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    for (marker, classification) in [
        (
            "native digest constructor",
            "native_digest_constructor_failed",
        ),
        ("native BYOB reader", "native_byob_reader_unavailable"),
        ("native BYOB read", "native_byob_read_failed"),
        ("native stage", "native_stream_contract_failed"),
        ("native R2 SDK", "sdk_dispatch_or_acknowledgement_unknown"),
        ("outcome unknown", "retained_unknown_effect"),
        ("mutation cutoff", "original_deadline_elapsed"),
        ("HEAD acknowledgement", "source_incarnation_mismatch"),
        ("digest differs", "source_integrity_mismatch"),
    ] {
        if causes.iter().any(|cause| cause.contains(marker)) {
            return classification;
        }
    }
    "original_or_runtime_contract_refused"
}

async fn rejection(
    env: &Env,
    key: &str,
    upload_id: &str,
    bytes: &[u8],
    expires_at: u64,
) -> Result<String> {
    // Promise rejection without a positively identified provider refusal remains
    // unknown. The SDK helper redacts diagnostics; the direct driver separately
    // records actual S3 NoSuchUpload responses before acceptance.
    Ok(
        managed::rejected_closed_part_checked(env, key, upload_id, bytes, || {
            probe_dispatch_time(expires_at)
        })
        .await?
        .into(),
    )
}

fn payload() -> Vec<u8> {
    (0..32768)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect()
}

fn part(bytes: &[u8]) -> Result<DirectPart> {
    use md5::{Digest as _, Md5};
    Ok(DirectPart {
        part_number: 1,
        offset: WireInteger::new(0),
        byte_size: WireInteger::new(bytes.len() as u64),
        sha256: hex::encode(Sha256::digest(bytes)),
        checksum: DirectPartChecksum {
            algorithm: DirectChecksumAlgorithm::Md5,
            value: base64::engine::general_purpose::STANDARD.encode(Md5::digest(bytes)),
        },
    })
}

fn intent(run_id: &str, part: &DirectPart) -> DirectUploadIntent {
    DirectUploadIntent {
        version: 1,
        client_operation_id: run_id.into(),
        target: DirectUploadTarget::CacheObject {
            cache_id: "sdk-qualification".into(),
            path: "content".into(),
        },
        expected_sha256: part.sha256.clone(),
        byte_size: part.byte_size,
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    }
}

fn sign_part(
    env: &Env,
    original: &ProbeOriginal,
    key: &str,
    upload_id: &str,
    part: &DirectPart,
) -> Result<aos_hub_core::sigv4::DirectSignedProviderRequest> {
    let access = env
        .secret("HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID")?
        .to_string();
    let secret = env
        .secret("HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY")?
        .to_string();
    let host = format!("{}.r2.cloudflarestorage.com", original.account_id);
    let path = format!("/{}/{key}", original.bucket_name);
    let date = aos_hub_core::sigv4::amz_date_from_unix(aos_hub_core::clock::now_unix_secs());
    aos_hub_core::sigv4::presign_direct_upload_part(
        &aos_hub_core::sigv4::PresignParams {
            access_key: &access,
            secret_key: &secret,
            region: "auto",
            service: "s3",
            scheme: "https",
            host: &host,
            path: &path,
            expires_secs: 30,
            amz_date: &date,
        },
        upload_id,
        part,
        30,
    )
}

fn probe_dispatch_time(expires_at: u64) -> Result<()> {
    ensure!(
        u64::try_from(aos_hub_core::clock::now_unix_secs())? < expires_at,
        "SDK probe original mutation cutoff elapsed"
    );
    Ok(())
}
