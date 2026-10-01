//! Signed, resumable mirror effects in the existing physical-key Durable Object.
//!
//! The object retains the complete original before provider dispatch. Every
//! mutation uses the permanent legacy unknown-effect journal, and positive
//! receipts contain enough progress to recover after a crash before the next
//! progress write. Scheduler expiry never authorizes a second attempt.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_work::{
    digest, MirrorOriginal, MirrorPart, MirrorProgress, MirrorStep, MirrorVerifiedObject,
    MIRROR_PART_BYTES,
};
use aos_hub_core::storage_work::{
    StorageObjectIdentity, StorageWorkKey, StorageWorkOperation, StorageWorkPlan,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use futures_util::StreamExt as _;
use js_sys::{Array, Object, Reflect};
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{
    Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, ResponseBody,
    Storage,
};

use crate::direct_upload::{config::QualifiedConfig, managed};
use crate::hybrid_object::HybridObjectGuard;
use crate::hybrid_object_state::{Mutation, MutationKind, MutationOutcome, MutationReceipt};

const OWNER: &str = "mirror-owner";
const PROGRESS: &str = "mirror-progress";

enum Authority {
    Production {
        config: QualifiedConfig,
        acceptance: super::acceptance::AcceptedMirror,
    },
    #[cfg(feature = "do-e2e")]
    Candidate(super::candidate::CandidateMirrorAuthority),
}

impl Authority {
    async fn load(env: &Env, original: &MirrorOriginal, candidate: bool) -> Result<Self> {
        if candidate {
            #[cfg(feature = "do-e2e")]
            return Ok(Self::Candidate(super::candidate::load(env, original)?));

            #[cfg(not(feature = "do-e2e"))]
            anyhow::bail!("controlled mirror effects are absent from production");
        }
        ensure!(
            !original
                .placement_prefix
                .starts_with(".aos-mirror-qualification/"),
            "production mirror cannot authorize controlled destinations"
        );
        let config = QualifiedConfig::load(env).await?;
        let (profile, _) = config.managed(env)?;
        ensure!(
            profile.digest()? == original.protected_profile_digest,
            "mirror profile or qualification changed original"
        );
        let acceptance =
            super::acceptance::require(env, &profile, &config.acceptance_evidence, original)
                .await?;
        Ok(Self::Production { config, acceptance })
    }

    fn latest_now(&self) -> Result<u64> {
        match self {
            Self::Production { config, acceptance } => {
                let now = config.latest_now()?;
                acceptance.check(now)?;
                Ok(now)
            }
            #[cfg(feature = "do-e2e")]
            Self::Candidate(candidate) => candidate.latest_now(),
        }
    }
}

/// Reads the held final original and its exact positive provider receipt.
///
/// This read never creates or recovers an effect. Archived acknowledgements are
/// terminal replay evidence, and cannot authorize a new Native SQL commit.
pub(crate) async fn retained_final(
    guard: &HybridObjectGuard,
    key: &str,
) -> Result<(MirrorOriginal, MirrorProgress)> {
    let storage = guard.state.storage();
    let original: MirrorOriginal = storage
        .get(OWNER)
        .await?
        .context("mirror final key has no held original")?;
    let progress: MirrorProgress = storage
        .get(PROGRESS)
        .await?
        .context("mirror final owner has no positive progress")?;
    let completed = super::guard_state::expected_final_mutation(key, &original, &progress)?;
    let receipt: MutationReceipt = storage
        .get(&crate::hybrid_object::receipt_key(&completed))
        .await?
        .context("mirror final completion has no retained provider receipt")?;
    let pending: Option<Mutation> = storage.get("pending-mutation").await?;
    let legacy_delete = storage
        .get::<crate::hybrid_object_state::DeleteClaim>("pending-delete")
        .await?;
    super::guard_state::validate_retained_final(
        key,
        Some(&original),
        Some(&progress),
        Some(&receipt),
        pending.as_ref(),
        legacy_delete.as_ref(),
    )
}

pub(crate) async fn deny_other_owner(storage: &Storage) -> Result<()> {
    ensure!(
        storage.get::<MirrorOriginal>(OWNER).await?.is_none(),
        "physical key retains a mirror owner awaiting Native acknowledgement"
    );
    Ok(())
}

/// Forwards the exact Native signature and original control, never object bytes.
pub(crate) async fn dispatch(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
) -> Result<(MirrorProgress, u64)> {
    dispatch_mode(env, plan, body, signature, false).await
}

#[cfg(feature = "do-e2e")]
pub(crate) async fn dispatch_candidate(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
) -> Result<(MirrorProgress, u64)> {
    dispatch_mode(env, plan, body, signature, true).await
}

async fn dispatch_mode(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
    candidate: bool,
) -> Result<(MirrorProgress, u64)> {
    dispatch_selected(env, plan, body, signature, candidate, None).await
}

pub(crate) async fn dispatch_selected(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
    candidate: bool,
    item_index: Option<usize>,
) -> Result<(MirrorProgress, u64)> {
    let (original, step) = selected_item(plan, item_index)?;
    let destination = matches!(
        step,
        MirrorStep::Status { destination: true }
            | MirrorStep::BeginPromotion
            | MirrorStep::CopyParts { .. }
            | MirrorStep::CompletePromotion
            | MirrorStep::Acknowledge { .. }
    );
    let key = if destination {
        plan.object_key(&original.path)?
    } else {
        original.stage_key()
    };
    let path = if candidate {
        "/mirror-candidate-transfer"
    } else {
        "/mirror-transfer"
    };
    call(env, &key, path, body, signature, item_index).await
}

fn selected_item(
    plan: &StorageWorkPlan,
    index: Option<usize>,
) -> Result<(&MirrorOriginal, &MirrorStep)> {
    match (&plan.operation, index) {
        (StorageWorkOperation::MirrorTransfer { original, step }, None) => Ok((original, step)),
        (StorageWorkOperation::MirrorTransferBatch { items }, Some(index)) => {
            let item = items
                .get(index)
                .context("mirror batch item index is invalid")?;
            Ok((&item.original, &item.step))
        }
        _ => anyhow::bail!("mirror control and selected item differ"),
    }
}

async fn call(
    env: &Env,
    key: &str,
    path: &str,
    body: &[u8],
    signature: &str,
    item_index: Option<usize>,
) -> Result<(MirrorProgress, u64)> {
    let namespace = env.durable_object("HYBRID_OBJECT_GUARD")?;
    let stub = namespace
        .id_from_name(&crate::hybrid_object::guard_name(env, key)?)?
        .get_stub()?;
    let headers = Headers::new();
    headers.set("x-aos-hybrid-object-key", key)?;
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, signature)?;
    if let Some(index) = item_index {
        headers.set("x-aos-mirror-batch-item", &index.to_string())?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(std::str::from_utf8(body)?)));
    let request = Request::new_with_init(&format!("https://hybrid-object{path}"), &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "mirror guard refused the retained original or effect (status {})",
        response.status_code()
    );
    let mut bytes = Vec::new();
    let mut chunks = response.stream()?;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len() + chunk.len() <= 256 * 1024,
            "mirror guard result exceeds control bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn fetch(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
) -> worker::Result<Response> {
    match execute(guard, key, request).await {
        Ok(result) => Response::from_json(&result),
        Err(error) => {
            worker::console_error!("mirror_guard_failed: {error:#}");
            Response::error("mirror original or provider effect is not settled", 409)
        }
    }
}

async fn execute(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
) -> Result<(MirrorProgress, u64)> {
    ensure!(
        request.method() == Method::Post,
        "mirror guard requires POST"
    );
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .context("mirror signature missing")?;
    let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
        .await?
        .context("mirror control exceeds bound")?;
    let deployment = guard.env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let route = request.url()?.path().to_owned();
    let candidate = route.starts_with("/mirror-candidate-");
    let plan = if candidate {
        #[cfg(feature = "do-e2e")]
        {
            aos_hub_core::mirror_candidate::verify_mirror_candidate_plan(
                &super::candidate::key(&guard.env)?,
                &signature,
                &body,
                &deployment,
                aos_hub_core::clock::now_unix_secs(),
            )?
        }
        #[cfg(not(feature = "do-e2e"))]
        anyhow::bail!("controlled mirror effects are absent from production");
    } else {
        StorageWorkKey::new(guard.env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?.verify_plan(
            &signature,
            &body,
            &deployment,
            aos_hub_core::clock::now_unix_secs(),
        )?
    };
    let stage_ack = matches!(
        route.as_str(),
        "/mirror-stage-ack" | "/mirror-candidate-stage-ack"
    );
    let source_lookup = matches!(
        route.as_str(),
        "/mirror-source" | "/mirror-candidate-source"
    );
    let item_index = request
        .headers()
        .get("x-aos-mirror-batch-item")?
        .map(|index| index.parse::<usize>())
        .transpose()?;
    let (original, step) = selected_item(&plan, item_index)?;
    let final_key = plan.object_key(&original.path)?;
    let destination = key == final_key;
    ensure!(
        destination || key == original.stage_key(),
        "mirror guard key changed original"
    );
    let storage = guard.state.storage();
    let retained: Option<MirrorOriginal> = storage.get(OWNER).await?;
    let archived = format!("mirror-ack:{}", original.job_id);
    if destination {
        if storage
            .get::<bool>(&format!("mirror-ack-released:{}", original.job_id))
            .await?
            == Some(true)
        {
            if let Some(progress) = storage.get::<MirrorProgress>(&archived).await? {
                let archived_original = storage
                    .get::<MirrorOriginal>(&format!("mirror-ack-original:{}", original.job_id))
                    .await?
                    .context("mirror acknowledgement lacks archived original")?;
                ensure!(
                    archived_original == *original,
                    "mirror acknowledgement changed archived original"
                );
                progress.validate(original)?;
                ensure!(
                    matches!(
                        step,
                        MirrorStep::Status { .. } | MirrorStep::Acknowledge { .. }
                    ),
                    "acknowledged mirror cannot dispatch new effects"
                );
                if let MirrorStep::Acknowledge { commit_digest } = step {
                    ensure!(
                        progress.commit_digest(original)? == *commit_digest,
                        "mirror archived acknowledgement changed proof"
                    );
                }
                if retained.as_ref() == Some(original) {
                    storage.delete(OWNER).await?;
                }
                return Ok((progress, 0));
            }
        }
    }
    if !destination && stage_ack {
        if let Some(commit) = storage
            .get::<String>(&format!("mirror-stage-ack:{}", original.job_id))
            .await?
        {
            let archived_original = storage
                .get::<MirrorOriginal>(&format!("mirror-ack-original:{}", original.job_id))
                .await?
                .context("mirror stage ACK lacks original")?;
            ensure!(
                archived_original == *original
                    && matches!(step, MirrorStep::Acknowledge { commit_digest } if *commit_digest == commit),
                "mirror stage ACK changed archived original"
            );
            let progress = storage
                .get::<MirrorProgress>(&archived)
                .await?
                .context("mirror stage ACK lacks positive source proof")?;
            progress.validate(original)?;
            return Ok((progress, 0));
        }
    }
    if let Some(retained) = &retained {
        ensure!(
            retained == original,
            "physical key is owned by another mirror original"
        );
    }
    let mut progress = storage
        .get::<MirrorProgress>(PROGRESS)
        .await?
        .unwrap_or(MirrorProgress {
            original_digest: digest(original)?,
            ..Default::default()
        });
    if retained.is_none() {
        progress = MirrorProgress {
            original_digest: digest(original)?,
            ..Default::default()
        };
    }
    progress.validate(original)?;
    if source_lookup {
        ensure!(
            !destination && retained.as_ref() == Some(original),
            "mirror source is not independently retained"
        );
        return Ok((progress, 0));
    }
    if let MirrorStep::Status {
        destination: expected,
    } = step
    {
        ensure!(
            *expected == destination,
            "mirror status selected another key"
        );
        return Ok((progress, 0));
    }

    if destination {
        if let MirrorStep::Acknowledge { commit_digest } = step {
            ensure!(
                progress.commit_digest(original)? == *commit_digest,
                "Native mirror acknowledgement changed final original"
            );
            storage
                .put(
                    &format!("mirror-ack-original:{}", original.job_id),
                    original,
                )
                .await?;
            storage.put(&archived, &progress).await?;
            storage
                .put(&format!("mirror-ack-released:{}", original.job_id), true)
                .await?;
            storage.delete(OWNER).await?;
            // Final publication is settled independently of private reclamation.
            // The source owner and its full original remain durable on error.
            let cleanup_env = guard.env.clone();
            let cleanup_key = original.stage_key();
            let cleanup_body = body.clone();
            let cleanup_signature = signature.clone();
            guard.state.wait_until(async move {
                if let Err(error) = call(
                    &cleanup_env,
                    &cleanup_key,
                    if candidate {
                        "/mirror-candidate-stage-ack"
                    } else {
                        "/mirror-stage-ack"
                    },
                    &cleanup_body,
                    &cleanup_signature,
                    item_index,
                )
                .await
                {
                    worker::console_error!("mirror_private_cleanup_unsettled: {error:#}");
                }
            });
            return Ok((progress, 0));
        }
    }

    // Historical positive state and ACK above remain readable. The current
    // catalogue key contract limits only admission of new final effects.
    if !stage_ack && progress.destination.is_none() {
        ensure!(
            original.path.len() <= 512,
            "mirror final catalogue paths must fit 512 UTF-8 bytes"
        );
    }

    crate::direct_guard::deny_legacy(&storage).await?;
    let authority = Authority::load(&guard.env, original, candidate).await?;
    let current = || -> Result<()> {
        let latest = authority.latest_now()?;
        plan.validate(&deployment, i64::try_from(latest)?)?;
        Ok(())
    };
    current()?;
    if retained.is_none() {
        ensure!(
            matches!(step, MirrorStep::Begin | MirrorStep::BeginPromotion),
            "mirror original was not retained before this phase"
        );
        // Both pending effect classes must be settled before taking ownership.
        crate::hybrid_object_state::ensure_ready(
            storage.get("pending-mutation").await?.as_ref(),
            storage.get("pending-delete").await?.as_ref(),
        )?;
        storage.put(OWNER, original).await?;
        storage.put(PROGRESS, &progress).await?;
    }
    let measured = match &original.verification {
        aos_hub_core::mirror_work::MirrorVerification::Nar { nar_size, .. } => {
            original.verification.size().max(*nar_size)
        }
        _ => original.verification.size(),
    };
    let zstd = matches!(&original.verification, aos_hub_core::mirror_work::MirrorVerification::Nar { compression, .. } if compression == "zstd");
    let class =
        if !zstd && measured <= aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES {
            crate::direct_upload::provider_capacity::Class::Metadata
        } else {
            crate::direct_upload::provider_capacity::Class::Bulk
        };
    let mut source_bytes = 0;
    if stage_ack {
        let MirrorStep::Acknowledge { commit_digest } = step else {
            anyhow::bail!("private mirror cleanup requires Native ACK");
        };
        ensure!(
            !destination && retained.as_ref() == Some(original),
            "mirror cleanup source owner changed"
        );
        let verified = progress
            .verified
            .as_ref()
            .context("mirror cleanup lacks positive verified source")?;
        let effect = effect(
            key,
            original,
            "stage-delete",
            &(commit_digest, &verified.object),
        )?;
        if replay(guard, &effect).await?.is_none() {
            let head = managed::invoke_await_class_checked(
                &managed::bucket(&guard.env)?,
                "head",
                &[JsValue::from_str(key)],
                class,
                &current,
            )
            .await?;
            ensure!(
                identity(key, managed::identity(&head)?) == verified.object,
                "mirror cleanup source incarnation changed"
            );
            managed::invoke_await_class_checked(
                &managed::bucket(&guard.env)?,
                "delete",
                &[JsValue::from_str(key)],
                class,
                &current,
            )
            .await?;
            settle(guard, effect, &progress).await?;
        }
        storage
            .put(
                &format!("mirror-ack-original:{}", original.job_id),
                original,
            )
            .await?;
        storage.put(&archived, &progress).await?;
        storage
            .put(
                &format!("mirror-stage-ack:{}", original.job_id),
                commit_digest,
            )
            .await?;
        storage.delete(OWNER).await?;
        return Ok((progress, 0));
    }
    match step {
        MirrorStep::Begin => {
            ensure!(!destination, "mirror Begin requires private stage");
            if progress.stage_upload_id.is_none() && progress.stage_object.is_none() {
                let effect = effect(key, original, "stage-create", &())?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    let created = managed::create_class_checked(
                        &guard.env,
                        key,
                        original.verification.size() == 0,
                        class,
                        &current,
                    )
                    .await?;
                    progress.stage_upload_id = created.upload_id;
                    progress.stage_object = created.empty.map(|receipt| identity(key, receipt));
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::UploadParts {
            first_part,
            maximum_parts,
        } => {
            ensure!(!destination, "mirror source parts require private stage");
            let upload = progress
                .stage_upload_id
                .clone()
                .context("mirror stage Create has no positive identity")?;
            let count = original.verification.size().div_ceil(MIRROR_PART_BYTES) as u32;
            ensure!(
                *first_part <= progress.stage_parts.len() as u32 + 1,
                "mirror source part position changed"
            );
            for number in *first_part..(*first_part + maximum_parts).min(count + 1) {
                if number <= progress.stage_parts.len() as u32 {
                    continue;
                }
                let offset = u64::from(number - 1) * MIRROR_PART_BYTES;
                let size = MIRROR_PART_BYTES.min(original.verification.size() - offset);
                let _buffer = super::buffers::acquire(
                    class == crate::direct_upload::provider_capacity::Class::Metadata,
                    &current,
                )
                .await?;
                let (bytes, etag) = upstream_part(
                    original,
                    offset,
                    size,
                    progress.upstream_etag.as_deref(),
                    class,
                    &current,
                )
                .await?;
                source_bytes += size;
                if let Some(prior) = &progress.upstream_etag {
                    ensure!(
                        etag.as_ref() == Some(prior),
                        "mirror upstream incarnation changed"
                    );
                } else {
                    progress.upstream_etag = etag;
                }
                let sha256 = hex::encode(Sha256::digest(&bytes));
                current()?;
                let effect = effect(
                    key,
                    original,
                    &format!("stage-part:{number}"),
                    &(
                        upload.as_str(),
                        number,
                        size,
                        &sha256,
                        &progress.upstream_etag,
                    ),
                )?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    let etag =
                        upload_part(&guard.env, key, &upload, number, &bytes, class, &current)
                            .await?;
                    progress.stage_parts.push(MirrorPart {
                        part_number: number,
                        size,
                        sha256,
                        etag,
                    });
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::CloseStage => {
            ensure!(!destination, "mirror stage Close selected final key");
            if progress.stage_object.is_none() {
                let upload = progress
                    .stage_upload_id
                    .as_deref()
                    .context("mirror Close lacks Create receipt")?;
                ensure!(
                    progress
                        .stage_parts
                        .iter()
                        .map(|part| part.size)
                        .sum::<u64>()
                        == original.verification.size(),
                    "mirror Close manifest is incomplete"
                );
                let effect = effect(
                    key,
                    original,
                    "stage-complete",
                    &(upload, &progress.stage_parts),
                )?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    progress.stage_object = Some(
                        complete(
                            &guard.env,
                            key,
                            upload,
                            &progress.stage_parts,
                            class,
                            &current,
                        )
                        .await?,
                    );
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::VerifyStage => {
            ensure!(!destination, "mirror verification requires private stage");
            if progress.verified.is_none() {
                let _buffer = super::buffers::acquire(
                    class == crate::direct_upload::provider_capacity::Class::Metadata,
                    &current,
                )
                .await?;
                let expected = progress
                    .stage_object
                    .clone()
                    .context("mirror verification lacks positive Close")?;
                let (receipt, stream, _capacity) =
                    managed::get_class_checked(&guard.env, key, None, class, &current).await?;
                ensure!(
                    identity(key, receipt) == expected,
                    "mirror closed source incarnation changed"
                );
                let mut verifier = super::verify::Verifier::new(&original.verification)?;
                let reader = crate::direct_digest::Reader::new(stream.into())?;
                loop {
                    ensure!(
                        i64::try_from(authority.latest_now()?)?
                            <= plan.issued_at.saturating_add(10 * 60),
                        "mirror immutable verification execution exceeded its finite deadline"
                    );
                    let (view, done) = reader.read().await?;
                    source_bytes += u64::from(view.length());
                    verifier.feed(&view.to_vec())?;
                    if done {
                        break;
                    }
                }
                let (sha256, nar) = verifier.finish()?;
                progress.verified = Some(MirrorVerifiedObject {
                    object: expected,
                    sha256,
                    nar_sha256: nar.as_ref().map(|(_, sha)| sha.clone()),
                    nar_size: nar.map(|(size, _)| size),
                });
            }
        }
        MirrorStep::BeginPromotion => {
            ensure!(destination, "mirror promotion requires final key");
            if progress.verified.is_none() {
                let (source, _) = call(
                    &guard.env,
                    &original.stage_key(),
                    if candidate {
                        "/mirror-candidate-source"
                    } else {
                        "/mirror-source"
                    },
                    &body,
                    &signature,
                    item_index,
                )
                .await?;
                ensure!(
                    source.verified.is_some(),
                    "mirror source has not been independently verified"
                );
                progress = source;
            }
            if progress.destination_upload_id.is_none() && progress.destination.is_none() {
                let effect = effect(key, original, "destination-create", &progress.verified)?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    let created = managed::create_class_checked(
                        &guard.env,
                        key,
                        original.verification.size() == 0,
                        class,
                        &current,
                    )
                    .await?;
                    progress.destination_upload_id = created.upload_id;
                    if let Some(receipt) = created.empty {
                        let mut final_object = progress
                            .verified
                            .clone()
                            .context("mirror source proof missing")?;
                        final_object.object = identity(key, receipt);
                        progress.destination = Some(final_object);
                    }
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::CopyParts {
            first_part,
            maximum_parts,
        } => {
            ensure!(
                destination && *first_part <= progress.destination_parts.len() as u32 + 1,
                "mirror destination part position changed"
            );
            let upload = progress
                .destination_upload_id
                .clone()
                .context("mirror destination Create has no positive identity")?;
            let verified = progress
                .verified
                .clone()
                .context("mirror copy has no verified source")?;
            for number in *first_part
                ..(*first_part + maximum_parts).min(progress.stage_parts.len() as u32 + 1)
            {
                if number <= progress.destination_parts.len() as u32 {
                    continue;
                }
                let _buffer = super::buffers::acquire(
                    class == crate::direct_upload::provider_capacity::Class::Metadata,
                    &current,
                )
                .await?;
                let source = &progress.stage_parts[number as usize - 1];
                let (receipt, stream, capacity) = managed::get_class_checked(
                    &guard.env,
                    &original.stage_key(),
                    Some((u64::from(number - 1) * MIRROR_PART_BYTES, source.size)),
                    class,
                    &current,
                )
                .await?;
                ensure!(
                    identity(&original.stage_key(), receipt) == verified.object,
                    "mirror copy source incarnation changed"
                );
                let response = Response::from_body(ResponseBody::Stream(stream))?;
                let bytes = read_part(response, source.size).await?;
                drop(capacity);
                source_bytes += source.size;
                ensure!(
                    hex::encode(Sha256::digest(&bytes)) == source.sha256,
                    "mirror copy range changed source bytes"
                );
                current()?;
                let effect = effect(
                    key,
                    original,
                    &format!("destination-part:{number}"),
                    &(upload.as_str(), source, &verified.object),
                )?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    let etag =
                        upload_part(&guard.env, key, &upload, number, &bytes, class, &current)
                            .await?;
                    progress.destination_parts.push(MirrorPart {
                        etag,
                        ..source.clone()
                    });
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::CompletePromotion => {
            ensure!(destination, "mirror final Complete selected private key");
            if progress.destination.is_none() {
                let upload = progress
                    .destination_upload_id
                    .as_deref()
                    .context("mirror final Complete lacks Create")?;
                ensure!(
                    progress.destination_parts.len() == progress.stage_parts.len(),
                    "mirror destination manifest is incomplete"
                );
                let effect = effect(
                    key,
                    original,
                    "destination-complete",
                    &(upload, &progress.destination_parts, &progress.verified),
                )?;
                if let Some(replay) = replay(guard, &effect).await? {
                    progress = replay;
                } else {
                    let object = complete(
                        &guard.env,
                        key,
                        upload,
                        &progress.destination_parts,
                        class,
                        &current,
                    )
                    .await?;
                    let mut verified = progress
                        .verified
                        .clone()
                        .context("mirror final Complete lacks source proof")?;
                    verified.object = object;
                    progress.destination = Some(verified);
                    settle(guard, effect, &progress).await?;
                }
            }
        }
        MirrorStep::Acknowledge { .. } => {
            anyhow::bail!("private cleanup requires its exact authenticated route")
        }
        MirrorStep::Status { .. } => anyhow::bail!("mirror status did not return its observation"),
    }
    progress.validate(original)?;
    storage.put(PROGRESS, &progress).await?;
    Ok((progress, source_bytes))
}

fn effect(
    key: &str,
    original: &MirrorOriginal,
    phase: &str,
    payload: &impl serde::Serialize,
) -> Result<Mutation> {
    Mutation::new(
        key,
        &format!("{}:{phase}", original.job_id),
        MutationKind::Mirror,
        &(original, payload),
    )
}

async fn replay(guard: &HybridObjectGuard, effect: &Mutation) -> Result<Option<MirrorProgress>> {
    match guard.begin_mutation(effect).await? {
        Some(MutationOutcome::Mirror { progress }) => Ok(Some(progress)),
        None => Ok(None),
        _ => anyhow::bail!("mirror effect has incompatible positive receipt"),
    }
}

async fn settle(
    guard: &HybridObjectGuard,
    effect: Mutation,
    progress: &MirrorProgress,
) -> Result<()> {
    guard
        .finish_mutation(
            effect,
            MutationOutcome::Mirror {
                progress: progress.clone(),
            },
        )
        .await?;
    Ok(())
}

fn identity(key: &str, receipt: managed::ObjectReceipt) -> StorageObjectIdentity {
    StorageObjectIdentity {
        key: key.into(),
        size: receipt.byte_size.get(),
        etag: receipt.etag,
        provider_version: Some(receipt.version),
    }
}

async fn upload_part(
    env: &Env,
    key: &str,
    upload: &str,
    number: u32,
    bytes: &[u8],
    class: crate::direct_upload::provider_capacity::Class,
    current: impl Fn() -> Result<()>,
) -> Result<String> {
    ensure!(
        bytes.len() as u64 <= MIRROR_PART_BYTES,
        "mirror part buffer exceeds bound"
    );
    let upload = managed::resume(&managed::bucket(env)?, key, upload)?;
    let result = managed::invoke_await_class_checked(
        &upload,
        "uploadPart",
        &[
            JsValue::from(number),
            js_sys::Uint8Array::from(bytes).into(),
        ],
        class,
        current,
    )
    .await?;
    let etag = Reflect::get(&result, &JsValue::from_str("etag"))
        .map_err(|_| anyhow::anyhow!("mirror SDK part has no ETag"))?
        .as_string()
        .context("mirror SDK ETag is not text")?;
    aos_hub_core::surface_write::strong_if_match_etag(&etag)
}

async fn complete(
    env: &Env,
    key: &str,
    upload: &str,
    parts: &[MirrorPart],
    class: crate::direct_upload::provider_capacity::Class,
    current: impl Fn() -> Result<()>,
) -> Result<StorageObjectIdentity> {
    ensure!(!parts.is_empty(), "mirror Complete requires retained parts");
    let encoded = Array::new();
    for part in parts {
        let member = Object::new();
        Reflect::set(
            &member,
            &JsValue::from_str("partNumber"),
            &JsValue::from(part.part_number),
        )
        .map_err(|_| anyhow::anyhow!("mirror part encoding failed"))?;
        Reflect::set(
            &member,
            &JsValue::from_str("etag"),
            &JsValue::from_str(part.etag.trim_matches('"')),
        )
        .map_err(|_| anyhow::anyhow!("mirror ETag encoding failed"))?;
        encoded.push(&member);
    }
    let upload = managed::resume(&managed::bucket(env)?, key, upload)?;
    let receipt =
        managed::invoke_await_class_checked(&upload, "complete", &[encoded.into()], class, current)
            .await?;
    Ok(identity(key, managed::identity(&receipt)?))
}

async fn read_part(response: Response, length: u64) -> Result<Vec<u8>> {
    ensure!(
        length <= MIRROR_PART_BYTES,
        "mirror part exceeds buffer bound"
    );
    let mut bytes = Vec::with_capacity(length as usize);
    let (_, body) = response.into_parts();
    let ResponseBody::Stream(stream) = body else {
        anyhow::bail!("mirror range requires a native bounded stream");
    };
    let reader = crate::direct_digest::Reader::new(stream.into())?;
    loop {
        let (view, done) = reader.read().await?;
        ensure!(
            bytes.len() as u64 + u64::from(view.length()) <= length,
            "mirror range body exceeds original size"
        );
        bytes.extend_from_slice(&view.to_vec());
        if done {
            break;
        }
    }
    ensure!(
        bytes.len() as u64 == length,
        "mirror range body is truncated"
    );
    Ok(bytes)
}

/// Uses the repository's platform Fetch egress policy; it makes no DNS pin claim.
async fn upstream_part(
    original: &MirrorOriginal,
    offset: u64,
    length: u64,
    etag: Option<&str>,
    class: crate::direct_upload::provider_capacity::Class,
    current: impl Fn() -> Result<()>,
) -> Result<(Vec<u8>, Option<String>)> {
    let base = url::Url::parse(&format!(
        "{}/",
        original.upstream_base.trim_end_matches('/')
    ))?;
    let url = base.join(&original.path)?;
    ensure!(
        url.origin() == base.origin() && url.path().starts_with(base.path()),
        "mirror source escaped approved origin/path"
    );
    aos_hub_core::url_guard::is_safe_remote_url(url.as_str())?;
    let headers = Headers::new();
    headers.set("range", &format!("bytes={offset}-{}", offset + length - 1))?;
    headers.set("accept-encoding", "identity")?;
    if let Some(etag) = etag {
        headers.set("if-match", etag)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(url.as_str(), &init)?;
    let _capacity =
        crate::direct_upload::provider_capacity::acquire_class_checked(1, class, &current).await?;
    current()?;
    crate::direct_upload::provider_capacity::record_dispatch();
    let response = Fetch::Request(request).send().await?;
    let full = offset == 0 && length == original.verification.size();
    ensure!(
        response.status_code() == 206 || (full && response.status_code() == 200),
        "mirror upstream refused exact range or redirected"
    );
    if response.status_code() == 206 {
        ensure!(
            response.headers().get("content-range")?.as_deref()
                == Some(&format!(
                    "bytes {offset}-{}/{}",
                    offset + length - 1,
                    original.verification.size()
                )),
            "mirror upstream range changed original geometry"
        );
    }
    let etag = response
        .headers()
        .get("etag")?
        .map(|etag| aos_hub_core::surface_write::strong_if_match_etag(&etag))
        .transpose()?;
    Ok((read_part(response, length).await?, etag))
}
