//! OCI-specific controls and streamed multipart staging on the existing guard.
//!
//! The application role authenticates Native's exact OCI original. A distinct
//! physical role authenticates the same original twice across DO dispatch.
//! Positive replay is metadata-only; unknown effects never redispatch.

use std::{rc::Rc, time::Duration};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::OciSha256State,
    storage_authority::{
        external_object::oci::{
            control::{
                ExternalOciRequest, OciControl, EXTERNAL_OCI_SIGNATURE_HEADER,
                MAX_EXTERNAL_OCI_CONTROL_BYTES,
            },
            reply::{EXTERNAL_OCI_RECEIPT_HEADER, MAX_EXTERNAL_OCI_REPLY_BYTES},
            OciBytes, OciObjectOriginal, EXTERNAL_OCI_PART_BYTES,
        },
        lease::LeaseEffect,
    },
    storage_work::StorageWorkKey,
};
use base64::Engine as _;
use md5::Digest as _;
use rand::TryRngCore as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::super::{
    config::configured,
    protocol::{digest, SCOPE_HEADER},
    storage::{ExternalObjectGuard, BINDING},
};
use super::{
    config,
    provider::Provider,
    state::{Effect, Phase, Receipt},
    storage::Journal,
};
use crate::oci_projection::lifetime::{Owner, Scope};

const PHYSICAL_PATH: &str = "/oci-turn";
const CONTROL_HEADER: &str = "x-aos-external-oci-control";
const GUARD_SIGNATURE: &str = "x-aos-external-oci-guard-signature";
const PHYSICAL_DOMAIN: &[u8] = b"aos.external-oci-physical-request.v1\0";

fn application_key(env: &Env) -> Result<StorageWorkKey> {
    Ok(StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?)
}

fn latest(object: &super::super::config::Config) -> Result<i64> {
    let clock = object.clock();
    clock
        .observed_at
        .checked_add(clock.uncertainty)
        .context("external OCI clock overflow")
}

fn current(work: &ExternalOciRequest, object: &super::super::config::Config) -> Result<()> {
    work.validate(&work.original.deployment_id, latest(object)?)
}

/// Relays only an authenticated OCI chunk original and its bounded raw stream.
///
/// The public upload handler obtains this control from Native before consuming
/// bytes. No client-supplied header can create it. Raw bodies remain at Worker.
///
/// # Errors
/// Refuses an invalid original, application signature or physical reply.
pub(crate) async fn stage(
    env: &Env,
    body: worker::web_sys::ReadableStream,
    control: &[u8],
    signature: &str,
) -> Result<aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply> {
    let object = configured(env)?.context("external object consumer disabled")?;
    let work = ExternalOciRequest::authenticate(
        &application_key(env)?,
        signature,
        control,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        latest(&object)?,
    )?;
    ensure!(
        matches!(work.operation, OciControl::Stage),
        "OCI body requires staging original"
    );
    Ok(relay(env, &object, &work, control, signature, Some(body))
        .await?
        .1)
}

/// Executes a closed signed control, with no provider body in the request.
///
/// # Errors
/// Refuses unsupported controls, authentication failures or unmatched receipts.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        ensure!(
            request.method() == Method::Post,
            "external OCI control method refused"
        );
        let signature = request
            .headers()
            .get(EXTERNAL_OCI_SIGNATURE_HEADER)?
            .context("external OCI application signature absent")?;
        let bytes = crate::hybrid::read_bounded_body(&mut request, MAX_EXTERNAL_OCI_CONTROL_BYTES)
            .await?
            .context("external OCI control oversized")?;
        let object = configured(env)?.context("external object consumer disabled")?;
        let work = ExternalOciRequest::authenticate(
            &application_key(env)?,
            &signature,
            &bytes,
            &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
            latest(&object)?,
        )?;
        ensure!(
            !matches!(work.operation, OciControl::Stage),
            "staging requires a separate body"
        );
        relay(env, &object, &work, &bytes, &signature, None).await
    }
    .await;
    match result {
        Ok(reply) => signed_response(env, &reply.0, &reply.1),
        Err(_) => Response::error("external OCI control refused", 409),
    }
}

async fn relay(
    env: &Env,
    object: &super::super::config::Config,
    work: &ExternalOciRequest,
    bytes: &[u8],
    application_signature: &str,
    body: Option<worker::web_sys::ReadableStream>,
) -> Result<(
    ExternalOciRequest,
    aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply,
)> {
    let guard = super::super::storage::key(env)?;
    let name = work.original.scope.guard_name()?;
    let headers = Headers::new();
    headers.set(
        CONTROL_HEADER,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    )?;
    headers.set(EXTERNAL_OCI_SIGNATURE_HEADER, application_signature)?;
    headers.set(
        GUARD_SIGNATURE,
        &guard.sign_body(&[PHYSICAL_DOMAIN, bytes].concat())?,
    )?;
    headers.set(SCOPE_HEADER, &name)?;
    headers.set("cache-control", "private, no-store")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    if let Some(body) = body {
        init.with_body(Some(body.into()));
    }
    let request = Request::new_with_init(&format!("https://guard.invalid{PHYSICAL_PATH}"), &init)?;
    current(work, object)?;
    let namespace = env.durable_object(BINDING)?;
    let response = namespace
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request)
        .await?;
    current(work, object)?;
    ensure!(
        response.status_code() == 200,
        "physical OCI control refused"
    );
    let signature = response
        .headers()
        .get(EXTERNAL_OCI_RECEIPT_HEADER)?
        .context("external OCI physical reply signature absent")?;
    let bytes = crate::hybrid::read_bounded_response(response, MAX_EXTERNAL_OCI_REPLY_BYTES)
        .await?
        .context("external OCI physical reply oversized")?;
    current(work, object)?;
    let reply = aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply::authenticate(
        work, &guard, &signature, &bytes,
    )?;
    Ok((work.clone(), reply))
}

fn signed_response(
    env: &Env,
    work: &ExternalOciRequest,
    reply: &aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply,
) -> worker::Result<Response> {
    let (bytes, signature) = reply
        .sign(
            work,
            &super::super::storage::key(env).map_err(super::super::storage::error)?,
        )
        .map_err(super::super::storage::error)?;
    let headers = Headers::new();
    headers.set(EXTERNAL_OCI_RECEIPT_HEADER, &signature)?;
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn oci_fetch(
        &self,
        request: &mut Request,
    ) -> worker::Result<Response> {
        match self.oci_handle(request).await {
            Ok((work, reply)) => signed_response(&self.env, &work, &reply),
            Err(_) => Response::error("external OCI physical turn refused", 409),
        }
    }

    async fn oci_handle(
        &self,
        request: &mut Request,
    ) -> Result<(
        ExternalOciRequest,
        aos_hub_core::storage_authority::external_object::oci::reply::ExternalOciReply,
    )> {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == PHYSICAL_PATH,
            "external OCI physical route refused"
        );
        // Take cancellation ownership before any guard storage or capacity
        // wait. Metadata replay and unknown effects never consume the body.
        let incoming_owner = Owner::new(());
        let _incoming_scope = Scope(Rc::clone(&incoming_owner));
        let incoming_reader = request.inner().body()
            .map(|stream| crate::direct_digest::Reader::new(stream.into()))
            .transpose()?.map(|reader| incoming_owner.attach(reader)).transpose()?;

        let encoded = request
            .headers()
            .get(CONTROL_HEADER)?
            .context("OCI control absent")?;
        ensure!(
            encoded.len() <= MAX_EXTERNAL_OCI_CONTROL_BYTES * 4 / 3 + 4,
            "OCI physical control oversized"
        );
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
        let guard = super::super::storage::key(&self.env)?;
        guard.verify_body(
            &request
                .headers()
                .get(GUARD_SIGNATURE)?
                .context("OCI guard signature absent")?,
            &[PHYSICAL_DOMAIN, &bytes].concat(),
        )?;
        let object = configured(&self.env)?.context("external object consumer disabled")?;
        let work = ExternalOciRequest::authenticate(
            &application_key(&self.env)?,
            &request
                .headers()
                .get(EXTERNAL_OCI_SIGNATURE_HEADER)?
                .context("OCI application signature absent")?,
            &bytes,
            &self.env.var("HUB_DEPLOYMENT_ID")?.to_string(),
            latest(&object)?,
        )?;
        let name = work.original.scope.guard_name()?;
        ensure!(
            work.original.scope.guard_namespace_id == object.guard_namespace_id
                && request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                && self
                    .env
                    .durable_object(BINDING)?
                    .id_from_name(&name)?
                    .to_string()
                    == self.state.id().to_string(),
            "OCI request addressed to another physical guard"
        );
        let gate = loop {
            current(&work, &object)?;
            if let Some(gate) = self.gate.try_lock_owned() {
                break gate;
            }
            worker::Delay::from(Duration::from_millis(50)).await;
        };
        current(&work, &object)?;
        let config = config::configured(&self.env, &object)?;
        config.profile(&work.original)?;
        if matches!(work.operation, OciControl::RecoverOriginal) {
            let retained = Journal::recover(&self.state.storage(), &work.original).await?;
            current(&work, &object)?;
            let reply = if let Some(retained) = retained {
                retained.reply(&work)?
            } else {
                // No locator proves neither settlement nor provider absence.
                // Stage separately requires fresh Native authority and an
                // atomic retained-original/owner reservation before dispatch.
                let declared = super::state::Session::declare(work.original.clone(), config.digest()?)?;
                let mut reply = declared.reply(&work)?;
                reply.retained_original = None;
                reply
            };
            return Ok((work, reply));
        }
        let retained = Journal::lookup(&self.state.storage(), &work.original).await?;
        current(&work, &object)?;
        if let Some(session) = retained {
            if matches!(work.operation, OciControl::Status)
                || session.phase == Phase::Closed
                || session.pending.is_some()
            {
                // Unknown remains explicitly held; a historical positive never
                // obtains a new lease or causes a new provider dispatch.
                return Ok((work.clone(), session.reply(&work)?));
            }
        } else {
            ensure!(
                !matches!(work.operation, OciControl::Status),
                "OCI original is not retained"
            );
        }
        // Qualification precedes ownership changes. Metadata-only historical
        // status above remains readable without granting a new producer effect.
        let profile = config.profile(&work.original)?;
        let accepted = config::require(&self.env, &object, profile,
            &work.original.writer.placement_prefix).await?;
        current(&work, &object)?;
        accepted.current(&object)?;
        crate::direct_guard::deny_legacy(&self.state.storage()).await?;
        let mut journal = Journal::open(self.state.storage(), &object, &config, &work).await?;
        if let OciControl::InstallSources { first, sources } = &work.operation {
            journal.install_sources(*first, sources).await?;
            current(&work, &object)?;
            accepted.current(&object)?;
            return Ok((work.clone(), journal.session.reply(&work)?));
        }
        accepted.current(&object)?;
        let publication = crate::hybrid_binding::resolve_for_delivery(
            &self.env,
            work.original.writer.binding_id.get(),
            work.original.writer.binding_resource_version.get(),
        )
        .await?;
        let buffer = crate::mirror_import::buffers::acquire(false, || {
            current(&work, &object)?;
            accepted.current(&object)
        })
        .await?;
        let owner = Owner::new((gate, buffer));
        let _scope = Scope(Rc::clone(&owner));
        let provider = Provider {
            state: &self.state,
            object: &object,
            profile,
            work: &work,
            accepted: &accepted,
            publication,
        };
        provider.current()?;
        match work.operation {
            OciControl::Stage => {
                let reader = incoming_reader.context("OCI staging stream absent")?;
                stage_body(
                    &self.env,
                    &provider,
                    &mut journal,
                    reader,
                    Rc::clone(&owner),
                )
                .await?;
            }
            OciControl::Compose { maximum_parts } => {
                super::compose::advance(&self.env, &provider, &mut journal,
                    maximum_parts, Rc::clone(&owner)).await?;
            }
            _ => anyhow::bail!("OCI phase requires a separate readback adapter"),
        }
        provider.current()?;
        Ok((work.clone(), journal.session.reply(&work)?))
    }
}

pub(super) async fn effect<R: 'static>(
    env: &Env,
    provider: &Provider<'_>,
    journal: &mut Journal,
    effect: Effect,
    body: Option<&[u8]>,
    parts: &[aos_hub_core::surface_write::PartTag],
    owner: Rc<Owner<R>>,
) -> Result<()> {
    provider.current()?;
    let token = super::super::stage::acquire_configured_lease(
        env,
        provider.object,
        &provider.profile.issuer_installation,
        &provider.profile.write_cohort,
        &provider.profile.write_cohort.admitted_prefix,
    )
    .await?;
    provider.current()?;
    let allowed = match effect {
        Effect::Create => LeaseEffect::MultipartCreate,
        Effect::EmptyPut { .. } => LeaseEffect::Put,
        Effect::Part { .. } => LeaseEffect::MultipartPart,
        Effect::Complete { .. } => LeaseEffect::MultipartComplete,
        Effect::Abort => LeaseEffect::MultipartAbort,
    };
    let validated = provider.object.verifier()?.validate_lease(
        token.as_bytes(),
        &provider.profile.write_cohort,
        &provider.object.timing_profile,
        &journal.head.floor,
        &journal.session.original.scope.full_key,
        allowed,
        provider.object.clock(),
    )?;
    journal.retain_floor(validated.next_floor).await?;
    provider.current()?;
    let mut random = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| anyhow::anyhow!("OCI dispatch randomness unavailable"))?;
    journal.begin(effect, hex::encode(random)).await?;
    let object = provider.object.clone();
    let cohort = provider.profile.write_cohort.clone();
    let floor = journal.head.floor.clone();
    let key = journal.session.original.scope.full_key.clone();
    let before = Rc::new(move || {
        object.verifier()?.validate_lease(
            token.as_bytes(),
            &cohort,
            &object.timing_profile,
            &floor,
            &key,
            allowed,
            object.clock(),
        )?;
        Ok(())
    });
    let positive = provider
        .mutation(&journal.session, body, parts, owner, before)
        .await?;
    // Only an exact positive SDK receipt clears the original pending attempt.
    let receipt = Receipt {
        original_digest: journal.session.original.fingerprint()?,
        pending: journal
            .session
            .pending
            .clone()
            .context("OCI pending effect lost")?,
        positive,
    };
    journal.acknowledge(receipt).await
}

async fn stage_body<R: 'static>(
    env: &Env,
    provider: &Provider<'_>,
    journal: &mut Journal,
    reader: Rc<crate::direct_digest::Reader>,
    owner: Rc<Owner<R>>,
) -> Result<()> {
    ensure!(
        matches!(
            journal.session.original.object,
            OciObjectOriginal::Chunk { .. }
        ),
        "raw staging body is not a chunk original"
    );
    if journal.session.phase == Phase::Declared {
        effect(
            env,
            provider,
            journal,
            Effect::Create,
            None,
            &[],
            Rc::clone(&owner),
        )
        .await?;
    }
    let mut chunk_hash = OciSha256State::initial();
    let mut upload_hash = match &journal.session.original.object {
        OciObjectOriginal::Chunk { prior_sha256, .. } => prior_sha256.clone(),
        _ => anyhow::bail!("raw OCI source differs"),
    };
    let maximum = match &journal.session.original.object {
        OciObjectOriginal::Chunk { maximum_bytes, .. } => *maximum_bytes,
        _ => 0,
    };
    let mut part = Vec::with_capacity(EXTERNAL_OCI_PART_BYTES as usize);
    let mut number = 1;
    loop {
        let (view, done) = provider.bounded(reader.read()).await?;
        ensure!(
            chunk_hash
                .total_bytes
                .checked_add(view.length() as u64)
                .is_some_and(|total| total <= maximum),
            "OCI source exceeds original allowance"
        );
        let bytes = view.to_vec();
        for slice in bytes.chunks(EXTERNAL_OCI_PART_BYTES as usize) {
            let mut remaining = slice;
            while !remaining.is_empty() {
                let count = remaining
                    .len()
                    .min(EXTERNAL_OCI_PART_BYTES as usize - part.len());
                let selected = &remaining[..count];
                part.extend_from_slice(selected);
                chunk_hash.update(selected)?;
                upload_hash.update(selected)?;
                remaining = &remaining[count..];
                if part.len() == EXTERNAL_OCI_PART_BYTES as usize {
                    stage_part(
                        env,
                        provider,
                        journal,
                        number,
                        &part,
                        &chunk_hash,
                        &upload_hash,
                        Rc::clone(&owner),
                    )
                    .await?;
                    number += 1;
                    part.clear();
                }
            }
        }
        if done {
            break;
        }
    }
    if !part.is_empty() {
        stage_part(
            env,
            provider,
            journal,
            number,
            &part,
            &chunk_hash,
            &upload_hash,
            Rc::clone(&owner),
        )
        .await?;
    }
    let bytes = OciBytes {
        sha256: chunk_hash.final_digest()?.encoded(),
        size: chunk_hash.total_bytes,
    };
    journal.seal_source(&bytes).await?;
    let parts = journal.parts().await?;
    let complete = Effect::Complete {
        bytes,
        parts_digest: digest(&parts)?,
    };
    effect(env, provider, journal, complete, None, &parts, owner).await
}

async fn stage_part<R: 'static>(
    env: &Env,
    provider: &Provider<'_>,
    journal: &mut Journal,
    number: u32,
    part: &[u8],
    chunk_hash: &OciSha256State,
    upload_hash: &OciSha256State,
    owner: Rc<Owner<R>>,
) -> Result<()> {
    let bytes = OciBytes {
        sha256: aos_oci_types::Sha256Digest::digest(part).encoded(),
        size: part.len() as u64,
    };
    if number < journal.session.next_part {
        let retained = journal.part(number).await?;
        ensure!(
            retained.bytes == bytes,
            "OCI replayed source differs from positive part"
        );
        provider.current()?;
        return Ok(());
    }
    let checksum_md5 = base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(part));
    effect(
        env,
        provider,
        journal,
        Effect::Part {
            part_number: number,
            bytes,
            checksum_md5,
            next_sha256: chunk_hash.clone(),
            next_upload_sha256: upload_hash.clone(),
        next_source_cursor: None,
        },
        Some(part),
        &[],
        owner,
    )
    .await
}
