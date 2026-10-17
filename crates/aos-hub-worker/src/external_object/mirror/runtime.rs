//! Authenticated External mirror controls beneath permanent physical key gates.
//!
//! Each mutation first retains its full original and exact effect. Positive
//! replay and Native acknowledgement do not load new producer permission.
//! Unknown SDK outcomes remain fenced; no deadline releases their journal.

use std::{rc::Rc, time::Duration};

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    mirror_work::{
        MIRROR_PART_BYTES, MirrorPart, MirrorProgress, MirrorStep, digest,
        external::journal::MirrorExternalEffect,
    },
    storage_work::{StorageWorkKey, StorageWorkPlan},
};
use base64::Engine as _;
use md5::Digest as _;
use sha2::Digest as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::super::{
    config::configured,
    protocol::SCOPE_HEADER,
    storage::{BINDING, ExternalObjectGuard},
};
use super::{
    config,
    control::{
        Action, Control, MAX_CONTROL_BYTES, PHYSICAL_PATH, RECEIPT_HEADER, Reply, SIGNATURE_HEADER,
    },
    provider::{self, Provider},
    storage::Journal,
};
use crate::oci_projection::lifetime::{Owner, Scope};

pub(super) fn latest(object: &super::super::config::Config) -> Result<i64> {
    let clock = object.clock();
    clock
        .observed_at
        .checked_add(clock.uncertainty)
        .context("mirror clock overflow")
}

fn application(env: &Env) -> Result<StorageWorkKey> {
    Ok(StorageWorkKey::new(
        env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
    )?)
}

fn validate(
    env: &Env,
    object: &super::super::config::Config,
    control: &Control,
) -> Result<StorageWorkPlan> {
    control.authenticate(
        &application(env)?,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        latest(object)?,
    )
}

pub(crate) async fn dispatch(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
    item_index: Option<usize>,
) -> Result<(MirrorProgress, u64)> {
    let object = configured(env)?.context("External object consumer disabled")?;
    let control = Control::new(body, signature, item_index, Action::Execute)?;
    ensure!(
        validate(env, &object, &control)? == *plan,
        "mirror relay changed validated plan"
    );
    let reply = relay(env, &object, &control).await?;
    let (original, _) = control.selected(plan)?;
    reply.progress.validate(original)?;
    ensure!(
        reply.source_bytes <= original.verification.size(),
        "mirror source count escapes original"
    );
    Ok((reply.progress, reply.source_bytes))
}

pub(super) fn address(
    object: &super::super::config::Config,
    control: &Control,
    plan: &StorageWorkPlan,
) -> Result<String> {
    let (original, step) = control.selected(plan)?;
    let selected = original
        .external_destination
        .as_ref()
        .context("mirror External prerequisite absent")?;
    let key = if control.destination(step) {
        original.destination_key()
    } else {
        original.stage_key()
    };
    object
        .scope(&selected.protected_profile.profile.write_cohort, key)?
        .guard_name()
}

pub(super) async fn relay(
    env: &Env,
    object: &super::super::config::Config,
    control: &Control,
) -> Result<Reply> {
    let plan = validate(env, object, control)?;
    let name = address(object, control, &plan)?;
    let (body, signature) = control.sign(&super::super::storage::key(env)?)?;
    let response = env
        .durable_object(BINDING)?
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request(body, &signature, &name)?)
        .await?;
    validate(env, object, control)?;
    ensure!(
        response.status_code() == 200,
        "External mirror physical control refused"
    );
    let signature = response
        .headers()
        .get(RECEIPT_HEADER)?
        .context("mirror physical reply signature absent")?;
    let bytes = crate::hybrid::read_bounded_response(response, 256 * 1024)
        .await?
        .context("mirror physical reply exceeds bound")?;
    validate(env, object, control)?;
    let reply = Reply::verify(
        control,
        &super::super::storage::key(env)?,
        &bytes,
        &signature,
    )?;
    let (original, _) = control.selected(&plan)?;
    reply.progress.validate(original)?;
    Ok(reply)
}

pub(super) fn request(body: Vec<u8>, signature: &str, name: &str) -> Result<Request> {
    let headers = Headers::new();
    headers.set(SIGNATURE_HEADER, signature)?;
    headers.set(SCOPE_HEADER, name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    Ok(Request::new_with_init(
        &format!("https://guard.invalid{PHYSICAL_PATH}"),
        &init,
    )?)
}

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn mirror_fetch(
        &self,
        request: &mut Request,
    ) -> worker::Result<Response> {
        match self.mirror_handle(request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                worker::console_error!("external_mirror_unsettled: {error:#}");
                Response::error(
                    "External mirror original or provider effect remains unsettled",
                    409,
                )
            }
        }
    }

    async fn mirror_handle(&self, request: &mut Request) -> Result<Response> {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == PHYSICAL_PATH,
            "mirror physical route refused"
        );
        let bytes = crate::hybrid::read_bounded_body(request, MAX_CONTROL_BYTES)
            .await?
            .context("mirror physical control exceeds bound")?;
        let control = Control::verify(
            &super::super::storage::key(&self.env)?,
            &bytes,
            &request
                .headers()
                .get(SIGNATURE_HEADER)?
                .context("mirror physical MAC absent")?,
        )?;
        let object = configured(&self.env)?.context("External object consumer disabled")?;
        let plan = validate(&self.env, &object, &control)?;
        let name = address(&object, &control, &plan)?;
        ensure!(
            request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                && self
                    .env
                    .durable_object(BINDING)?
                    .id_from_name(&name)?
                    .to_string()
                    == self.state.id().to_string(),
            "mirror addressed another physical key"
        );
        let (original, step) = control.selected(&plan)?;
        let destination = control.destination(step);
        let gate = loop {
            validate(&self.env, &object, &control)?;
            if let Some(gate) = self.gate.try_lock_owned() {
                break gate;
            }
            worker::Delay::from(Duration::from_millis(50)).await;
        };
        validate(&self.env, &object, &control)?;
        let stored = Journal::lookup(&self.state.storage(), original).await?;
        if let Some(session) = &stored {
            ensure!(
                session.destination == destination,
                "mirror retained physical role differs"
            );
            ensure!(
                session.pending.is_none(),
                "mirror provider intent remains unknown"
            );
            if let Some(commit) = &session.acknowledged_commit {
                ensure!(
                    match (&control.action, step) {
                        (Action::Execute, MirrorStep::Status { .. }) => true,
                        (
                            Action::Execute | Action::StageAcknowledgement { .. },
                            MirrorStep::Acknowledge { commit_digest },
                        ) => commit == commit_digest,
                        _ => false,
                    },
                    "terminal mirror cannot issue another producer effect"
                );
                if let Action::StageAcknowledgement { progress } = &control.action {
                    ensure!(
                        session.progress == **progress,
                        "archived private mirror ACK changed evidence"
                    );
                }
                return signed(&self.env, &control, session.progress.clone(), 0);
            }
            if matches!(
                (&control.action, step),
                (Action::Execute, MirrorStep::Status { .. })
            ) {
                return signed(&self.env, &control, session.progress.clone(), 0);
            }
        } else {
            ensure!(
                matches!(step, MirrorStep::Begin | MirrorStep::BeginPromotion)
                    && control.action == Action::Execute,
                "mirror original not retained before this phase"
            );
        }
        if matches!(control.action, Action::StageAcknowledgement { .. })
            || matches!(step, MirrorStep::Acknowledge { .. })
        {
            let (head, session) =
                super::storage::current(&self.state.storage(), &object, original, destination)
                    .await?;
            let mut journal = Journal::resume(self.state.storage(), head, session);
            let progress = match &control.action {
                Action::StageAcknowledgement { progress } => progress.as_ref().clone(),
                Action::Execute => journal.session.progress.clone(),
                _ => anyhow::bail!("mirror ACK action differs"),
            };
            let MirrorStep::Acknowledge { commit_digest } = step else {
                anyhow::bail!("mirror ACK lacks commit");
            };
            journal.acknowledge_commit(&progress, commit_digest).await?;
            validate(&self.env, &object, &control)?;
            if destination {
                let mut source = control.clone();
                source.action = Action::StageAcknowledgement {
                    progress: Box::new(progress.clone()),
                };
                // The final SQL publication is already positively committed.
                // Private-stage ACK loss retains cost; it never dispatches Delete.
                let env = self.env.clone();
                let object = object.clone();
                self.state.wait_until(async move {
                    if let Err(error) = relay(&env, &object, &source).await {
                        worker::console_error!("external_mirror_private_ack_unsettled: {error:#}");
                    }
                });
            }
            return signed(&self.env, &control, progress, 0);
        }

        let config = config::configured(&self.env, &object)?;
        let domain = config.domain(original)?;
        let qualified = crate::direct_upload::config::QualifiedConfig::load(&self.env).await?;
        let profile = qualified
            .mirror_profile(&self.env, &original.protected_profile_digest)
            .await?;
        let accepted = crate::mirror_import::acceptance::require(
            &self.env,
            &profile,
            &qualified.acceptance_evidence,
            original,
        )
        .await?;
        let acceptance = accepted.external_window(&domain.commitment()?, original)?;
        validate(&self.env, &object, &control)?;
        crate::direct_guard::deny_legacy(&self.state.storage()).await?;
        let source = if destination && stored.is_none() {
            let mut source = control.clone();
            source.action = Action::SourceProgress;
            Some(relay(&self.env, &object, &source).await?.progress)
        } else {
            None
        };
        let mut journal = Journal::open(
            self.state.storage(),
            &object,
            domain,
            original,
            destination,
            acceptance,
            source,
        )
        .await?;
        let publication = crate::hybrid_binding::resolve_for_delivery(
            &self.env,
            plan.binding_id,
            plan.binding_resource_version,
        )
        .await?;
        let provider = Provider {
            env: &self.env,
            state: &self.state,
            object: &object,
            domain,
            original,
            plan: &plan,
            acceptance: &accepted,
            publication,
        };
        provider.current()?;
        let gate_owner = Owner::new(gate);
        if control.action == Action::SourceProgress {
            super::storage::current(&self.state.storage(), &object, original, false).await?;
            ensure!(
                journal.session.progress.verified.is_some(),
                "mirror source is not fully verified"
            );
            return signed(&self.env, &control, journal.session.progress, 0);
        }
        if let Action::SourceRange { part_number } = control.action {
            return super::source::stream(
                &provider,
                &mut journal,
                &control,
                part_number,
                gate_owner,
            )
            .await;
        }
        let buffer = crate::mirror_import::buffers::acquire(false, || provider.current()).await?;
        let owner = Owner::new((gate_owner, buffer));
        let _scope = Scope(Rc::clone(&owner));
        let mut source_bytes = 0;
        match step {
            MirrorStep::Begin | MirrorStep::BeginPromotion => {
                let upload = if destination {
                    &journal.session.progress.destination_upload_id
                } else {
                    &journal.session.progress.stage_upload_id
                };
                if upload.is_none() && journal.session.closed.is_none() {
                    let effect = if original.verification.size() == 0 {
                        MirrorExternalEffect::EmptyPut
                    } else {
                        MirrorExternalEffect::Create
                    };
                    provider::effect(&provider, &mut journal, effect, None, Rc::clone(&owner))
                        .await?;
                }
            }
            MirrorStep::UploadParts {
                first_part,
                maximum_parts,
            }
            | MirrorStep::CopyParts {
                first_part,
                maximum_parts,
            } => {
                ensure!(
                    destination == matches!(step, MirrorStep::CopyParts { .. }),
                    "mirror part phase selected another physical role"
                );
                let count = original.verification.size().div_ceil(MIRROR_PART_BYTES);
                for number in
                    *first_part..(*first_part + maximum_parts).min(u32::try_from(count)? + 1)
                {
                    let parts = if destination {
                        &journal.session.progress.destination_parts
                    } else {
                        &journal.session.progress.stage_parts
                    };
                    if number <= parts.len() as u32 {
                        continue;
                    }
                    ensure!(
                        number == parts.len() as u32 + 1,
                        "mirror part group skipped retained geometry"
                    );
                    let offset = u64::from(number - 1) * MIRROR_PART_BYTES;
                    let size = (original.verification.size() - offset).min(MIRROR_PART_BYTES);
                    let bytes = if destination {
                        super::source::read(
                            &provider,
                            &journal,
                            &control,
                            number,
                            size,
                            Rc::clone(&owner),
                        )
                        .await?
                    } else {
                        super::reads::upstream_part(
                            &provider,
                            &mut journal,
                            offset,
                            size,
                            Rc::clone(&owner),
                        )
                        .await?
                    };
                    let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                    if destination {
                        let source =
                            &journal.session.progress.stage_parts[usize::try_from(number - 1)?];
                        ensure!(
                            source.part_number == number
                                && source.size == size
                                && source.sha256 == sha256,
                            "mirror copy changed verified source part bytes"
                        );
                    } else {
                        source_bytes += size;
                    }
                    let checksum_md5 =
                        base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&bytes));
                    let part = MirrorPart {
                        part_number: number,
                        size,
                        sha256,
                        etag: String::new(),
                    };
                    provider::effect(
                        &provider,
                        &mut journal,
                        MirrorExternalEffect::Part { part, checksum_md5 },
                        Some(Rc::new(bytes)),
                        Rc::clone(&owner),
                    )
                    .await?;
                }
            }
            MirrorStep::CloseStage | MirrorStep::CompletePromotion => {
                ensure!(
                    destination == matches!(step, MirrorStep::CompletePromotion),
                    "mirror Complete selected another physical role"
                );
                if journal.session.closed.is_none() {
                    let (upload, parts) = if destination {
                        (
                            &journal.session.progress.destination_upload_id,
                            &journal.session.progress.destination_parts,
                        )
                    } else {
                        (
                            &journal.session.progress.stage_upload_id,
                            &journal.session.progress.stage_parts,
                        )
                    };
                    let effect = MirrorExternalEffect::Complete {
                        upload_id: upload
                            .clone()
                            .context("mirror Complete lacks positive Create")?,
                        parts_digest: digest(parts)?,
                    };
                    provider::effect(&provider, &mut journal, effect, None, Rc::clone(&owner))
                        .await?;
                }
                if destination && journal.session.progress.destination.is_none() {
                    super::reads::verify(&provider, &mut journal, Rc::clone(&owner)).await?;
                }
            }
            MirrorStep::VerifyStage => {
                ensure!(!destination, "mirror stage verification selected final key");
                if journal.session.progress.verified.is_none() {
                    super::reads::verify(&provider, &mut journal, Rc::clone(&owner)).await?;
                }
            }
            _ => anyhow::bail!("mirror physical action unsupported"),
        }
        provider.current()?;
        signed(&self.env, &control, journal.session.progress, source_bytes)
    }
}

pub(super) fn signed(
    env: &Env,
    control: &Control,
    progress: MirrorProgress,
    source_bytes: u64,
) -> Result<Response> {
    let reply = Reply {
        request_digest: digest(control)?,
        progress,
        source_bytes,
    };
    let (bytes, signature) = reply.sign(control, &super::super::storage::key(env)?)?;
    let response = Response::from_bytes(bytes)?;
    response.headers().set(RECEIPT_HEADER, &signature)?;
    response.headers().set("content-type", "application/json")?;
    response
        .headers()
        .set("cache-control", "private, no-store")?;
    Ok(response)
}
