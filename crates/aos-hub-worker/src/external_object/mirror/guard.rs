//! Independently authenticated, metadata-only final External mirror lookup.
//!
//! This role reads the held full original, its immutable Complete receipt and
//! actual full-stream verification. It never loads producer permission, calls
//! the provider, reconstructs an absent receipt or clears an unknown owner.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    mirror_guard::{batch::*, *},
    mirror_work::{MirrorOriginal, MirrorProgress, digest},
};
use worker::{Env, Headers, Request, Response};

use super::super::{
    config::configured,
    storage::{BINDING, ExternalObjectGuard},
};
use crate::mirror_import::guard_proof;

pub(crate) fn address(env: &Env, original: &MirrorOriginal) -> Result<String> {
    original.validate()?;
    let selected = original
        .external_destination
        .as_ref()
        .context("External mirror original absent")?;
    let object = configured(env)?.context("External object guard disabled")?;
    object
        .scope(
            &selected.protected_profile.profile.write_cohort,
            original.destination_key(),
        )?
        .guard_name()
}

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn mirror_guard_fetch(
        &self,
        request: &mut Request,
        batch: bool,
        candidate: bool,
    ) -> worker::Result<Response> {
        let operation = async {
            // The independent guard role verifies the complete original again
            // inside the addressed physical object, before waiting on its key.
            ensure!(
                !candidate,
                "External mirror cannot borrow Managed candidate guard"
            );
            if batch {
                let index = request
                    .headers()
                    .get(guard_proof::batch::ITEM_INDEX_HEADER)?
                    .context("mirror final selected index absent")?;
                let selected = index.parse::<usize>()?;
                ensure!(
                    index == selected.to_string(),
                    "mirror final index is noncanonical"
                );
                let (lookup, _, _) =
                    guard_proof::batch::authenticate(request, &self.env, candidate).await?;
                let item = lookup
                    .items
                    .get(selected)
                    .context("mirror final selected item absent")?;
                self.check_address(&item.original).await?;
                let gate = loop {
                    lookup.validate(&lookup.deployment_id, guard_proof::latest_now(&self.env)?)?;
                    if let Some(gate) = self.gate.try_lock_owned() {
                        break gate;
                    }
                    worker::Delay::from(Duration::from_millis(50)).await;
                };
                let retained = self.retained_mirror_final(&item.original).await;
                let observed_at = guard_proof::latest_now(&self.env)?;
                lookup.validate(&lookup.deployment_id, observed_at)?;
                let result = match retained {
                    Ok(progress) if progress == item.expected => MirrorGuardBatchResult::Positive {
                        original_digest: digest(&item.original)?,
                        progress,
                        observed_at,
                    },
                    _ => MirrorGuardBatchResult::Refused {
                        original_digest: digest(&item.original)?,
                        refusal: MirrorGuardBatchRefusal::Unavailable,
                    },
                };
                let observation = MirrorGuardBatchObservation {
                    version: 1,
                    request_digest: digest(&lookup)?,
                    request_nonce: lookup.request_nonce.clone(),
                    issuer: guard_proof::issuer(&self.env)?,
                    item_index: selected,
                    result,
                    observed_at,
                };
                let signed = sign_mirror_guard_batch_observation(
                    &guard_proof::key(&self.env)?,
                    &observation,
                    &lookup,
                )?;
                drop(gate);
                response(signed)
            } else {
                let (lookup, _, _) =
                    guard_proof::authenticate(request, &self.env, candidate).await?;
                self.check_address(&lookup.original).await?;
                let gate = loop {
                    lookup.validate(&lookup.deployment_id, guard_proof::latest_now(&self.env)?)?;
                    if let Some(gate) = self.gate.try_lock_owned() {
                        break gate;
                    }
                    worker::Delay::from(Duration::from_millis(50)).await;
                };
                let progress = self.retained_mirror_final(&lookup.original).await?;
                ensure!(
                    progress == lookup.expected,
                    "mirror final guard retained different full progress"
                );
                let observed_at = guard_proof::latest_now(&self.env)?;
                lookup.validate(&lookup.deployment_id, observed_at)?;
                let reply = MirrorGuardReply {
                    version: 1,
                    request_digest: digest(&lookup)?,
                    request_nonce: lookup.request_nonce.clone(),
                    original_digest: digest(&lookup.original)?,
                    issuer: guard_proof::issuer(&self.env)?,
                    progress,
                    observed_at,
                };
                let signed =
                    sign_mirror_guard_reply(&guard_proof::key(&self.env)?, &reply, &lookup)?;
                drop(gate);
                response(signed)
            }
        }
        .await;
        match operation {
            Ok(response) => Ok(response),
            Err(_) => Response::error("External mirror final guard unavailable or unsettled", 409),
        }
    }

    async fn check_address(&self, original: &MirrorOriginal) -> Result<()> {
        let name = address(&self.env, original)?;
        ensure!(
            self.env
                .durable_object(BINDING)?
                .id_from_name(&name)?
                .to_string()
                == self.state.id().to_string(),
            "mirror final challenge addressed another physical guard"
        );
        Ok(())
    }

    async fn retained_mirror_final(&self, original: &MirrorOriginal) -> Result<MirrorProgress> {
        let object = configured(&self.env)?.context("External object guard disabled")?;
        let (_, session) =
            super::storage::current(&self.state.storage(), &object, original, true).await?;
        ensure!(
            session.original == *original
                && session.progress.destination.is_some()
                && session.progress.destination_closure == session.closed,
            "mirror final guard lacks actual verified completion"
        );
        session.progress.commit_digest(original)?;
        Ok(session.progress)
    }
}

fn response(signed: SignedMirrorGuardControl) -> Result<Response> {
    let headers = Headers::new();
    headers.set(MIRROR_GUARD_SIGNATURE_HEADER, &signed.signature)?;
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(signed.body)?.with_headers(headers))
}
