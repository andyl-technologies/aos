//! Restartable Native completion work outside public control request deadlines.

use aos_hub_core::hybrid_ingress::{HybridNarinfoProjection, HybridObjectProjection};

use super::*;
use crate::direct_upload::native_targets::NativeVerifiedPlacement;

impl NativeDirectUpload {
    pub(super) async fn schedule(self: &Arc<Self>, claims: Claims, session_id: &str) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|_, task| !task.is_finished());
        if jobs.contains_key(session_id) {
            return Ok(());
        }
        ensure!(jobs.len() < 64, "Native completion queue is full");
        let runtime = Arc::clone(self);
        let session = session_id.to_owned();
        let handle = tokio::spawn(async move {
            let Ok(_permit) = Arc::clone(&runtime.verification).acquire_owned().await else {
                return;
            };
            // Read errors and expired user permissions leave known completed
            // objects restartable. A dispatched write retains a pending marker.
            let _ = runtime.advance(&claims, &session).await;
        });
        jobs.insert(session_id.to_owned(), handle);
        Ok(())
    }

    async fn advance(&self, claims: &Claims, session_id: &str) -> Result<()> {
        let record = self
            .db
            .native_direct_upload(&self.deployment, session_id)
            .await?
            .context("Native completion original absent")?;
        let state: NativeUploadState = serde_json::from_str(&record.state_json)?;
        let (mut record, mut state) = self.load(claims, &state.session).await?;
        if state.state == DirectSessionState::Committed {
            return self.cleanup(&mut record, &mut state).await;
        }
        ensure!(
            state.complete.is_some() && state.pending.is_none() && !terminal(state.state),
            "Native completion cannot resume an uncertain write"
        );
        for index in 0..state.destinations.len() {
            let pin = state.original.placements[index].clone();
            let provider = self.provider(&pin, "write").await?;
            let path = state.destinations[index].staging_path.clone();
            let parts = state.manifest(index)?;
            if state.destinations[index].staging_object.is_none() {
                self.before_write(
                    claims,
                    &mut record,
                    &mut state,
                    format!("complete-stage-{index}"),
                )
                .await?;
                let result = if state.original.intent.byte_size.get() == 0 {
                    provider
                        .empty(&path, None, aos_hub_core::clock::now_unix_secs())
                        .await
                } else {
                    let upload = state.destinations[index]
                        .staging_upload
                        .as_deref()
                        .context("Native staging upload absent")?;
                    provider
                        .complete(
                            &path,
                            upload,
                            &state.original.intent,
                            &state.destinations[index].placement,
                            &parts,
                            aos_hub_core::clock::now_unix_secs(),
                        )
                        .await
                };
                match result {
                    Ok(object) => {
                        state.destinations[index].staging_object = Some(object);
                        state.pending = None;
                    }
                    Err(error) => {
                        self.unknown(&mut record, &mut state).await?;
                        return Err(error);
                    }
                }
                self.save(&mut record, &state, Vec::new()).await?;
            }
            if !state.destinations[index].verified {
                let provider = self.provider(&pin, "read").await?;
                let object = state.destinations[index]
                    .staging_object
                    .as_ref()
                    .context("Native closed stage absent")?;
                let narinfo = matches!(&state.original.intent.target, DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo"));
                let result = provider
                    .verify(
                        &path,
                        object,
                        &state.original.intent,
                        narinfo,
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .await;
                let result = match result {
                    Ok(result) => result,
                    Err(error)
                        if error
                            .is::<crate::direct_upload::native_provider::NativeIntegrityMismatch>(
                            ) =>
                    {
                        state.integrity_failed = true;
                        self.save(&mut record, &state, Vec::new()).await?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                if narinfo {
                    let projection = HybridObjectProjection::Narinfo(
                        HybridNarinfoProjection::from_bytes(&result.metadata)?,
                    );
                    ensure!(
                        state
                            .projection
                            .as_ref()
                            .is_none_or(|prior| prior == &projection),
                        "Native metadata differs across destinations"
                    );
                    state.projection = Some(projection);
                }
                state.destinations[index].verified = true;
                state.verified_sha256 = Some(result.sha256);
                state.verified_size = Some(result.byte_size);
                self.save(&mut record, &state, Vec::new()).await?;
            }
        }
        state.state = DirectSessionState::StagedVerified;
        self.save(&mut record, &state, Vec::new()).await?;

        if matches!(state.original.owner, NativeTargetOwner::Cache { .. }) {
            if !state.baseline_checked {
                let provider = self.provider(&state.original.placements[0], "read").await?;
                state.baseline = provider
                    .inspect(&state.original.path, aos_hub_core::clock::now_unix_secs())
                    .await?;
                state.baseline_checked = true;
                self.save(&mut record, &state, Vec::new()).await?;
            }
            let prior =
                state
                    .baseline
                    .as_ref()
                    .map(|baseline| aos_hub_core::db::WriteObjectIdentity {
                        size: baseline.size,
                        sha256: baseline.sha256.clone(),
                        strong_etag: Some(baseline.etag.clone()),
                    });
            self.targets
                .activate_cache(
                    claims,
                    &state.original,
                    prior.as_ref(),
                    aos_hub_core::clock::now_unix_secs(),
                )
                .await?;
        }

        for index in 0..state.destinations.len() {
            if state.destinations[index].final_object.is_some() {
                continue;
            }
            let provider = self
                .provider(&state.original.placements[index], "write")
                .await?;
            let final_path = state.original.path.clone();
            let parts = state.manifest(index)?;
            if state.original.intent.byte_size.get() == 0 {
                let prior = self
                    .provider(&state.original.placements[index], "read")
                    .await?
                    .head(&final_path, aos_hub_core::clock::now_unix_secs())
                    .await?;
                self.before_write(
                    claims,
                    &mut record,
                    &mut state,
                    format!("empty-final-{index}"),
                )
                .await?;
                match provider
                    .empty(
                        &final_path,
                        prior.as_ref().map(|object| object.etag.as_str()),
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .await
                {
                    Ok(object) => {
                        state.destinations[index].final_object = Some(object);
                        state.pending = None;
                    }
                    Err(error) => {
                        self.unknown(&mut record, &mut state).await?;
                        return Err(error);
                    }
                }
                self.save(&mut record, &state, Vec::new()).await?;
            } else {
                if state.destinations[index].final_upload.is_none() {
                    self.before_write(
                        claims,
                        &mut record,
                        &mut state,
                        format!("create-final-{index}"),
                    )
                    .await?;
                    match provider
                        .create(&final_path, aos_hub_core::clock::now_unix_secs())
                        .await
                    {
                        Ok(upload) => {
                            state.destinations[index].final_upload = Some(upload);
                            state.pending = None;
                        }
                        Err(error) => {
                            self.unknown(&mut record, &mut state).await?;
                            return Err(error);
                        }
                    }
                    self.save(&mut record, &state, Vec::new()).await?;
                }
                for part in parts {
                    if state.destinations[index].copied_parts.len()
                        >= part.part.part_number as usize
                    {
                        continue;
                    }
                    self.before_write(
                        claims,
                        &mut record,
                        &mut state,
                        format!("copy-final-{index}-{}", part.part.part_number),
                    )
                    .await?;
                    let destination = &state.destinations[index];
                    let result = provider
                        .copy_part(
                            &destination.staging_path,
                            &final_path,
                            destination
                                .final_upload
                                .as_deref()
                                .context("Native final upload absent")?,
                            &part.part,
                            aos_hub_core::clock::now_unix_secs(),
                        )
                        .await;
                    match result {
                        Ok(etag) => {
                            state.destinations[index]
                                .copied_parts
                                .push(DirectManifestPart {
                                    part: part.part,
                                    etag,
                                });
                            state.pending = None;
                        }
                        Err(error) => {
                            self.unknown(&mut record, &mut state).await?;
                            return Err(error);
                        }
                    }
                    self.save(&mut record, &state, Vec::new()).await?;
                }
                self.before_write(
                    claims,
                    &mut record,
                    &mut state,
                    format!("complete-final-{index}"),
                )
                .await?;
                let destination = &state.destinations[index];
                let result = provider
                    .complete(
                        &final_path,
                        destination
                            .final_upload
                            .as_deref()
                            .context("Native final upload absent")?,
                        &state.original.intent,
                        &destination.placement,
                        &destination.copied_parts,
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .await;
                match result {
                    Ok(object) => {
                        state.destinations[index].final_object = Some(object);
                        state.pending = None;
                    }
                    Err(error) => {
                        self.unknown(&mut record, &mut state).await?;
                        return Err(error);
                    }
                }
                self.save(&mut record, &state, Vec::new()).await?;
            }
        }

        // Provider copy checksums can be composite. Verify each actual final
        // object's complete SHA before publishing catalogue or OCI metadata.
        let mut finals = Vec::new();
        for (pin, destination) in state.original.placements.iter().zip(&state.destinations) {
            let object = destination
                .final_object
                .as_ref()
                .context("Native final object absent")?;
            let verification = self
                .provider(pin, "read")
                .await?
                .verify(
                    &state.original.path,
                    object,
                    &state.original.intent,
                    false,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .await;
            if let Err(error) = verification {
                if error.is::<crate::direct_upload::native_provider::NativeIntegrityMismatch>() {
                    state.integrity_failed = true;
                    self.save(&mut record, &state, Vec::new()).await?;
                }
                return Err(error);
            }
            finals.push(NativeVerifiedPlacement {
                placement_id: pin.placement_id,
                etag: object.etag.clone(),
                provider_version: object.provider_version.clone(),
            });
        }
        valid_claims(claims)?;
        let statements = self
            .targets
            .final_statements(
                claims,
                &state.original,
                &finals,
                state.projection.as_ref(),
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
        state.state = DirectSessionState::Committed;
        state.resource_version = WireInteger::new(state.resource_version.get() + 1);
        self.save(&mut record, &state, statements).await?;
        self.cleanup(&mut record, &mut state).await
    }

    async fn cleanup(
        &self,
        record: &mut NativeDirectUploadRecord,
        state: &mut NativeUploadState,
    ) -> Result<()> {
        for index in 0..state.destinations.len() {
            let Some(object) = state.destinations[index].staging_object.clone() else {
                continue;
            };
            self.provider(&state.original.placements[index], "write")
                .await?
                .delete(
                    &state.destinations[index].staging_path,
                    &object.etag,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .await?;
            state.destinations[index].staging_object = None;
            self.save(record, state, Vec::new()).await?;
        }
        Ok(())
    }

    async fn before_write(
        &self,
        claims: &Claims,
        record: &mut NativeDirectUploadRecord,
        state: &mut NativeUploadState,
        operation: String,
    ) -> Result<()> {
        ensure!(
            state.pending.is_none(),
            "Native provider operation remains uncertain"
        );
        valid_claims(claims)?;
        let now = aos_hub_core::clock::now_unix_secs();
        ensure!(now < state.original.expires_at, "Native upload expired");
        self.targets.authorize(claims, &state.original, now).await?;
        state.pending = Some(format!("{}:{operation}", self.process_id));
        let fences = self
            .targets
            .authority_statements(
                claims,
                &state.original,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
        self.save(record, state, fences).await
    }

    async fn unknown(
        &self,
        record: &mut NativeDirectUploadRecord,
        state: &mut NativeUploadState,
    ) -> Result<()> {
        state.state = DirectSessionState::BlockedUnknown;
        self.save(record, state, Vec::new()).await
    }

    pub(super) async fn abort(
        &self,
        claims: &Claims,
        item: &DirectAbortRequest,
    ) -> Result<DirectSessionStatus> {
        let _control = self
            .control(&item.session.session_id)
            .await
            .lock_owned()
            .await;
        let (mut record, mut state) = self.load(claims, &item.session).await?;
        if let Some(original) = &state.abort {
            ensure!(original == item, conflict());
            if state.state == DirectSessionState::Aborted {
                return state.status(None);
            }
        } else {
            ensure!(
                state.complete.is_none()
                    && state.pending.is_none()
                    && state.state == DirectSessionState::Active
                    && state.resource_version == item.expected_resource_version,
                conflict()
            );
            state.abort = Some(item.clone());
            state.state = DirectSessionState::Aborting;
            state.resource_version = WireInteger::new(state.resource_version.get() + 1);
            self.save(&mut record, &state, Vec::new()).await?;
        }
        for index in 0..state.destinations.len() {
            let Some(upload) = state.destinations[index].staging_upload.clone() else {
                continue;
            };
            self.before_write(
                claims,
                &mut record,
                &mut state,
                format!("abort-stage-{index}"),
            )
            .await?;
            let result = self
                .provider(&state.original.placements[index], "write")
                .await?
                .abort(
                    &state.destinations[index].staging_path,
                    &upload,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .await;
            if let Err(error) = result {
                self.unknown(&mut record, &mut state).await?;
                return Err(error);
            }
            state.destinations[index].staging_upload = None;
            state.pending = None;
            self.save(&mut record, &state, Vec::new()).await?;
        }
        let statements = self
            .targets
            .abort_statements(
                claims,
                &state.original,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
        state.state = DirectSessionState::Aborted;
        self.save(&mut record, &state, statements).await?;
        state.status(None)
    }
}
