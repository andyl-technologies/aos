//! Public Native direct-upload coordinator using the shared client protocol.
//!
//! SQL owns multipart progress and publication. Clients send object parts to
//! storage; Native streams completed objects for verification. Completion work
//! runs independently of short HTTP control requests and is polled with Status.

mod completion;

use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    auth::jwt::{Claims, JwtKeys},
    backend::CheckedStatement,
    db::{Database, NativeDirectUploadRecord},
    direct_upload::*,
    s3surface::S3Surface,
    secret_version::SecretVersionResolver,
    storage_credential::{DatabaseStorageCredentialResolver, StorageCredentialResolver},
};
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse as _, Response},
};
use futures_util::{stream, StreamExt as _};
use tokio::sync::{Mutex, Semaphore};

use super::{
    native_provider::NativeS3Upload,
    native_state::{digest, NativeDestination, NativePartState, NativeUploadState},
    native_targets::{NativePlacementPin, NativeTargetOwner, NativeUploadTargets},
};

/// Standalone public transport; no paired Worker or private logical signature.
pub(crate) struct NativeDirectUpload {
    db: Arc<Database>,
    targets: NativeUploadTargets,
    jwt: JwtKeys,
    deployment: String,
    process_id: String,
    enabled: bool,
    credentials: DatabaseStorageCredentialResolver,
    http: reqwest::Client,
    verification: Arc<Semaphore>,
    jobs: Mutex<BTreeMap<String, tokio::task::JoinHandle<()>>>,
    controls: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
}

impl NativeDirectUpload {
    /// Creates the standalone broker using the existing SQL and credential ports.
    ///
    /// # Errors
    /// Returns an error for an invalid deployment identity or concurrency limit.
    pub(crate) fn new(
        db: Arc<Database>,
        rpc: Arc<aos_hub_core::service::RpcService>,
        jwt: JwtKeys,
        deployment: Option<String>,
        secrets: Arc<dyn SecretVersionResolver>,
        http: reqwest::Client,
        maximum_parallel: usize,
    ) -> Result<Arc<Self>> {
        let enabled = deployment.is_some();
        let deployment = deployment.unwrap_or_else(|| "native-unconfigured".to_owned());
        ensure!(
            valid_direct_identity(&deployment) && (1..=16).contains(&maximum_parallel),
            "invalid Native upload runtime configuration"
        );
        Ok(Arc::new(Self {
            targets: NativeUploadTargets::new(Arc::clone(&db), rpc, deployment.clone()),
            credentials: DatabaseStorageCredentialResolver::new(Arc::clone(&db), secrets),
            db,
            jwt,
            deployment,
            process_id: uuid::Uuid::new_v4().to_string(),
            enabled,
            http,
            verification: Arc::new(Semaphore::new(maximum_parallel)),
            jobs: Mutex::new(BTreeMap::new()),
            controls: Mutex::new(BTreeMap::new()),
        }))
    }

    /// Handles the shared public JSON API with current bearer authentication.
    pub(crate) async fn handle(self: &Arc<Self>, request: axum::extract::Request) -> Response {
        match self.handle_checked(request).await {
            Ok(body) => (
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response(),
            Err(status) => status.into_response(),
        }
    }

    async fn handle_checked(
        self: &Arc<Self>,
        request: axum::extract::Request,
    ) -> Result<Vec<u8>, StatusCode> {
        if request.method() != axum::http::Method::POST || request.uri().query().is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut authorizations = request.headers().get_all(header::AUTHORIZATION).iter();
        let authorization = authorizations
            .next()
            .and_then(|header| header.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if authorizations.next().is_some() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let claims = self
            .jwt
            .verify(authorization)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        self.targets
            .current_actor(&claims)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let method = request
            .uri()
            .path()
            .strip_prefix("/aos.hub.v1.DirectUploadService/")
            .ok_or(StatusCode::NOT_FOUND)?
            .to_owned();
        let body = axum::body::to_bytes(request.into_body(), MAX_DIRECT_CONTROL_BYTES)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        if method == "GetCapabilities" {
            let query: DirectGetCapabilities =
                decode_direct_control(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            let capabilities = self
                .capabilities(&claims, query.target)
                .await
                .map_err(|_| StatusCode::CONFLICT)?;
            return encode_direct_control(&capabilities)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE);
        }
        if !self.enabled {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let public =
            decode_direct_public_request(&method, &body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let reply = self.dispatch(&claims, public).await;
        reply
            .validate()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        encode_direct_control(&reply).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    async fn capabilities(
        &self,
        claims: &Claims,
        target: DirectCapabilitiesTarget,
    ) -> Result<DirectUploadCapabilities> {
        let now = aos_hub_core::clock::now_unix_secs();
        let actor = self.targets.current_actor(claims).await?;
        let resolved = self
            .targets
            .capability_target(claims, &actor, &target, now)
            .await?;
        let mut profiles = Vec::new();
        for pin in resolved.placements.iter().filter(|_| self.enabled) {
            let provider = self.provider(pin, "presign").await?;
            let placement = self.reference(pin, "capabilities")?;
            profiles.push(DirectProviderProfile {
                placement_id: placement.placement_id,
                placement_resource_version: placement.placement_resource_version,
                write_spec_version: placement.write_spec_version,
                binding_id: placement.binding_id,
                binding_resource_version: placement.binding_resource_version,
                binding_write_revision: placement.binding_write_revision,
                checksum_algorithm: placement.checksum_algorithm,
                provider_origin: provider.origin("probe")?,
                profile_fingerprint: placement.profile_fingerprint,
                private_policy_digest: placement.private_policy_digest,
            });
        }
        let requested_delivery_url = match &target {
            DirectCapabilitiesTarget::CacheDelivery { delivery_url } => Some(delivery_url.clone()),
            _ => None,
        };
        let capabilities = DirectUploadCapabilities {
            target: resolved.target,
            requested_delivery_url,
            deployment_id: if self.enabled {
                self.deployment.clone()
            } else {
                String::new()
            },
            principal_id: if self.enabled {
                actor.principal_id(&self.deployment)?
            } else {
                String::new()
            },
            version: 1,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            transfer_mode: if profiles.is_empty() {
                DirectAdvertisedTransferMode::Legacy
            } else {
                DirectAdvertisedTransferMode::DirectRequired
            },
            config_generation: integer(resolved.config_generation)?,
            valid_until: WireInteger::new(u64::try_from(now)? + 30),
            maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
            maximum_batch_items: MAX_DIRECT_BATCH_ITEMS as u32,
            maximum_batch_parts: MAX_DIRECT_BATCH_PARTS as u32,
            minimum_object_bytes: WireInteger::new(0),
            maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
            minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
            maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
            profiles,
        };
        capabilities.validate_for(&target)?;
        Ok(capabilities)
    }

    fn reference(&self, pin: &NativePlacementPin, path: &str) -> Result<DirectPlacementRef> {
        let profile = digest(&("native-storage-config-v1", pin))?;
        let policy = digest(&(
            "native-private-staging-v1",
            &self.deployment,
            pin.binding_id,
        ))?;
        Ok(DirectPlacementRef {
            placement_id: integer(pin.placement_id)?,
            placement_resource_version: integer(pin.placement_resource_version)?,
            write_spec_version: integer(pin.write_spec_version)?,
            binding_id: integer(pin.binding_id)?,
            binding_resource_version: integer(pin.binding_resource_version)?,
            binding_write_revision: integer(pin.binding_write_revision)?,
            placement_fingerprint: digest(&(pin, path))?,
            profile_fingerprint: profile,
            private_policy_digest: policy,
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
        })
    }

    async fn provider(&self, pin: &NativePlacementPin, purpose: &str) -> Result<NativeS3Upload> {
        let row = self
            .db
            .surface_placement(pin.placement_id)
            .await?
            .context("Native upload placement absent")?;
        ensure!(
            row.resource_version == pin.placement_resource_version
                && row.write_spec_version == pin.write_spec_version
                && row.binding_id == pin.binding_id,
            "Native upload placement changed"
        );
        let binding = self
            .db
            .binding(pin.binding_id)
            .await?
            .context("Native upload binding absent")?;
        ensure!(
            binding.resource_version == pin.binding_resource_version,
            "Native upload binding changed"
        );
        let generation = match purpose {
            "write" => pin.write_credential_generation,
            "read" => pin.read_credential_generation,
            "presign" => pin.presign_credential_generation,
            _ => anyhow::bail!("invalid upload credential purpose"),
        };
        let material = self
            .credentials
            .resolve_exact(pin.binding_id, purpose, generation)
            .await?;
        let surface = S3Surface::from_binding(&binding, &row.prefix, Some(material.secret()?))?
            .context("Native upload backend cannot sign multipart requests")?;
        Ok(NativeS3Upload::new(surface, self.http.clone()))
    }

    async fn load(
        &self,
        claims: &Claims,
        session: &DirectSessionRef,
    ) -> Result<(NativeDirectUploadRecord, NativeUploadState)> {
        valid_claims(claims)?;
        let record = self
            .db
            .native_direct_upload(&self.deployment, &session.session_id)
            .await?
            .context("Native upload absent")?;
        let mut state: NativeUploadState = serde_json::from_str(&record.state_json)?;
        ensure!(
            state.session == *session
                && state.session.logical_fingerprint == digest(&state.original)?
                && state.original.session_id == record.session_id
                && state.original.intent.client_operation_id == record.client_operation_id
                && state.original.intent.expected_sha256 == record.source_sha256
                && i64::try_from(state.original.intent.byte_size.get())? == record.declared_size
                && state.verified_sha256 == record.verified_sha256
                && state.verified_size.map(i64::try_from).transpose()? == record.verified_size
                && phase(state.state) == record.state,
            "Native upload session changed"
        );
        ensure!(
            !state.integrity_failed,
            DirectUploadRefusal {
                code: DirectItemErrorCode::Invalid
            }
        );
        ensure!(
            state.destinations.len() == state.original.placements.len(),
            "Native upload destination count changed"
        );
        for (pin, destination) in state.original.placements.iter().zip(&state.destinations) {
            ensure!(
                destination.placement == self.reference(pin, &state.original.path)?
                    && destination.staging_path
                        == format!(
                            ".aos-direct-upload/native/{}/{}",
                            record.session_id, pin.placement_id
                        ),
                "Native upload destination changed"
            );
        }
        self.targets
            .authorize(
                claims,
                &state.original,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await?;
        ensure!(
            state.original.actor.principal_id(&self.deployment)? == record.principal_id,
            "Native upload principal changed"
        );
        // A crash after dispatch cannot establish whether the provider wrote.
        // Keep the original marker and expose that uncertainty after restart.
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| !pending.starts_with(&format!("{}:", self.process_id)))
        {
            state.state = DirectSessionState::BlockedUnknown;
        }
        Ok((record, state))
    }

    async fn save(
        &self,
        record: &mut NativeDirectUploadRecord,
        state: &NativeUploadState,
        target: Vec<CheckedStatement>,
    ) -> Result<()> {
        let expected = record.resource_version;
        let mut next = record.clone();
        next.resource_version = expected
            .checked_add(1)
            .context("Native journal version overflow")?;
        next.state_json = serde_json::to_string(state)?;
        next.state = phase(state.state).to_owned();
        next.verified_sha256 = state.verified_sha256.clone();
        next.verified_size = state.verified_size.map(i64::try_from).transpose()?;
        *record = self
            .db
            .replace_native_direct_upload(&next, expected, target)
            .await?;
        Ok(())
    }

    async fn dispatch(
        self: &Arc<Self>,
        claims: &Claims,
        request: DirectUploadRequest,
    ) -> DirectUploadResponse {
        let operation_id = match &request {
            DirectUploadRequest::BeginBatch(batch) => &batch.operation_id,
            DirectUploadRequest::StatusBatch(batch) => &batch.operation_id,
            DirectUploadRequest::GrantPartsBatch(batch) => &batch.operation_id,
            DirectUploadRequest::ReportPartsBatch(batch) => &batch.operation_id,
            DirectUploadRequest::CompleteBatch(batch) => &batch.operation_id,
            DirectUploadRequest::Abort(batch) => &batch.operation_id,
        }
        .clone();
        let mut reply = DirectUploadResponse {
            operation_id,
            sessions: Vec::new(),
            grants: Vec::new(),
            errors: Vec::new(),
        };
        match request {
            DirectUploadRequest::BeginBatch(batch) => {
                let results = bounded(batch.items.into_iter().map(|intent| async move {
                    (
                        intent.client_operation_id.clone(),
                        self.begin(claims, intent).await,
                    )
                }))
                .await;
                for (id, result) in results {
                    append(&mut reply, &id, result);
                }
            }
            DirectUploadRequest::StatusBatch(batch) => {
                let results = bounded(batch.items.into_iter().map(|query| async move {
                    let result = async {
                        let (_, state) = self.load(claims, &query.session).await?;
                        if state.complete.is_some()
                            && state.pending.is_none()
                            && (!terminal(state.state)
                                || (state.state == DirectSessionState::Committed
                                    && state
                                        .destinations
                                        .iter()
                                        .any(|destination| destination.staging_object.is_some())))
                        {
                            self.schedule(claims.clone(), &state.session.session_id)
                                .await?;
                        }
                        state.status(Some(&query))
                    }
                    .await;
                    (query.session.session_id, result)
                }))
                .await;
                for (id, result) in results {
                    append(&mut reply, &id, result);
                }
            }
            DirectUploadRequest::GrantPartsBatch(batch) => {
                let results = bounded(batch.items.into_iter().map(|item| async move {
                    (item.operation_id.clone(), self.grant(claims, &item).await)
                }))
                .await;
                for (id, result) in results {
                    match result {
                        Ok(grant) => reply.grants.push(grant),
                        Err(error) => refusal(&mut reply, &id, &error),
                    }
                }
            }
            DirectUploadRequest::ReportPartsBatch(batch) => {
                let results = bounded(batch.items.into_iter().map(|item| async move {
                    (item.operation_id.clone(), self.report(claims, &item).await)
                }))
                .await;
                for (id, result) in results {
                    append(&mut reply, &id, result);
                }
            }
            DirectUploadRequest::CompleteBatch(batch) => {
                for item in batch.items {
                    append(
                        &mut reply,
                        &item.session.session_id,
                        self.freeze(claims, &item).await,
                    );
                }
            }
            DirectUploadRequest::Abort(batch) => {
                for item in batch.items {
                    append(
                        &mut reply,
                        &item.session.session_id,
                        self.abort(claims, &item).await,
                    );
                }
            }
        }
        reply
    }

    async fn begin(
        &self,
        claims: &Claims,
        intent: DirectUploadIntent,
    ) -> Result<DirectSessionStatus> {
        let now = aos_hub_core::clock::now_unix_secs();
        let actor = self.targets.current_actor(claims).await?;
        let principal = actor.principal_id(&self.deployment)?;
        let session_id = deterministic_business_operation_id(
            &self.deployment,
            &principal,
            &intent.client_operation_id,
        )?;
        let _control = self.control(&session_id).await.lock_owned().await;
        if let Some(existing) = self
            .db
            .native_direct_upload_by_operation(
                &self.deployment,
                &principal,
                &intent.client_operation_id,
            )
            .await?
        {
            let state: NativeUploadState = serde_json::from_str(&existing.state_json)?;
            ensure!(
                state.original.intent == intent && state.original.actor == actor,
                conflict()
            );
            let (_, state) = self.load(claims, &state.session).await?;
            return state.status(None);
        }
        let target = self
            .targets
            .resolve_target(claims, &actor, &intent, false, now)
            .await?;
        ensure!(
            !target.placements.is_empty() && target.placements.len() <= MAX_DIRECT_PLACEMENTS,
            "Native upload has no writable destination"
        );
        let mut pins = Vec::new();
        for row in &target.placements {
            pins.push(self.targets.placement_pin(row).await?);
        }
        for pin in &pins {
            for purpose in ["write", "read", "presign"] {
                self.provider(pin, purpose).await?;
            }
        }
        let original = self
            .targets
            .reserve(claims, &actor, &intent, &session_id, pins, now)
            .await?;
        let session = DirectSessionRef {
            session_id: session_id.clone(),
            logical_fingerprint: digest(&original)?,
        };
        let mut destinations = Vec::new();
        for pin in &original.placements {
            destinations.push(NativeDestination {
                placement: self.reference(pin, &original.path)?,
                staging_path: format!(
                    ".aos-direct-upload/native/{session_id}/{}",
                    pin.placement_id
                ),
                staging_upload: None,
                staging_object: None,
                verified: false,
                final_upload: None,
                copied_parts: Vec::new(),
                final_object: None,
                parts: BTreeMap::new(),
            });
        }
        let mut state = NativeUploadState {
            original,
            session,
            resource_version: WireInteger::new(1),
            state: DirectSessionState::Creating,
            destinations,
            complete: None,
            abort: None,
            pending: None,
            projection: None,
            verified_sha256: None,
            verified_size: None,
            baseline_checked: false,
            baseline: None,
            integrity_failed: false,
        };
        let mut record = NativeDirectUploadRecord {
            session_id,
            deployment_id: self.deployment.clone(),
            principal_id: principal,
            client_operation_id: intent.client_operation_id.clone(),
            oci_upload_id: match &intent.target {
                DirectUploadTarget::OciBlob { upload_id } => Some(upload_id.clone()),
                _ => None,
            },
            state: "creating".into(),
            source_sha256: intent.expected_sha256.clone(),
            declared_size: i64::try_from(intent.byte_size.get())?,
            verified_sha256: None,
            verified_size: None,
            materialization_placement_id: state
                .original
                .placements
                .first()
                .map(|pin| pin.placement_id),
            materialization_binding_id: state.original.placements.first().map(|pin| pin.binding_id),
            state_json: serde_json::to_string(&state)?,
            resource_version: 1,
        };
        record = self.db.create_native_direct_upload(&record).await?;
        if intent.byte_size.get() > 0 {
            for index in 0..state.destinations.len() {
                state.pending = Some(format!("{}:create-stage-{index}", self.process_id));
                self.save(&mut record, &state, Vec::new()).await?;
                let result = self
                    .provider(&state.original.placements[index], "write")
                    .await?
                    .create(&state.destinations[index].staging_path, now)
                    .await;
                match result {
                    Ok(upload) => {
                        state.destinations[index].staging_upload = Some(upload);
                        state.pending = None;
                    }
                    Err(error) => {
                        state.state = DirectSessionState::BlockedUnknown;
                        self.save(&mut record, &state, Vec::new()).await?;
                        return Err(error);
                    }
                }
                self.save(&mut record, &state, Vec::new()).await?;
            }
        }
        state.state = DirectSessionState::Active;
        self.save(&mut record, &state, Vec::new()).await?;
        state.status(None)
    }

    async fn grant(
        &self,
        claims: &Claims,
        item: &DirectGrantPartRequest,
    ) -> Result<DirectPartGrant> {
        let _control = self
            .control(&item.session.session_id)
            .await
            .lock_owned()
            .await;
        let (mut record, mut state) = self.load(claims, &item.session).await?;
        ensure!(
            state.state == DirectSessionState::Active && state.complete.is_none(),
            conflict()
        );
        item.part.validate(&state.original.intent)?;
        let index = state
            .destinations
            .iter()
            .position(|destination| destination.placement == item.placement)
            .context("foreign Native destination")?;
        ensure!(
            item.part.checksum.algorithm == DirectChecksumAlgorithm::Md5,
            "Native checksum differs"
        );
        let now = aos_hub_core::clock::now_unix_secs();
        let expires = (now + 300).min(state.original.expires_at);
        ensure!(expires > now, "Native upload expired");
        let destination = &mut state.destinations[index];
        let grant_id = digest(&(
            &state.session,
            &item.placement,
            &item.operation_id,
            &item.part,
        ))?;
        let part = destination
            .parts
            .entry(item.part.part_number)
            .or_insert_with(|| NativePartState {
                grant_id: grant_id.clone(),
                grant_revision: WireInteger::new(1),
                operation_id: item.operation_id.clone(),
                part: item.part.clone(),
                expires_at: WireInteger::new(expires as u64),
                observed: None,
            });
        ensure!(
            part.part == item.part && part.operation_id == item.operation_id,
            conflict()
        );
        if part.expires_at.get() <= now as u64 {
            part.grant_revision = WireInteger::new(part.grant_revision.get() + 1);
            part.expires_at = WireInteger::new(expires as u64);
        }
        let retained = part.clone();
        let upload_id = destination
            .staging_upload
            .clone()
            .context("Native staging upload absent")?;
        let path = destination.staging_path.clone();
        self.save(&mut record, &state, Vec::new()).await?;
        let provider = self
            .provider(&state.original.placements[index], "presign")
            .await?;
        let signed = provider.part(
            &path,
            &upload_id,
            &retained.part,
            now,
            u32::try_from(retained.expires_at.get() - now as u64)?,
        )?;
        Ok(DirectPartGrant {
            session_id: state.session.session_id,
            logical_fingerprint: state.session.logical_fingerprint,
            placement: item.placement.clone(),
            grant_id: retained.grant_id,
            grant_revision: retained.grant_revision,
            part: retained.part,
            method: "PUT".into(),
            url: signed.url,
            required_headers: signed.required_headers,
            expires_at: retained.expires_at,
        })
    }

    async fn report(
        &self,
        claims: &Claims,
        item: &DirectPartReport,
    ) -> Result<DirectSessionStatus> {
        let _control = self
            .control(&item.session.session_id)
            .await
            .lock_owned()
            .await;
        let (mut record, mut state) = self.load(claims, &item.session).await?;
        ensure!(state.state == DirectSessionState::Active, conflict());
        let destination = state
            .destinations
            .iter_mut()
            .find(|destination| destination.placement == item.placement)
            .context("foreign Native destination")?;
        let part = destination
            .parts
            .get_mut(&item.observed.part.part_number)
            .context("Native part was not granted")?;
        ensure!(
            part.grant_id == item.grant_id
                && part.grant_revision == item.grant_revision
                && part.part == item.observed.part,
            conflict()
        );
        ensure!(
            part.observed
                .as_ref()
                .is_none_or(|previous| previous == &item.observed),
            conflict()
        );
        part.observed = Some(item.observed.clone());
        self.save(&mut record, &state, Vec::new()).await?;
        state.status(None)
    }

    async fn freeze(
        self: &Arc<Self>,
        claims: &Claims,
        item: &DirectCompleteRequest,
    ) -> Result<DirectSessionStatus> {
        let _control = self
            .control(&item.session.session_id)
            .await
            .lock_owned()
            .await;
        let (mut record, mut state) = self.load(claims, &item.session).await?;
        if let Some(original) = &state.complete {
            ensure!(original == item, conflict());
        } else {
            ensure!(
                state.state == DirectSessionState::Active
                    && state.resource_version == item.expected_resource_version
                    && item.manifests.len() == state.destinations.len(),
                conflict()
            );
            state.complete = Some(item.clone());
            for index in 0..state.destinations.len() {
                state.manifest(index)?;
            }
            state.resource_version = WireInteger::new(state.resource_version.get() + 1);
            state.state = DirectSessionState::CompletingStaging;
            self.save(&mut record, &state, Vec::new()).await?;
        }
        if !terminal(state.state) && state.pending.is_none() {
            self.schedule(claims.clone(), &state.session.session_id)
                .await?;
        }
        state.status(None)
    }

    async fn control(&self, session: &str) -> Arc<Mutex<()>> {
        let mut controls = self.controls.lock().await;
        controls.retain(|_, mutex| mutex.strong_count() > 0);
        if let Some(mutex) = controls.get(session).and_then(Weak::upgrade) {
            return mutex;
        }
        let mutex = Arc::new(Mutex::new(()));
        controls.insert(session.to_owned(), Arc::downgrade(&mutex));
        mutex
    }
}

async fn bounded<F, T>(operations: impl IntoIterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    stream::iter(operations).buffered(8).collect().await
}

fn integer(value: i64) -> Result<WireInteger> {
    Ok(WireInteger::new(u64::try_from(value)?))
}

fn terminal(state: DirectSessionState) -> bool {
    matches!(
        state,
        DirectSessionState::Committed
            | DirectSessionState::Aborted
            | DirectSessionState::BlockedUnknown
    )
}

fn phase(state: DirectSessionState) -> &'static str {
    match state {
        DirectSessionState::Creating => "creating",
        DirectSessionState::Active => "uploading",
        DirectSessionState::Committed => "committed",
        DirectSessionState::Aborting => "aborting",
        DirectSessionState::Aborted => "aborted",
        DirectSessionState::BlockedUnknown => "blocked_unknown",
        DirectSessionState::StagedVerified | DirectSessionState::Promoting => "verified",
        _ => "completing",
    }
}

fn conflict() -> DirectUploadRefusal {
    DirectUploadRefusal {
        code: DirectItemErrorCode::Conflict,
    }
}

fn valid_claims(claims: &Claims) -> Result<()> {
    let now = aos_hub_core::clock::now_unix_secs();
    ensure!(
        claims.iat <= now && now < claims.exp,
        DirectUploadRefusal {
            code: DirectItemErrorCode::Denied
        }
    );
    Ok(())
}

fn append(reply: &mut DirectUploadResponse, id: &str, result: Result<DirectSessionStatus>) {
    match result {
        Ok(status) => {
            if let Some(prior) = reply
                .sessions
                .iter_mut()
                .find(|prior| prior.session == status.session)
            {
                *prior = status;
            } else {
                reply.sessions.push(status);
            }
        }
        Err(error) => refusal(reply, id, &error),
    }
}

fn refusal(reply: &mut DirectUploadResponse, id: &str, error: &anyhow::Error) {
    reply.errors.push(DirectItemError {
        item_id: id.into(),
        code: error
            .downcast_ref::<DirectUploadRefusal>()
            .map_or(DirectItemErrorCode::Unavailable, |refusal| refusal.code),
    });
}
