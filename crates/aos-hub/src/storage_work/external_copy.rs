//! Native placement-copy controls derived from retained SQL operations.
//!
//! Both sealed stable targets resolve independently before row pins are
//! projected. A cold retry reads the permanent original before observing the
//! source: a replacement HEAD can never silently become the old copy's source.
//! Native receives compact progress only and never reads an object body.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    db::{
        BindingRecord, BindingWriteRevisionRecord, ConsumerScopeGrantRecord, SurfaceObjectRecord,
        SurfacePlacementRecord, SurfaceTarget, TopologyOperationRecord,
    },
    fetch::SurfaceListedEvidence,
    storage_authority::{
        external_object::copy::{
            CopyIncarnationMode, CopyPlacementPin, CopySourceBindingPin, CopySourceObject,
            CopyTopologyOriginal, ExternalCopyOriginal,
            control::{
                CopyClaim, CopyControl, CopyProgress, EXTERNAL_COPY_PATH, ExternalCopyReply,
                ExternalCopyRequest, MAX_EXTERNAL_COPY_CONTROL_BYTES,
            },
            metadata::{
                CopyMetadataReply, CopyMetadataRequest, EXTERNAL_COPY_METADATA_PATH,
                RetainedCopyOriginal,
            },
            session::CopyPhase,
        },
        lease::LeaseInteger,
    },
    storage_work::{STORAGE_WORK_SIGNATURE_HEADER, StorageWorkOperation, StorageWorkOutcome},
};
use base64::Engine as _;

use super::{HybridSurfaceWrites, RemoteStorageWorkClient, telemetry::ExchangeTelemetry};

mod context;

impl RemoteStorageWorkClient {
    /// Queries installed copy metadata and its genuine retained owner once.
    ///
    /// # Errors
    /// Refuses invalid permission, excessive replies, wrong correlation or expiry.
    pub async fn external_copy_metadata(
        &self,
        request: &CopyMetadataRequest,
    ) -> Result<CopyMetadataReply> {
        Ok(self.external_copy_metadata_observed(request).await?.0)
    }

    async fn external_copy_metadata_observed(
        &self,
        request: &CopyMetadataRequest,
    ) -> Result<(
        CopyMetadataReply,
        Option<super::telemetry::context::ControlObservation>,
    )> {
        let mut exchange =
            ExchangeTelemetry::control(&request.plan.plan_id, "external_copy_metadata");
        let result = async {
            let now = aos_hub_core::clock::now_unix_secs();
            let (body, signature) = request
                .sign(&self.key, &self.deployment_id, now)
                .inspect_err(|_| exchange.finish("invalid_plan"))?;
            let (reply, signature) = self
                .copy_exchange(EXTERNAL_COPY_METADATA_PATH, body, signature, &mut exchange)
                .await?;
            let authenticated = CopyMetadataReply::authenticate(
                &self.key,
                &signature,
                &reply,
                request,
                &self.deployment_id,
                aos_hub_core::clock::now_unix_secs(),
            )
            .inspect_err(|_| exchange.finish("invalid_result"))?;
            exchange.authenticated_control(&reply);
            Ok(authenticated)
        }
        .await;
        if result.is_ok() {
            exchange.finish("success");
        }
        result.map(|value| (value, exchange.control_observation()))
    }

    /// Sends one fresh claim permission without retrying an ambiguous effect.
    ///
    /// # Errors
    /// Refuses stale permission, Worker failure, excessive bytes or changed originals.
    pub async fn external_copy_control(
        &self,
        request: &ExternalCopyRequest,
    ) -> Result<CopyProgress> {
        Ok(self.external_copy_control_observed(request).await?.0)
    }

    async fn external_copy_control_observed(
        &self,
        request: &ExternalCopyRequest,
    ) -> Result<(
        CopyProgress,
        Option<super::telemetry::context::ControlObservation>,
    )> {
        let mut exchange =
            ExchangeTelemetry::control(&request.plan.plan_id, "external_copy_control");
        let result = async {
            let (body, signature) = request
                .sign(
                    &self.key,
                    &self.deployment_id,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .inspect_err(|_| exchange.finish("invalid_plan"))?;
            let (reply, signature) = self
                .copy_exchange(EXTERNAL_COPY_PATH, body, signature, &mut exchange)
                .await?;
            let authenticated = ExternalCopyReply::authenticate(
                &self.key,
                &signature,
                &reply,
                request,
                aos_hub_core::clock::now_unix_secs(),
            )
            .inspect_err(|_| exchange.finish("invalid_result"))?;
            exchange.authenticated_control(&reply);
            Ok(authenticated.progress)
        }
        .await;
        if result.is_ok() {
            exchange.finish("success");
        }
        result.map(|value| (value, exchange.control_observation()))
    }

    async fn copy_exchange(
        &self,
        path: &str,
        body: Vec<u8>,
        signature: String,
        exchange: &mut ExchangeTelemetry<'_>,
    ) -> Result<(Vec<u8>, String)> {
        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("copy transport capacity closed")?;
        let mut endpoint = url::Url::parse(&self.endpoint)?;
        endpoint.set_path(path);
        // This client has retries disabled. A timeout cannot acknowledge or
        // redispatch the immutable provider turn retained by the Worker guard.
        exchange.offer_control(path, &body);
        let mut outbound = crate::outbound_inventory::Observation::start(
            crate::outbound_inventory::Owner::ExternalCopy,
            crate::outbound_inventory::Image::Nonsecret(&body),
            Some(exchange.transport_call_id()),
        );
        let response = self
            .semantic_observation_http
            .post(endpoint)
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .header(
                super::telemetry::STORAGE_CALL_ID_HEADER,
                exchange.transport_call_id(),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .context("requesting external placement copy")
            .inspect_err(|_| exchange.finish("transport_failed"))?;
        outbound.response(response.status().as_u16());
        if response.status() != reqwest::StatusCode::OK {
            exchange.discard_status_response();
            exchange.finish("http_rejected");
            anyhow::bail!("external placement copy refused");
        }
        let signature = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("copy reply signature absent")
            .inspect_err(|_| exchange.finish("invalid_result"))?
            .to_str()
            .inspect_err(|_| exchange.finish("invalid_result"))?
            .to_owned();
        let body = crate::storage_work::read_inventory_observed_response(
            response,
            MAX_EXTERNAL_COPY_CONTROL_BYTES,
            &mut outbound,
            |length| {
                exchange.observe_body(length);
            },
        )
        .await
        .inspect_err(|_| exchange.finish("response_read_failed"))?;
        Ok((body, signature))
    }
}

/// Pins current SQL eligibility independently of provider progress.
struct CurrentCopy {
    topology: CopyTopologyOriginal,
    source: CopyPlacementPin,
    destination: CopyPlacementPin,
    source_binding: BindingRecord,
    binding: BindingRecord,
    revision: BindingWriteRevisionRecord,
    source_grant: ConsumerScopeGrantRecord,
    grant: ConsumerScopeGrantRecord,
}

impl HybridSurfaceWrites {
    /// Observes the installed policy without reading source ownership or bytes.
    pub(super) async fn external_copy_policy(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        path: &str,
    ) -> Result<aos_hub_core::surface_write::PlacementCopyPolicy> {
        let current = self
            .current_copy(operation, source, destination, true)
            .await?;
        self.ensure_copy_snapshots(&current).await?;
        let claim = self
            .recheck_copy(&current, operation, claim_token, source, destination)
            .await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let plan = self.work.plan_for_placement(
            destination,
            &current.binding,
            StorageWorkOperation::Head { path: path.into() },
            now,
        )?;
        let mut query = self.copy_metadata_query(&current, source, Some(claim), plan, path, now)?;
        query.profile_only = true;
        let metadata = self.work.external_copy_metadata(&query).await?;
        let selector = metadata.selector(&query)?;
        self.check_source_selector(
            &current,
            selector.transfer.as_ref().map(|pins| &pins.source_binding),
        )
        .await?;
        ensure!(
            selector.binding_stable_id == current.binding.stable_id
                && metadata.profile.binding_write_revision.get() == current.revision.revision
                && metadata.profile.write_generation.get()
                    == current.revision.write_credential_generation,
            "installed copy policy differs from current SQL"
        );
        self.check_snapshot(&current, &selector.snapshot_revision)
            .await?;
        self.recheck_copy(&current, operation, claim_token, source, destination)
            .await?;
        Ok(aos_hub_core::surface_write::PlacementCopyPolicy {
            profile_digest: metadata.profile.profile_digest,
            catalogue_only: metadata
                .transfer
                .as_ref()
                .map_or(metadata.profile.protected_versionless, |pins| {
                    pins.source_incarnation == CopyIncarnationMode::GuardedClosure
                }),
        })
    }

    /// Reads a failed or running original without a dispatch claim or provider I/O.
    ///
    /// Callers select an already authorized topology operation. This method
    /// independently checks its current targets, grant and provider snapshot;
    /// the result is diagnostic history, never permission to settle or resume.
    ///
    /// # Errors
    /// Refuses changed current SQL selectors, unsupported bindings, invalid
    /// installed profiles or a foreign/corrupt guard-retained original.
    pub async fn retained_external_copy_original(
        &self,
        operation: &TopologyOperationRecord,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        path: &str,
    ) -> Result<Option<RetainedCopyOriginal>> {
        let current = self
            .current_copy(operation, source, destination, false)
            .await?;
        self.ensure_copy_snapshots(&current).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let plan = self.work.plan_for_placement(
            destination,
            &current.binding,
            StorageWorkOperation::Head { path: path.into() },
            now,
        )?;
        let query = self.copy_metadata_query(&current, source, None, plan, path, now)?;
        let (reply, observation) = self.work.external_copy_metadata_observed(&query).await?;
        let latest = self
            .current_copy(operation, source, destination, false)
            .await?;
        compare_current(&current, &latest)?;
        let selector = reply.selector(&query)?;
        self.check_source_selector(
            &current,
            selector.transfer.as_ref().map(|pins| &pins.source_binding),
        )
        .await?;
        ensure!(
            selector.binding_stable_id == current.binding.stable_id
                && reply.profile.binding_write_revision.get() == current.revision.revision
                && reply.profile.write_generation.get()
                    == current.revision.write_credential_generation,
            "diagnostic copy profile differs from current SQL"
        );
        self.check_snapshot(&current, &selector.snapshot_revision)
            .await?;
        context::after_sql(
            observation,
            &current,
            None,
            None,
            &reply.profile.profile_digest,
            &selector.snapshot_revision,
            selector.transfer.as_ref().map(|pins| &pins.source_binding),
        );
        Ok(reply.retained)
    }

    /// Copies through the existing guard using a genuine running operation claim.
    ///
    /// # Errors
    /// Refuses unresolved physical effects, changed SQL originals or authorities,
    /// unsupported providers and any unacknowledged transport/provider outcome.
    pub(super) async fn copy_external_claimed(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        path: &str,
        listed: Option<&SurfaceListedEvidence>,
    ) -> Result<Option<u64>> {
        self.copy_external_with_policy(
            operation,
            claim_token,
            source,
            destination,
            path,
            listed,
            None,
        )
        .await
    }

    pub(super) async fn copy_external_with_policy(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        path: &str,
        listed: Option<&SurfaceListedEvidence>,
        policy: Option<&aos_hub_core::surface_write::PlacementCopyPolicy>,
    ) -> Result<Option<u64>> {
        let current = self
            .current_copy(operation, source, destination, true)
            .await?;
        let catalogue = self.copy_catalogue(source, path).await?;
        let expected_sha256 = catalogue
            .as_ref()
            .and_then(|object| object.content_hash.as_deref())
            .map(catalogue_sha256)
            .transpose()?;
        self.ensure_copy_snapshots(&current).await?;
        let claim = self
            .recheck_copy(&current, operation, claim_token, source, destination)
            .await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let plan = self.work.plan_for_placement(
            destination,
            &current.binding,
            StorageWorkOperation::Head { path: path.into() },
            now,
        )?;
        let query = self.copy_metadata_query(&current, source, Some(claim), plan, path, now)?;
        let (metadata, metadata_observation) =
            self.work.external_copy_metadata_observed(&query).await?;
        self.recheck_catalogue(source, path, &catalogue).await?;
        self.recheck_copy(&current, operation, claim_token, source, destination)
            .await?;
        let selector = metadata.selector(&query)?;
        self.check_source_selector(
            &current,
            selector.transfer.as_ref().map(|pins| &pins.source_binding),
        )
        .await?;
        if let Some(policy) = policy {
            ensure!(
                metadata.profile.profile_digest == policy.profile_digest
                    && metadata
                        .transfer
                        .as_ref()
                        .map_or(metadata.profile.protected_versionless, |pins| pins
                            .source_incarnation
                            == CopyIncarnationMode::GuardedClosure)
                        == policy.catalogue_only,
                "installed placement copy policy changed before object dispatch"
            );
        }
        ensure!(
            selector.binding_stable_id == current.binding.stable_id
                && metadata.profile.binding_write_revision.get() == current.revision.revision
                && metadata.profile.write_generation.get()
                    == current.revision.write_credential_generation,
            "installed copy writer differs from current SQL"
        );
        self.check_snapshot(&current, &selector.snapshot_revision)
            .await?;

        let original = if let Some(retained) = metadata.retained {
            // Recovery preserves the genuine first source even if a current
            // provider HEAD would now describe another version of that key.
            selector.validate_retained(&retained.original, &retained.progress)?;
            ensure!(
                expected_sha256 == retained.original.expected_sha256,
                "retained copy differs from current catalogue SHA-256"
            );
            require_retained_catalogue_size(
                retained.original.version,
                retained.original.source_object.bytes.get(),
                catalogue.as_ref(),
            )?;
            if retained.progress.pending {
                anyhow::bail!("copy retains an unresolved provider turn");
            }
            if retained.progress.phase == CopyPhase::Closed {
                self.recheck_catalogue(source, path, &catalogue).await?;
                context::after_sql(
                    metadata_observation,
                    &current,
                    query.claim.as_ref(),
                    catalogue.as_ref(),
                    &retained.original.profile_digest,
                    &retained.original.snapshot_revision,
                    retained
                        .original
                        .transfer
                        .as_ref()
                        .map(|pins| &pins.source_binding),
                );
                return Ok(Some(retained.original.source_object.bytes.get() as u64));
            }
            ensure!(
                retained.progress.phase != CopyPhase::Aborted,
                "copy original was positively aborted; schedule a new reviewed operation"
            );
            retained.original
        } else {
            let listed = listed.context("external copy requires actual inventory evidence")?;
            let plan = self.work.plan_for_placement(
                source,
                &current.source_binding,
                StorageWorkOperation::Head { path: path.into() },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let result = self.work.execute(&plan).await?;
            self.recheck_catalogue(source, path, &catalogue).await?;
            self.recheck_copy(&current, operation, claim_token, source, destination)
                .await?;
            self.check_snapshot(&current, &selector.snapshot_revision)
                .await?;
            self.check_source_selector(
                &current,
                selector.transfer.as_ref().map(|pins| &pins.source_binding),
            )
            .await?;
            let StorageWorkOutcome::Head { object, .. } = result.outcome else {
                anyhow::bail!("external copy source has no current versioned HEAD");
            };
            ensure!(
                object.key == plan.object_key(path)?
                    && object.size == u64::try_from(listed.size)?
                    && listed
                        .provider_version
                        .as_ref()
                        .is_none_or(|version| object.provider_version.as_ref() == Some(version))
                    && object.etag
                        == aos_hub_core::surface_write::strong_if_match_etag(&listed.strong_etag)?,
                "external copy source changed after inventory"
            );
            if let Some(logical) = &catalogue {
                ensure!(
                    logical
                        .size
                        .is_none_or(|bytes| u64::try_from(bytes).ok() == Some(object.size)),
                    "copy source size differs from current catalogue"
                );
            }
            let source_protected = metadata
                .transfer
                .as_ref()
                .map_or(metadata.profile.protected_versionless, |pins| {
                    pins.source_incarnation == CopyIncarnationMode::GuardedClosure
                });
            if metadata.transfer.is_some() {
                ensure!(
                    expected_sha256.is_some()
                        && catalogue.as_ref().and_then(|object| object.size)
                            == Some(i64::try_from(object.size)?),
                    "cross-binding copy requires a trusted catalogue hash and exact size"
                );
            }
            let protected = if source_protected {
                let closure = metadata
                    .source_closure
                    .as_ref()
                    .context("versionless copy requires a current positive source receipt")?;
                closure.validate()?;
                let trusted = expected_sha256
                    .as_ref()
                    .context("versionless copy refuses an uncatalogued source hash")?;
                let logical = catalogue
                    .as_ref()
                    .context("versionless copy requires the exact current catalogue object")?;
                ensure!(
                    logical.size == Some(closure.bytes.get())
                        && closure.bytes.get() as u64 == object.size
                        && &closure.sha256 == trusted
                        && closure
                            .etag
                            .as_ref()
                            .is_none_or(|etag| etag == &object.etag)
                        && object.provider_version.is_none(),
                    "versionless source closure differs from trusted catalogue or observed HEAD"
                );
                Some(closure)
            } else {
                None
            };
            ExternalCopyOriginal {
                version: if metadata.transfer.is_some() {
                    3
                } else if metadata.profile.protected_versionless {
                    2
                } else {
                    1
                },
                deployment_id: self.work.deployment_id.clone(),
                topology: current.topology.clone(),
                binding_id: LeaseInteger::new(current.binding.id)?,
                binding_stable_id: current.binding.stable_id.clone(),
                binding_resource_version: LeaseInteger::new(current.binding.resource_version)?,
                snapshot_revision: selector.snapshot_revision.clone(),
                source: current.source.clone(),
                destination: current.destination.clone(),
                path: path.into(),
                source_object: CopySourceObject {
                    provider_version: if protected.is_some() {
                        None
                    } else {
                        Some(object.provider_version.context(
                            "external copy requires a real non-null immutable provider version",
                        )?)
                    },
                    etag: object.etag,
                    bytes: LeaseInteger::new(i64::try_from(object.size)?)?,
                    guard_stamp: protected.map(|closure| closure.guard_stamp.clone()),
                },
                read_generation: metadata
                    .transfer
                    .as_ref()
                    .map_or(metadata.profile.read_generation, |pins| {
                        pins.source_binding.read_generation
                    }),
                write_generation: metadata.profile.write_generation,
                binding_write_revision: metadata.profile.binding_write_revision,
                profile_digest: metadata.profile.profile_digest,
                part_bytes: metadata.profile.part_bytes,
                expected_sha256,
                source_receipt_digest: protected.map(|closure| closure.receipt_digest.clone()),
                transfer: metadata.transfer,
            }
        };
        original.validate()?;
        ensure!(
            original.source_object.bytes.get() > 0,
            "empty external copy is not qualified"
        );
        context::after_sql(
            metadata_observation,
            &current,
            query.claim.as_ref(),
            catalogue.as_ref(),
            &original.profile_digest,
            &original.snapshot_revision,
            original.transfer.as_ref().map(|pins| &pins.source_binding),
        );
        // Create + ordered parts + Complete. Each iteration is a new metadata
        // permission over the same original; it never invents another upload.
        for _ in 0..original
            .part_count()?
            .checked_add(2)
            .context("copy step bound overflow")?
        {
            let claim = self
                .recheck_copy(&current, operation, claim_token, source, destination)
                .await?;
            self.check_snapshot(&current, &original.snapshot_revision)
                .await?;
            self.check_source_selector(
                &current,
                original.transfer.as_ref().map(|pins| &pins.source_binding),
            )
            .await?;
            let now = aos_hub_core::clock::now_unix_secs();
            let plan = self.work.plan_for_placement(
                destination,
                &current.binding,
                StorageWorkOperation::CopyObject {
                    source_binding_id: original
                        .transfer
                        .as_ref()
                        .map(|pins| pins.source_binding.binding_id.get()),
                    source_placement_id: source.id,
                    source_placement_resource_version: source.resource_version,
                    source_prefix: source.prefix.clone(),
                    path: path.into(),
                    expected_size: original.source_object.bytes.get() as u64,
                    expected_etag: original.source_object.etag.clone(),
                },
                now,
            )?;
            self.recheck_catalogue(source, path, &catalogue).await?;
            let request = if original.transfer.is_some() {
                let source_plan = self.work.plan_for_placement(
                    source,
                    &current.source_binding,
                    StorageWorkOperation::Head { path: path.into() },
                    now,
                )?;
                ExternalCopyRequest::new_cross_binding(
                    original.clone(),
                    claim,
                    plan,
                    source_plan,
                    CopyControl::Advance,
                    now,
                )?
            } else {
                ExternalCopyRequest::new(original.clone(), claim, plan, CopyControl::Advance, now)?
            };
            let (progress, observation) =
                self.work.external_copy_control_observed(&request).await?;
            self.recheck_catalogue(source, path, &catalogue).await?;
            self.recheck_copy(&current, operation, claim_token, source, destination)
                .await?;
            self.check_snapshot(&current, &original.snapshot_revision)
                .await?;
            self.check_source_selector(
                &current,
                original.transfer.as_ref().map(|pins| &pins.source_binding),
            )
            .await?;
            progress.validate(&original)?;
            ensure!(
                !progress.pending,
                "copy retains an unresolved provider turn"
            );
            if progress.phase == CopyPhase::Closed {
                self.recheck_catalogue(source, path, &catalogue).await?;
                context::after_sql(
                    observation,
                    &current,
                    Some(&request.claim),
                    catalogue.as_ref(),
                    &original.profile_digest,
                    &original.snapshot_revision,
                    original.transfer.as_ref().map(|pins| &pins.source_binding),
                );
                return Ok(Some(original.source_object.bytes.get() as u64));
            }
            ensure!(
                progress.phase != CopyPhase::Aborted,
                "copy original was aborted"
            );
            context::after_sql(
                observation,
                &current,
                Some(&request.claim),
                catalogue.as_ref(),
                &original.profile_digest,
                &original.snapshot_revision,
                original.transfer.as_ref().map(|pins| &pins.source_binding),
            );
        }
        anyhow::bail!("external copy exceeded its original bounded action count")
    }

    async fn ensure_copy_snapshots(&self, current: &CurrentCopy) -> Result<()> {
        self.work
            .ensure_remote_binding_snapshot(&self.db, &current.binding)
            .await?;
        if current.source_binding.id != current.binding.id {
            self.work
                .ensure_remote_binding_snapshot(&self.db, &current.source_binding)
                .await?;
        }
        Ok(())
    }

    fn copy_metadata_query(
        &self,
        current: &CurrentCopy,
        source: &SurfacePlacementRecord,
        claim: Option<CopyClaim>,
        plan: aos_hub_core::storage_work::StorageWorkPlan,
        path: &str,
        now: i64,
    ) -> Result<CopyMetadataRequest> {
        if current.source_binding.id == current.binding.id {
            return CopyMetadataRequest::new(
                current.topology.clone(),
                current.source.clone(),
                current.destination.clone(),
                claim,
                plan,
                path.into(),
                now,
            );
        }
        let source_plan = self.work.plan_for_placement(
            source,
            &current.source_binding,
            StorageWorkOperation::Head { path: path.into() },
            now,
        )?;
        CopyMetadataRequest::new_cross_binding(
            current.topology.clone(),
            current.source.clone(),
            current.destination.clone(),
            claim,
            plan,
            source_plan,
            path.into(),
            now,
        )
    }

    async fn check_source_selector(
        &self,
        current: &CurrentCopy,
        pin: Option<&CopySourceBindingPin>,
    ) -> Result<()> {
        let Some(pin) = pin else {
            ensure!(
                current.source_binding.id == current.binding.id,
                "independent source pins absent"
            );
            return Ok(());
        };
        ensure!(
            pin.binding_id.get() == current.source_binding.id
                && pin.binding_stable_id == current.source_binding.stable_id
                && pin.binding_resource_version.get() == current.source_binding.resource_version,
            "copy source Read binding differs from current SQL"
        );
        let credentials = self
            .db
            .list_current_binding_credentials(current.source_binding.id)
            .await?;
        self.work.validate_published_binding_snapshot(
            &current.source_binding,
            &credentials,
            &pin.snapshot_revision,
        )?;
        ensure!(
            credentials
                .iter()
                .any(|credential| credential.purpose == "read"
                    && credential.generation == pin.read_generation.get()),
            "copy current source Read generation differs"
        );
        Ok(())
    }

    async fn copy_catalogue(
        &self,
        source: &SurfacePlacementRecord,
        path: &str,
    ) -> Result<Option<SurfaceObjectRecord>> {
        let surface = match (source.registry_id, source.cache_id) {
            (Some(id), None) => SurfaceTarget::Registry(id),
            (None, Some(id)) => SurfaceTarget::BinaryCache(id),
            _ => anyhow::bail!("copy source has no exact logical surface"),
        };
        let object = self.db.surface_object_named(surface, path).await?;
        if let Some(object) = &object {
            ensure!(
                object.object_key == path
                    && object.lifecycle_state == "active"
                    && object.registry_id == source.registry_id
                    && object.cache_id == source.cache_id,
                "copy source catalogue is not the selected active object"
            );
        }
        Ok(object)
    }

    async fn recheck_catalogue(
        &self,
        source: &SurfacePlacementRecord,
        path: &str,
        original: &Option<SurfaceObjectRecord>,
    ) -> Result<()> {
        ensure!(
            self.copy_catalogue(source, path).await? == *original,
            "copy source catalogue changed after selection"
        );
        Ok(())
    }

    async fn current_copy(
        &self,
        original: &TopologyOperationRecord,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        dispatch: bool,
    ) -> Result<CurrentCopy> {
        let operation = self
            .db
            .topology_operation(&original.operation_id)
            .await?
            .context("copy operation disappeared")?;
        ensure!(
            operation.resource_version == original.resource_version
                && if dispatch {
                    operation.state == "running"
                } else {
                    matches!(operation.state.as_str(), "running" | "failed" | "cancelled")
                },
            "copy operation no longer matches current original or phase"
        );
        let targets = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await?;
        ensure!(
            targets.len() == 2,
            "copy requires exactly two sealed placement targets"
        );
        let source_target = targets
            .iter()
            .find(|target| target.role == "source")
            .context("copy source target absent")?;
        let destination_target = targets
            .iter()
            .find(|target| target.role == "primary")
            .context("copy destination target absent")?;
        let topology =
            CopyTopologyOriginal::from_records(&operation, source_target, destination_target)?;
        ensure!(
            topology
                == CopyTopologyOriginal::from_records(original, source_target, destination_target)?,
            "copy operation immutable original changed"
        );
        // Generation equality alone cannot establish target identity. Resolve
        // both exact sealed selectors independently to their actual SQL row IDs.
        let resolved_source = self
            .db
            .surface_placement_by_operation_target(&source_target.stable_id)
            .await?
            .context("copy source target disappeared")?;
        let resolved_destination = self
            .db
            .surface_placement_by_operation_target(&destination_target.stable_id)
            .await?
            .context("copy destination target disappeared")?;
        ensure!(
            resolved_source.id == source.id
                && resolved_destination.id == destination.id
                && resolved_source.effective_read_enabled
                && resolved_destination.desired_state == "active",
            "copy resolved another or ineligible placement"
        );
        for target in [source_target, destination_target] {
            ensure!(
                self.db
                    .topology_operation_target_scope("placement", &target.stable_id)
                    .await?
                    .as_deref()
                    == Some(target.authorization_scope_key.as_str()),
                "copy target authorization scope changed"
            );
        }
        let source_pin = CopyPlacementPin::from_record(&resolved_source, &topology.source)?;
        let destination_pin =
            CopyPlacementPin::from_record(&resolved_destination, &topology.destination)?;
        ensure!(
            source_pin == CopyPlacementPin::from_record(source, &topology.source)?
                && destination_pin
                    == CopyPlacementPin::from_record(destination, &topology.destination)?,
            "copy caller placement differs from resolved original"
        );
        let binding = self
            .db
            .binding(destination.binding_id)
            .await?
            .context("copy binding disappeared")?;
        let source_binding = if source.binding_id == binding.id {
            binding.clone()
        } else {
            self.db
                .binding(source.binding_id)
                .await?
                .context("copy source binding disappeared")?
        };
        ensure!(
            matches!(binding.kind.as_str(), "s3" | "r2")
                && !binding.is_instance_default
                && matches!(source_binding.kind.as_str(), "s3" | "r2")
                && !source_binding.is_instance_default,
            "external copy requires independently admitted external bindings"
        );
        let revision = self
            .db
            .placement_publication_write_revision(destination.id)
            .await?
            .context("copy destination lacks a current validated writer")?;
        ensure!(
            revision.binding_id == binding.id && revision.writes_supported,
            "copy writer differs from physical binding"
        );
        let owner = if let Some(id) = destination.registry_id {
            self.db
                .registry_by_id(id)
                .await?
                .context("copy registry disappeared")?
                .owner_scope_key
        } else if let Some(id) = destination.cache_id {
            self.db
                .binary_cache_by_id(id)
                .await?
                .context("copy cache disappeared")?
                .owner_scope_key
        } else {
            anyhow::bail!("copy surface absent");
        };
        let grant = self
            .db
            .placement_copy_consumer_grant(&binding, &owner)
            .await?;
        let source_grant = if source_binding.id == binding.id {
            grant.clone()
        } else {
            self.db
                .placement_copy_consumer_grant(&source_binding, &owner)
                .await?
        };
        Ok(CurrentCopy {
            topology,
            source: source_pin,
            destination: destination_pin,
            source_binding,
            binding,
            revision,
            source_grant,
            grant,
        })
    }

    async fn recheck_copy(
        &self,
        pinned: &CurrentCopy,
        operation: &TopologyOperationRecord,
        token: &str,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
    ) -> Result<CopyClaim> {
        let current = self
            .current_copy(operation, source, destination, true)
            .await?;
        compare_current(pinned, &current)?;
        self.db
            .placement_copy_claim(operation, token, aos_hub_core::clock::now_unix_secs())
            .await
    }

    async fn check_snapshot(&self, current: &CurrentCopy, expected: &str) -> Result<()> {
        let credentials = self
            .db
            .list_current_binding_credentials(current.binding.id)
            .await?;
        self.work
            .validate_published_binding_snapshot(&current.binding, &credentials, expected)?;
        Ok(())
    }
}

fn compare_current(pinned: &CurrentCopy, current: &CurrentCopy) -> Result<()> {
    ensure!(
        current.topology == pinned.topology
            && current.source == pinned.source
            && current.destination == pinned.destination
            && current.source_binding.resource_version == pinned.source_binding.resource_version
            && current.source_binding.stable_id == pinned.source_binding.stable_id
            && current.binding.resource_version == pinned.binding.resource_version
            && current.binding.stable_id == pinned.binding.stable_id
            && current.revision == pinned.revision
            && current.source_grant == pinned.source_grant
            && current.grant == pinned.grant,
        "copy current SQL authority changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

// Versionless recovery keeps the admission's mandatory trusted catalogue size.
// Version one preserves its existing optional catalogue-size compatibility.
fn require_retained_catalogue_size(
    version: u8,
    original_bytes: i64,
    catalogue: Option<&SurfaceObjectRecord>,
) -> Result<()> {
    if matches!(version, 2 | 3) {
        ensure!(
            catalogue.and_then(|object| object.size) == Some(original_bytes),
            "retained protected copy lacks exact current catalogue size"
        );
    } else if let Some(object) = catalogue {
        ensure!(
            object.size.is_none_or(|bytes| bytes == original_bytes),
            "retained copy differs from current catalogue size"
        );
    }
    Ok(())
}

// Matches the catalogue SHA-256 encodings already accepted by placement scans.
// The retained copy original always carries one canonical lowercase digest.
fn catalogue_sha256(value: &str) -> Result<String> {
    let bytes = if let Some(encoded) = value.strip_prefix("sha256-") {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    } else {
        hex::decode(value.strip_prefix("sha256:").unwrap_or(value))?
    };
    ensure!(bytes.len() == 32, "catalogue content is not SHA-256");
    Ok(hex::encode(bytes))
}
