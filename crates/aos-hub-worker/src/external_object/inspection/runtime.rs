//! Current-publication typed parsers over closed or immutable-version sources.
//!
//! Only the source guard opens provider streams. This adapter retains the
//! authenticated application cutoff, real capacity reservation and native
//! cancellation owner through each EOF. Versionless reads require a permanent
//! producer closure; versioned reads require actual version/ETag/size discovery
//! and exact conditional responses. Both emit bounded storage-local parser DTOs.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    fetch::{StreamedRead, SurfaceFetch},
    storage_work::{
        protected_inspection::ProtectedInspectionSource, StorageBindingPublication,
        StorageObjectIdentity, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan,
        StorageWorkResult,
    },
};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use worker::{Env, ResponseBody};

use super::super::{
    config::{configured, Config},
    copy::{
        self,
        config::Domain,
        lifetime::Lifetime,
        source,
        source_protocol::{InspectionLookup, Operation},
        window::DispatchWindow,
    },
    executor::select_cohort,
};
use super::selection::Selection;

/// Selects an installed inventory mode without creating authority.
///
/// # Errors
/// Refuses malformed or incomplete installed configuration and stale, ambiguous
/// or changed physical binding coordinates. It never removes expired identity.
pub(crate) fn installed_inventory_mode(
    env: &Env,
    snapshot: &aos_hub_core::storage_work::StorageBindingSnapshot,
) -> Result<super::InventoryDomainMode> {
    let Some(object) = configured(env)? else {
        let copy = js_sys::Reflect::get(
            env.as_ref(),
            &wasm_bindgen::JsValue::from_str(copy::config::CONFIG_VAR),
        )
        .map_err(|_| anyhow::anyhow!("inventory copy configuration unavailable"))?;
        ensure!(
            copy.is_undefined(),
            "installed inventory copy domain lacks its object configuration"
        );
        return Ok(super::InventoryDomainMode::Unconfigured);
    };
    let config = copy::config::configured(env, &object)?;
    super::inventory_domain_mode(snapshot, object.manages(snapshot)?, config.as_ref())
}

/// Executes compact typed reads under the current installed source authority.
///
/// # Errors
/// Refuses stale plans, unclosed or changed sources, unavailable leases,
/// cancellation, exceeded format bounds or invalid semantic projections.
pub(crate) async fn execute(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
    signal: &worker::web_sys::AbortSignal,
) -> Result<Option<StorageWorkResult>> {
    execute_with_control(env, plan, publication, signal, None).await
}

/// Parses an attached registry control while companion reads retain their gate.
///
/// # Errors
/// Refuses mismatched bytes, changed sources, stale permission, cancellation,
/// missing installed cohorts or an unacknowledged coordinated control write.
pub(crate) async fn execute_prepared(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
    signal: &worker::web_sys::AbortSignal,
    control: &[u8],
) -> Result<Option<StorageWorkResult>> {
    aos_hub_core::storage_work::prepared_control::validate_body(&plan.operation, control)?;
    execute_with_control(env, plan, publication, signal, Some(control)).await
}

async fn execute_with_control(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
    signal: &worker::web_sys::AbortSignal,
    control: Option<&[u8]>,
) -> Result<Option<StorageWorkResult>> {
    if !supported(&plan.operation) {
        return Ok(None);
    }
    let Some(object) = configured(env)? else {
        return Ok(None);
    };
    if !object.manages(&publication.snapshot)? {
        return Ok(None);
    }
    let config = copy::config::configured(env, &object)?
        .context("protected inspection copy domain absent")?;
    let domain = config
        .domains
        .iter()
        .find(|domain| domain.read_cohort.association.binding_id.get() == plan.binding_id)
        .context("protected inspection read domain absent")?;
    let reader = GuardedReader {
        env,
        plan,
        publication,
        signal,
        object: &object,
        domain,
        versioned_sources: std::cell::RefCell::new(Vec::new()),
    };
    reader.current()?;
    crate::direct_upload::provider_capacity::policy::configure_bounded(
        env,
        u32::from(domain.provider_concurrency),
        3,
    )?;

    let fresh = || reader.current();
    let buffer_window = DispatchWindow {
        expires_at: plan.expires_at,
        uncertainty: object.clock_uncertainty,
        client_signal: signal,
        fresh: &fresh,
        lifetime: Lifetime::new(signal.clone())?,
    };
    let _parser_buffer = buffer_window
        .run(super::acquire_parser_buffer(&plan.operation, &fresh))
        .await?;
    reader.current()?;

    use StorageWorkOperation as Op;
    let (outcome, source_bytes) = match &plan.operation {
        Op::VerifyPreparedGitIndex { .. } | Op::PutPreparedControl { .. } => {
            let control = control.context("prepared inspection has no attached control")?;
            let result =
                crate::surface::prepared_control::validate_control(&reader, plan, control).await?;
            reader.current()?;
            if matches!(plan.operation, Op::PutPreparedControl { .. }) {
                super::super::put_prepared_control(env, plan, publication, control, signal).await?;
            }
            result
        }
        Op::Head { path } => {
            let (metadata, _, _, scope) = reader.lookup(path).await?;
            if let Some(identity) = metadata.versioned_source {
                let evidence =
                    aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
                        version: 1,
                        producer_profile_digest: domain.producer_profile_digest.clone(),
                        configured_domain_digest: domain.commitment()?,
                        scope,
                        source: identity.clone(),
                        range: None,
                        metadata_only: true,
                        sha256: hex::encode(Sha256::digest([])),
                    };
                evidence.validate()?;
                reader.versioned_sources.borrow_mut().push(evidence);
                reader.current()?;
                return Ok(Some(reader.result(
                    StorageWorkOutcome::Head {
                        object: identity,
                        guarded_source: None,
                    },
                    0,
                )));
            }
            let Some(closure) = metadata.closure else {
                return Ok(Some(crate::surface::storage_work_result(
                    plan,
                    StorageWorkOutcome::NotFound,
                    0,
                )));
            };
            let identity = StorageObjectIdentity {
                key: plan.object_key(path)?,
                size: u64::try_from(closure.bytes.get())?,
                etag: metadata.etag.context("protected HEAD tag absent")?,
                provider_version: None,
            };
            let guarded = ProtectedInspectionSource {
                version: 1,
                scope,
                closure,
            };
            guarded.validate_identity(
                plan,
                path,
                &domain.read_cohort.association.binding_prefix,
                &identity,
            )?;
            (
                StorageWorkOutcome::Head {
                    object: identity,
                    guarded_source: Some(guarded),
                },
                0,
            )
        }
        Op::HashOciRange {
            path,
            start,
            end,
            sha256_state,
            ..
        } => {
            let mut state = sha256_state.clone();
            state.validate()?;
            ensure!(
                state.total_bytes == *start,
                "protected inventory continuation offset differs"
            );
            let Some((identity, guarded)) = reader
                .read_into(
                    path,
                    Some((*start, *end)),
                    aos_hub_core::storage_work::MAX_OCI_HASH_RANGE_BYTES,
                    None,
                    |chunk| {
                        if !chunk.is_empty() {
                            state.update(chunk)?;
                        }
                        Ok(())
                    },
                )
                .await?
            else {
                anyhow::bail!("protected inventory lost its retained source");
            };
            ensure!(
                state.total_bytes == end.checked_add(1).context("inventory interval overflow")?,
                "protected inventory did not finish its exact interval"
            );
            (
                StorageWorkOutcome::OciRangeHashed {
                    source: identity,
                    start: *start,
                    end: *end,
                    sha256_state: state,
                    guarded_source: guarded,
                },
                end - start + 1,
            )
        }
        Op::InspectMetadata { path } => {
            let Some(read) = reader
                .whole(path, aos_hub_core::storage_work::MAX_METADATA_BYTES, None)
                .await?
            else {
                return Ok(Some(crate::surface::storage_work_result(
                    plan,
                    StorageWorkOutcome::NotFound,
                    0,
                )));
            };
            let source_bytes = read.identity.size;
            (
                StorageWorkOutcome::Metadata {
                    source: read.identity,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(read.bytes),
                },
                source_bytes,
            )
        }
        Op::InspectMetadataObjects { paths, cursor } => {
            let mut result =
                crate::surface::metadata_batch::inspect(&reader, plan, paths, *cursor).await?;
            result.versioned_sources = reader.versioned_sources.borrow().clone();
            while serde_json::to_vec(&result)?.len() > aos_hub_core::storage_work::MAX_RESULT_BYTES
            {
                let StorageWorkOutcome::MetadataObjects { page } = &mut result.outcome else {
                    anyhow::bail!("metadata evidence result mode differs");
                };
                ensure!(
                    page.objects.len() > 1,
                    "metadata source evidence cannot fit first object"
                );
                page.objects.pop();
                page.next_cursor = Some(*cursor + page.objects.len());
            }
            reader.current()?;
            return Ok(Some(result));
        }
        Op::InspectGitObject { oid } => {
            let (projection, count) =
                crate::surface::inspect_guarded_git_object(&reader, plan, oid).await?;
            let outcome = projection.map_or(StorageWorkOutcome::NotFound, |projection| {
                StorageWorkOutcome::GitObject {
                    source: projection.source,
                    oid: projection.oid,
                    object_kind: projection.object_kind,
                    content_base64: projection.content_base64,
                }
            });
            (outcome, count)
        }
        Op::InspectGitObjects { oids } => {
            crate::surface::inspect_guarded_git_objects(&reader, plan, oids).await?
        }
        Op::FilterGitTreeEntries { oid, names, cursor } => {
            crate::tree_projection::inspect_with_reader(&reader, plan, oid, names, cursor.as_ref())
                .await?
        }
        Op::InspectDocumentation {
            package_name,
            package_version,
            platform,
            artifact,
            cursor,
        } => {
            crate::surface::inspect_documentation(
                &reader,
                package_name,
                package_version,
                platform,
                artifact,
                *cursor,
            )
            .await?
        }
        Op::InspectDocumentationContent {
            package_name,
            package_version,
            platform,
            artifact,
        } => {
            crate::documentation_projection::inspect_content(
                &reader,
                package_name,
                package_version,
                platform,
                artifact,
            )
            .await?
        }
        Op::InspectOciRange { path, start, end } => {
            let Some((bytes, identity, guarded)) =
                reader.range_bytes(path, *start, *end, None).await?
            else {
                return Ok(Some(crate::surface::storage_work_result(
                    plan,
                    StorageWorkOutcome::NotFound,
                    0,
                )));
            };
            (
                StorageWorkOutcome::OciRange {
                    guarded_source: guarded,
                    source: identity,
                    start: *start,
                    end: *end,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                },
                end - start + 1,
            )
        }
        Op::InspectStoredGitPack { .. } | Op::FilterStoredGitPackTree { .. } => {
            return reader.pack().await.map(Some);
        }
        _ => anyhow::bail!("protected typed operation differs"),
    };
    reader.current()?;
    Ok(Some(reader.result(outcome, source_bytes)))
}

fn supported(operation: &StorageWorkOperation) -> bool {
    matches!(
        operation,
        StorageWorkOperation::Head { .. }
            | StorageWorkOperation::VerifyPreparedGitIndex { .. }
            | StorageWorkOperation::PutPreparedControl { .. }
            | StorageWorkOperation::HashOciRange { .. }
            | StorageWorkOperation::InspectMetadata { .. }
            | StorageWorkOperation::InspectMetadataObjects { .. }
            | StorageWorkOperation::InspectGitObject { .. }
            | StorageWorkOperation::InspectGitObjects { .. }
            | StorageWorkOperation::FilterGitTreeEntries { .. }
            | StorageWorkOperation::InspectDocumentation { .. }
            | StorageWorkOperation::InspectDocumentationContent { .. }
            | StorageWorkOperation::InspectOciRange { .. }
            | StorageWorkOperation::InspectStoredGitPack { .. }
            | StorageWorkOperation::FilterStoredGitPackTree { .. }
    )
}

struct GuardedReader<'a> {
    env: &'a Env,
    plan: &'a StorageWorkPlan,
    publication: &'a StorageBindingPublication,
    signal: &'a worker::web_sys::AbortSignal,
    object: &'a Config,
    domain: &'a Domain,
    versioned_sources: std::cell::RefCell<
        Vec<aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource>,
    >,
}

struct Whole {
    bytes: Vec<u8>,
    identity: StorageObjectIdentity,
    guarded: Option<ProtectedInspectionSource>,
}

// Lifetime registrations handle the actual caller signal. Their Drop removes
// the registration, so this separate owner also aborts on deadline unwind.
struct RequestAbort(worker::web_sys::AbortController);

impl RequestAbort {
    fn new() -> Result<Self> {
        worker::web_sys::AbortController::new()
            .map(Self)
            .map_err(|_| anyhow::anyhow!("inspection request cancellation unavailable"))
    }

    fn signal(&self) -> worker::web_sys::AbortSignal {
        self.0.signal()
    }
}

impl Drop for RequestAbort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl GuardedReader<'_> {
    fn versioned(&self) -> bool {
        self.domain
            .provider_contract
            .protected_versionless
            .is_none()
    }

    fn result(&self, outcome: StorageWorkOutcome, source_bytes: u64) -> StorageWorkResult {
        let mut result = crate::surface::storage_work_result(self.plan, outcome, source_bytes);
        result.versioned_sources = self.versioned_sources.borrow().clone();
        result
    }

    fn current(&self) -> Result<()> {
        let clock = self.object.clock();
        let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let association = &self.domain.read_cohort.association;
        self.plan.validate(&deployment, clock.observed_at)?;
        ensure!(!self.signal.aborted(), "inspection invocation canceled");
        self.publication
            .snapshot
            .authorizes(self.plan, &deployment, clock.observed_at)?;
        ensure!(
            association.binding_stable_id == self.publication.snapshot.binding_stable_id
                && association.binding_resource_version.get() == self.plan.binding_resource_version
                && association.binding_prefix == self.publication.snapshot.object_prefix
                && select_cohort(
                    self.object,
                    self.publication,
                    "read",
                    association.binding_write_revision.get()
                )? == &self.domain.read_cohort,
            "inspection current publication differs"
        );
        Ok(())
    }

    async fn lookup(
        &self,
        path: &str,
    ) -> Result<(
        InspectionLookup,
        String,
        Selection,
        aos_hub_core::storage_authority::control::StorageAuthorityObjectScope,
    )> {
        self.current()?;
        let selection = Selection::from_plan(self.plan, path)?;
        let scope = self.object.scope(
            &self.domain.read_cohort,
            aos_hub_core::keymap::r2_key(
                &self.domain.read_cohort.association.binding_prefix,
                &self.plan.object_key(path)?,
            ),
        )?;
        let fresh = || self.current();
        let window = DispatchWindow {
            expires_at: self.plan.expires_at,
            uncertainty: self.object.clock_uncertainty,
            client_signal: self.signal,
            fresh: &fresh,
            lifetime: Lifetime::new(self.signal.clone())?,
        };
        let lease = window
            .run(super::super::stage::planning::acquire_configured_lease(
                self.env,
                self.object,
                &self.domain.issuer_installation,
                &self.domain.read_cohort,
                &self.domain.read_cohort.admitted_prefix,
            ))
            .await?;
        self.current()?;
        let message = source::inspection_request(
            self.plan,
            self.domain.commitment()?,
            scope.clone(),
            selection.clone(),
            if self.versioned() {
                Operation::InspectVersionedLookup {
                    read_lease: lease.clone(),
                }
            } else {
                Operation::InspectLookup {
                    read_lease: lease.clone(),
                }
            },
        )?;
        let controller = RequestAbort::new()?;
        let _registration = window
            .lifetime
            .register(controller.0.clone().into(), "abort")?;
        let result = window
            .run(source::inspection_lookup(
                self.env,
                &message,
                &controller.signal(),
            ))
            .await?;
        window.check()?;
        self.current()?;
        Ok((result, lease, selection, scope))
    }

    async fn read_into(
        &self,
        path: &str,
        interval: Option<(u64, u64)>,
        maximum: usize,
        initial: Option<crate::direct_upload::provider_capacity::Permit>,
        mut consume: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<(StorageObjectIdentity, Option<ProtectedInspectionSource>)>> {
        let (metadata, lease, selection, scope) = self.lookup(path).await?;
        let (identity, guarded) = if self.versioned() {
            let Some(identity) = metadata.versioned_source else {
                return Ok(None);
            };
            ensure!(
                metadata.closure.is_none(),
                "versioned read adopted a closure"
            );
            (identity, None)
        } else {
            let Some(closure) = metadata.closure else {
                return Ok(None);
            };
            let identity = StorageObjectIdentity {
                key: self.plan.object_key(path)?,
                size: u64::try_from(closure.bytes.get())?,
                etag: metadata.etag.context("closed inspection tag absent")?,
                provider_version: None,
            };
            let guarded = ProtectedInspectionSource {
                version: 1,
                scope: scope.clone(),
                closure,
            };
            guarded.validate_identity(
                self.plan,
                path,
                &self.domain.read_cohort.association.binding_prefix,
                &identity,
            )?;
            (identity, Some(guarded))
        };
        let etag = identity.etag.clone();
        let total = identity.size;
        if let StorageWorkOperation::HashOciRange {
            total,
            strong_etag,
            guarded_source,
            expected_provider_version,
            ..
        } = &self.plan.operation
        {
            ensure!(
                guarded_source.as_ref() == guarded.as_ref()
                    && expected_provider_version == &identity.provider_version
                    && *total == identity.size
                    && strong_etag == &identity.etag,
                "protected inventory HEAD changed its frozen closed source"
            );
        }
        let (offset, bytes) = match interval {
            Some((start, end)) => {
                ensure!(start <= end && end < total, "inspection range differs");
                (start, end - start + 1)
            }
            None => (0, total),
        };
        ensure!(
            bytes <= maximum as u64 && bytes <= aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES,
            "inspection format read bound exceeded"
        );
        let mut sha = Sha256::new();
        let range_bound = self
            .domain
            .provider_contract
            .maximum_copy_read_range_bytes
            .context("typed inspection accepted Read range bound absent")?
            .get() as u64;
        ensure!(
            range_bound > 0 && range_bound <= aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES,
            "inspection accepted source range bound differs"
        );
        let mut initial = initial;
        let mut completed = 0_u64;
        let mut opened_empty = false;
        while completed < bytes || self.versioned() && bytes == 0 && !opened_empty {
            opened_empty = true;
            let range_bytes = (bytes - completed).min(range_bound);
            let range_offset = offset
                .checked_add(completed)
                .context("inspection range offset overflow")?;
            let fresh = || self.current();
            let window = DispatchWindow {
                expires_at: self.plan.expires_at,
                uncertainty: self.object.clock_uncertainty,
                client_signal: self.signal,
                fresh: &fresh,
                lifetime: Lifetime::new(self.signal.clone())?,
            };
            let mut message = source::inspection_request(
                self.plan,
                self.domain.commitment()?,
                scope.clone(),
                selection.clone(),
                match &guarded {
                    Some(guarded) => Operation::InspectRange {
                        closure: guarded.closure.clone(),
                        read_lease: lease.clone(),
                        etag: etag.clone(),
                        offset: range_offset,
                        bytes: range_bytes,
                    },
                    None => Operation::InspectVersionedRange {
                        source: identity.clone(),
                        read_lease: lease.clone(),
                        offset: range_offset,
                        bytes: range_bytes,
                    },
                },
            )?;
            let reservation = source::reserve(&mut message, initial.take(), &window).await?;
            let controller = RequestAbort::new()?;
            let _registration = window
                .lifetime
                .register(controller.0.clone().into(), "abort")?;
            let response = window
                .run(source::range(self.env, &message, &controller.signal()))
                .await?;
            let ResponseBody::Stream(body) = response.body() else {
                anyhow::bail!("inspection stream absent");
            };
            let mut unhanded =
                super::super::oci::byte_stream::UnhandedStream::new(body.clone().into());
            let reader = copy::stream::Reader::new(body.clone().into(), &window.lifetime)?;
            unhanded.disarm();
            let mut counted = 0_u64;
            loop {
                let (view, done) = window.run(reader.read()).await?;
                counted = counted
                    .checked_add(u64::from(view.length()))
                    .context("inspection count overflow")?;
                ensure!(
                    counted <= range_bytes && (!done || counted == range_bytes),
                    "inspection source truncated or excessive"
                );
                let chunk = view.to_vec();
                sha.update(&chunk);
                consume(&chunk)?;
                if done {
                    break;
                }
            }
            window.check()?;
            completed = completed
                .checked_add(counted)
                .context("inspection range total overflow")?;
            drop(reservation);
        }
        ensure!(
            completed == bytes,
            "inspection did not consume its exact signed interval"
        );
        let sha256 = hex::encode(sha.finalize());
        if interval.is_none() {
            let expected = guarded
                .as_ref()
                .map(|guarded| guarded.closure.sha256.as_str())
                .or(selection.expected_sha256.as_deref());
            ensure!(
                expected.is_none_or(|expected| sha256 == expected),
                "inspection complete encoded SHA differs from its selected source"
            );
        }
        let (after, _, _, after_scope) = self.lookup(path).await?;
        ensure!(
            after_scope == scope
                && after.etag.as_deref() == Some(&etag)
                && match &guarded {
                    Some(guarded) =>
                        after.closure.as_ref() == Some(&guarded.closure)
                            && after.versioned_source.is_none(),
                    None =>
                        after.closure.is_none()
                            && after.versioned_source.as_ref() == Some(&identity),
                },
            "inspection source incarnation changed after EOF"
        );
        self.current()?;
        if self.versioned() {
            let evidence =
                aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource {
                    version: 1,
                    producer_profile_digest: self.domain.producer_profile_digest.clone(),
                    configured_domain_digest: self.domain.commitment()?,
                    scope,
                    metadata_only: false,
                    source: identity.clone(),
                    range: interval,
                    sha256,
                };
            evidence.validate_identity(
                self.plan,
                path,
                &self.domain.read_cohort.association.binding_prefix,
                &identity,
            )?;
            let mut completed = self.versioned_sources.borrow_mut();
            ensure!(
                completed.len() < 128,
                "inspection completed source evidence exceeds bound"
            );
            if !completed.contains(&evidence) {
                completed.push(evidence);
            }
        }
        Ok(Some((identity, guarded)))
    }

    async fn whole(
        &self,
        path: &str,
        maximum: usize,
        initial: Option<crate::direct_upload::provider_capacity::Permit>,
    ) -> Result<Option<Whole>> {
        let mut bytes = Vec::new();
        let read = self
            .read_into(path, None, maximum, initial, |chunk| {
                ensure!(
                    bytes
                        .len()
                        .checked_add(chunk.len())
                        .is_some_and(|size| size <= maximum),
                    "inspection body bound exceeded"
                );
                bytes.extend_from_slice(chunk);
                Ok(())
            })
            .await?;
        Ok(read.map(|(identity, guarded)| Whole {
            bytes,
            identity,
            guarded,
        }))
    }

    async fn range_bytes(
        &self,
        path: &str,
        start: u64,
        end: u64,
        initial: Option<crate::direct_upload::provider_capacity::Permit>,
    ) -> Result<
        Option<(
            Vec<u8>,
            StorageObjectIdentity,
            Option<ProtectedInspectionSource>,
        )>,
    > {
        let mut bytes = Vec::new();
        let read = self
            .read_into(
                path,
                Some((start, end)),
                aos_hub_core::storage_work::MAX_OCI_RANGE_BYTES,
                initial,
                |chunk| {
                    bytes.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .await?;
        Ok(read.map(|(identity, guarded)| (bytes, identity, guarded)))
    }
}

#[async_trait::async_trait(?Send)]
impl SurfaceFetch for GuardedReader<'_> {
    fn describe(&self) -> String {
        "guarded storage-local inspection".into()
    }

    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let maximum = usize::try_from(Selection::from_plan(self.plan, path)?.maximum_bytes)?;
        Ok(self
            .whole(path, maximum, None)
            .await?
            .map(|read| read.bytes))
    }

    async fn inspection_provider_version(
        &self,
        path: &str,
        size: u64,
        etag: &str,
    ) -> Result<Option<String>> {
        if !self.versioned() {
            return Ok(None);
        }
        let key = self.plan.object_key(path)?;
        let completed = self.versioned_sources.borrow();
        let mut matching = completed.iter().filter(|evidence| {
            evidence.range.is_none()
                && evidence.source.key == key
                && evidence.source.size == size
                && evidence.source.etag == etag
        });
        let source = matching
            .next()
            .context("versioned completed inspection evidence absent")?;
        ensure!(
            matching.all(|other| other.source == source.source),
            "versioned inspection identity ambiguous"
        );
        Ok(source.source.provider_version.clone())
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let metadata = self.lookup(path).await?.0;
        Ok(metadata
            .versioned_source
            .map(|source| source.size)
            .or_else(|| metadata.closure.map(|source| source.bytes.get() as u64)))
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        let read = match range {
            Some((start, end)) => self.range_bytes(path, start, end, None).await?,
            None => {
                let maximum =
                    usize::try_from(Selection::from_plan(self.plan, path)?.maximum_bytes)?;
                self.whole(path, maximum, None)
                    .await?
                    .map(|read| (read.bytes, read.identity, read.guarded))
            }
        };
        Ok(read.map(|(bytes, identity, _)| StreamedRead {
            body: axum::body::Body::from(bytes),
            total: identity.size,
            range,
            strong_etag: Some(identity.etag),
            snapshot_lease_id: None,
        }))
    }
}

#[async_trait::async_trait(?Send)]
impl crate::tree_projection::SourceReader for GuardedReader<'_> {
    async fn read(
        &self,
        path: &str,
        maximum: usize,
    ) -> Result<Option<crate::tree_projection::VerifiedSource>> {
        Ok(self.whole(path, maximum, None).await?.map(|read| {
            crate::tree_projection::VerifiedSource {
                bytes: read.bytes,
                identity: read.identity,
                guarded: read.guarded,
            }
        }))
    }
}

impl GuardedReader<'_> {
    async fn pack(&self) -> Result<StorageWorkResult> {
        use crate::direct_upload::provider_capacity::{self, Class};
        use aos_hub_core::mirror_inspection::{MirrorPackProjection, MirrorPackTreeProjection};
        use aos_registry_surface::{
            object::Oid,
            pack_index::projection::{ContentRange, PairReader, Selection as PackSelection},
        };

        let (index_path, selections, profile) = match &self.plan.operation {
            StorageWorkOperation::InspectStoredGitPack {
                index_path,
                selections,
                protected_profile_digest,
            } => (
                index_path.as_str(),
                selections.as_slice(),
                protected_profile_digest.as_str(),
            ),
            StorageWorkOperation::FilterStoredGitPackTree { query } => (
                query.index_path.as_str(),
                &[][..],
                query.protected_profile_digest.as_str(),
            ),
            _ => anyhow::bail!("not a stored pair inspection"),
        };
        ensure!(
            profile == self.domain.producer_profile_digest,
            "stored pair producer profile differs from the installed domain"
        );
        let fresh = || self.current();
        let _buffer = crate::mirror_import::buffers::acquire(false, &fresh).await?;
        let atomic = provider_capacity::acquire_class_checked(2, Class::Bulk, &fresh).await?;
        let (pack_permit, index_permit) = provider_capacity::transfer::split(atomic)?;
        let pack_path = aos_registry_surface::pack_index::companion_pack_path(index_path)
            .context("stored pair path is not canonical")?;
        let mut verifier = PairReader::new(index_path)?;
        // Feed the bounded verifier directly; no second full encoded copy is
        // retained. Release the first source gate at EOF before opening its
        // companion. The second atomic slot stays owned throughout that wait.
        let (pack, pack_guard) = self
            .read_into(
                &pack_path,
                None,
                8 * 1024 * 1024,
                Some(pack_permit),
                |chunk| verifier.feed_pack(chunk),
            )
            .await?
            .context("stored pack has no positively closed source")?;
        let (index, index_guard) = self
            .read_into(
                index_path,
                None,
                4 * 1024 * 1024,
                Some(index_permit),
                |chunk| verifier.feed_index(chunk),
            )
            .await?
            .context("stored index has no positively closed source")?;
        self.current()?;
        let selected = selections
            .iter()
            .map(|selection| {
                Ok(PackSelection {
                    oid: Oid::from_hex(&selection.oid)?,
                    range: selection.range.map(|range| ContentRange {
                        start: range.start,
                        end: range.end,
                    }),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let outcome = if let StorageWorkOperation::FilterStoredGitPackTree { query } =
            &self.plan.operation
        {
            let placeholder = "0".repeat(64);
            let mut cursor = query.cursor.clone();
            if let Some(cursor) = &mut cursor {
                cursor.source_commitment = placeholder.clone();
            }
            let verified = verifier.finish_tree_projection(Oid::from_hex(&query.oid)?, |tree| {
                aos_hub_core::tree_projection::project_tree(
                    &query.oid,
                    tree,
                    &query.names,
                    cursor.as_ref(),
                    &placeholder,
                )
            })?;
            let mut pair = MirrorPackProjection::from_verified(
                verified.pair,
                pack.etag.clone(),
                index.etag.clone(),
            )?;
            pair.pack.provider_version = pack.provider_version.clone();
            pair.index.provider_version = index.provider_version.clone();
            pair.pack.guarded_source = pack_guard.clone();
            pair.index.guarded_source = index_guard.clone();
            let commitment = pair.source_commitment()?;
            ensure!(
                query
                    .cursor
                    .as_ref()
                    .is_none_or(|cursor| cursor.source_commitment == commitment),
                "guarded stored pair cursor changed even if its selected tree disappeared"
            );
            let (object_size, page) = match verified.tree {
                Some(tree) => {
                    let mut page = tree.projection;
                    page.source_commitment = commitment.clone();
                    if let Some(cursor) = &mut page.next_cursor {
                        cursor.source_commitment = commitment;
                    }
                    (Some(tree.object_size), Some(page))
                }
                None => (None, None),
            };
            let projection = MirrorPackTreeProjection {
                pair,
                tree_oid: query.oid.clone(),
                object_size,
                page,
            };
            projection.validate(query)?;
            StorageWorkOutcome::GitPackTreeProjection { projection }
        } else {
            let verified = verifier.finish_available(&selected)?;
            let mut projection = MirrorPackProjection::from_available(
                verified,
                pack.etag.clone(),
                index.etag.clone(),
            )?;
            projection.pack.provider_version = pack.provider_version.clone();
            projection.index.provider_version = index.provider_version.clone();
            projection.pack.guarded_source = pack_guard.clone();
            projection.index.guarded_source = index_guard.clone();
            projection.validate(index_path, selections)?;
            StorageWorkOutcome::GitPackProjection { projection }
        };
        // The two gates are never nested. Recheck both exact retained closures
        // after decoding before exposing a commitment or selected content.
        for (path, identity, guarded) in [
            (pack_path.as_str(), &pack, &pack_guard),
            (index_path, &index, &index_guard),
        ] {
            let (current, _, _, scope) = self.lookup(path).await?;
            ensure!(
                current.etag.as_ref() == Some(&identity.etag)
                    && match guarded {
                        Some(guarded) =>
                            scope == guarded.scope
                                && current.closure.as_ref() == Some(&guarded.closure),
                        None =>
                            current.closure.is_none()
                                && current.versioned_source.as_ref() == Some(identity),
                    },
                "stored pair incarnation changed during verification"
            );
        }
        self.current()?;
        Ok(self.result(
            outcome,
            pack.size
                .checked_add(index.size)
                .context("stored pair byte count overflow")?,
        ))
    }
}
