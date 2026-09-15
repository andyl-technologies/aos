//! Durable storage allocation and child-view command-handler implementation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, MAX_SAFE_INTEGER, ResourceId,
    ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA,
    ResourceContext, SupportedPurposes, resource_set_digest, validate_admission_resource,
    validate_resource_context, validate_resource_contexts,
};
use rustix::fs::{FlockOperation, Mode, OFlags, fchmod, fchown, flock, fstat, mkdirat, openat};
use rustix::process::{Gid, Uid};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    resolve_storage_view_path, validate_provider_owned_path, validate_requested_storage_path,
    validate_storage_claim,
};

const STORAGE_ALLOCATION_INTERFACE: &str = "aos.storage.allocation";
const PERSISTENT_STORAGE_ALLOCATION_INTERFACE: &str = "aos.storage.persistent-allocation";
const STORAGE_VIEW_INTERFACE: &str = "aos.storage.view";
const FILESYSTEM_ENTRY_INTERFACE: &str = "aos.filesystem.entry";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.filesystem.storage-context/v1";
const CLAIM_SCHEMA: &str = "aos.filesystem.storage-claim/v1";
const REALIZATION_SCHEMA: &str = "aos.filesystem.storage-realization/v1";
const ENTRY_REALIZATION_SCHEMA: &str = "aos.filesystem.entry-realization/v1";
const VIEW_REALIZATION_SCHEMA: &str = "aos.filesystem.storage-view-realization/v1";
const LOCK_RETRY: Duration = Duration::from_millis(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Owns filesystem paths used by the package-owned storage handler.
#[derive(Clone, Debug)]
pub struct FilesystemProvider {
    state_root: PathBuf,
    instance_root: PathBuf,
    persistent_root: PathBuf,
    identity_root: PathBuf,
    mutable_roots: Vec<PathBuf>,
}

impl FilesystemProvider {
    /// Constructs the production provider rooted in mutable AOS state.
    #[must_use]
    pub fn production() -> Self {
        Self {
            state_root: "/var/lib/aos/provider-filesystem".into(),
            instance_root: "/run/aos/storage".into(),
            persistent_root: "/var/lib/aos/storage".into(),
            identity_root: "/etc".into(),
            mutable_roots: vec!["/run".into(), "/var/lib".into()],
        }
    }

    /// Handles one bounded command invocation and returns canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error unless the purpose and input schema match, the selected
    /// interface belongs to this provider, all native context is exact, and the
    /// requested filesystem operation completes safely.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest =
                    serde_json::from_slice(input).context("decoding storage admission request")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    serde_json::from_slice(input).context("decoding storage invocation")?;
                ensure!(
                    invocation.schema == INVOCATION_SCHEMA,
                    "unsupported invocation schema"
                );
                ensure!(
                    purpose == purpose_name(invocation.purpose),
                    "invocation purpose differs from argv"
                );
                serde_json::to_value(self.invoke(invocation)?)?
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };
        aos_contract::canonical::canonical_json(&result)
            .context("encoding canonical storage response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        let interface = request.method.interface.name.as_str();
        let desired = request.resource_spec.value.clone();
        let (path, observation, revision) = match interface {
            STORAGE_ALLOCATION_INTERFACE | PERSISTENT_STORAGE_ALLOCATION_INTERFACE => {
                let input: StorageAllocationRequest = decode_value(&desired)?;
                let path = self.storage_path(interface, &request.resource_spec.resource, &input)?;
                let realization: StorageAllocationRealization =
                    decode_value(&request.resource_spec.realization)?;
                ensure!(
                    realization.schema == REALIZATION_SCHEMA
                        && Path::new(&realization.path) == path,
                    "storage realization differs from the deterministic planned path"
                );
                let ownership = self.resolve_ownership(&input)?;
                let claim = self.claim_for(&request.resource_spec.resource)?;
                let claims = self.claims_except(&request.resource_spec.resource)?;
                validate_storage_claim(&path, claims.into_iter().map(|claim| claim.path))?;
                if input.requested_path.is_some() {
                    validate_requested_storage_path(&path)?;
                }
                let state = inspect_storage(
                    &path,
                    claim.as_ref(),
                    request.resource_spec.revision,
                    parse_mode(&input.mode)?,
                    ownership,
                )?;
                if path.exists() && claim.is_none() {
                    return rejected_admission(storage_observation(&desired, None, "unknown")?);
                }
                let observation = storage_observation(
                    &desired,
                    state.is_present().then(|| path_string(&path)).transpose()?,
                    state.observation_state(),
                )?;
                (path, observation, state.revision())
            }
            STORAGE_VIEW_INTERFACE => {
                let input: StorageViewRequest = decode_value(&desired)?;
                let realization: StorageViewRealization =
                    decode_value(&request.resource_spec.realization)?;
                ensure!(
                    realization.schema == VIEW_REALIZATION_SCHEMA
                        && realization.source == input.source
                        && realization.relative_path == input.relative_path,
                    "storage view realization differs from its checked request"
                );
                let source = exact_resource_context(&request.resources, &input.source)?;
                let source_context = decode_provider_context(source)?;
                ensure!(
                    source_context.kind == StorageContextKind::Allocation,
                    "storage view source is not an admitted allocation"
                );
                let root = Path::new(&source_context.path);
                let path = if root.exists() {
                    resolve_storage_view_path(root, input.relative_path.as_deref())?
                } else {
                    planned_child_path(root, input.relative_path.as_deref())?
                };
                let present = root.is_dir();
                let observation = storage_view_observation(
                    &desired,
                    present.then(|| path_string(&path)).transpose()?,
                    if present { "ready" } else { "absent" },
                )?;
                let revision = if present {
                    AdmissionRevision::Present {
                        revision: request.resource_spec.revision,
                    }
                } else {
                    AdmissionRevision::Absent
                };
                (path, observation, revision)
            }
            FILESYSTEM_ENTRY_INTERFACE => self.admit_entry(&request)?,
            _ => bail!("selected interface is not owned by the filesystem storage provider"),
        };
        let kind = match interface {
            STORAGE_VIEW_INTERFACE => StorageContextKind::View,
            FILESYSTEM_ENTRY_INTERFACE => StorageContextKind::Entry,
            _ => StorageContextKind::Allocation,
        };
        let native_context = ability_value(json!({
            "schema": PROVIDER_CONTEXT_SCHEMA,
            "kind": kind,
            "path": path_string(&path)?,
        }))?;
        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision,
            incarnation: None,
            observation,
            native_context,
            supported_purposes: SupportedPurposes::from_ordered(vec![
                InvocationPurpose::Effect,
                InvocationPurpose::Reconcile,
                InvocationPurpose::Cancel,
            ])
            .context("constructing filesystem supported-purpose set")?,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method differs from durable recovery authority"
        );
        let request = &invocation.request;
        ensure!(
            request.schema == REQUEST_SCHEMA,
            "unsupported durable request schema"
        );
        ensure!(
            resource_set_digest(&request.resources)? == request.native_context_digest,
            "invocation resource-set digest differs"
        );
        let target = exact_resource_context(&request.resources, &request.target)?;
        let bound = validate_resource_context(target)?;
        ensure!(
            bound.resource_spec.resource == request.target.resource,
            "bound target resource differs"
        );
        ensure!(
            bound.resource_spec.revision == target.revision,
            "bound target revision differs"
        );
        let provider_context: StorageProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            provider_context.schema == PROVIDER_CONTEXT_SCHEMA,
            "unsupported filesystem context schema"
        );

        let interface = invocation.method.interface.name.as_str();
        let observation_before = self.observe_request(interface, &bound, &request.resources)?;
        let (disposition, evidence, mut outputs) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => (
                InvocationDisposition::Completed,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
                self.release(
                    interface,
                    &bound,
                    &provider_context,
                    invocation.control.attempt_remaining_millis,
                )?;
                let evidence = self.observe_request(interface, &bound, &request.resources)?;
                (InvocationDisposition::Completed, evidence, BTreeMap::new())
            }
            InvocationPurpose::Effect => {
                if interface == FILESYSTEM_ENTRY_INTERFACE {
                    self.apply_entry(
                        &bound,
                        &provider_context,
                        &request.resources,
                        invocation.control.attempt_remaining_millis,
                    )?;
                } else {
                    self.apply(
                        interface,
                        &bound,
                        &provider_context,
                        invocation.control.attempt_remaining_millis,
                    )?;
                }
                let evidence = self.observe_request(interface, &bound, &request.resources)?;
                let outputs = successful_outputs(
                    interface,
                    invocation.method.method.as_str(),
                    &request.target,
                    &provider_context,
                )?;
                (InvocationDisposition::Completed, evidence, outputs)
            }
            InvocationPurpose::Reconcile if invocation.method.method.as_str() == "release" => {
                match observation_state(&observation_before) {
                    Some("absent") => (
                        InvocationDisposition::Completed,
                        observation_before,
                        BTreeMap::new(),
                    ),
                    Some("ready") => {
                        self.release(
                            interface,
                            &bound,
                            &provider_context,
                            invocation.control.recovery_remaining_millis,
                        )?;
                        let evidence =
                            self.observe_request(interface, &bound, &request.resources)?;
                        (InvocationDisposition::Completed, evidence, BTreeMap::new())
                    }
                    _ => (
                        InvocationDisposition::InterventionRequired,
                        observation_before,
                        BTreeMap::new(),
                    ),
                }
            }
            InvocationPurpose::Reconcile => match observation_state(&observation_before) {
                Some("ready") => {
                    let outputs = successful_outputs(
                        interface,
                        invocation.method.method.as_str(),
                        &request.target,
                        &provider_context,
                    )?;
                    (
                        InvocationDisposition::Completed,
                        observation_before,
                        outputs,
                    )
                }
                Some("absent") => (
                    InvocationDisposition::SafeToRetry,
                    observation_before,
                    BTreeMap::new(),
                ),
                _ => (
                    InvocationDisposition::StillIndeterminate,
                    observation_before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Cancel => match observation_state(&observation_before) {
                Some("absent") => (
                    InvocationDisposition::RejectedBeforeEffect,
                    observation_before,
                    BTreeMap::new(),
                ),
                Some("ready") => {
                    let outputs = successful_outputs(
                        interface,
                        invocation.method.method.as_str(),
                        &request.target,
                        &provider_context,
                    )?;
                    (
                        InvocationDisposition::Completed,
                        observation_before,
                        outputs,
                    )
                }
                _ => (
                    InvocationDisposition::Indeterminate,
                    observation_before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Compensate => (
                InvocationDisposition::RejectedBeforeEffect,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::ReconcileCompensation => (
                InvocationDisposition::InterventionRequired,
                observation_before,
                BTreeMap::new(),
            ),
        };
        if disposition == InvocationDisposition::Completed {
            outputs.insert(LocalKey::new("observation")?, evidence.clone());
        }
        Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition,
            evidence,
            outputs,
            native_context_digest: request.native_context_digest,
        })
    }

    fn apply(
        &self,
        interface: &str,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        remaining_millis: u64,
    ) -> Result<()> {
        ensure!(
            context.kind == StorageContextKind::Allocation,
            "storage views have no mutating effect"
        );
        ensure!(
            interface == STORAGE_ALLOCATION_INTERFACE
                || interface == PERSISTENT_STORAGE_ALLOCATION_INTERFACE,
            "selected method has no storage allocation effect"
        );
        let input: StorageAllocationRequest = decode_value(&bound.resource_spec.value)?;
        let expected = self.storage_path(interface, &bound.resource_spec.resource, &input)?;
        let realization: StorageAllocationRealization =
            decode_value(&bound.resource_spec.realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA
                && Path::new(&realization.path) == expected
                && Path::new(&context.path) == expected,
            "planned or admitted storage path drifted before effect"
        );
        let ownership = self.resolve_ownership(&input)?;

        let _lock = StateLock::acquire(&self.state_root, remaining_millis)?;
        let claims = self.claims_except(&bound.resource_spec.resource)?;
        validate_storage_claim(&expected, claims.into_iter().map(|claim| claim.path))?;
        let own_claim = self.claim_for(&bound.resource_spec.resource)?;
        if expected.exists() && own_claim.is_none() {
            bail!("refusing to claim an existing unowned storage path");
        }
        if let Some(claim) = own_claim.as_ref() {
            let metadata = fs::symlink_metadata(&expected)
                .context("inspecting claimed storage path before allocation")?;
            ensure_claimed_identity(&metadata, claim)?;
        }
        let identity = create_directory_nofollow(
            &expected,
            parse_mode(&input.mode)?,
            ownership,
            own_claim.is_some(),
        )?;
        self.write_claim(&StorageClaim {
            schema: CLAIM_SCHEMA.into(),
            resource: bound.resource_spec.resource.clone(),
            path: expected,
            revision: bound.resource_spec.revision,
            mode: input.mode,
            uid: ownership.uid.map(Uid::as_raw),
            gid: ownership.gid.map(Gid::as_raw),
            device: identity.device,
            inode: identity.inode,
            kind: ClaimedEntryKind::Directory,
            content_digest: None,
            active: true,
        })
    }

    fn apply_entry(
        &self,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        resources: &[ResourceContext],
        remaining_millis: u64,
    ) -> Result<()> {
        ensure!(
            context.kind == StorageContextKind::Entry,
            "filesystem entry effect has the wrong admitted context kind"
        );
        let input: FilesystemEntryRequest = decode_value(&bound.resource_spec.value)?;
        let expected = PathBuf::from(&input.destination);
        ensure!(
            Path::new(&context.path) == expected,
            "admitted filesystem entry destination drifted before effect"
        );
        self.validate_entry_prerequisites(&input, resources)?;
        let source = self.resolve_entry_source(&input, resources)?;
        let ownership = self.resolve_entry_ownership(&input)?;
        let mode = parse_mode(&input.mode)?;

        let _lock = StateLock::acquire(&self.state_root, remaining_millis)?;
        let claims = self.claims_except(&bound.resource_spec.resource)?;
        validate_entry_claims(&expected, &input.prerequisites, &claims)?;
        let own_claim = self.claim_for(&bound.resource_spec.resource)?;
        if expected.exists() && own_claim.is_none() {
            bail!("refusing to claim an existing unowned filesystem entry");
        }
        let (identity, content_digest) = match (&input.entry, source.as_deref()) {
            (FilesystemEntryKind::Directory, None) => (
                create_entry_directory_nofollow(&expected, mode, ownership, own_claim.as_ref())?,
                None,
            ),
            (
                FilesystemEntryKind::CopiedFile {
                    maximum_size_bytes, ..
                },
                Some(source),
            ) => {
                let (identity, digest) = copy_file_atomic_nofollow(
                    source,
                    &expected,
                    *maximum_size_bytes,
                    mode,
                    ownership,
                    own_claim.as_ref(),
                )?;
                (identity, Some(digest))
            }
            _ => bail!("filesystem entry source differs from its declared kind"),
        };
        self.write_claim(&StorageClaim {
            schema: CLAIM_SCHEMA.into(),
            resource: bound.resource_spec.resource.clone(),
            path: expected,
            revision: bound.resource_spec.revision,
            mode: input.mode,
            uid: ownership.uid.map(Uid::as_raw),
            gid: ownership.gid.map(Gid::as_raw),
            device: identity.device,
            inode: identity.inode,
            kind: input.entry.claimed_kind(),
            content_digest,
            active: true,
        })
    }

    fn release(
        &self,
        interface: &str,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        remaining_millis: u64,
    ) -> Result<()> {
        let expected = match interface {
            STORAGE_ALLOCATION_INTERFACE | PERSISTENT_STORAGE_ALLOCATION_INTERFACE => {
                ensure!(
                    context.kind == StorageContextKind::Allocation,
                    "storage release has the wrong admitted context kind"
                );
                let input: StorageAllocationRequest = decode_value(&bound.resource_spec.value)?;
                self.storage_path(interface, &bound.resource_spec.resource, &input)?
            }
            FILESYSTEM_ENTRY_INTERFACE => {
                ensure!(
                    context.kind == StorageContextKind::Entry,
                    "filesystem entry release has the wrong admitted context kind"
                );
                let input: FilesystemEntryRequest = decode_value(&bound.resource_spec.value)?;
                PathBuf::from(input.destination)
            }
            _ => bail!("selected method has no filesystem release effect"),
        };
        ensure!(
            Path::new(&context.path) == expected,
            "admitted storage path drifted before release"
        );

        let _lock = StateLock::acquire(&self.state_root, remaining_millis)?;
        if interface == PERSISTENT_STORAGE_ALLOCATION_INTERFACE {
            let mut claim = self
                .claim_for(&bound.resource_spec.resource)?
                .context("persistent release requires its durable ownership claim")?;
            let metadata = fs::symlink_metadata(&expected)
                .context("inspecting persistent allocation before detach")?;
            ensure_claimed_identity(&metadata, &claim)?;
            ensure!(
                claim.revision == bound.resource_spec.revision,
                "persistent allocation revision differs before detach"
            );
            claim.active = false;
            return self.write_claim(&claim);
        }
        release_claimed_entry(
            &expected,
            self.claim_for(&bound.resource_spec.resource)?.as_ref(),
            &bound.resource_spec.resource,
            bound.resource_spec.revision,
        )?;
        self.remove_claim(&bound.resource_spec.resource)
    }

    fn observe_request(
        &self,
        interface: &str,
        bound: &BoundNativeContext,
        resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        let desired = &bound.resource_spec.value;
        match interface {
            STORAGE_ALLOCATION_INTERFACE | PERSISTENT_STORAGE_ALLOCATION_INTERFACE => {
                let input: StorageAllocationRequest = decode_value(desired)?;
                let path = self.storage_path(interface, &bound.resource_spec.resource, &input)?;
                let claim = self.claim_for(&bound.resource_spec.resource)?;
                let ownership = self.resolve_ownership(&input)?;
                let state = inspect_storage(
                    &path,
                    claim.as_ref(),
                    bound.resource_spec.revision,
                    parse_mode(&input.mode)?,
                    ownership,
                )?;
                storage_observation(
                    desired,
                    state.is_present().then(|| path_string(&path)).transpose()?,
                    state.observation_state(),
                )
            }
            STORAGE_VIEW_INTERFACE => {
                let input: StorageViewRequest = decode_value(desired)?;
                let source = exact_resource_context(resources, &input.source)?;
                let source_context = decode_provider_context(source)?;
                let root = Path::new(&source_context.path);
                let path = if root.exists() {
                    resolve_storage_view_path(root, input.relative_path.as_deref())?
                } else {
                    planned_child_path(root, input.relative_path.as_deref())?
                };
                let present = root.is_dir();
                storage_view_observation(
                    desired,
                    present.then(|| path_string(&path)).transpose()?,
                    if present { "ready" } else { "absent" },
                )
            }
            FILESYSTEM_ENTRY_INTERFACE => self.observe_entry(bound, resources),
            _ => bail!("selected interface is not owned by the filesystem storage provider"),
        }
    }

    fn observe_entry(
        &self,
        bound: &BoundNativeContext,
        resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        let desired = &bound.resource_spec.value;
        let input: FilesystemEntryRequest = decode_value(desired)?;
        let path = PathBuf::from(&input.destination);
        let source = self.resolve_entry_source(&input, resources)?;
        let ownership = self.resolve_entry_ownership(&input)?;
        let claim = self.claim_for(&bound.resource_spec.resource)?;
        let state = inspect_entry(
            &path,
            claim.as_ref(),
            bound.resource_spec.revision,
            parse_mode(&input.mode)?,
            ownership,
            input.entry.claimed_kind(),
            source.as_deref(),
            input.entry.maximum_size_bytes(),
        )?;
        entry_observation(
            desired,
            state.is_present().then(|| path_string(&path)).transpose()?,
            state.observation_state(),
        )
    }

    fn storage_path(
        &self,
        interface: &str,
        resource: &ResourceId,
        request: &StorageAllocationRequest,
    ) -> Result<PathBuf> {
        if let Some(path) = &request.requested_path {
            let path = PathBuf::from(path);
            validate_requested_storage_path(&path)?;
            return Ok(path);
        }
        let root = if interface == PERSISTENT_STORAGE_ALLOCATION_INTERFACE {
            &self.persistent_root
        } else {
            &self.instance_root
        };
        let encoded = aos_contract::canonical::to_vec(resource)?;
        let digest = Sha256::digest(encoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(root.join(digest))
    }

    fn admit_entry(
        &self,
        request: &AdmissionRequest,
    ) -> Result<(PathBuf, AbilityValue, AdmissionRevision)> {
        let desired = &request.resource_spec.value;
        let input: FilesystemEntryRequest = decode_value(desired)?;
        let realization: FilesystemEntryRealization =
            decode_value(&request.resource_spec.realization)?;
        let path = PathBuf::from(&input.destination);
        let roots = self
            .mutable_roots
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        validate_provider_owned_path(&path, &roots)?;
        ensure!(
            realization.schema == ENTRY_REALIZATION_SCHEMA && Path::new(&realization.path) == path,
            "filesystem entry realization differs from its planned destination"
        );
        let source = self.resolve_entry_source(&input, &request.resources)?;
        ensure!(
            realization.source_path.as_deref()
                == source.as_deref().map(path_string).transpose()?.as_deref(),
            "filesystem entry realization differs from its resolved source"
        );
        self.validate_entry_prerequisites(&input, &request.resources)?;
        let claims = self.claims_except(&request.resource_spec.resource)?;
        validate_entry_claims(&path, &input.prerequisites, &claims)?;

        let ownership = self.resolve_entry_ownership(&input)?;
        let claim = self.claim_for(&request.resource_spec.resource)?;
        let state = inspect_entry(
            &path,
            claim.as_ref(),
            request.resource_spec.revision,
            parse_mode(&input.mode)?,
            ownership,
            input.entry.claimed_kind(),
            source.as_deref(),
            input.entry.maximum_size_bytes(),
        )?;
        ensure!(
            !path.exists() || claim.is_some(),
            "refusing to admit an existing unclaimed filesystem entry"
        );
        let observation = entry_observation(
            desired,
            state.is_present().then(|| path_string(&path)).transpose()?,
            state.observation_state(),
        )?;
        Ok((path, observation, state.revision()))
    }

    fn resolve_entry_ownership(
        &self,
        request: &FilesystemEntryRequest,
    ) -> Result<StorageOwnership> {
        let allocation = StorageAllocationRequest {
            _name: request._name.clone(),
            _purpose: String::new(),
            mode: request.mode.clone(),
            requested_path: None,
            owner: request.owner.clone(),
            group: request.group.clone(),
        };
        self.resolve_ownership(&allocation)
    }

    fn resolve_entry_source(
        &self,
        request: &FilesystemEntryRequest,
        resources: &[ResourceContext],
    ) -> Result<Option<PathBuf>> {
        let FilesystemEntryKind::CopiedFile {
            source,
            maximum_size_bytes: _,
        } = &request.entry
        else {
            return Ok(None);
        };
        let path = match source {
            FilesystemEntrySource::ArtifactFile { reference } => {
                authenticated_artifact_path(reference)?
            }
            FilesystemEntrySource::ExecutionPath { resource, path } => {
                ensure!(
                    request
                        .prerequisites
                        .iter()
                        .any(|prerequisite| prerequisite == resource),
                    "filesystem entry source resource is not an explicit prerequisite"
                );
                let context = exact_resource_context(resources, resource)?;
                let realized = context
                    .observation
                    .as_json()
                    .get("realized")
                    .and_then(serde_json::Value::as_str)
                    .context("filesystem entry source has no realized execution path")?;
                ensure!(
                    realized == path,
                    "filesystem entry source path differs from evidence"
                );
                PathBuf::from(path)
            }
        };
        ensure_regular_nofollow(&path)?;
        Ok(Some(path))
    }

    fn validate_entry_prerequisites(
        &self,
        request: &FilesystemEntryRequest,
        resources: &[ResourceContext],
    ) -> Result<()> {
        ensure!(
            request
                .prerequisites
                .windows(2)
                .all(|pair| pair[0].resource < pair[1].resource),
            "filesystem entry prerequisites are not in strict resource order"
        );
        for prerequisite in &request.prerequisites {
            exact_resource_context(resources, prerequisite)?;
        }
        Ok(())
    }

    fn resolve_ownership(&self, request: &StorageAllocationRequest) -> Result<StorageOwnership> {
        let uid = request
            .owner
            .as_deref()
            .map(|name| resolve_identity(&self.identity_root.join("passwd"), name, 2, "principal"))
            .transpose()?
            .map(Uid::from_raw);
        let gid = request
            .group
            .as_deref()
            .map(|name| resolve_identity(&self.identity_root.join("group"), name, 2, "group"))
            .transpose()?
            .map(Gid::from_raw);
        Ok(StorageOwnership { uid, gid })
    }

    fn claims_except(&self, resource: &ResourceId) -> Result<Vec<StorageClaim>> {
        let mut claims = Vec::new();
        let root = self.state_root.join("claims");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(claims),
            Err(error) => return Err(error).context("reading storage claims"),
        };
        for entry in entries {
            let entry = entry.context("reading storage claim entry")?;
            let metadata =
                fs::symlink_metadata(entry.path()).context("inspecting storage claim")?;
            ensure!(
                metadata.is_file(),
                "storage claim entry is not a regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                ensure!(metadata.nlink() == 1, "storage claim entry is hard-linked");
            }
            let claim: StorageClaim = serde_json::from_slice(&fs::read(entry.path())?)
                .context("decoding storage claim")?;
            ensure!(
                claim.schema == CLAIM_SCHEMA,
                "unsupported storage claim schema"
            );
            if &claim.resource != resource {
                claims.push(claim);
            }
        }
        Ok(claims)
    }

    fn claim_for(&self, resource: &ResourceId) -> Result<Option<StorageClaim>> {
        let path = self.claim_path(resource)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(metadata.is_file(), "storage claim is not a regular file");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    ensure!(metadata.nlink() == 1, "storage claim is hard-linked");
                }
                let bytes = fs::read(&path).context("reading storage claim")?;
                let claim: StorageClaim =
                    serde_json::from_slice(&bytes).context("decoding storage claim")?;
                ensure!(
                    claim.schema == CLAIM_SCHEMA && claim.resource == *resource,
                    "storage claim identity differs"
                );
                Ok(Some(claim))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("inspecting storage claim"),
        }
    }

    fn claim_path(&self, resource: &ResourceId) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical("aos.filesystem.storage-claim-name/v1", resource)?;
        Ok(self
            .state_root
            .join("claims")
            .join(format!("{}.json", digest.hex())))
    }

    fn write_claim(&self, claim: &StorageClaim) -> Result<()> {
        let claims = self.state_root.join("claims");
        ensure_private_directory(&self.state_root)?;
        ensure_private_directory(&claims)?;
        let destination = self.claim_path(&claim.resource)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary =
            destination.with_extension(format!("{}.{}.tmp", std::process::id(), sequence));
        let bytes = aos_contract::canonical::to_vec(claim)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .context("creating storage claim temporary file")?;
        let result = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            File::open(&claims)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove_claim(&self, resource: &ResourceId) -> Result<()> {
        let path = self.claim_path(resource)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(self.state_root.join("claims"))?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing released storage claim"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageAllocationRequest {
    #[serde(rename = "name")]
    _name: LocalKey,
    #[serde(rename = "purpose")]
    _purpose: String,
    mode: String,
    #[serde(default)]
    requested_path: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageAllocationRealization {
    schema: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageViewRequest {
    #[serde(rename = "name")]
    _name: LocalKey,
    source: ResourceReference,
    #[serde(rename = "access")]
    _access: String,
    #[serde(default)]
    relative_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageViewRealization {
    schema: String,
    source: ResourceReference,
    #[serde(default)]
    relative_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemEntryRequest {
    #[serde(rename = "name")]
    _name: LocalKey,
    entry: FilesystemEntryKind,
    destination: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
    mode: String,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum FilesystemEntryKind {
    Directory,
    CopiedFile {
        source: FilesystemEntrySource,
        maximum_size_bytes: u64,
    },
}

impl FilesystemEntryKind {
    const fn claimed_kind(&self) -> ClaimedEntryKind {
        match self {
            Self::Directory => ClaimedEntryKind::Directory,
            Self::CopiedFile { .. } => ClaimedEntryKind::File,
        }
    }

    const fn maximum_size_bytes(&self) -> Option<u64> {
        match self {
            Self::Directory => None,
            Self::CopiedFile {
                maximum_size_bytes, ..
            } => Some(*maximum_size_bytes),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum FilesystemEntrySource {
    ArtifactFile {
        reference: ArtifactFileReference,
    },
    ExecutionPath {
        resource: ResourceReference,
        path: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFileReference {
    artifact: ArtifactReference,
    path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemEntryRealization {
    schema: String,
    path: String,
    #[serde(default)]
    source_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum StorageContextKind {
    Allocation,
    Entry,
    View,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageProviderContext {
    schema: String,
    kind: StorageContextKind,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageClaim {
    schema: String,
    resource: ResourceId,
    path: PathBuf,
    revision: RevisionId,
    mode: String,
    uid: Option<u32>,
    gid: Option<u32>,
    device: u64,
    inode: u64,
    kind: ClaimedEntryKind,
    content_digest: Option<Sha256Digest>,
    active: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ClaimedEntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy)]
struct StorageOwnership {
    uid: Option<Uid>,
    gid: Option<Gid>,
}

struct StorageIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct RegularFileObservation {
    digest: Sha256Digest,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
}

enum StorageState {
    Absent,
    Exact(RevisionId),
    Retained(RevisionId),
    Divergent(RevisionId),
}

impl StorageState {
    const fn is_present(&self) -> bool {
        matches!(self, Self::Exact(_) | Self::Divergent(_))
    }

    const fn observation_state(&self) -> &'static str {
        match self {
            Self::Absent | Self::Retained(_) => "absent",
            Self::Exact(_) => "ready",
            Self::Divergent(_) => "failed",
        }
    }

    const fn revision(&self) -> AdmissionRevision {
        match self {
            Self::Absent => AdmissionRevision::Absent,
            Self::Exact(revision) | Self::Retained(revision) | Self::Divergent(revision) => {
                AdmissionRevision::Present {
                    revision: *revision,
                }
            }
        }
    }
}

fn inspect_storage(
    path: &Path,
    claim: Option<&StorageClaim>,
    desired: RevisionId,
    mode: u32,
    ownership: StorageOwnership,
) -> Result<StorageState> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(StorageState::Absent),
        Err(error) => return Err(error).context("inspecting storage path"),
    };
    use std::os::unix::fs::MetadataExt as _;

    let expected_uid = ownership.uid.map(Uid::as_raw);
    let expected_gid = ownership.gid.map(Gid::as_raw);
    let exact_claim = claim.filter(|claim| {
        claim.path == path
            && claim.revision == desired
            && claim.uid == expected_uid
            && claim.gid == expected_gid
            && claim.device == metadata.dev()
            && claim.inode == metadata.ino()
            && claim.kind == ClaimedEntryKind::Directory
            && claim.content_digest.is_none()
    });
    let exact = metadata.is_dir()
        && metadata.permissions().mode() & 0o7777 == mode
        && expected_uid.is_none_or(|uid| metadata.uid() == uid)
        && expected_gid.is_none_or(|gid| metadata.gid() == gid)
        && exact_claim.is_some();
    if exact {
        return Ok(if exact_claim.is_some_and(|claim| claim.active) {
            StorageState::Exact(desired)
        } else {
            StorageState::Retained(desired)
        });
    }
    let observed = Sha256Digest::of_canonical(
        "aos.filesystem.observed-storage/v1",
        &json!({
            "directory": metadata.is_dir(),
            "mode": format!("{:04o}", metadata.permissions().mode() & 0o7777),
            "uid": metadata.uid(),
            "gid": metadata.gid(),
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "path": path_string(path)?,
            "claim_revision": claim.map(|claim| claim.revision),
        }),
    )?;
    Ok(StorageState::Divergent(RevisionId(observed)))
}

#[allow(clippy::too_many_arguments)]
fn inspect_entry(
    path: &Path,
    claim: Option<&StorageClaim>,
    desired: RevisionId,
    mode: u32,
    ownership: StorageOwnership,
    kind: ClaimedEntryKind,
    source: Option<&Path>,
    maximum_size_bytes: Option<u64>,
) -> Result<StorageState> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(StorageState::Absent),
        Err(error) => return Err(error).context("inspecting filesystem entry"),
    };
    let expected_uid = ownership.uid.map(Uid::as_raw);
    let expected_gid = ownership.gid.map(Gid::as_raw);
    let expected_content = match (kind, source, maximum_size_bytes) {
        (ClaimedEntryKind::Directory, None, None) => None,
        (ClaimedEntryKind::File, Some(source), Some(maximum)) => {
            Some(inspect_regular_file_nofollow(source, maximum)?.digest)
        }
        _ => bail!("filesystem entry source contract is inconsistent"),
    };
    let observed_file = (kind == ClaimedEntryKind::File)
        .then(|| {
            inspect_regular_file_nofollow(
                path,
                maximum_size_bytes.context("copied file has no byte bound")?,
            )
        })
        .transpose()?;
    let observed_content = observed_file.as_ref().map(|observed| observed.digest);
    let observed_mode = observed_file
        .as_ref()
        .map_or_else(|| metadata.permissions().mode() & 0o7777, |file| file.mode);
    let observed_uid = observed_file
        .as_ref()
        .map_or_else(|| metadata.uid(), |file| file.uid);
    let observed_gid = observed_file
        .as_ref()
        .map_or_else(|| metadata.gid(), |file| file.gid);
    let observed_device = observed_file
        .as_ref()
        .map_or_else(|| metadata.dev(), |file| file.device);
    let observed_inode = observed_file
        .as_ref()
        .map_or_else(|| metadata.ino(), |file| file.inode);
    let kind_matches = metadata.is_dir() || observed_file.is_some();
    let exact = kind_matches
        && observed_mode == mode
        && expected_uid.is_none_or(|uid| observed_uid == uid)
        && expected_gid.is_none_or(|gid| observed_gid == gid)
        && observed_content == expected_content
        && claim.is_some_and(|claim| {
            claim.path == path
                && claim.revision == desired
                && claim.uid == expected_uid
                && claim.gid == expected_gid
                && claim.device == observed_device
                && claim.inode == observed_inode
                && claim.kind == kind
                && claim.content_digest == expected_content
                && claim.active
        });
    if exact {
        return Ok(StorageState::Exact(desired));
    }
    let observed = Sha256Digest::of_canonical(
        "aos.filesystem.observed-entry/v1",
        &json!({
            "kind": kind,
            "mode": format!("{observed_mode:04o}"),
            "uid": observed_uid,
            "gid": observed_gid,
            "device": observed_device,
            "inode": observed_inode,
            "path": path_string(path)?,
            "content_digest": observed_content,
            "claim_revision": claim.map(|claim| claim.revision),
        }),
    )?;
    Ok(StorageState::Divergent(RevisionId(observed)))
}

fn rejected_admission(observation: AbilityValue) -> Result<AdmissionResult> {
    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Rejected,
        revision: AdmissionRevision::Unknown,
        incarnation: None,
        observation,
        native_context: ability_value(json!({"rejected": true}))?,
        supported_purposes: SupportedPurposes::from_ordered(Vec::new())
            .context("constructing empty supported-purpose set")?,
    })
}

fn storage_observation(
    expected: &AbilityValue,
    realized: Option<String>,
    state: &str,
) -> Result<AbilityValue> {
    ability_value(json!({
        "schema": "aos.ability.storage-allocation-observation/v1",
        "expected": expected.as_json(),
        "realized": realized,
        "state": state,
    }))
}

fn storage_view_observation(
    expected: &AbilityValue,
    realized: Option<String>,
    state: &str,
) -> Result<AbilityValue> {
    ability_value(json!({
        "schema": "aos.ability.storage-view-observation/v1",
        "expected": expected.as_json(),
        "realized": realized,
        "state": state,
    }))
}

fn entry_observation(
    expected: &AbilityValue,
    realized: Option<String>,
    state: &str,
) -> Result<AbilityValue> {
    ability_value(json!({
        "schema": "aos.ability.filesystem-entry-observation/v1",
        "expected": expected.as_json(),
        "realized": realized,
        "state": state,
    }))
}

fn successful_outputs(
    interface: &str,
    method: &str,
    target: &ResourceReference,
    context: &StorageProviderContext,
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    if method == "observe" || method == "release" {
        return Ok(outputs);
    }
    let path_key = LocalKey::new(if interface == FILESYSTEM_ENTRY_INTERFACE {
        "execution-path"
    } else {
        "storage-path"
    })?;
    outputs.insert(path_key, ability_value(json!(context.path))?);
    outputs.insert(
        LocalKey::new("retained-resource")?,
        ability_value(serde_json::to_value(target)?)?,
    );
    Ok(outputs)
}

fn release_claimed_entry(
    path: &Path,
    claim: Option<&StorageClaim>,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<()> {
    let Some(claim) = claim else {
        ensure!(
            !path.exists(),
            "refusing to release an unclaimed storage path"
        );
        return Ok(());
    };
    ensure!(
        claim.resource == *resource && claim.path == path && claim.revision == revision,
        "storage release claim differs from the checked resource revision"
    );
    let quarantine = release_quarantine_path(path, resource)?;
    let target = fs::symlink_metadata(path);
    let retained = fs::symlink_metadata(&quarantine);
    match (target, retained) {
        (Ok(metadata), Err(error)) if error.kind() == io::ErrorKind::NotFound => {
            ensure_claimed_identity(&metadata, claim)?;
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                path,
                rustix::fs::CWD,
                &quarantine,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .context("quarantining storage directory for release")?;
            sync_parent(path)?;
        }
        (Err(error), Ok(metadata)) if error.kind() == io::ErrorKind::NotFound => {
            ensure_claimed_identity(&metadata, claim)?;
        }
        (Err(target_error), Err(retained_error))
            if target_error.kind() == io::ErrorKind::NotFound
                && retained_error.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        (Ok(_), Ok(_)) => bail!("storage release quarantine conflicts with the live path"),
        (Err(error), _) => return Err(error).context("inspecting storage release target"),
        (_, Err(error)) => return Err(error).context("inspecting storage release quarantine"),
    }

    let retained =
        fs::symlink_metadata(&quarantine).context("rechecking quarantined storage directory")?;
    ensure_claimed_identity(&retained, claim)?;
    match claim.kind {
        ClaimedEntryKind::Directory => {
            fs::remove_dir_all(&quarantine).context("removing quarantined filesystem directory")?
        }
        ClaimedEntryKind::File => {
            fs::remove_file(&quarantine).context("removing quarantined filesystem file")?
        }
    }
    sync_parent(&quarantine)
}

fn ensure_claimed_identity(metadata: &fs::Metadata, claim: &StorageClaim) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    ensure!(
        !metadata.file_type().is_symlink()
            && match claim.kind {
                ClaimedEntryKind::Directory => metadata.is_dir(),
                ClaimedEntryKind::File => metadata.is_file(),
            }
            && metadata.dev() == claim.device
            && metadata.ino() == claim.inode,
        "storage directory identity differs from its durable claim"
    );
    Ok(())
}

fn release_quarantine_path(path: &Path, resource: &ResourceId) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("storage release path has no final component")?;
    let digest = Sha256Digest::of_canonical("aos.filesystem.storage-release/v1", resource)?;
    Ok(path.with_file_name(format!(
        ".{}.aos-release-{}",
        name.to_string_lossy(),
        digest.hex()
    )))
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("storage path has no parent")?;
    File::open(parent)
        .context("opening storage parent for synchronization")?
        .sync_all()
        .context("synchronizing storage parent")
}

fn exact_resource_context<'a>(
    resources: &'a [ResourceContext],
    reference: &ResourceReference,
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| &context.reference == reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "request does not contain one exact referenced-resource context"
    );
    Ok(matches[0])
}

fn decode_provider_context(context: &ResourceContext) -> Result<StorageProviderContext> {
    let bound = validate_resource_context(context)?;
    let provider: StorageProviderContext = decode_value(&bound.provider_context)?;
    ensure!(
        provider.schema == PROVIDER_CONTEXT_SCHEMA,
        "unsupported storage provider context"
    );
    Ok(provider)
}

fn observation_state(observation: &AbilityValue) -> Option<&str> {
    observation.as_json().get("state")?.as_str()
}

fn planned_child_path(root: &Path, relative: Option<&str>) -> Result<PathBuf> {
    let Some(relative) = relative else {
        return Ok(root.to_path_buf());
    };
    let path = Path::new(relative);
    ensure!(
        !path.as_os_str().is_empty() && !path.is_absolute(),
        "storage child path is not relative"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "storage child path is not normalized"
    );
    Ok(root.join(path))
}

fn authenticated_artifact_path(reference: &ArtifactFileReference) -> Result<PathBuf> {
    let relative = Path::new(&reference.path);
    ensure!(
        !relative.as_os_str().is_empty()
            && !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "artifact file path is not a strict relative path"
    );
    let artifact = fs::canonicalize(&reference.artifact.store_path)
        .context("canonicalizing authenticated artifact root")?;
    let candidate = fs::canonicalize(artifact.join(relative))
        .context("canonicalizing authenticated artifact file")?;
    ensure!(
        candidate.starts_with(&artifact),
        "artifact file escapes its authenticated artifact root"
    );
    Ok(candidate)
}

fn ensure_regular_nofollow(path: &Path) -> Result<()> {
    let descriptor = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening filesystem entry source")?;
    let metadata = fstat(&descriptor).context("inspecting filesystem entry source")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "filesystem entry source is not a regular file"
    );
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let descriptor = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening filesystem entry file")?;
    let metadata = fstat(&descriptor).context("inspecting filesystem entry file")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "filesystem entry is not a regular file"
    );
    Ok(File::from(descriptor))
}

fn inspect_regular_file_nofollow(
    path: &Path,
    maximum_size_bytes: u64,
) -> Result<RegularFileObservation> {
    ensure!(
        maximum_size_bytes > 0 && maximum_size_bytes <= MAX_SAFE_INTEGER,
        "filesystem entry byte bound is outside the portable integer range"
    );
    let mut file = open_regular_nofollow(path)?;
    let initial = fstat(&file).context("inspecting filesystem entry before reading")?;
    let mut digest = Sha256::new();
    stream_file(&mut file, None, maximum_size_bytes, &mut digest)?;
    let final_metadata = fstat(&file).context("re-inspecting filesystem entry after reading")?;
    ensure_unchanged_regular_file(&initial, &final_metadata)?;
    Ok(RegularFileObservation {
        digest: Sha256Digest::from_bytes(digest.finalize().into()),
        mode: u32::from(final_metadata.st_mode) & 0o7777,
        uid: final_metadata.st_uid,
        gid: final_metadata.st_gid,
        device: final_metadata.st_dev,
        inode: final_metadata.st_ino,
    })
}

fn ensure_unchanged_regular_file(
    initial: &rustix::fs::Stat,
    final_metadata: &rustix::fs::Stat,
) -> Result<()> {
    ensure!(
        initial.st_dev == final_metadata.st_dev
            && initial.st_ino == final_metadata.st_ino
            && initial.st_nlink == final_metadata.st_nlink
            && initial.st_size == final_metadata.st_size
            && initial.st_mtime == final_metadata.st_mtime
            && initial.st_mtime_nsec == final_metadata.st_mtime_nsec
            && initial.st_ctime == final_metadata.st_ctime
            && initial.st_ctime_nsec == final_metadata.st_ctime_nsec,
        "filesystem entry changed while it was read"
    );
    Ok(())
}

fn stream_file(
    source: &mut File,
    mut destination: Option<&mut File>,
    maximum_size_bytes: u64,
    digest: &mut Sha256,
) -> Result<()> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .context("reading filesystem entry source")?;
        if count == 0 {
            return Ok(());
        }
        copied = copied
            .checked_add(u64::try_from(count).context("filesystem entry length overflow")?)
            .context("filesystem entry length overflow")?;
        ensure!(
            copied <= maximum_size_bytes,
            "filesystem entry exceeds its declared byte bound"
        );
        digest.update(&buffer[..count]);
        if let Some(file) = destination.as_deref_mut() {
            file.write_all(&buffer[..count])?;
        }
    }
}

fn validate_entry_claims(
    candidate: &Path,
    prerequisites: &[ResourceReference],
    existing: &[StorageClaim],
) -> Result<()> {
    for claim in existing {
        if candidate == claim.path || claim.path.starts_with(candidate) {
            bail!("filesystem entry collides with an existing claim");
        }
        if candidate.starts_with(&claim.path) {
            ensure!(
                claim.active
                    && claim.kind == ClaimedEntryKind::Directory
                    && prerequisites
                        .iter()
                        .any(|reference| reference.resource == claim.resource),
                "filesystem entry parent is not an exact declared directory prerequisite"
            );
        }
    }
    Ok(())
}

fn parse_mode(mode: &str) -> Result<u32> {
    ensure!(
        (mode.len() == 3 || mode.len() == 4)
            && mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "storage mode is not canonical octal"
    );
    u32::from_str_radix(mode, 8).context("decoding storage mode")
}

fn create_directory_nofollow(
    path: &Path,
    mode: u32,
    ownership: StorageOwnership,
    allow_existing_final: bool,
) -> Result<StorageIdentity> {
    let mut directory = openat(
        rustix::fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let components = path.components().skip(1).collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            bail!("storage path is not normalized");
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(&directory, *component, flags, Mode::empty()) {
            Ok(next) => {
                ensure!(
                    index + 1 < components.len() || allow_existing_final,
                    "refusing to claim an existing unowned storage directory"
                );
                directory = next;
            }
            Err(error) if error == rustix::io::Errno::NOENT => {
                let created_mode = if index + 1 == components.len() {
                    mode
                } else {
                    0o700
                };
                match mkdirat(&directory, *component, Mode::from_raw_mode(created_mode)) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST)
                        if index + 1 < components.len() || allow_existing_final => {}
                    Err(rustix::io::Errno::EXIST) => {
                        bail!("storage directory appeared before its ownership claim")
                    }
                    Err(error) => return Err(error).context("creating storage directory"),
                }
                directory = openat(&directory, *component, flags, Mode::empty())
                    .context("opening newly created storage directory")?;
            }
            Err(error) => return Err(error).context("refusing storage symlink or non-directory"),
        }
    }
    if ownership.uid.is_some() || ownership.gid.is_some() {
        fchown(&directory, ownership.uid, ownership.gid)
            .context("setting storage directory ownership")?;
    }
    fchmod(&directory, Mode::from_raw_mode(mode)).context("setting storage directory mode")?;
    let identity = fstat(&directory).context("inspecting realized storage directory")?;
    Ok(StorageIdentity {
        device: identity.st_dev,
        inode: identity.st_ino,
    })
}

fn create_entry_directory_nofollow(
    path: &Path,
    mode: u32,
    ownership: StorageOwnership,
    own_claim: Option<&StorageClaim>,
) -> Result<StorageIdentity> {
    let parent = path.parent().context("filesystem entry has no parent")?;
    let name = path
        .file_name()
        .context("filesystem entry has no final component")?;
    let directory = open_directory_nofollow(parent)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let entry = match openat(&directory, name, flags, Mode::empty()) {
        Ok(entry) => {
            let claim = own_claim.context("existing filesystem directory has no durable claim")?;
            let metadata = fstat(&entry).context("inspecting existing filesystem directory")?;
            ensure_raw_claimed_identity(&metadata, claim)?;
            entry
        }
        Err(rustix::io::Errno::NOENT) => {
            mkdirat(&directory, name, Mode::from_raw_mode(mode))
                .context("creating filesystem entry directory")?;
            openat(&directory, name, flags, Mode::empty())
                .context("opening created filesystem entry directory")?
        }
        Err(error) => return Err(error).context("opening filesystem entry directory"),
    };
    apply_metadata(&entry, mode, ownership)?;
    raw_storage_identity(&entry)
}

fn copy_file_atomic_nofollow(
    source_path: &Path,
    path: &Path,
    maximum_size_bytes: u64,
    mode: u32,
    ownership: StorageOwnership,
    own_claim: Option<&StorageClaim>,
) -> Result<(StorageIdentity, Sha256Digest)> {
    ensure!(
        maximum_size_bytes > 0 && maximum_size_bytes <= MAX_SAFE_INTEGER,
        "filesystem entry byte bound is outside the portable integer range"
    );
    let mut source = open_regular_nofollow(source_path)?;
    let initial_source = fstat(&source).context("inspecting filesystem entry source")?;
    let parent_path = path.parent().context("filesystem entry has no parent")?;
    let name = path
        .file_name()
        .context("filesystem entry has no final component")?;
    let parent = open_directory_nofollow(parent_path)?;
    if let Some(claim) = own_claim {
        let current = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("opening claimed filesystem file")?;
        let metadata = fstat(&current).context("inspecting claimed filesystem file")?;
        ensure_raw_claimed_identity(&metadata, claim)?;
    }

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(".aos-entry-{}.{}.tmp", std::process::id(), sequence);
    let descriptor = openat(
        &parent,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .context("creating filesystem entry temporary file")?;
    let result = (|| -> Result<(StorageIdentity, Sha256Digest)> {
        let mut file = File::from(descriptor);
        let mut digest = Sha256::new();
        stream_file(
            &mut source,
            Some(&mut file),
            maximum_size_bytes,
            &mut digest,
        )?;
        let final_source = fstat(&source).context("re-inspecting filesystem entry source")?;
        ensure_unchanged_regular_file(&initial_source, &final_source)?;
        apply_metadata(&file, mode, ownership)?;
        file.sync_all()?;
        drop(file);
        rustix::fs::renameat_with(
            &parent,
            &temporary,
            &parent,
            name,
            if own_claim.is_some() {
                rustix::fs::RenameFlags::empty()
            } else {
                rustix::fs::RenameFlags::NOREPLACE
            },
        )
        .context("publishing filesystem entry atomically")?;
        File::from(parent.try_clone()?).sync_all()?;
        let published = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok((
            raw_storage_identity(&published)?,
            Sha256Digest::from_bytes(digest.finalize().into()),
        ))
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &temporary, rustix::fs::AtFlags::empty());
    }
    result
}

fn open_directory_nofollow(path: &Path) -> Result<OwnedFd> {
    let mut directory = openat(
        rustix::fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in path.components().skip(1) {
        let Component::Normal(component) = component else {
            bail!("filesystem entry parent is not normalized");
        };
        directory = openat(
            &directory,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("opening filesystem entry parent")?;
    }
    Ok(directory)
}

fn apply_metadata(
    descriptor: &impl std::os::fd::AsFd,
    mode: u32,
    ownership: StorageOwnership,
) -> Result<()> {
    if ownership.uid.is_some() || ownership.gid.is_some() {
        fchown(descriptor, ownership.uid, ownership.gid)
            .context("setting filesystem entry ownership")?;
    }
    fchmod(descriptor, Mode::from_raw_mode(mode)).context("setting filesystem entry mode")
}

fn raw_storage_identity(descriptor: &impl std::os::fd::AsFd) -> Result<StorageIdentity> {
    let identity = fstat(descriptor).context("inspecting realized filesystem entry")?;
    Ok(StorageIdentity {
        device: identity.st_dev,
        inode: identity.st_ino,
    })
}

fn ensure_raw_claimed_identity(metadata: &rustix::fs::Stat, claim: &StorageClaim) -> Result<()> {
    ensure!(
        metadata.st_dev == claim.device && metadata.st_ino == claim.inode,
        "filesystem entry identity differs from its durable claim"
    );
    Ok(())
}

fn resolve_identity(path: &Path, name: &str, field: usize, label: &str) -> Result<u32> {
    let descriptor: OwnedFd = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} identity database"))?;
    let metadata = fstat(&descriptor).context("inspecting identity database")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "{label} identity database is not a regular file"
    );

    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)
        .context("reading identity database")?;
    let maximum_bytes = usize::try_from(ABILITY_LIMITS_V1.max_document_bytes)
        .context("ability document bound does not fit this platform")?;
    ensure!(
        bytes.len() <= maximum_bytes,
        "{label} identity database exceeds the ability document bound"
    );
    let document = std::str::from_utf8(&bytes).context("identity database is not UTF-8")?;
    let matches = document
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.len() > field && fields[0] == name).then(|| fields[field])
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "{label} identity must resolve exactly once"
    );
    matches[0]
        .parse::<u32>()
        .with_context(|| format!("{label} has an invalid numeric identity"))
}

struct StateLock {
    _file: File,
}

impl StateLock {
    fn acquire(state_root: &Path, remaining_millis: u64) -> Result<Self> {
        ensure_private_directory(state_root)?;
        let path = state_root.join("mutation.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .context("opening filesystem provider state lock")?;
        let metadata = file
            .metadata()
            .context("inspecting filesystem provider state lock")?;
        ensure!(
            metadata.is_file(),
            "filesystem provider state lock is not a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            ensure!(
                metadata.nlink() == 1,
                "filesystem provider state lock is hard-linked"
            );
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining_millis))
            .context("storage lock deadline overflow")?;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK && Instant::now() < deadline =>
                {
                    thread::sleep(LOCK_RETRY);
                }
                Err(error) => {
                    return Err(error).context("acquiring filesystem provider state lock");
                }
            }
        }
    }
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("creating filesystem provider state directory")?;
    let metadata = fs::symlink_metadata(path).context("inspecting provider state directory")?;
    ensure!(
        metadata.is_dir(),
        "filesystem provider state path is not a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .context("storage path is not UTF-8")
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing canonical ability value")
}

fn decode_value<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding checked ability value")
}

const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AccessMode, EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName,
        MethodReference, MethodSemantics, ResourceLifetime,
    };
    use aos_provider_protocol::{
        ADMISSION_REQUEST_SCHEMA, INVOCATION_SCHEMA, InvocationControl, REQUEST_SCHEMA,
        ResourceSpec,
    };
    use tempfile::tempdir;

    use super::*;

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).expect("test key is valid")
    }

    fn interface(name: &str) -> InterfaceKey {
        InterfaceKey {
            name: InterfaceName::new(name).expect("test interface is valid"),
            abi: NonZeroU32::MIN,
            descriptor: Sha256Digest::of_bytes(name),
        }
    }

    fn resource(key_name: &str) -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: key("test"),
                    key: key("host"),
                    stage: ExecutionStage::Host,
                },
                key: key("filesystem"),
            },
            key: key(key_name),
        }
    }

    fn provider(temporary: &Path) -> FilesystemProvider {
        let identity_root = temporary.join("etc");
        fs::create_dir_all(&identity_root).expect("identity fixture directory exists");
        fs::write(
            identity_root.join("passwd"),
            format!(
                "service:x:{}:{}:service:/:/sbin/nologin\n",
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw()
            ),
        )
        .expect("principal fixture is written");
        fs::write(
            identity_root.join("group"),
            format!("service:x:{}:\n", rustix::process::getegid().as_raw()),
        )
        .expect("group fixture is written");
        FilesystemProvider {
            state_root: temporary.join("state"),
            instance_root: temporary.join("instance"),
            persistent_root: temporary.join("persistent"),
            identity_root,
            mutable_roots: vec![temporary.join("entries")],
        }
    }

    fn admission_request(provider: &FilesystemProvider, resource: ResourceId) -> AdmissionRequest {
        let interface = interface(STORAGE_ALLOCATION_INTERFACE);
        let value = ability_value(json!({
            "name": "runtime",
            "purpose": "runtime",
            "mode": "0750",
        }))
        .expect("request value is valid");
        let decoded: StorageAllocationRequest =
            decode_value(&value).expect("request fixture decodes");
        let path = provider
            .storage_path(STORAGE_ALLOCATION_INTERFACE, &resource, &decoded)
            .expect("planned path computes");
        let target = ResourceReference {
            interface: interface.clone(),
            resource: resource.clone(),
            operations: vec![key("allocate"), key("observe")],
            lifetime: ResourceLifetime::Instance,
        };
        AdmissionRequest {
            schema: ADMISSION_REQUEST_SCHEMA.into(),
            method: MethodReference {
                interface,
                method: key("allocate"),
            },
            semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            target,
            resource_spec: ResourceSpec {
                resource,
                kind: aos_ability_model::InterfaceName::new(STORAGE_ALLOCATION_INTERFACE)
                    .expect("storage resource kind is valid"),
                lifetime: aos_ability_model::ResourceLifetime::Instance,
                value,
                realization: ability_value(json!({
                    "schema": REALIZATION_SCHEMA,
                    "path": path_string(&path).expect("planned path is UTF-8"),
                }))
                .expect("realization is valid"),
                revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
            },
            resources: Vec::new(),
            control: InvocationControl {
                attempt_remaining_millis: 10_000,
                recovery_remaining_millis: 10_000,
                cancelled: false,
            },
        }
    }

    fn entry_request(
        provider: &FilesystemProvider,
        resource: ResourceId,
        relative_path: &str,
        entry: serde_json::Value,
        source_path: Option<&Path>,
        prerequisites: Vec<ResourceReference>,
        resources: Vec<ResourceContext>,
    ) -> AdmissionRequest {
        let interface = interface(FILESYSTEM_ENTRY_INTERFACE);
        let destination = provider.mutable_roots[0].join(relative_path);
        let target = ResourceReference {
            interface: interface.clone(),
            resource: resource.clone(),
            operations: vec![key("materialize"), key("observe"), key("release")],
            lifetime: ResourceLifetime::Instance,
        };
        let value = ability_value(json!({
            "name": resource.key,
            "entry": entry,
            "destination": destination,
            "owner": "service",
            "group": "service",
            "mode": "0750",
            "prerequisites": prerequisites,
        }))
        .expect("filesystem entry request is valid");
        AdmissionRequest {
            schema: ADMISSION_REQUEST_SCHEMA.into(),
            method: MethodReference {
                interface,
                method: key("materialize"),
            },
            semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            target,
            resource_spec: ResourceSpec {
                resource,
                kind: InterfaceName::new(FILESYSTEM_ENTRY_INTERFACE)
                    .expect("filesystem entry kind is valid"),
                lifetime: ResourceLifetime::Instance,
                value,
                realization: ability_value(json!({
                    "schema": ENTRY_REALIZATION_SCHEMA,
                    "path": destination,
                    "source_path": source_path,
                }))
                .expect("filesystem entry realization is valid"),
                revision: RevisionId(Sha256Digest::of_bytes(relative_path)),
            },
            resources,
            control: InvocationControl {
                attempt_remaining_millis: 10_000,
                recovery_remaining_millis: 10_000,
                cancelled: false,
            },
        }
    }

    fn persistent_request(provider: &FilesystemProvider, resource: ResourceId) -> AdmissionRequest {
        let mut request = admission_request(provider, resource);
        let interface = interface(PERSISTENT_STORAGE_ALLOCATION_INTERFACE);
        request.method.interface = interface.clone();
        request.target.interface = interface;
        request.target.lifetime = ResourceLifetime::Persistent;
        request.resource_spec.kind = InterfaceName::new(PERSISTENT_STORAGE_ALLOCATION_INTERFACE)
            .expect("persistent storage kind is valid");
        request.resource_spec.lifetime = ResourceLifetime::Persistent;
        let input: StorageAllocationRequest =
            decode_value(&request.resource_spec.value).expect("persistent request fixture decodes");
        let path = provider
            .storage_path(
                PERSISTENT_STORAGE_ALLOCATION_INTERFACE,
                &request.resource_spec.resource,
                &input,
            )
            .expect("persistent planned path computes");
        request.resource_spec.realization = ability_value(json!({
            "schema": REALIZATION_SCHEMA,
            "path": path,
        }))
        .expect("persistent realization is valid");
        request
    }

    fn target_context(request: &AdmissionRequest, admission: &AdmissionResult) -> ResourceContext {
        let bound = ability_value(
            serde_json::to_value(BoundNativeContext {
                schema: aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA.into(),
                resource_spec: request.resource_spec.clone(),
                provider_context: admission.native_context.clone(),
            })
            .expect("bound context serializes"),
        )
        .expect("bound context is canonical");
        let assignment = serde_json::from_value(serde_json::json!({
            "provider": request.target.resource.provider,
            "interface": request.method.interface,
            "implementation": {
                "descriptor": format!("sha256:{}", "4".repeat(64)),
                "artifact": {
                    "content": format!("sha256:{}", "5".repeat(64)),
                    "store_path": "/nix/store/00000000000000000000000000000000-fixture",
                    "nar_hash": format!("sha256:{}", "6".repeat(64)),
                    "closure": format!("sha256:{}", "7".repeat(64)),
                },
                "handler": "fixture",
            },
            "incarnation": "fixture-incarnation",
        }))
        .expect("provider assignment fixture is valid");
        ResourceContext {
            reference: request.target.clone(),
            assignment,
            revision: request.resource_spec.revision,
            observation: admission.observation.clone(),
            native_context_digest: aos_provider_protocol::native_context_digest(&bound)
                .expect("context digest computes"),
            native_context: bound,
        }
    }

    fn invocation(
        purpose: InvocationPurpose,
        request: &AdmissionRequest,
        context: ResourceContext,
    ) -> Invocation {
        let resources = vec![context];
        let native_context_digest =
            resource_set_digest(&resources).expect("resource set digest computes");
        Invocation {
            schema: INVOCATION_SCHEMA.into(),
            purpose,
            method: request.method.clone(),
            semantics: request.semantics.clone(),
            request: aos_provider_protocol::DurableRequest {
                schema: REQUEST_SCHEMA.into(),
                method: request.method.clone(),
                semantics: request.semantics.clone(),
                recovery: aos_provider_protocol::RecoveryMethods {
                    reconcile: Some(request.method.clone()),
                    cancel: Some(request.method.clone()),
                    compensate: None,
                },
                target: request.target.clone(),
                inputs: request.resource_spec.value.clone(),
                native_context_digest,
                resources,
            },
            control: request.control.clone(),
        }
    }

    fn invocation_with_dependencies(
        purpose: InvocationPurpose,
        request: &AdmissionRequest,
        target: ResourceContext,
        mut dependencies: Vec<ResourceContext>,
    ) -> Invocation {
        dependencies.push(target);
        dependencies.sort_by(|left, right| left.reference.resource.cmp(&right.reference.resource));
        let native_context_digest =
            resource_set_digest(&dependencies).expect("resource set digest computes");
        Invocation {
            schema: INVOCATION_SCHEMA.into(),
            purpose,
            method: request.method.clone(),
            semantics: request.semantics.clone(),
            request: aos_provider_protocol::DurableRequest {
                schema: REQUEST_SCHEMA.into(),
                method: request.method.clone(),
                semantics: request.semantics.clone(),
                recovery: aos_provider_protocol::RecoveryMethods {
                    reconcile: Some(request.method.clone()),
                    cancel: Some(request.method.clone()),
                    compensate: None,
                },
                target: request.target.clone(),
                inputs: request.resource_spec.value.clone(),
                native_context_digest,
                resources: dependencies,
            },
            control: request.control.clone(),
        }
    }

    #[test]
    fn allocation_effect_creates_an_owned_exact_directory() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let request = admission_request(&provider, resource("runtime"));
        let admission = provider
            .admit(request.clone())
            .expect("absent allocation admits");
        assert_eq!(admission.revision, AdmissionRevision::Absent);
        let context = target_context(&request, &admission);

        let result = provider
            .invoke(invocation(InvocationPurpose::Effect, &request, context))
            .expect("allocation effect succeeds");
        assert_eq!(result.disposition, InvocationDisposition::Completed);
        assert!(result.outputs.contains_key(&key("storage-path")));
        assert!(result.outputs.contains_key(&key("retained-resource")));
        assert!(result.outputs.contains_key(&key("observation")));

        let observed = provider
            .admit(request)
            .expect("created allocation observes");
        assert_eq!(
            observed.revision,
            AdmissionRevision::Present {
                revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
            }
        );
    }

    #[test]
    fn allocation_applies_and_observes_resolved_principal_and_group() {
        use std::os::unix::fs::MetadataExt as _;

        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let mut request = admission_request(&provider, resource("owned"));
        request.resource_spec.value = ability_value(json!({
            "name": "owned",
            "purpose": "state",
            "mode": "0750",
            "owner": "service",
            "group": "service",
        }))
        .expect("owned request is valid");
        let admission = provider
            .admit(request.clone())
            .expect("owned allocation admits");
        let context = target_context(&request, &admission);

        let result = provider
            .invoke(invocation(InvocationPurpose::Effect, &request, context))
            .expect("owned allocation effect succeeds");

        assert_eq!(result.disposition, InvocationDisposition::Completed);
        let provider_context: StorageProviderContext =
            decode_value(&admission.native_context).expect("provider context decodes");
        let metadata = fs::metadata(provider_context.path).expect("storage directory exists");
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.gid(), rustix::process::getegid().as_raw());
        let observed = provider
            .admit(request)
            .expect("owned allocation remains admissible");
        assert_eq!(
            observed.revision,
            AdmissionRevision::Present {
                revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
            }
        );
    }

    #[test]
    fn admission_rejects_a_realization_that_differs_from_the_planned_path() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let mut request = admission_request(&provider, resource("drifted-realization"));
        request.resource_spec.realization = ability_value(json!({
            "schema": REALIZATION_SCHEMA,
            "path": temporary.path().join("other"),
        }))
        .expect("drifted realization is valid JSON");

        let error = provider
            .admit(request)
            .expect_err("a drifted planned path must be rejected");

        assert!(error.to_string().contains("planned path"), "{error:#}");
    }

    #[test]
    fn cancellation_of_an_absent_allocation_never_creates_it() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let request = admission_request(&provider, resource("cancelled"));
        let admission = provider
            .admit(request.clone())
            .expect("absent allocation admits");
        let context = target_context(&request, &admission);
        let provider_context: StorageProviderContext =
            decode_value(&admission.native_context).expect("provider context decodes");

        let result = provider
            .invoke(invocation(InvocationPurpose::Cancel, &request, context))
            .expect("cancellation observes absence");
        assert_eq!(
            result.disposition,
            InvocationDisposition::RejectedBeforeEffect
        );
        assert!(!Path::new(&provider_context.path).exists());
    }

    #[test]
    fn release_removes_only_the_exact_claimed_directory_and_reconciles_absence() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let mut request = admission_request(&provider, resource("released"));
        let allocation = provider.admit(request.clone()).expect("allocation admits");
        let allocation_context = target_context(&request, &allocation);
        provider
            .invoke(invocation(
                InvocationPurpose::Effect,
                &request,
                allocation_context,
            ))
            .expect("allocation effect succeeds");
        let provider_context: StorageProviderContext =
            decode_value(&allocation.native_context).expect("provider context decodes");
        fs::write(
            Path::new(&provider_context.path).join("content"),
            b"retained bytes",
        )
        .expect("fixture content is written");

        request.method.method = key("release");
        request.target.operations.push(key("release"));
        let release = provider
            .admit(request.clone())
            .expect("present allocation admits for release");
        let release_context = target_context(&request, &release);
        let result = provider
            .invoke(invocation(
                InvocationPurpose::Effect,
                &request,
                release_context.clone(),
            ))
            .expect("release effect succeeds");

        assert_eq!(result.disposition, InvocationDisposition::Completed);
        assert_eq!(result.outputs.len(), 1);
        assert!(result.outputs.contains_key(&key("observation")));
        assert!(!Path::new(&provider_context.path).exists());
        assert!(
            provider
                .claim_for(&request.resource_spec.resource)
                .expect("claim lookup succeeds")
                .is_none()
        );

        let reconciled = provider
            .invoke(invocation(
                InvocationPurpose::Reconcile,
                &request,
                release_context,
            ))
            .expect("released absence reconciles");
        assert_eq!(reconciled.disposition, InvocationDisposition::Completed);
        assert_eq!(observation_state(&reconciled.evidence), Some("absent"));
    }

    #[test]
    fn filesystem_entries_enforce_declared_parent_order_and_copy_exact_content() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        fs::create_dir_all(&provider.mutable_roots[0]).expect("mutable fixture root exists");

        let parent_request = entry_request(
            &provider,
            resource("wrapper-root"),
            "wrappers",
            json!({"kind":"directory"}),
            None,
            Vec::new(),
            Vec::new(),
        );
        let parent_admission = provider
            .admit(parent_request.clone())
            .expect("parent directory admits");
        provider
            .invoke(invocation(
                InvocationPurpose::Effect,
                &parent_request,
                target_context(&parent_request, &parent_admission),
            ))
            .expect("parent directory materializes");
        let observed_parent = provider
            .admit(parent_request.clone())
            .expect("parent directory observes");
        let parent_context = target_context(&parent_request, &observed_parent);

        let artifact = temporary.path().join("artifact");
        fs::create_dir(&artifact).expect("artifact root exists");
        fs::write(artifact.join("wrapper"), b"exact wrapper bytes").expect("artifact file exists");
        let source =
            fs::canonicalize(artifact.join("wrapper")).expect("artifact source canonicalizes");
        let source_value = json!({
            "kind": "artifact-file",
            "reference": {
                "artifact": {
                    "content": format!("sha256:{}", "1".repeat(64)),
                    "store_path": artifact,
                    "nar_hash": format!("sha256:{}", "2".repeat(64)),
                    "closure": format!("sha256:{}", "3".repeat(64)),
                },
                "path": "wrapper",
            },
        });
        let child_request = entry_request(
            &provider,
            resource("wrapper-bin"),
            "wrappers/tool",
            json!({
                "kind": "copied-file",
                "source": source_value,
                "maximum_size_bytes": MAX_SAFE_INTEGER,
            }),
            Some(&source),
            vec![parent_request.target.clone()],
            vec![parent_context.clone()],
        );
        let child_admission = provider
            .admit(child_request.clone())
            .expect("child file with an exact parent prerequisite admits");
        let result = provider
            .invoke(invocation_with_dependencies(
                InvocationPurpose::Effect,
                &child_request,
                target_context(&child_request, &child_admission),
                vec![parent_context.clone()],
            ))
            .expect("child file materializes");

        assert_eq!(result.disposition, InvocationDisposition::Completed);
        assert_eq!(
            fs::read(provider.mutable_roots[0].join("wrappers/tool"))
                .expect("copied file is readable"),
            b"exact wrapper bytes"
        );
        assert!(result.outputs.contains_key(&key("execution-path")));

        let bound_error = inspect_regular_file_nofollow(&source, 4)
            .expect_err("copy source larger than the declared bound must fail");
        assert!(bound_error.to_string().contains("byte bound"));
        let range_error = inspect_regular_file_nofollow(&source, MAX_SAFE_INTEGER + 1)
            .expect_err("copy source bound outside canonical JSON range must fail");
        assert!(range_error.to_string().contains("portable integer"));

        let undeclared_child = entry_request(
            &provider,
            resource("undeclared-child"),
            "wrappers/other",
            json!({"kind":"directory"}),
            None,
            Vec::new(),
            Vec::new(),
        );
        let error = provider
            .admit(undeclared_child)
            .expect_err("an undeclared claimed parent must fail admission");
        assert!(error.to_string().contains("parent"), "{error:#}");
    }

    #[test]
    fn persistent_release_detaches_ownership_without_deleting_retained_data() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let mut request = persistent_request(&provider, resource("persistent"));
        let admission = provider
            .admit(request.clone())
            .expect("persistent allocation admits");
        provider
            .invoke(invocation(
                InvocationPurpose::Effect,
                &request,
                target_context(&request, &admission),
            ))
            .expect("persistent allocation materializes");
        let context: StorageProviderContext =
            decode_value(&admission.native_context).expect("provider context decodes");
        let retained = Path::new(&context.path).join("retained");
        fs::write(&retained, b"persistent data").expect("persistent fixture is written");

        request.method.method = key("release");
        request.target.operations.push(key("release"));
        let release = provider
            .admit(request.clone())
            .expect("persistent release admits");
        provider
            .invoke(invocation(
                InvocationPurpose::Effect,
                &request,
                target_context(&request, &release),
            ))
            .expect("persistent allocation detaches");

        assert_eq!(
            fs::read(retained).expect("persistent bytes remain"),
            b"persistent data"
        );
        let resource_id = request.resource_spec.resource.clone();
        let detached = provider
            .admit(request)
            .expect("detached persistent allocation remains observable");
        assert!(matches!(
            detached.revision,
            AdmissionRevision::Present { .. }
        ));
        assert_eq!(observation_state(&detached.observation), Some("absent"));
        assert!(
            !provider
                .claim_for(&resource_id)
                .expect("persistent claim is readable")
                .is_some_and(|claim| claim.active)
        );
    }

    #[test]
    fn invocation_rejects_resource_set_drift_before_allocation() {
        let temporary = tempdir().expect("temporary directory exists");
        let provider = provider(temporary.path());
        let request = admission_request(&provider, resource("drifted"));
        let admission = provider
            .admit(request.clone())
            .expect("absent allocation admits");
        let context = target_context(&request, &admission);
        let provider_context: StorageProviderContext =
            decode_value(&admission.native_context).expect("provider context decodes");
        let mut invocation = invocation(InvocationPurpose::Effect, &request, context);
        invocation.request.native_context_digest = Sha256Digest::of_bytes(b"other-resource-set");

        let error = provider
            .invoke(invocation)
            .expect_err("resource-set drift must fail before effect");

        assert!(
            error.to_string().contains("resource-set digest"),
            "{error:#}"
        );
        assert!(!Path::new(&provider_context.path).exists());
    }
}
