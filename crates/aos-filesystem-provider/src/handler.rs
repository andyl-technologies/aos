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
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, MAX_SAFE_INTEGER,
    MethodReference, ResourceId, ResourceReference, RevisionId,
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

const PROVIDER_CONTEXT_SCHEMA: &str = "aos.filesystem.storage-context/v1";
const CLAIM_SCHEMA: &str = "aos.filesystem.storage-claim/v1";
const VIEW_CLAIM_SCHEMA: &str = "aos.filesystem.storage-view-claim/v1";
const REALIZATION_SCHEMA: &str = "aos.filesystem.storage-realization/v1";
const ENTRY_REALIZATION_SCHEMA: &str = "aos.filesystem.entry-realization/v1";
const VIEW_REALIZATION_SCHEMA: &str = "aos.filesystem.storage-view-realization/v1";
const INSTANCE_ALLOCATION_INTERFACE: &str = "aos.filesystem.storage-allocation-effects";
const PERSISTENT_ALLOCATION_INTERFACE: &str =
    "aos.filesystem.persistent-storage-allocation-effects";
const STORAGE_VIEW_INTERFACE: &str = "aos.filesystem.storage-view-effects";
const FILESYSTEM_ENTRY_INTERFACE: &str = "aos.filesystem.filesystem-entry-effects";
const LOCK_RETRY: Duration = Duration::from_millis(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FilesystemRole {
    InstanceAllocation,
    PersistentAllocation,
    StorageView,
    FilesystemEntry,
}

impl FilesystemRole {
    fn from_method(method: &MethodReference) -> Result<Self> {
        match method.interface.name.as_str() {
            INSTANCE_ALLOCATION_INTERFACE => Ok(Self::InstanceAllocation),
            PERSISTENT_ALLOCATION_INTERFACE => Ok(Self::PersistentAllocation),
            STORAGE_VIEW_INTERFACE => Ok(Self::StorageView),
            FILESYSTEM_ENTRY_INTERFACE => Ok(Self::FilesystemEntry),
            _ => bail!("selected interface does not belong to the filesystem provider"),
        }
    }

    const fn context_kind(self) -> StorageContextKind {
        match self {
            Self::InstanceAllocation | Self::PersistentAllocation => StorageContextKind::Allocation,
            Self::StorageView => StorageContextKind::View,
            Self::FilesystemEntry => StorageContextKind::Entry,
        }
    }
}

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
    /// role belongs to this provider, all native context is exact, and the
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
                let role = FilesystemRole::from_method(&request.method)?;
                serde_json::to_value(self.admit(role, request)?)?
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
                ensure!(
                    invocation.method_is_bound(),
                    "invocation method differs from durable recovery authority"
                );
                let role = FilesystemRole::from_method(&invocation.method)?;
                serde_json::to_value(self.invoke(role, invocation)?)?
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };
        aos_contract::canonical::canonical_json(&result)
            .context("encoding canonical storage response")
    }

    fn admit(&self, role: FilesystemRole, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        let desired = request.resource_spec.value.clone();
        let (path, observation, revision) = match role {
            FilesystemRole::InstanceAllocation | FilesystemRole::PersistentAllocation => {
                let input: StorageAllocationRequest = decode_value(&desired)?;
                let path = self.storage_path(role, &request.resource_spec.resource, &input)?;
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
            FilesystemRole::StorageView => {
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
                ensure!(
                    root == Path::new(&input.source_path),
                    "storage view planned source path differs from its admitted allocation"
                );
                let path = if root.exists() {
                    resolve_storage_view_path(root, input.relative_path.as_deref())?
                } else {
                    planned_child_path(root, input.relative_path.as_deref())?
                };
                ensure!(
                    path == Path::new(&realization.path),
                    "storage view realization path differs from its resolved planned path"
                );
                let claim = self.view_claim_for(&request.resource_spec.resource)?;
                let state = inspect_view(
                    root,
                    &path,
                    claim.as_ref(),
                    &request.resource_spec.resource,
                    request.resource_spec.revision,
                    &input.source,
                    source.revision,
                )?;
                let observation = storage_view_observation(
                    &desired,
                    state.is_present().then(|| path_string(&path)).transpose()?,
                    state.observation_state(),
                )?;
                (path, observation, state.revision())
            }
            FilesystemRole::FilesystemEntry => self.admit_entry(&request)?,
        };
        let native_context = ability_value(json!({
            "schema": PROVIDER_CONTEXT_SCHEMA,
            "kind": role.context_kind(),
            "path": path_string(&path)?,
        }))?;
        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision,
            incarnation: Some(request.assignment.incarnation),
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

    fn invoke(&self, role: FilesystemRole, invocation: Invocation) -> Result<InvocationResult> {
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
        ensure!(
            request.target.interface == request.method.interface
                && invocation.method.interface == request.method.interface,
            "invocation method differs from the checked target interface"
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

        ensure!(
            provider_context.kind == role.context_kind(),
            "admitted filesystem context differs from the selected handler role"
        );
        let observation_before = self.observe_request(role, &bound, &request.resources)?;
        let (disposition, evidence, mut outputs) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => (
                InvocationDisposition::Completed,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
                self.release(
                    role,
                    &bound,
                    &provider_context,
                    invocation.control.attempt_remaining_millis,
                )?;
                let evidence = self.observe_request(role, &bound, &request.resources)?;
                (InvocationDisposition::Completed, evidence, BTreeMap::new())
            }
            InvocationPurpose::Effect => {
                if role == FilesystemRole::FilesystemEntry {
                    self.apply_entry(
                        &bound,
                        &provider_context,
                        &request.resources,
                        invocation.control.attempt_remaining_millis,
                    )?;
                } else if role == FilesystemRole::StorageView {
                    self.apply_view(
                        &bound,
                        &provider_context,
                        &request.resources,
                        invocation.control.attempt_remaining_millis,
                    )?;
                } else {
                    self.apply(
                        role,
                        &bound,
                        &provider_context,
                        invocation.control.attempt_remaining_millis,
                    )?;
                }
                let evidence = self.observe_request(role, &bound, &request.resources)?;
                let outputs = successful_outputs(
                    role,
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
                            role,
                            &bound,
                            &provider_context,
                            invocation.control.recovery_remaining_millis,
                        )?;
                        let evidence = self.observe_request(role, &bound, &request.resources)?;
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
                        role,
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
                        role,
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
        role: FilesystemRole,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        remaining_millis: u64,
    ) -> Result<()> {
        ensure!(
            context.kind == StorageContextKind::Allocation,
            "storage views have no mutating effect"
        );
        ensure!(
            matches!(
                role,
                FilesystemRole::InstanceAllocation | FilesystemRole::PersistentAllocation
            ),
            "selected method has no storage allocation effect"
        );
        let input: StorageAllocationRequest = decode_value(&bound.resource_spec.value)?;
        let expected = self.storage_path(role, &bound.resource_spec.resource, &input)?;
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

    fn apply_view(
        &self,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        resources: &[ResourceContext],
        remaining_millis: u64,
    ) -> Result<()> {
        ensure!(
            context.kind == StorageContextKind::View,
            "storage-view effect has the wrong admitted context kind"
        );
        let input: StorageViewRequest = decode_value(&bound.resource_spec.value)?;
        let source = exact_resource_context(resources, &input.source)?;
        let source_context = decode_provider_context(source)?;
        ensure!(
            source_context.kind == StorageContextKind::Allocation,
            "storage view source is not an admitted allocation"
        );
        let root = Path::new(&source_context.path);
        ensure!(
            root == Path::new(&input.source_path),
            "storage view planned source path differs from its admitted allocation"
        );
        ensure!(root.is_dir(), "storage view source is not materialized");
        let path = resolve_storage_view_path(root, input.relative_path.as_deref())?;
        let realization: StorageViewRealization = decode_value(&bound.resource_spec.realization)?;
        ensure!(
            Path::new(&context.path) == path && Path::new(&realization.path) == path,
            "admitted storage-view path drifted before effect"
        );

        let _lock = StateLock::acquire(&self.state_root, remaining_millis)?;
        self.write_view_claim(&StorageViewClaim {
            schema: VIEW_CLAIM_SCHEMA.into(),
            resource: bound.resource_spec.resource.clone(),
            revision: bound.resource_spec.revision,
            source: input.source,
            source_revision: source.revision,
            path,
            active: true,
        })
    }

    fn release(
        &self,
        role: FilesystemRole,
        bound: &BoundNativeContext,
        context: &StorageProviderContext,
        remaining_millis: u64,
    ) -> Result<()> {
        let expected = match role {
            FilesystemRole::InstanceAllocation | FilesystemRole::PersistentAllocation => {
                ensure!(
                    context.kind == StorageContextKind::Allocation,
                    "storage release has the wrong admitted context kind"
                );
                let input: StorageAllocationRequest = decode_value(&bound.resource_spec.value)?;
                self.storage_path(role, &bound.resource_spec.resource, &input)?
            }
            FilesystemRole::FilesystemEntry => {
                ensure!(
                    context.kind == StorageContextKind::Entry,
                    "filesystem entry release has the wrong admitted context kind"
                );
                let input: FilesystemEntryRequest = decode_value(&bound.resource_spec.value)?;
                PathBuf::from(input.destination)
            }
            FilesystemRole::StorageView => {
                ensure!(
                    context.kind == StorageContextKind::View,
                    "storage-view release has the wrong admitted context kind"
                );
                let input: StorageViewRequest = decode_value(&bound.resource_spec.value)?;
                let realization: StorageViewRealization =
                    decode_value(&bound.resource_spec.realization)?;
                ensure!(
                    realization.schema == VIEW_REALIZATION_SCHEMA
                        && realization.source == input.source
                        && realization.relative_path == input.relative_path
                        && realization.path == context.path,
                    "storage-view realization drifted before release"
                );
                PathBuf::from(&context.path)
            }
        };
        ensure!(
            Path::new(&context.path) == expected,
            "admitted storage path drifted before release"
        );

        let _lock = StateLock::acquire(&self.state_root, remaining_millis)?;
        if role == FilesystemRole::StorageView {
            let claim = self
                .view_claim_for(&bound.resource_spec.resource)?
                .context("storage-view release requires its durable ownership claim")?;
            ensure!(
                claim.resource == bound.resource_spec.resource
                    && claim.revision == bound.resource_spec.revision
                    && claim.path == expected,
                "storage-view release claim differs from the checked resource revision"
            );
            return self.remove_view_claim(&bound.resource_spec.resource);
        }
        if role == FilesystemRole::PersistentAllocation {
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
        role: FilesystemRole,
        bound: &BoundNativeContext,
        resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        let desired = &bound.resource_spec.value;
        match role {
            FilesystemRole::InstanceAllocation | FilesystemRole::PersistentAllocation => {
                let input: StorageAllocationRequest = decode_value(desired)?;
                let path = self.storage_path(role, &bound.resource_spec.resource, &input)?;
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
            FilesystemRole::StorageView => {
                let input: StorageViewRequest = decode_value(desired)?;
                let source = exact_resource_context(resources, &input.source)?;
                let source_context = decode_provider_context(source)?;
                let root = Path::new(&source_context.path);
                ensure!(
                    root == Path::new(&input.source_path),
                    "storage view planned source path differs from its admitted allocation"
                );
                let path = if root.exists() {
                    resolve_storage_view_path(root, input.relative_path.as_deref())?
                } else {
                    planned_child_path(root, input.relative_path.as_deref())?
                };
                let claim = self.view_claim_for(&bound.resource_spec.resource)?;
                let state = inspect_view(
                    root,
                    &path,
                    claim.as_ref(),
                    &bound.resource_spec.resource,
                    bound.resource_spec.revision,
                    &input.source,
                    source.revision,
                )?;
                storage_view_observation(
                    desired,
                    state.is_present().then(|| path_string(&path)).transpose()?,
                    state.observation_state(),
                )
            }
            FilesystemRole::FilesystemEntry => self.observe_entry(bound, resources),
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
        role: FilesystemRole,
        resource: &ResourceId,
        request: &StorageAllocationRequest,
    ) -> Result<PathBuf> {
        if let Some(path) = &request.requested_path {
            let path = PathBuf::from(path);
            validate_requested_storage_path(&path)?;
            return Ok(path);
        }
        let root = if role == FilesystemRole::PersistentAllocation {
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
        let path = match source.as_ref() {
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
            let claim: StorageClaim = read_private_record(&entry.path(), "storage claim")?
                .context("storage claim disappeared while enumerating it")?;
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
        let claim: Option<StorageClaim> = read_private_record(&path, "storage claim")?;
        if let Some(claim) = claim.as_ref() {
            ensure!(
                claim.schema == CLAIM_SCHEMA && claim.resource == *resource,
                "storage claim identity differs"
            );
        }
        Ok(claim)
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
        write_private_record(&claims, &destination, claim)
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

    fn view_claim_for(&self, resource: &ResourceId) -> Result<Option<StorageViewClaim>> {
        let path = self.view_claim_path(resource)?;
        let claim: Option<StorageViewClaim> = read_private_record(&path, "storage-view claim")?;
        if let Some(claim) = claim.as_ref() {
            ensure!(
                claim.schema == VIEW_CLAIM_SCHEMA && claim.resource == *resource,
                "storage-view claim identity differs"
            );
        }
        Ok(claim)
    }

    fn view_claim_path(&self, resource: &ResourceId) -> Result<PathBuf> {
        let digest =
            Sha256Digest::of_canonical("aos.filesystem.storage-view-claim-name/v1", resource)?;
        Ok(self
            .state_root
            .join("views")
            .join(format!("{}.json", digest.hex())))
    }

    fn write_view_claim(&self, claim: &StorageViewClaim) -> Result<()> {
        let views = self.state_root.join("views");
        ensure_private_directory(&self.state_root)?;
        ensure_private_directory(&views)?;
        write_private_record(&views, &self.view_claim_path(&claim.resource)?, claim)
    }

    fn remove_view_claim(&self, resource: &ResourceId) -> Result<()> {
        let path = self.view_claim_path(resource)?;
        match fs::remove_file(&path) {
            Ok(()) => {
                File::open(self.state_root.join("views"))?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing released storage-view claim"),
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
    source_path: String,
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
    path: String,
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
        source: Box<FilesystemEntrySource>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageViewClaim {
    schema: String,
    resource: ResourceId,
    revision: RevisionId,
    source: ResourceReference,
    source_revision: RevisionId,
    path: PathBuf,
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

mod filesystem;
use filesystem::*;

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
mod tests;
