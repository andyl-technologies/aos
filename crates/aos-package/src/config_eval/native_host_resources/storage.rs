//! Persistent storage ownership and PostgreSQL principal-slot allocation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::builtin::{HOST_STORAGE_OBSERVATION_SCHEMA, HOST_STORAGE_PATH_OUTPUT};
use aos_ability_model::{LocalKey, ResourceId};
use serde::{Deserialize, Serialize};

use super::super::native_resource_map::NativeResourceQualification;
use super::{
    HostState, NativeDependencyBinding, NativeHostRecord, NativeHostRequest, POSTGRESQL_GID,
    POSTGRESQL_SLOT_COUNT, STORAGE_ROOT, StorageInput, ability_value, decode_input,
    ensure_directory, invalid, new_state, path_text, postgresql_slot_principal,
    postgresql_slot_uid, protected_directory, read_state_optional, record,
    remove_atomic_temporary_root, require_current_state, resource_key, storage_path, store_error,
    write_state,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum StoragePhase {
    Preparing,
    Attached,
    Releasing,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageBinding {
    pub(crate) storage_resource: ResourceId,
    pub(crate) storage_path: String,
    pub(crate) cluster: String,
    pub(crate) purpose: String,
    pub(crate) slot: u8,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) principal: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageStateDetails {
    phase: StoragePhase,
    binding: StorageBinding,
}

/// Names one complete desired persistent-storage lease before operation admission.
#[derive(Clone, Debug)]
pub(crate) struct StorageAllocationRequest {
    pub(crate) resource: ResourceId,
    pub(crate) cluster: String,
    pub(crate) purpose: String,
}

/// Retains the catalog-wide deterministic slot assignment for one activation.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostResourceAllocations {
    storage: BTreeMap<ResourceId, StorageBinding>,
    postgresql_storage: BTreeMap<ResourceId, ResourceId>,
    endpoint_storage: BTreeMap<ResourceId, ResourceId>,
}

impl HostResourceAllocations {
    pub(crate) fn build(
        mut requests: Vec<StorageAllocationRequest>,
        mut postgresql_storage: BTreeMap<ResourceId, ResourceId>,
        mut postgresql_endpoint: BTreeMap<ResourceId, ResourceId>,
    ) -> Result<Self, io::Error> {
        super::endpoint::scan_endpoint_ledger_for_storage()?;
        requests.sort_by(|left, right| left.resource.cmp(&right.resource));
        let ledger = scan_storage_ledger()?;
        let mut retained = BTreeMap::new();
        let mut used_slots = BTreeSet::new();
        for details in ledger.values() {
            let binding = details.binding.clone();
            used_slots.insert(binding.slot);
            retained.insert(binding.storage_resource.clone(), binding);
        }

        let mut storage = BTreeMap::new();
        for request in requests {
            if let Some(binding) = retained.get(&request.resource) {
                require_binding_identity(
                    binding,
                    &request.resource,
                    &request.cluster,
                    &request.purpose,
                )?;
                storage.insert(request.resource, binding.clone());
                continue;
            }
            let slot = (0..POSTGRESQL_SLOT_COUNT)
                .find(|slot| !used_slots.contains(slot))
                .ok_or_else(|| invalid("PostgreSQL principal-slot pool is exhausted"))?;
            used_slots.insert(slot);
            let path = storage_path(&request.resource)?;
            let binding = StorageBinding {
                storage_resource: request.resource.clone(),
                storage_path: path_text(&path)?,
                cluster: request.cluster,
                purpose: request.purpose,
                slot,
                uid: postgresql_slot_uid(slot)?,
                gid: POSTGRESQL_GID,
                principal: postgresql_slot_principal(slot)?,
            };
            storage.insert(request.resource, binding);
        }

        // Retained leases remain authoritative even when the next graph only
        // observes or tears down their PostgreSQL consumer.
        for (resource, binding) in retained {
            storage.entry(resource).or_insert(binding);
        }
        for (postgresql, association) in super::postgresql::retained_associations()? {
            let storage_resource = association.storage.storage_resource.clone();
            if storage.get(&storage_resource) != Some(&association.storage) {
                return Err(invalid(
                    "retained PostgreSQL and storage ledgers disagree about their binding",
                ));
            }
            if let Some(desired_storage) = postgresql_storage.get(&postgresql) {
                if desired_storage != &storage_resource {
                    return Err(invalid(
                        "retained PostgreSQL resource selected another storage producer",
                    ));
                }
            } else {
                postgresql_storage.insert(postgresql.clone(), storage_resource);
            }
            if let Some(desired_endpoint) = postgresql_endpoint.get(&postgresql) {
                if desired_endpoint != &association.endpoint_resource {
                    return Err(invalid(
                        "retained PostgreSQL resource selected another endpoint producer",
                    ));
                }
            } else {
                postgresql_endpoint.insert(postgresql, association.endpoint_resource);
            }
        }

        let mut claimed_storage = BTreeSet::new();
        for (postgresql, storage_resource) in &postgresql_storage {
            if !storage.contains_key(storage_resource) {
                return Err(invalid(
                    "PostgreSQL resource names a storage producer outside the catalog",
                ));
            }
            if !claimed_storage.insert(storage_resource.clone()) {
                return Err(invalid(
                    "one storage producer is claimed by multiple PostgreSQL resources",
                ));
            }
            if postgresql == storage_resource {
                return Err(invalid(
                    "PostgreSQL resource cannot produce its own storage",
                ));
            }
        }
        let mut endpoint_storage = BTreeMap::new();
        for (postgresql, endpoint) in postgresql_endpoint {
            let storage_resource = postgresql_storage
                .get(&postgresql)
                .ok_or_else(|| invalid("PostgreSQL endpoint association has no storage binding"))?;
            if endpoint_storage
                .insert(endpoint.clone(), storage_resource.clone())
                .is_some()
            {
                return Err(invalid(
                    "one endpoint producer is claimed by multiple PostgreSQL resources",
                ));
            }
            let binding = storage.get(storage_resource).ok_or_else(|| {
                invalid("endpoint association names an unavailable storage binding")
            })?;
            super::endpoint::authenticate_endpoint_storage_binding(&endpoint, binding)?;
        }
        Ok(Self {
            storage,
            postgresql_storage,
            endpoint_storage,
        })
    }

    pub(crate) fn storage(&self, resource: &ResourceId) -> Option<StorageBinding> {
        self.storage.get(resource).cloned()
    }

    pub(crate) fn postgresql(&self, resource: &ResourceId) -> Option<StorageBinding> {
        let storage = self.postgresql_storage.get(resource)?;
        self.storage.get(storage).cloned()
    }

    pub(crate) fn endpoint(&self, resource: &ResourceId) -> Option<StorageBinding> {
        let storage = self.endpoint_storage.get(resource)?;
        self.storage.get(storage).cloned()
    }
}

pub(super) fn execute_storage(request: &NativeHostRequest) -> Result<NativeHostRecord, io::Error> {
    let input: StorageInput = decode_input(&request.durable.inputs, "host storage")?;
    let binding = request
        .durable
        .storage_binding
        .as_ref()
        .ok_or_else(|| invalid("durable storage request has no principal-slot binding"))?;
    require_binding_request(binding, &request.durable.resource, &input)?;
    let path = Path::new(&binding.storage_path);

    match request.durable.method.as_str() {
        "ensure" => {
            revalidate_reserved_binding(binding)?;
            write_storage_state(request, StoragePhase::Preparing, binding.clone())?;
            ensure_directory(path, binding.uid, binding.gid, 0o700)?;
            write_storage_state(request, StoragePhase::Attached, binding.clone())?;
            storage_record(request, path, true, true, Some(request.durable.revision))
        }
        "observe" => {
            let state = require_current_state(request)?;
            let details = storage_details(&state)?;
            if &details.binding != binding {
                return Err(invalid("storage observation binding changed"));
            }
            if details.phase != StoragePhase::Attached {
                return Err(invalid("storage attachment is not active"));
            }
            protected_directory(path, binding.uid, binding.gid, 0o700)?;
            storage_record(request, path, true, true, Some(state.revision))
        }
        "release" => {
            let Some(state) = super::read_state_optional(&request.resource.state_path)? else {
                return match fs::symlink_metadata(path) {
                    Ok(_) => Err(invalid(
                        "storage directory exists without an ownership marker",
                    )),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        remove_atomic_temporary_root(&request.resource.state_path, 0o600)?;
                        storage_record(request, path, false, false, None)
                    }
                    Err(error) => Err(error),
                };
            };
            super::require_matching_state(request, &state)?;
            let details = storage_details(&state)?;
            if details.binding != *binding {
                return Err(invalid("storage release binding changed"));
            }
            protected_directory(path, binding.uid, binding.gid, 0o700)?;
            write_storage_state(request, StoragePhase::Releasing, binding.clone())?;
            // Persistent storage and its slot lease survive logical release.
            write_storage_state(request, StoragePhase::Released, binding.clone())?;
            storage_record(request, path, false, true, Some(request.durable.revision))
        }
        _ => Err(invalid("unsupported storage method")),
    }
}

fn resolve_storage_binding(
    storage_path: &str,
    cluster: &str,
) -> Result<(PathBuf, HostState, StorageStateDetails), io::Error> {
    let ledger = scan_storage_ledger()?;
    let path = PathBuf::from(storage_path);
    let digest = canonical_storage_digest(&path)?;
    let marker = Path::new(STORAGE_ROOT).join(format!(".{digest}.json"));
    let state = read_state_optional(&marker)?
        .ok_or_else(|| invalid("PostgreSQL storage path has no ownership ledger"))?;
    let details = storage_details(&state)?;
    validate_ledger_entry(&marker, &state, &details)?;
    if details.binding.storage_path != storage_path
        || details.binding.cluster != cluster
        || details.binding.purpose != "database"
        || details.phase != StoragePhase::Attached
    {
        return Err(invalid(
            "PostgreSQL storage does not match an attached database binding",
        ));
    }
    protected_directory(&path, details.binding.uid, details.binding.gid, 0o700)?;
    if !ledger.contains_key(&marker) {
        return Err(invalid(
            "storage binding disappeared from the global ledger",
        ));
    }
    Ok((marker, state, details))
}

pub(super) fn authenticate_storage_dependency(
    dependency: &NativeDependencyBinding,
    storage_path: &str,
    cluster: &str,
) -> Result<StorageBinding, io::Error> {
    let (marker, state, details) = resolve_storage_binding(storage_path, cluster)?;
    if state.resource != dependency.resource
        || state.revision != dependency.revision
        || state.qualification != dependency.qualification
        || details.binding.storage_resource != dependency.resource
    {
        return Err(invalid(
            "storage dependency differs from its producer qualification",
        ));
    }
    let expected_marker =
        Path::new(STORAGE_ROOT).join(format!(".{}.json", resource_key(&dependency.resource)?));
    if marker != expected_marker {
        return Err(invalid("storage dependency marker path is inconsistent"));
    }
    Ok(details.binding)
}

pub(super) fn authenticate_exact_binding(binding: &StorageBinding) -> Result<(), io::Error> {
    let ledger = scan_storage_ledger()?;
    let marker = Path::new(STORAGE_ROOT).join(format!(
        ".{}.json",
        resource_key(&binding.storage_resource)?
    ));
    let details = ledger
        .get(&marker)
        .ok_or_else(|| invalid("endpoint storage binding has no ownership ledger"))?;
    if details.binding != *binding || details.phase != StoragePhase::Attached {
        return Err(invalid(
            "endpoint storage binding is not the exact attached lease",
        ));
    }
    protected_directory(
        Path::new(&binding.storage_path),
        binding.uid,
        binding.gid,
        0o700,
    )
}

pub(super) fn storage_health(state: &HostState) -> Result<(bool, bool), io::Error> {
    let details = storage_details(state)?;
    let path = Path::new(&details.binding.storage_path);
    let exists = match fs::symlink_metadata(path) {
        Ok(_) => {
            protected_directory(path, details.binding.uid, details.binding.gid, 0o700)?;
            true
        }
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && details.phase == StoragePhase::Preparing =>
        {
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(invalid("settled persistent storage is absent"));
        }
        Err(error) => return Err(error),
    };
    Ok((exists, details.phase == StoragePhase::Attached))
}

fn revalidate_reserved_binding(binding: &StorageBinding) -> Result<(), io::Error> {
    let ledger = scan_storage_ledger()?;
    for details in ledger.values() {
        let existing = &details.binding;
        if existing.storage_resource == binding.storage_resource {
            if existing != binding {
                return Err(invalid("reserved storage slot changed before publication"));
            }
            return Ok(());
        }
        if existing.slot == binding.slot
            || existing.uid == binding.uid
            || existing.storage_path == binding.storage_path
        {
            return Err(invalid("reserved storage slot collided before publication"));
        }
    }
    if Path::new(&binding.storage_path).try_exists()? {
        return Err(invalid(
            "storage directory exists without an ownership ledger",
        ));
    }
    Ok(())
}

fn scan_storage_ledger() -> Result<BTreeMap<PathBuf, StorageStateDetails>, io::Error> {
    let mut ledger = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for entry in fs::read_dir(STORAGE_ROOT)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("storage ledger contains a non-UTF-8 entry"))?;
        if let Some(digest) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|digest| canonical_digest(digest))
        {
            let path = entry.path();
            let state = read_state_optional(&path)?
                .ok_or_else(|| invalid("storage ledger entry disappeared during scan"))?;
            let details = storage_details(&state)?;
            validate_ledger_entry(&path, &state, &details)?;
            if resource_key(&details.binding.storage_resource)? != digest {
                return Err(invalid("storage ledger filename differs from its resource"));
            }
            ledger.insert(path, details);
        } else if super::is_protected_atomic_temporary(&entry.path())? {
            continue;
        } else if canonical_digest(&name) && entry.file_type()?.is_dir() {
            directories.insert(name);
        } else {
            return Err(invalid("storage root contains an unknown entry"));
        }
    }

    let mut slots = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut resources = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for details in ledger.values() {
        let binding = &details.binding;
        if !slots.insert(binding.slot)
            || !uids.insert(binding.uid)
            || !resources.insert(binding.storage_resource.clone())
            || !paths.insert(binding.storage_path.clone())
        {
            return Err(invalid("storage ledger contains a duplicate binding"));
        }
        let path = Path::new(&binding.storage_path);
        match fs::symlink_metadata(path) {
            Ok(_) => protected_directory(path, binding.uid, binding.gid, 0o700)?,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && details.phase == StoragePhase::Preparing => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(invalid(
                    "settled persistent storage is absent from its owned path",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    for directory in directories {
        if !ledger.keys().any(|marker| {
            marker.file_name().and_then(|name| name.to_str()) == Some(&format!(".{directory}.json"))
        }) {
            return Err(invalid(
                "storage directory exists without an ownership ledger",
            ));
        }
    }
    Ok(ledger)
}

fn validate_ledger_entry(
    marker: &Path,
    state: &HostState,
    details: &StorageStateDetails,
) -> Result<(), io::Error> {
    let NativeResourceQualification::HostStorage { cluster, purpose } = &state.qualification else {
        return Err(invalid("storage ledger has another qualification"));
    };
    let binding = &details.binding;
    let expected_path = storage_path(&state.resource)?;
    let expected_marker =
        Path::new(STORAGE_ROOT).join(format!(".{}.json", resource_key(&state.resource)?));
    if binding.storage_resource != state.resource
        || binding.storage_path != path_text(&expected_path)?
        || binding.cluster != *cluster
        || binding.purpose != *purpose
        || binding.slot >= POSTGRESQL_SLOT_COUNT
        || binding.uid != postgresql_slot_uid(binding.slot)?
        || binding.gid != POSTGRESQL_GID
        || binding.principal != postgresql_slot_principal(binding.slot)?
        || marker != expected_marker
    {
        return Err(invalid("storage ledger entry is inconsistent"));
    }
    Ok(())
}

fn require_binding_request(
    binding: &StorageBinding,
    resource: &ResourceId,
    input: &StorageInput,
) -> Result<(), io::Error> {
    if binding.storage_resource != *resource
        || binding.storage_path != path_text(&storage_path(resource)?)?
        || binding.cluster != input.cluster
        || binding.purpose != input.purpose
    {
        return Err(invalid(
            "storage principal-slot binding differs from request",
        ));
    }
    Ok(())
}

fn require_binding_identity(
    binding: &StorageBinding,
    resource: &ResourceId,
    cluster: &str,
    purpose: &str,
) -> Result<(), io::Error> {
    if binding.storage_resource != *resource
        || binding.storage_path != path_text(&storage_path(resource)?)?
        || binding.cluster != cluster
        || binding.purpose != purpose
    {
        return Err(invalid(
            "retained storage lease differs from the desired stable identity",
        ));
    }
    Ok(())
}

fn storage_details(state: &HostState) -> Result<StorageStateDetails, io::Error> {
    serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid storage ledger details: {error}")))
}

fn write_storage_state(
    request: &NativeHostRequest,
    phase: StoragePhase,
    binding: StorageBinding,
) -> Result<(), io::Error> {
    write_state(
        &request.resource.state_path,
        &new_state(
            request,
            serde_json::to_value(StorageStateDetails { phase, binding }).map_err(store_error)?,
        ),
    )
}

fn canonical_storage_digest(path: &Path) -> Result<&str, io::Error> {
    if path.parent() != Some(Path::new(STORAGE_ROOT)) {
        return Err(invalid(
            "storage path is outside the protected storage root",
        ));
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|digest| canonical_digest(digest))
        .ok_or_else(|| invalid("storage path has a noncanonical resource digest"))
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn storage_record(
    request: &NativeHostRequest,
    path: &Path,
    attached: bool,
    exists: bool,
    observed_revision: Option<aos_ability_model::RevisionId>,
) -> Result<NativeHostRecord, io::Error> {
    let result = serde_json::json!({
        "schema": HOST_STORAGE_OBSERVATION_SCHEMA,
        "requested_revision": request.durable.revision.0.to_string(),
        "observed_revision": observed_revision.map(|revision| revision.0.to_string()),
        "attached": attached,
        "exists": exists,
        "path": path_text(path)?,
    });
    let outputs = matches!(request.durable.method.as_str(), "ensure" | "observe")
        .then(|| -> Result<_, io::Error> {
            Ok(BTreeMap::from([(
                LocalKey::new(HOST_STORAGE_PATH_OUTPUT).map_err(store_error)?,
                ability_value(serde_json::Value::String(path_text(path)?))?,
            )]))
        })
        .transpose()?
        .unwrap_or_default();
    record(result, outputs)
}
