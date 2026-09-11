//! Protected on-disk state and filesystem invariants.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::Path;

use aos_ability_model::{ResourceId, RevisionId};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::super::native_resource_map::NativeResourceQualification;
use super::{NativeHostRequest, NativeHostResourceSpec, invalid, store_error};

pub(super) const RUNTIME_ROOT: &str = "/var/lib/aos/ability-runtime";
pub(super) const CREDENTIAL_SOURCE_ROOT: &str = "/var/lib/aos/ability-runtime/credential-sources";
pub(super) const CREDENTIAL_ROOT: &str = "/var/lib/aos/ability-runtime/credentials";
pub(super) const ENDPOINT_ROOT: &str = "/var/lib/aos/ability-runtime/endpoints";
pub(super) const STORAGE_ROOT: &str = "/var/lib/aos/ability-runtime/storage";
pub(super) const POLICY_ROOT: &str = "/var/lib/aos/ability-runtime/network-policy";
pub(super) const POSTGRESQL_ROOT: &str = "/var/lib/aos/ability-runtime/postgresql";
const STATE_SCHEMA: &str = "aos.ability.native-host-resource-state/v1";
pub(super) const MAX_STATE_BYTES: u64 = 256 * 1024;
pub(super) const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
pub(super) const POSTGRESQL_GID: u32 = 71;
pub(super) const POSTGRESQL_SLOT_COUNT: u8 = 64;
pub(super) const POSTGRESQL_UID_BASE: u32 = 7100;
pub(super) const POSTGRESQL_PROBE_UID_BASE: u32 = 7200;
pub(super) const POSTGRESQL_BROKER_UID_BASE: u32 = 7300;

pub(super) fn postgresql_slot_uid(slot: u8) -> Result<u32, io::Error> {
    if slot >= POSTGRESQL_SLOT_COUNT {
        return Err(invalid(
            "PostgreSQL principal slot is outside the fixed pool",
        ));
    }
    Ok(POSTGRESQL_UID_BASE + u32::from(slot))
}

pub(super) fn postgresql_slot_principal(slot: u8) -> Result<String, io::Error> {
    postgresql_slot_uid(slot)?;
    Ok(format!("aos-ability-pg-{slot:02}"))
}

pub(super) fn postgresql_probe_uid(slot: u8) -> Result<u32, io::Error> {
    if slot >= POSTGRESQL_SLOT_COUNT {
        return Err(invalid("PostgreSQL probe slot is outside the fixed pool"));
    }
    Ok(POSTGRESQL_PROBE_UID_BASE + u32::from(slot))
}

pub(super) fn postgresql_probe_gid(slot: u8) -> Result<u32, io::Error> {
    postgresql_probe_uid(slot)
}

pub(super) fn postgresql_probe_principal(slot: u8) -> Result<String, io::Error> {
    postgresql_probe_uid(slot)?;
    Ok(format!("aos-ability-pg-probe-{slot:02}"))
}

pub(super) fn postgresql_broker_uid(slot: u8) -> Result<u32, io::Error> {
    if slot >= POSTGRESQL_SLOT_COUNT {
        return Err(invalid("PostgreSQL broker slot is outside the fixed pool"));
    }
    Ok(POSTGRESQL_BROKER_UID_BASE + u32::from(slot))
}

pub(super) fn postgresql_broker_principal(slot: u8) -> Result<String, io::Error> {
    postgresql_broker_uid(slot)?;
    Ok(format!("aos-ability-pg-broker-{slot:02}"))
}

#[derive(Clone, Copy)]
struct FileIdentity {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostState {
    pub(super) schema: String,
    pub(super) resource: ResourceId,
    pub(super) revision: RevisionId,
    pub(super) qualification: NativeResourceQualification,
    pub(super) details: serde_json::Value,
}

pub(super) fn new_state(request: &NativeHostRequest, details: serde_json::Value) -> HostState {
    HostState {
        schema: STATE_SCHEMA.to_string(),
        resource: request.durable.resource.clone(),
        revision: request.durable.revision,
        qualification: request.resource.spec.qualification.clone(),
        details,
    }
}

pub(super) fn require_state(request: &NativeHostRequest) -> Result<HostState, io::Error> {
    let state = read_state_optional(&request.resource.state_path)?
        .ok_or_else(|| invalid("host-resource state is absent"))?;
    require_matching_state(request, &state)?;
    Ok(state)
}

pub(super) fn require_current_state(request: &NativeHostRequest) -> Result<HostState, io::Error> {
    let state = require_state(request)?;
    if state.revision != request.durable.revision
        || state.qualification != request.resource.spec.qualification
    {
        return Err(invalid(
            "host-resource state lacks exact current revision authority",
        ));
    }
    Ok(state)
}

pub(super) fn require_matching_state(
    request: &NativeHostRequest,
    state: &HostState,
) -> Result<(), io::Error> {
    if state.schema != STATE_SCHEMA
        || state.resource != request.durable.resource
        || !same_stable_qualification(&state.qualification, &request.resource.spec.qualification)
    {
        return Err(invalid("host-resource state is foreign or mismatched"));
    }
    Ok(())
}

pub(super) fn state_matches_spec(state: &HostState, spec: &NativeHostResourceSpec) -> bool {
    state.schema == STATE_SCHEMA
        && state.resource == spec.resource
        && same_stable_qualification(&state.qualification, &spec.qualification)
}

fn same_stable_qualification(
    existing: &NativeResourceQualification,
    desired: &NativeResourceQualification,
) -> bool {
    match (existing, desired) {
        (
            NativeResourceQualification::Postgresql {
                cluster: old_cluster,
                database: old_database,
                postgresql_major: old_major,
                role: old_role,
                ..
            },
            NativeResourceQualification::Postgresql {
                cluster: new_cluster,
                database: new_database,
                postgresql_major: new_major,
                role: new_role,
                ..
            },
        ) => {
            old_cluster == new_cluster
                && old_database == new_database
                && old_major == new_major
                && old_role == new_role
        }
        _ => existing == desired,
    }
}

pub(super) fn write_state(path: &Path, state: &HostState) -> Result<(), io::Error> {
    let bytes = aos_contract::canonical::to_vec(state).map_err(store_error)?;
    atomic_write_root(path, &bytes, 0o600)
}

pub(super) fn read_state_optional(path: &Path) -> Result<Option<HostState>, io::Error> {
    let bytes = match read_protected_file(path, MAX_STATE_BYTES, 0, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let state: HostState =
        aos_contract::canonical::from_slice(&bytes, "native host state").map_err(store_error)?;
    if state.schema != STATE_SCHEMA {
        return Err(invalid("unsupported native host-resource state schema"));
    }
    Ok(Some(state))
}

/// Authenticates the production-created shared roots without repairing them.
pub(super) fn ensure_runtime_roots() -> Result<(), io::Error> {
    protected_directory(Path::new(RUNTIME_ROOT), 0, POSTGRESQL_GID, 0o710)?;
    for root in [
        CREDENTIAL_SOURCE_ROOT,
        CREDENTIAL_ROOT,
        ENDPOINT_ROOT,
        POLICY_ROOT,
    ] {
        protected_directory(Path::new(root), 0, 0, 0o700)?;
    }
    for root in [STORAGE_ROOT, POSTGRESQL_ROOT] {
        protected_directory(Path::new(root), 0, POSTGRESQL_GID, 0o710)?;
    }
    Ok(())
}

/// Creates one previously absent final leaf below an authenticated parent.
pub(super) fn ensure_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), io::Error> {
    if !path.is_absolute() {
        return Err(invalid("native host-resource directory is not absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("native host-resource directory has no parent"))?;
    authenticate_known_parent(parent)?;

    match fs::symlink_metadata(path) {
        Ok(_) => return protected_directory(path, uid, gid, mode),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    let result = (|| {
        chown_path(path, uid, gid)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        protected_directory(path, uid, gid, mode)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_dir(path);
    }
    result
}

pub(super) fn protected_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
    {
        return Err(invalid("native host-resource directory is not protected"));
    }
    Ok(())
}

pub(super) fn atomic_write_root(path: &Path, bytes: &[u8], mode: u32) -> Result<(), io::Error> {
    atomic_write(path, bytes, 0, 0, mode)
}

pub(super) fn remove_atomic_temporary_root(path: &Path, mode: u32) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("native host-resource file has no parent"))?;
    authenticate_known_parent(parent)?;
    let temporary = atomic_temporary_path(parent, path);
    recover_atomic_temporary(
        parent,
        &temporary,
        FileIdentity {
            uid: 0,
            gid: 0,
            mode,
        },
    )
}

fn atomic_write(path: &Path, bytes: &[u8], uid: u32, gid: u32, mode: u32) -> Result<(), io::Error> {
    if uid != 0 || gid != 0 {
        return Err(invalid(
            "the root adapter may publish files only below root-owned parents",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("native host-resource file has no parent"))?;
    authenticate_known_parent(parent)?;
    let identity = FileIdentity { uid, gid, mode };
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_regular_metadata(&metadata, identity)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let temporary = atomic_temporary_path(parent, path);
    recover_atomic_temporary(parent, &temporary, identity)?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_regular_metadata(&file.metadata()?, identity)?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_temporary_path(parent: &Path, path: &Path) -> std::path::PathBuf {
    parent.join(format!(
        ".aos-host-tmp-{}.tmp",
        Sha256Digest::of_bytes(path.as_os_str().as_encoded_bytes()).hex()
    ))
}

fn recover_atomic_temporary(
    parent: &Path,
    temporary: &Path,
    identity: FileIdentity,
) -> Result<(), io::Error> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temporary)
    {
        Ok(file) => {
            validate_temporary_metadata(&file.metadata()?, identity)?;
            drop(file);
            fs::remove_file(temporary)?;
            File::open(parent)?.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_temporary_metadata(
    metadata: &fs::Metadata,
    identity: FileIdentity,
) -> Result<(), io::Error> {
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != identity.uid
        || metadata.gid() != identity.gid
        || mode != identity.mode
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "native host-resource temporary file is not protected",
        ));
    }
    Ok(())
}

fn authenticate_known_parent(parent: &Path) -> Result<(), io::Error> {
    if parent == Path::new(CREDENTIAL_ROOT)
        || parent == Path::new(ENDPOINT_ROOT)
        || parent == Path::new(POLICY_ROOT)
    {
        return protected_directory(parent, 0, 0, 0o700);
    }
    if parent == Path::new(STORAGE_ROOT) || parent == Path::new(POSTGRESQL_ROOT) {
        return protected_directory(parent, 0, POSTGRESQL_GID, 0o710);
    }
    if parent.starts_with(CREDENTIAL_SOURCE_ROOT) {
        return protected_directory(parent, 0, 0, 0o700);
    }
    Err(invalid(
        "native host-resource file has an unexpected parent",
    ))
}

fn validate_regular_metadata(
    metadata: &fs::Metadata,
    identity: FileIdentity,
) -> Result<(), io::Error> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != identity.uid
        || metadata.gid() != identity.gid
        || metadata.mode() & 0o7777 != identity.mode
        || metadata.nlink() != 1
    {
        return Err(invalid("native host-resource file is not protected"));
    }
    Ok(())
}

pub(super) fn read_protected_file(
    path: &Path,
    limit: u64,
    owner: u32,
    mode: u32,
) -> Result<Vec<u8>, io::Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    validate_regular_metadata(
        &metadata,
        FileIdentity {
            uid: owner,
            gid: if owner == 0 { 0 } else { POSTGRESQL_GID },
            mode,
        },
    )?;
    if metadata.len() > limit {
        return Err(invalid("native host-resource file exceeds its size bound"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("native host-resource file exceeds its size bound"));
    }
    Ok(bytes)
}

pub(super) fn remove_regular_optional(path: &Path, owner: u32) -> Result<(), io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner
                && metadata.gid() == if owner == 0 { 0 } else { POSTGRESQL_GID }
                && metadata.nlink() == 1 =>
        {
            fs::remove_file(path)?;
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Ok(_) => Err(invalid(
            "refusing to remove an unprotected host-resource target",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn is_protected_atomic_temporary(path: &Path) -> Result<bool, io::Error> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    let Some(digest) = name
        .strip_prefix(".aos-host-tmp-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return Ok(false);
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("native host-resource temporary name is malformed"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "native host-resource temporary file is not protected",
        ));
    }
    Ok(true)
}

pub(super) fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}
