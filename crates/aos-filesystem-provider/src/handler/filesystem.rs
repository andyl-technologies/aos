//! Durable claims and race-safe filesystem operations.

use super::*;

pub(super) fn inspect_storage(
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

pub(super) fn inspect_view(
    root: &Path,
    path: &Path,
    claim: Option<&StorageViewClaim>,
    resource: &ResourceId,
    desired: RevisionId,
    source: &ResourceReference,
    source_revision: RevisionId,
) -> Result<StorageState> {
    let Some(claim) = claim else {
        return Ok(StorageState::Absent);
    };
    let exact = root.is_dir()
        && claim.active
        && claim.resource == *resource
        && claim.revision == desired
        && claim.source == *source
        && claim.source_revision == source_revision
        && claim.path == path;
    if exact {
        return Ok(StorageState::Exact(desired));
    }
    let observed = Sha256Digest::of_canonical(
        "aos.filesystem.observed-storage-view/v1",
        &json!({
            "root_present": root.is_dir(),
            "resource": claim.resource,
            "revision": claim.revision,
            "source": claim.source,
            "source_revision": claim.source_revision,
            "path": path_string(&claim.path)?,
            "active": claim.active,
        }),
    )?;
    Ok(StorageState::Divergent(RevisionId(observed)))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn inspect_entry(
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

pub(super) fn rejected_admission(observation: AbilityValue) -> Result<AdmissionResult> {
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

pub(super) fn storage_observation(
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

pub(super) fn storage_view_observation(
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

pub(super) fn entry_observation(
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

pub(super) fn successful_outputs(
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

pub(super) fn release_claimed_entry(
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

pub(super) fn write_private_record<T: Serialize>(
    directory: &Path,
    destination: &Path,
    value: &T,
) -> Result<()> {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = destination.with_extension(format!("{}.{}.tmp", std::process::id(), sequence));
    let bytes = aos_contract::canonical::to_vec(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating provider record temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn read_private_record<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &str,
) -> Result<Option<T>> {
    let descriptor = match openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("opening {label}")),
    };
    let metadata = fstat(&descriptor).with_context(|| format!("inspecting {label}"))?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "{label} is not a regular file"
    );
    ensure!(metadata.st_nlink == 1, "{label} is hard-linked");

    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= ABILITY_LIMITS_V1.max_document_bytes,
        "{label} exceeds the ability document bound"
    );
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding {label}"))
        .map(Some)
}

pub(super) fn ensure_claimed_identity(metadata: &fs::Metadata, claim: &StorageClaim) -> Result<()> {
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

pub(super) fn release_quarantine_path(path: &Path, resource: &ResourceId) -> Result<PathBuf> {
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

pub(super) fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("storage path has no parent")?;
    File::open(parent)
        .context("opening storage parent for synchronization")?
        .sync_all()
        .context("synchronizing storage parent")
}

pub(super) fn exact_resource_context<'a>(
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

pub(super) fn decode_provider_context(context: &ResourceContext) -> Result<StorageProviderContext> {
    let bound = validate_resource_context(context)?;
    let provider: StorageProviderContext = decode_value(&bound.provider_context)?;
    ensure!(
        provider.schema == PROVIDER_CONTEXT_SCHEMA,
        "unsupported storage provider context"
    );
    Ok(provider)
}

pub(super) fn observation_state(observation: &AbilityValue) -> Option<&str> {
    observation.as_json().get("state")?.as_str()
}

pub(super) fn planned_child_path(root: &Path, relative: Option<&str>) -> Result<PathBuf> {
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

pub(super) fn authenticated_artifact_path(reference: &ArtifactFileReference) -> Result<PathBuf> {
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

pub(super) fn ensure_regular_nofollow(path: &Path) -> Result<()> {
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

pub(super) fn open_regular_nofollow(path: &Path) -> Result<File> {
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

pub(super) fn inspect_regular_file_nofollow(
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
        mode: final_metadata.st_mode & 0o7777,
        uid: final_metadata.st_uid,
        gid: final_metadata.st_gid,
        device: final_metadata.st_dev,
        inode: final_metadata.st_ino,
    })
}

pub(super) fn ensure_unchanged_regular_file(
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

pub(super) fn stream_file(
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

pub(super) fn validate_entry_claims(
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

pub(super) fn parse_mode(mode: &str) -> Result<u32> {
    ensure!(
        (mode.len() == 3 || mode.len() == 4)
            && mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "storage mode is not canonical octal"
    );
    u32::from_str_radix(mode, 8).context("decoding storage mode")
}

pub(super) fn create_directory_nofollow(
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

pub(super) fn create_entry_directory_nofollow(
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

pub(super) fn copy_file_atomic_nofollow(
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

pub(super) fn open_directory_nofollow(path: &Path) -> Result<OwnedFd> {
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

pub(super) fn apply_metadata(
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

pub(super) fn raw_storage_identity(descriptor: &impl std::os::fd::AsFd) -> Result<StorageIdentity> {
    let identity = fstat(descriptor).context("inspecting realized filesystem entry")?;
    Ok(StorageIdentity {
        device: identity.st_dev,
        inode: identity.st_ino,
    })
}

pub(super) fn ensure_raw_claimed_identity(
    metadata: &rustix::fs::Stat,
    claim: &StorageClaim,
) -> Result<()> {
    ensure!(
        metadata.st_dev == claim.device && metadata.st_ino == claim.inode,
        "filesystem entry identity differs from its durable claim"
    );
    Ok(())
}

pub(super) fn resolve_identity(path: &Path, name: &str, field: usize, label: &str) -> Result<u32> {
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

pub(super) struct StateLock {
    _file: File,
}

impl StateLock {
    // Monotonic time bounds lock acquisition only; it never enters provider state.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn acquire(state_root: &Path, remaining_millis: u64) -> Result<Self> {
        ensure_private_directory(state_root)?;
        let path = state_root.join("mutation.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
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

pub(super) fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("creating filesystem provider state directory")?;
    let metadata = fs::symlink_metadata(path).context("inspecting provider state directory")?;
    ensure!(
        metadata.is_dir(),
        "filesystem provider state path is not a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
