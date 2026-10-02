//! No-follow filesystem primitives and bounded durable records.

use super::*;

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

pub(super) fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("storage path has no parent")?;
    File::open(parent)
        .context("opening storage parent for synchronization")?
        .sync_all()
        .context("synchronizing storage parent")
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

pub(super) fn copy_file_atomic_with_identity(
    source_path: &Path,
    path: &Path,
    maximum_size_bytes: u64,
    mode: u32,
    ownership: StorageOwnership,
    own_claim: Option<(u64, u64)>,
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
        ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                == rustix::fs::FileType::RegularFile
                && (metadata.st_dev, metadata.st_ino) == claim,
            "filesystem file differs from its durable identity claim"
        );
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

/// Allocates a regular file or updates a claimed file's metadata without truncation.
pub(super) fn allocate_file_nofollow(
    path: &Path,
    mode: u32,
    ownership: StorageOwnership,
    existing: Option<(u64, u64)>,
) -> Result<StorageIdentity> {
    let parent = open_directory_nofollow(path.parent().context("file has no parent")?)?;
    let name = path.file_name().context("file has no basename")?;
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let descriptor = match existing {
        Some(_) => openat(&parent, name, flags, Mode::empty()),
        None => openat(
            &parent,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ),
    }
    .context("opening owned mutable file")?;

    let metadata = fstat(&descriptor)?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "mutable file is not a regular file"
    );
    if let Some(identity) = existing {
        ensure!(
            (metadata.st_dev, metadata.st_ino) == identity,
            "mutable file changed before mutation"
        );
    }

    apply_metadata(&descriptor, mode, ownership)?;
    let identity = raw_storage_identity(&descriptor)?;
    File::from(descriptor).sync_all()?;
    Ok(identity)
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

/// Publishes an owned symlink through a verified parent directory descriptor.
pub(super) fn symlink_tree_atomic(
    source: &Path,
    path: &Path,
    ownership: StorageOwnership,
    own_claim: Option<(u64, u64)>,
) -> Result<StorageIdentity> {
    let parent = open_directory_nofollow(path.parent().context("tree entry has no parent")?)?;
    let name = path
        .file_name()
        .context("tree entry has no final component")?;
    if let Some(identity) = own_claim {
        let metadata = rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::Symlink
                && (metadata.st_dev, metadata.st_ino) == identity,
            "tree link differs from its durable identity claim"
        );
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(".aos-tree-{}.{}.tmp", std::process::id(), sequence);
    rustix::fs::symlinkat(source, &parent, &temporary)?;
    let result = (|| -> Result<StorageIdentity> {
        rustix::fs::chownat(
            &parent,
            &temporary,
            ownership.uid,
            ownership.gid,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
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
        )?;
        File::from(parent.try_clone()?).sync_all()?;
        let metadata = rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::Symlink,
            "published tree entry is not a symlink"
        );
        Ok(StorageIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &temporary, rustix::fs::AtFlags::empty());
    }
    result
}
