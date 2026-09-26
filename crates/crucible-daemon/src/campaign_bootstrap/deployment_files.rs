//! Secure deployment-file loading and path revalidation.

use super::*;

pub(super) fn load_policy(
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<UnixPeerCampaignPolicy, CampaignLocalServiceError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("stat-policy-file", path, source))?;
    if !path_metadata.is_file()
        || path_metadata.uid() != user_id
        || path_metadata.gid() != group_id
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "open-policy-file",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?
    .into();
    let file_metadata = file
        .metadata()
        .map_err(|source| io_error("stat-open-policy-file", path, source))?;
    if file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || !file_metadata.is_file()
        || file_metadata.uid() != user_id
        || file_metadata.gid() != group_id
        || file_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    if file_metadata.len() > MAX_CAMPAIGN_POLICY_BYTES as u64 {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }

    let mut bytes = Vec::with_capacity(file_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_CAMPAIGN_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-policy-file", path, source))?;
    if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }
    UnixPeerCampaignPolicy::from_toml_bytes(&bytes).map_err(Into::into)
}

pub(super) fn load_component_authorities(
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<(PlannerAuthorityKey, DebuggerAuthorityKey), CampaignLocalServiceError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat-component-authority-file", path, source))?;
    if !path_metadata.is_file()
        || path_metadata.uid() != user_id
        || path_metadata.gid() != group_id
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.len() != COMPONENT_AUTHORITY_FILE_BYTES as u64
    {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }

    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "open-component-authority-file",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?
    .into();
    let file_metadata = file
        .metadata()
        .map_err(|source| io_error("stat-open-component-authority-file", path, source))?;
    if file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || !file_metadata.is_file()
        || file_metadata.uid() != user_id
        || file_metadata.gid() != group_id
        || file_metadata.mode() & 0o777 != 0o600
        || file_metadata.len() != COMPONENT_AUTHORITY_FILE_BYTES as u64
    {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }

    let mut bytes = [0_u8; COMPONENT_AUTHORITY_FILE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read-component-authority-file", path, source))?;
    if &bytes[..COMPONENT_AUTHORITY_MAGIC.len()] != COMPONENT_AUTHORITY_MAGIC {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }
    let planner_bytes: [u8; 32] = bytes[8..40]
        .try_into()
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let debugger_bytes: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let planner = PlannerAuthorityKey::from_bytes(planner_bytes)
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let debugger = DebuggerAuthorityKey::from_bytes(debugger_bytes)
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    if planner_bytes == debugger_bytes {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }
    Ok((planner, debugger))
}

pub(super) fn prepare_subdirectory(
    root: &Path,
    name: &'static str,
    user_id: u32,
    group_id: u32,
) -> Result<PathBuf, CampaignLocalServiceError> {
    let path = root.join(name);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, Permissions::from_mode(0o700))
            .map_err(|source| io_error("set-state-subdirectory-mode", &path, source))?,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create-state-subdirectory", &path, source)),
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("stat-state-subdirectory", &path, source))?;
    if validate_secure_directory(&metadata, user_id, group_id).is_err()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CampaignLocalServiceError::InvalidStateSubdirectory);
    }
    Ok(path)
}

pub(super) fn validate_secure_directory(
    metadata: &fs::Metadata,
    user_id: u32,
    group_id: u32,
) -> Result<(), ()> {
    if metadata.is_dir()
        && metadata.uid() == user_id
        && metadata.gid() == group_id
        && metadata.mode() & 0o022 == 0
    {
        Ok(())
    } else {
        Err(())
    }
}

pub(super) fn require_same_file(
    file: &File,
    path_metadata: &fs::Metadata,
    path: &Path,
    operation: &'static str,
) -> Result<(), CampaignLocalServiceError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err(match operation {
            "policy-file" => CampaignLocalServiceError::InvalidPolicyFile,
            _ => CampaignLocalServiceError::InvalidStateDirectory,
        });
    }
    Ok(())
}

pub(super) fn revalidate_state_path(
    root: &File,
    original: &fs::Metadata,
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<(), CampaignLocalServiceError> {
    require_same_file(root, original, path, "state-directory")?;
    let current = fs::symlink_metadata(path)
        .map_err(|source| io_error("restat-state-directory", path, source))?;
    if current.dev() != original.dev()
        || current.ino() != original.ino()
        || validate_secure_directory(&current, user_id, group_id).is_err()
    {
        return Err(CampaignLocalServiceError::InvalidStateDirectory);
    }
    Ok(())
}

pub(super) fn valid_deployment_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && !bytes.contains(&0)
        && bytes.len() <= MAX_DEPLOYMENT_PATH_BYTES
}

pub(super) fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> CampaignLocalServiceError {
    CampaignLocalServiceError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}
