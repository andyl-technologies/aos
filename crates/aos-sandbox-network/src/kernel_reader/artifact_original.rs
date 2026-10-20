//! Keeps artifact construction and complete expected-snapshot validation.
//!
//! Both ordinary and retained callers use these same predicates and native
//! operations. The retained boundary keeps every resolved file and ancestor
//! until all identity, ancestry, length and digest comparisons have finished.
//! No artifact identity or successful measurement grants execution authority.

use super::*;

#[derive(Clone, Copy)]
enum CurrentFirst {
    Body,
    Hash,
    Path,
    ExecutableHash,
    Closed,
}

/// Holds one full currentness conjunction, including its fresh path pins.
pub(crate) struct NetworkArtifactCurrentOriginalV4 {
    ancestor_identities: Vec<DirectoryIdentity>,
    held_identity: Option<ArtifactIdentity>,
    held_hash: NetworkArtifactHashOriginalV4,
    resolved_path: NetworkArtifactPathOriginalV4,
    resolved: Option<(File, Vec<ArtifactAncestor>)>,
    resolved_identity: Option<ArtifactIdentity>,
    executable_candidate: Option<rustix::io::Result<OwnedFd>>,
    executable_file: Option<File>,
    executable_identity: Option<ArtifactIdentity>,
    executable_hash: NetworkArtifactHashOriginalV4,
    returned: Option<Result<(), NetworkKernelReaderError>>,
    first: Option<CurrentFirst>,
    closed: Option<NetworkKernelReaderError>,
    disposed: bool,
}

impl NetworkArtifactCurrentOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            ancestor_identities: Vec::new(),
            held_identity: None,
            held_hash: NetworkArtifactHashOriginalV4::new(),
            resolved_path: NetworkArtifactPathOriginalV4::new(),
            resolved: None,
            resolved_identity: None,
            executable_candidate: None,
            executable_file: None,
            executable_identity: None,
            executable_hash: NetworkArtifactHashOriginalV4::new(),
            returned: None,
            first: None,
            closed: None,
            disposed: false,
        }
    }

    /// Bounds the closed role's fresh walk and optional actual executable FD.
    pub(crate) fn receiving_obligations_v4(
        role: NetworkArtifactRoleV4,
        current_executable: bool,
    ) -> Option<(usize, usize, usize)> {
        let (walk_bytes, files, names) =
            NetworkArtifactPathOriginalV4::receiving_obligations_v4(role)?;
        let path_inline =
            2usize.checked_mul(std::mem::size_of::<NetworkArtifactPathOriginalV4>())?;
        let hash_inline =
            2usize.checked_mul(std::mem::size_of::<NetworkArtifactHashOriginalV4>())?;
        let hash_extra =
            NetworkArtifactHashOriginalV4::receiving_bytes_v4()?.checked_sub(hash_inline)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(walk_bytes.checked_sub(path_inline)?)?
            .checked_add(hash_extra.checked_mul(2)?)?
            .checked_add(
                files
                    .checked_sub(1)?
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<DirectoryIdentity>())?,
            )?;
        Some((
            bytes,
            files.checked_add(usize::from(current_executable))?,
            names.checked_add(if current_executable { 3 } else { 0 })?,
        ))
    }

    /// Validates the same actual artifact once without consuming its pins.
    ///
    /// # Errors
    /// Refuses a different role, incomplete native check or expected-snapshot
    /// mismatch. failure() borrows the exact first source; reentry stays closed.
    pub(crate) fn validate_once_v4(
        &mut self,
        artifact: &PinnedArtifact,
        role: NetworkArtifactRoleV4,
        current_executable: bool,
    ) -> Result<(), NetworkKernelReaderError> {
        self.enter_once(artifact, Some(role), current_executable)
    }

    fn enter_once(
        &mut self,
        artifact: &PinnedArtifact,
        role: Option<NetworkArtifactRoleV4>,
        current_executable: bool,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.returned.is_some() || self.closed.is_some() || self.disposed {
            self.closed.get_or_insert_with(marker);
            self.first.get_or_insert(CurrentFirst::Closed);
            return Err(marker());
        }
        self.returned = Some(self.validate(artifact, role, current_executable));
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(CurrentFirst::Body);
            Err(marker())
        }
    }

    fn validate(
        &mut self,
        artifact: &PinnedArtifact,
        role: Option<NetworkArtifactRoleV4>,
        current_executable: bool,
    ) -> Result<(), NetworkKernelReaderError> {
        if let Some(role) = role {
            // Check the finite role roster before allocating its ancestor
            // observations or reading an input that belongs to another role.
            artifact_path::require_role_shape(&artifact.path, role)?;
        }
        for ancestor in &artifact.ancestors {
            let current =
                DirectoryIdentity::from_descriptor(&ancestor.descriptor, ancestor.policy)?;
            self.ancestor_identities.push(current);
            if current != ancestor.identity {
                return Err(NetworkKernelReaderError::InvalidArtifact(
                    "artifact ancestry changed",
                ));
            }
        }

        let executable = artifact.identity.mode & 0o111 != 0;
        let current = ArtifactIdentity::from_descriptor(&artifact.descriptor, executable)?;
        self.held_identity = Some(current);
        if current != artifact.identity {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact identity or contents changed",
            ));
        }
        let digest = match self
            .held_hash
            .measure_once_v4(&artifact.descriptor, current.size)
        {
            Ok(digest) => digest,
            Err(_) => {
                self.first = Some(CurrentFirst::Hash);
                return Err(marker());
            }
        };
        if digest != artifact.digest {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact identity or contents changed",
            ));
        }

        if self
            .resolved_path
            .capture_path_once_v4(&artifact.path, role)
            .is_err()
        {
            self.first = Some(CurrentFirst::Path);
            return Err(marker());
        }
        self.resolved = self.resolved_path.take_completed_parts_once_v4();
        let (resolved, ancestors) = self.resolved.as_ref().ok_or_else(marker)?;
        let resolved_identity = ArtifactIdentity::from_descriptor(resolved, executable)?;
        self.resolved_identity = Some(resolved_identity);
        require_same_path(artifact, resolved_identity, ancestors)?;
        if current_executable && role.is_none() {
            // The ordinary validate_current_executable formerly returned from
            // validate_current before opening /proc/self/exe. Preserve that
            // successful local descriptor boundary; selected owners retain
            // these pins through the complete outer conjunction instead.
            self.dispose_immediate_resolved();
        }

        if current_executable {
            self.executable_candidate = Some(rustix::fs::open(
                "/proc/self/exe",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ));
            match self.executable_candidate.take() {
                Some(Ok(descriptor)) => self.executable_file = Some(File::from(descriptor)),
                Some(Err(errno)) => {
                    self.executable_candidate = Some(Err(errno));
                    return Err(kernel_io(errno));
                }
                None => return Err(marker()),
            }
            let file = self.executable_file.as_ref().ok_or_else(marker)?;
            let identity = ArtifactIdentity::from_descriptor(file, true)?;
            self.executable_identity = Some(identity);
            if identity != artifact.identity {
                return Err(NetworkKernelReaderError::InvalidArtifact(
                    "enforcement artifact is not the current executable",
                ));
            }
            let digest = match self.executable_hash.measure_once_v4(file, identity.size) {
                Ok(digest) => digest,
                Err(_) => {
                    self.first = Some(CurrentFirst::ExecutableHash);
                    return Err(marker());
                }
            };
            if digest != artifact.digest {
                return Err(NetworkKernelReaderError::InvalidArtifact(
                    "enforcement artifact is not the current executable",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CurrentFirst::Hash => self.held_hash.failure(),
            CurrentFirst::Path => self.resolved_path.failure(),
            CurrentFirst::ExecutableHash => self.executable_hash.failure(),
            CurrentFirst::Body => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            CurrentFirst::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    /// Closes only temporary native leaves after the entire conjunction passes.
    ///
    /// The retained input artifact and all returned payload pins remain held by
    /// their real owners. A refusal keeps the whole reached temporary prefix.
    /// This physical close supplies no financial capacity credit.
    ///
    /// # Errors
    /// Refuses reentry, any negative/ambiguous conjunction or prior refusal.
    pub(crate) fn dispose_positive_temporary_once_v4(
        &mut self,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.disposed
            || self.closed.is_some()
            || self.first.is_some()
            || !matches!(self.returned, Some(Ok(())))
        {
            return Err(marker());
        }
        self.disposed = true;
        drop(self.resolved.take());
        drop(self.executable_file.take());
        // A successful path has already moved all native leaves into resolved.
        // Keep its model/result provenance; do not reconstruct another owner.
        Ok(())
    }

    fn dispose_immediate_resolved(&mut self) {
        if let Some((resolved, ancestors)) = self.resolved.take() {
            drop(ancestors);
            drop(resolved);
        }
    }

    fn dispose_immediate_native(&mut self) {
        // These explicit local dispositions preserve the old facade's reverse
        // local order. The selected entry never calls this ordinary boundary.
        drop(self.executable_file.take());
        self.dispose_immediate_resolved();
    }

    fn take_original_error(&mut self) -> Option<NetworkKernelReaderError> {
        match self.first? {
            CurrentFirst::Hash => self.held_hash.take_returned_error_v4(),
            CurrentFirst::Path => self.resolved_path.take_returned_error_v4(),
            CurrentFirst::ExecutableHash => self.executable_hash.take_returned_error_v4(),
            CurrentFirst::Body => self.returned.take()?.err(),
            CurrentFirst::Closed => self.closed.take(),
        }
    }
}

fn require_same_path(
    artifact: &PinnedArtifact,
    resolved_identity: ArtifactIdentity,
    resolved_ancestors: &[ArtifactAncestor],
) -> Result<(), NetworkKernelReaderError> {
    if resolved_identity != artifact.identity
        || resolved_ancestors.len() != artifact.ancestors.len()
        || resolved_ancestors
            .iter()
            .zip(&artifact.ancestors)
            .any(|(current, retained)| current.identity != retained.identity)
    {
        return Err(NetworkKernelReaderError::InvalidArtifact(
            "fixed artifact path no longer names its retained object",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OpenFirst {
    Path,
    Hash,
    Current,
    Body,
    Closed,
}

/// Keeps the input, initial File/ancestry and whole initial currentness attempt.
pub(crate) struct NetworkArtifactOpeningOriginalV4 {
    path: Option<PathBuf>,
    path_original: NetworkArtifactPathOriginalV4,
    initial: Option<(File, Vec<ArtifactAncestor>)>,
    identity: Option<ArtifactIdentity>,
    hash: NetworkArtifactHashOriginalV4,
    artifact: Option<PinnedArtifact>,
    current: NetworkArtifactCurrentOriginalV4,
    returned: Option<Result<(), NetworkKernelReaderError>>,
    first: Option<OpenFirst>,
    closed: Option<NetworkKernelReaderError>,
    taken: bool,
}

impl NetworkArtifactOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            path: None,
            path_original: NetworkArtifactPathOriginalV4::new(),
            initial: None,
            identity: None,
            hash: NetworkArtifactHashOriginalV4::new(),
            artifact: None,
            current: NetworkArtifactCurrentOriginalV4::new(),
            returned: None,
            first: None,
            closed: None,
            taken: false,
        }
    }

    pub(crate) fn receiving_obligations_v4(
        role: NetworkArtifactRoleV4,
    ) -> Option<(usize, usize, usize)> {
        let (walk_bytes, walk_files, walk_names) =
            NetworkArtifactPathOriginalV4::receiving_obligations_v4(role)?;
        let (current_bytes, current_files, current_names) =
            NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(role, false)?;
        let current_inline =
            2usize.checked_mul(std::mem::size_of::<NetworkArtifactCurrentOriginalV4>())?;
        let path_inline =
            2usize.checked_mul(std::mem::size_of::<NetworkArtifactPathOriginalV4>())?;
        let hash_inline =
            2usize.checked_mul(std::mem::size_of::<NetworkArtifactHashOriginalV4>())?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(current_bytes.checked_sub(current_inline)?)?
            .checked_add(walk_bytes.checked_sub(path_inline)?)?
            .checked_add(
                NetworkArtifactHashOriginalV4::receiving_bytes_v4()?.checked_sub(hash_inline)?,
            )?
            .checked_add(2 * (4096 + 1))?;
        Some((
            bytes,
            walk_files.checked_add(current_files)?,
            walk_names.checked_add(current_names)?,
        ))
    }

    /// Opens the exact compiled role and completes its initial currentness.
    ///
    /// # Errors
    /// Refuses unsafe paths, native acquisition/metadata/read failures, changed
    /// identities or contents, and repeated entry while retaining first cause.
    pub(crate) fn open_once_v4(
        &mut self,
        path: PathBuf,
        role: NetworkArtifactRoleV4,
    ) -> Result<(), NetworkKernelReaderError> {
        self.enter_once(path, role.executable(), Some(role))
    }

    fn enter_once(
        &mut self,
        path: PathBuf,
        executable: bool,
        role: Option<NetworkArtifactRoleV4>,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.returned.is_some() || self.closed.is_some() || self.taken {
            self.closed.get_or_insert_with(marker);
            self.first.get_or_insert(OpenFirst::Closed);
            return Err(marker());
        }
        self.path = Some(path);
        self.returned = Some(self.open(executable, role));
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(OpenFirst::Body);
            Err(marker())
        }
    }

    fn open(
        &mut self,
        executable: bool,
        role: Option<NetworkArtifactRoleV4>,
    ) -> Result<(), NetworkKernelReaderError> {
        let path = self.path.as_ref().ok_or_else(marker)?;
        if self.path_original.capture_path_once_v4(path, role).is_err() {
            self.first = Some(OpenFirst::Path);
            return Err(marker());
        }
        self.initial = self.path_original.take_completed_parts_once_v4();
        let (descriptor, _) = self.initial.as_ref().ok_or_else(marker)?;
        let identity = ArtifactIdentity::from_descriptor(descriptor, executable)?;
        self.identity = Some(identity);
        let digest = match self.hash.measure_once_v4(descriptor, identity.size) {
            Ok(digest) => digest,
            Err(_) => {
                self.first = Some(OpenFirst::Hash);
                return Err(marker());
            }
        };
        let (descriptor, ancestors) = self.initial.take().ok_or_else(marker)?;
        self.artifact = Some(PinnedArtifact {
            path: self.path.take().ok_or_else(marker)?,
            descriptor,
            ancestors,
            identity,
            digest,
        });
        let artifact = self.artifact.as_ref().ok_or_else(marker)?;
        if self.current.enter_once(artifact, role, false).is_err() {
            self.first = Some(OpenFirst::Current);
            return Err(marker());
        }
        Ok(())
    }

    /// Moves the same completed artifact; failed currentness keeps every pin.
    pub(crate) fn take_completed_once_v4(&mut self) -> Option<PinnedArtifact> {
        if self.taken || self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.taken = true;
        self.artifact.take()
    }

    /// Closes initial currentness temporaries after the complete opening.
    ///
    /// The actual completed artifact's File/ancestors remain on this owner or
    /// on the exact successful take recipient. No account credit is returned.
    ///
    /// # Errors
    /// Refuses failed, incomplete or repeated local disposal.
    pub(crate) fn dispose_positive_temporary_once_v4(
        &mut self,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.closed.is_some() || self.first.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return Err(marker());
        }
        self.current.dispose_positive_temporary_once_v4()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            OpenFirst::Path => self.path_original.failure(),
            OpenFirst::Hash => self.hash.failure(),
            OpenFirst::Current => self.current.failure(),
            OpenFirst::Body => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            OpenFirst::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    fn dispose_immediate_native(&mut self) {
        self.current.dispose_immediate_native();
        if let Some((descriptor, ancestors)) = self.initial.take() {
            drop(ancestors);
            drop(descriptor);
        }
    }

    fn take_original_error(&mut self) -> Option<NetworkKernelReaderError> {
        match self.first? {
            OpenFirst::Path => self.path_original.take_returned_error_v4(),
            OpenFirst::Hash => self.hash.take_returned_error_v4(),
            OpenFirst::Current => self.current.take_original_error(),
            OpenFirst::Body => self.returned.take()?.err(),
            OpenFirst::Closed => self.closed.take(),
        }
    }
}

fn marker() -> NetworkKernelReaderError {
    NetworkKernelReaderError::InvalidArtifact("artifact original is incomplete or refused")
}

pub(super) fn open_local_v4(
    path: PathBuf,
    executable: bool,
) -> Result<PinnedArtifact, NetworkKernelReaderError> {
    let mut original = NetworkArtifactOpeningOriginalV4::new();
    let returned = original.enter_once(path, executable, None);
    original.dispose_immediate_native();
    if returned.is_err() {
        return Err(original.take_original_error().unwrap_or_else(marker));
    }
    original.take_completed_once_v4().ok_or_else(marker)
}

pub(super) fn validate_local_v4(
    artifact: &PinnedArtifact,
    current_executable: bool,
) -> Result<(), NetworkKernelReaderError> {
    let mut original = NetworkArtifactCurrentOriginalV4::new();
    let returned = original.enter_once(artifact, None, current_executable);
    original.dispose_immediate_native();
    if returned.is_err() {
        return Err(original.take_original_error().unwrap_or_else(marker));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn native_file() -> (PathBuf, File) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "aos-network-artifact-conjunction-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        (path, file)
    }

    #[test]
    fn expected_snapshot_mismatch_keeps_the_actual_fresh_file() {
        let (path, file) = native_file();
        let stat = rustix::fs::fstat(&file).unwrap();
        let expected = ArtifactIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: 1,
            mode: stat.st_mode,
            owner: stat.st_uid,
            group: stat.st_gid,
        };
        let mut changed = expected;
        changed.inode ^= 1;
        let artifact = PinnedArtifact {
            path: path.clone(),
            descriptor: file,
            ancestors: Vec::new(),
            identity: changed,
            digest: ObjectDigest::from_bytes([1; 32]),
        };
        let resolved = artifact.descriptor.try_clone().unwrap();
        let raw = resolved.as_raw_fd();
        let mut original = NetworkArtifactCurrentOriginalV4::new();
        original.resolved = Some((resolved, Vec::new()));
        // Exercise the SAME final expected-snapshot conjunction after parking
        // a real fresh native file. Earlier role/metadata checks are outside
        // this fixture's explicitly bounded comparison frontier.
        original.returned = Some(require_same_path(&artifact, expected, &[]));
        original.first = Some(CurrentFirst::Body);

        assert!(original.returned.as_ref().unwrap().is_err());
        let first = original
            .failure()
            .unwrap()
            .downcast_ref::<NetworkKernelReaderError>()
            .unwrap() as *const _;
        assert!(original.dispose_positive_temporary_once_v4().is_err());
        assert_eq!(original.resolved.as_ref().unwrap().0.as_raw_fd(), raw);
        assert_eq!(
            rustix::fs::fstat(&original.resolved.as_ref().unwrap().0)
                .unwrap()
                .st_ino,
            stat.st_ino
        );
        assert!(
            original
                .validate_once_v4(&artifact, NetworkArtifactRoleV4::Ip, false)
                .is_err()
        );
        assert_eq!(
            first,
            original
                .failure()
                .unwrap()
                .downcast_ref::<NetworkKernelReaderError>()
                .unwrap() as *const _
        );
        drop(original);
        drop(artifact);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn role_opening_keeps_real_missing_component_and_original_first_error() {
        let path = PathBuf::from(format!(
            "/nix/store/00000000000000000000000000000000-missing-network-opening-{}/sbin/ip",
            std::process::id(),
        ));
        let mut original = NetworkArtifactOpeningOriginalV4::new();

        assert!(
            original
                .open_once_v4(path.clone(), NetworkArtifactRoleV4::Ip)
                .is_err()
        );
        let first = original
            .failure()
            .unwrap()
            .downcast_ref::<NetworkKernelReaderError>()
            .unwrap() as *const _;
        assert!(original.take_completed_once_v4().is_none());
        assert!(
            original
                .open_once_v4(path, NetworkArtifactRoleV4::Ip)
                .is_err()
        );
        assert_eq!(
            first,
            original
                .failure()
                .unwrap()
                .downcast_ref::<NetworkKernelReaderError>()
                .unwrap() as *const _
        );
    }
}
