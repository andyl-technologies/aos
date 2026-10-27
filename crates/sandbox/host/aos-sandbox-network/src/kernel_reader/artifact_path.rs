//! Keeps the sole fixed-store walker and every pre-validation native prefix.
//!
//! The ordinary facade immediately consumes its local result. Enrolled child
//! callers instead retain this same owner through identity/hash/role checks
//! and all independent posts. A path or completed walk supplies no grant.

use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) enum NetworkArtifactRoleV4 {
    Ip,
    Nft,
    Enforcement,
    LeaseLoader,
    LeaseObject,
    BpfObserver,
}

impl NetworkArtifactRoleV4 {
    fn suffix(self) -> &'static [&'static str] {
        match self {
            Self::Ip => &["sbin", "ip"],
            Self::Nft => &["bin", "nft"],
            Self::Enforcement => &["bin", "aos-sandbox-network-worker"],
            Self::LeaseLoader => &["bin", "aos-sandbox-network-lease-gate-loader"],
            Self::LeaseObject => &["lib", "bpf", "aos-sandbox-network-lease-gate.bpf.o"],
            Self::BpfObserver => &["bin", "aos-sandbox-network-observer"],
        }
    }

    pub(crate) fn executable(self) -> bool {
        !matches!(self, Self::LeaseObject)
    }
}

pub(crate) struct NetworkArtifactPathOriginalV4 {
    // A failed new candidate drops before the earlier successful ancestors at
    // the ordinary boundary, matching the former walker's local disposition.
    candidate: Option<Result<OwnedFd, rustix::io::Errno>>,
    file: Option<File>,
    components: Vec<OsString>,
    ancestors: Vec<ArtifactAncestor>,
    role_validation: Option<Result<Vec<OsString>, NetworkKernelReaderError>>,
    returned: Option<Result<(), NetworkKernelReaderError>>,
    closed: Option<NetworkKernelReaderError>,
    entered: bool,
    taken: bool,
}

impl NetworkArtifactPathOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            candidate: None,
            file: None,
            components: Vec::new(),
            ancestors: Vec::new(),
            role_validation: None,
            returned: None,
            closed: None,
            entered: false,
            taken: false,
        }
    }

    /// Bounds only the compiled named role's real walk, allocation and entries.
    pub(crate) fn receiving_obligations_v4(
        role: NetworkArtifactRoleV4,
    ) -> Option<(usize, usize, usize)> {
        // Filesystem root, nix, store, one actual store entry and its fixed
        // suffix. The last component is the File, all earlier ones are dirs.
        let files = 4usize.checked_add(role.suffix().len())?;
        let directories = files.checked_sub(1)?;
        let validation_rows = 1usize.checked_add(role.suffix().len())?;
        let walker_rows = files.checked_sub(1)?;
        let component_rows = validation_rows.checked_add(walker_rows)?.checked_mul(2)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(component_rows.checked_mul(std::mem::size_of::<OsString>())?)?
            .checked_add(
                directories
                    .checked_mul(2)?
                    .checked_mul(std::mem::size_of::<ArtifactAncestor>())?,
            )?
            // Existing validator, normalization and walker own at most three
            // copies of the admitted 4096-byte pathname, each with growth2.
            .checked_add(3 * 2 * (4096 + 1))?;
        Some((bytes, files, files))
    }

    pub(crate) fn capture_role_once_v4(
        &mut self,
        path: &Path,
        role: NetworkArtifactRoleV4,
    ) -> Result<(), NetworkKernelReaderError> {
        if self.entered {
            return self.refuse_reentry();
        }
        self.entered = true;
        // Reject a different component roster before the existing allocating
        // validator. Invalid input cannot turn a six/seven-FD role invoice
        // into an arbitrary-depth directory walk or component allocation.
        self.role_validation =
            Some(require_role_shape(path, role).and_then(|()| validate_artifact_path(path)));
        let validated = self.role_validation.take();
        match validated {
            Some(Ok(components)) => {
                // Keep the actual validated model on this owner after the
                // shared walk; the temporary borrow cannot lose a native FD.
                self.returned = Some(self.walk(&components));
                self.role_validation = Some(Ok(components));
            }
            failure => {
                self.role_validation = failure;
            }
        }
        self.project()
    }

    pub(super) fn capture_path_once_v4(
        &mut self,
        path: &Path,
        role: Option<NetworkArtifactRoleV4>,
    ) -> Result<(), NetworkKernelReaderError> {
        if let Some(role) = role {
            return self.capture_role_once_v4(path, role);
        }
        if self.entered {
            return self.refuse_reentry();
        }
        self.entered = true;
        self.role_validation = Some(validate_artifact_path(path));
        match self.role_validation.take() {
            Some(Ok(components)) => {
                self.returned = Some(self.walk(&components));
                self.role_validation = Some(Ok(components));
            }
            failure => self.role_validation = failure,
        }
        self.project()
    }

    // Only an immediate ordinary facade consumes its actual returned Error.
    // Selected owners borrow failure() and keep the reached native prefix.
    pub(super) fn take_returned_error_v4(&mut self) -> Option<NetworkKernelReaderError> {
        if matches!(self.role_validation, Some(Err(_))) {
            return self.role_validation.take()?.err();
        }
        self.returned.take()?.err()
    }

    fn refuse_reentry(&mut self) -> Result<(), NetworkKernelReaderError> {
        self.closed.get_or_insert_with(marker);
        Err(marker())
    }

    fn project(&self) -> Result<(), NetworkKernelReaderError> {
        if self.closed.is_none() && matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(marker())
        }
    }

    fn walk(&mut self, artifact_components: &[OsString]) -> Result<(), NetworkKernelReaderError> {
        self.candidate = Some(rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        let root_identity =
            DirectoryIdentity::from_descriptor(self.candidate()?, DirectoryPolicy::Protected)?;
        let root = self.take_candidate()?;
        self.ancestors = vec![ArtifactAncestor {
            descriptor: root,
            identity: root_identity,
            policy: DirectoryPolicy::Protected,
        }];
        self.components = vec![OsString::from("nix"), OsString::from("store")];
        self.components.extend_from_slice(artifact_components);

        for index in 0..self.components.len() {
            let final_component = index + 1 == self.components.len();
            let flags = if final_component {
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC
            } else {
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
            };
            let parent = self
                .ancestors
                .last()
                .ok_or(NetworkKernelReaderError::InvalidArtifact(
                    "artifact ancestry is empty",
                ))?;
            self.candidate = Some(rustix::fs::openat2(
                parent.descriptor.as_fd(),
                &self.components[index],
                flags,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS
                    | rustix::fs::ResolveFlags::NO_SYMLINKS,
            ));
            if final_component {
                self.file = Some(File::from(self.take_candidate()?));
                return Ok(());
            }
            let policy = match index {
                0 => DirectoryPolicy::Protected,
                1 => DirectoryPolicy::StoreRoot,
                _ => DirectoryPolicy::Immutable,
            };
            let identity = DirectoryIdentity::from_descriptor(self.candidate()?, policy)?;
            let descriptor = self.take_candidate()?;
            self.ancestors.push(ArtifactAncestor {
                descriptor,
                identity,
                policy,
            });
        }
        Err(NetworkKernelReaderError::InvalidArtifact(
            "artifact path has no final component",
        ))
    }

    fn candidate(&self) -> Result<&OwnedFd, NetworkKernelReaderError> {
        match self.candidate.as_ref() {
            Some(Ok(candidate)) => Ok(candidate),
            Some(Err(errno)) => Err(kernel_io(*errno)),
            None => Err(marker()),
        }
    }

    fn take_candidate(&mut self) -> Result<OwnedFd, NetworkKernelReaderError> {
        match self.candidate.take() {
            Some(Ok(candidate)) => Ok(candidate),
            failure => {
                self.candidate = failure;
                Err(marker())
            }
        }
    }

    pub(super) fn take_completed_parts_once_v4(&mut self) -> Option<(File, Vec<ArtifactAncestor>)> {
        if self.taken || self.project().is_err() || self.file.is_none() || self.ancestors.is_empty()
        {
            return None;
        }
        self.taken = true;
        Some((self.file.take()?, std::mem::take(&mut self.ancestors)))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.role_validation
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

pub(super) fn require_role_shape(
    path: &Path,
    role: NetworkArtifactRoleV4,
) -> Result<(), NetworkKernelReaderError> {
    let refused = || {
        NetworkKernelReaderError::InvalidArtifact(
            "fixed Network artifact does not match its compiled role path",
        )
    };
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
        return Err(refused());
    }
    let relative = path.strip_prefix(NIX_STORE_ROOT).map_err(|_| refused())?;
    let mut components = relative.components();
    match components.next() {
        Some(Component::Normal(entry)) if entry.len() <= 255 && valid_store_entry(entry) => {}
        _ => return Err(refused()),
    }
    for expected in role.suffix() {
        match components.next() {
            Some(Component::Normal(actual)) if actual == *expected => {}
            _ => return Err(refused()),
        }
    }
    if components.next().is_some() {
        return Err(refused());
    }
    Ok(())
}

fn marker() -> NetworkKernelReaderError {
    NetworkKernelReaderError::InvalidArtifact(
        "fixed artifact path original remains incomplete or refused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_role_or_deep_path_refuses_before_any_native_walk() {
        let root = "/nix/store/00000000000000000000000000000000-role-test";
        for suffix in ["bin/nft", "sbin/ip/extra", "sbin/./ip", "sbin/../ip"] {
            let mut original = NetworkArtifactPathOriginalV4::new();
            let path = PathBuf::from(format!("{root}/{suffix}"));

            assert!(
                original
                    .capture_role_once_v4(&path, NetworkArtifactRoleV4::Ip)
                    .is_err()
            );
            assert!(original.candidate.is_none());
            assert!(original.ancestors.is_empty());
            assert!(original.components.is_empty());
            assert!(original.failure().is_some());
        }
    }

    #[test]
    fn native_missing_component_keeps_prior_directory_pins_and_first_error() {
        let mut original = NetworkArtifactPathOriginalV4::new();
        let entry = format!(
            "00000000000000000000000000000000-missing-network-artifact-{}",
            std::process::id()
        );
        let path = PathBuf::from("/nix/store").join(entry).join("sbin/ip");

        assert!(
            original
                .capture_role_once_v4(&path, NetworkArtifactRoleV4::Ip)
                .is_err()
        );
        assert!(matches!(original.candidate, Some(Err(_))));
        assert!(!original.ancestors.is_empty());
        let identities = original
            .ancestors
            .iter()
            .map(|ancestor| rustix::fs::fstat(&ancestor.descriptor).unwrap().st_ino)
            .collect::<Vec<_>>();
        let first = original
            .failure()
            .unwrap()
            .downcast_ref::<NetworkKernelReaderError>()
            .unwrap() as *const _;
        assert!(
            original
                .capture_role_once_v4(&path, NetworkArtifactRoleV4::Ip)
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
        assert_eq!(
            identities,
            original
                .ancestors
                .iter()
                .map(|ancestor| { rustix::fs::fstat(&ancestor.descriptor).unwrap().st_ino })
                .collect::<Vec<_>>()
        );
        assert!(original.take_completed_parts_once_v4().is_none());
    }

    #[test]
    fn compiled_role_supplier_covers_both_component_tables_and_real_names() {
        for role in [
            NetworkArtifactRoleV4::Ip,
            NetworkArtifactRoleV4::Nft,
            NetworkArtifactRoleV4::Enforcement,
            NetworkArtifactRoleV4::LeaseLoader,
            NetworkArtifactRoleV4::LeaseObject,
            NetworkArtifactRoleV4::BpfObserver,
        ] {
            let (bytes, files, names) =
                NetworkArtifactPathOriginalV4::receiving_obligations_v4(role).unwrap();
            assert_eq!(files, 4 + role.suffix().len());
            assert_eq!(names, files);
            assert!(bytes > 2 * std::mem::size_of::<NetworkArtifactPathOriginalV4>());
        }
    }
}
