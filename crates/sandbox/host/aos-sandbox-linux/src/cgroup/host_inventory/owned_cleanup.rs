//! Compares only two actual held role anchors in the existing global census.
//!
//! This is a mechanical current-identity observation. Neither a matching child
//! nor a caller's incarnation DATA grants permission to adopt or stop a runtime.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct OwnedCensusV8 {
    incarnation: [u8; 16],
    roles: [Option<(u64, u64)>; 2],
}

#[derive(Clone, Copy)]
pub(super) struct OwnedTreeV8 {
    name: [u8; 64],
    bytes: usize,
    identity: (u64, u64),
}

impl OwnedCensusV8 {
    pub(super) fn valid_v8(self) -> bool {
        self.incarnation != [0; 16] && self.roles.iter().flatten().all(|(_, inode)| *inode != 0)
    }

    pub(super) fn tree_v8(self, index: usize) -> Option<OwnedTreeV8> {
        let identity = *self.roles.get(index)?.as_ref()?;
        let prefix: &[u8] = match index {
            0 => b"aos-sandbox-",
            1 => b"aos-lease-guard-",
            _ => return None,
        };
        let mut name = [0; 64];
        name[..prefix.len()].copy_from_slice(prefix);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (offset, byte) in self.incarnation.into_iter().enumerate() {
            name[prefix.len() + offset * 2] = HEX[usize::from(byte >> 4)];
            name[prefix.len() + offset * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        let start = prefix.len() + 32;
        name[start..start + 8].copy_from_slice(b".service");
        Some(OwnedTreeV8 {
            name,
            bytes: start + 8,
            identity,
        })
    }
}

impl HostRuntimeCgroupAbsenceOriginalV5 {
    /// Bounds the same two rounds plus direct-task observations for two held roles.
    #[must_use]
    pub fn receiving_obligations_for_owned_cleanup_v8() -> Option<(usize, usize, usize)> {
        let base = Self::receiving_obligations_v5()?;
        Some((
            base.0.checked_add(
                CgroupSingleTaskObservationV1::requested_bytes_v1()?.checked_mul(4)?,
            )?,
            base.1
                .checked_add(4 * CgroupSingleTaskObservationV1::MAXIMUM_RETAINED_FILES_V1)?,
            base.2
                .checked_add(4 * (CgroupSingleTaskObservationV1::METADATA_ENTRIES_V1 + 1))?,
        ))
    }

    /// Captures one global round beside the actual fresh per-role cgroup anchors.
    ///
    /// Only those exact directory device/inodes may occur under the two role
    /// trees. Direct parent tasks, unknown children and any FUSE residue refuse.
    /// The caller retains these anchors and its genuine PIDFD/membership owners.
    ///
    /// # Errors
    /// Retains native failures, unknown/replaced children, changed round scope
    /// or reentry. The second complete round remains reached after the first fails.
    pub fn capture_next_owned_cleanup_once_v8(
        &mut self,
        actual_root: &BeneathRoot,
        incarnation: [u8; 16],
        payload: Option<&RetainedCgroupAnchor>,
        guardian: Option<&RetainedCgroupAnchor>,
    ) -> std::result::Result<(), HostRuntimeCgroupAbsenceRefusalV5> {
        let roles = [payload, guardian]
            .map(|anchor| anchor.map(|anchor| (anchor.root.identity().device, anchor.kernel_id())));
        self.capture_next_internal_v8(actual_root, Some(OwnedCensusV8 { incarnation, roles }))
    }

    /// Reports the complete owned comparison, which cannot prove total absence.
    #[must_use]
    pub fn completed_owned_cleanup_v8(&self) -> bool {
        self.owned.iter().all(Option::is_some) && self.completed_internal_v8()
    }
}

pub(super) fn require_selected_child_v8(
    directory: BorrowedFd<'_>,
    raw: &mut [MaybeUninit<u8>; 4096],
    first_child: &mut [u8; 256],
    first_child_bytes: &mut usize,
    selected: OwnedTreeV8,
    stat: &mut Option<rustix::io::Result<rustix::fs::Stat>>,
    identity: &mut Option<Result<()>>,
) -> Result<()> {
    let mut seen = false;
    require_no_child_directories_v6(
        directory,
        raw,
        first_child,
        first_child_bytes,
        &mut |name, kind| {
            if name.to_bytes() != &selected.name[..selected.bytes] {
                return Ok(false);
            }
            if seen || kind != rustix::fs::FileType::Directory {
                return Err(refused());
            }
            seen = true;
            *stat = Some(rustix::fs::statat(
                directory,
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ));
            *identity = Some(match stat.as_ref() {
                Some(Ok(stat))
                    if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                        == rustix::fs::FileType::Directory
                        && (stat.st_dev, stat.st_ino) == selected.identity =>
                {
                    Ok(())
                }
                Some(Err(source)) => Err(Error::Syscall {
                    operation: "fstatat(Host held cleanup role)",
                    source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                }),
                _ => Err(refused()),
            });
            match identity.as_ref() {
                Some(Ok(())) => Ok(true),
                _ => Err(refused()),
            }
        },
    )?;
    if !seen {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn refused() -> Error {
    Error::invalid(
        "Host owned cleanup census",
        "missing, changed or unknown native child",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn real_census_requires_exact_held_child_and_rejects_every_other_child() {
        let scope = OwnedCensusV8 {
            incarnation: [0xab; 16],
            roles: [Some((1, 1)), None],
        };
        let mut selected = scope.tree_v8(0).unwrap();
        let name = std::str::from_utf8(&selected.name[..selected.bytes]).unwrap();
        assert_eq!(name, "aos-sandbox-abababababababababababababababab.service");
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(name)).unwrap();
        let child = open(&directory.path().join(name));
        let identity = rustix::fs::fstat(&child).unwrap();
        selected.identity = (identity.st_dev, identity.st_ino);

        let capture = |selected| {
            let parent = open(directory.path());
            let mut raw = [MaybeUninit::uninit(); 4096];
            let mut first = [0; 256];
            let mut bytes = 0;
            let mut stat = None;
            let mut checked = None;
            require_selected_child_v8(
                parent.as_fd(),
                &mut raw,
                &mut first,
                &mut bytes,
                selected,
                &mut stat,
                &mut checked,
            )
        };
        assert!(capture(selected).is_ok());
        let mut substituted = selected;
        substituted.identity.1 ^= 1;
        assert!(capture(substituted).is_err());
        std::fs::create_dir(directory.path().join("unknown.service")).unwrap();
        assert!(capture(selected).is_err());
        std::fs::remove_dir(directory.path().join("unknown.service")).unwrap();
        std::os::unix::fs::symlink("elsewhere", directory.path().join("foreign")).unwrap();
        assert!(capture(selected).is_err());
        assert!(rustix::fs::fstat(&child).is_ok());
    }

    #[test]
    fn owned_round_failure_keeps_both_real_root_attempts_and_never_becomes_empty_completion() {
        let directory = tempfile::tempdir().unwrap();
        let root = BeneathRoot::from_owned(open(directory.path())).unwrap();
        let mut original = HostRuntimeCgroupAbsenceOriginalV5::new();

        assert!(
            original
                .capture_next_owned_cleanup_once_v8(&root, [1; 16], None, None)
                .is_err()
        );
        let first = original.failure_v5().unwrap() as *const dyn std::error::Error as *const ();
        assert!(
            original
                .capture_next_owned_cleanup_once_v8(&root, [1; 16], None, None)
                .is_err()
        );

        assert!(original.root_result.iter().all(Option::is_some));
        assert_eq!(
            original.failure_v5().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(!original.completed_v5());
        assert!(!original.completed_owned_cleanup_v8());
        assert!(rustix::fs::fstat(root.as_fd()).is_ok());
    }
}
