//! Retains native facts for one original initial-job credential object.
//!
//! All observations run before comparison, so a failed metadata read cannot
//! suppress the separately paid mount/label observations. These facts alone
//! grant no role, contents, credential provenance or authority.

use std::fs::{File, Metadata};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_linux::inventory::MountId;
use rustix::fs::{StatVfs, StatVfsMountFlags};

pub(super) struct Observation {
    metadata: Option<std::io::Result<Metadata>>,
    mount: Option<aos_linux_descriptors::Result<MountId>>,
    filesystem: Option<rustix::io::Result<StatVfs>>,
    label: Option<rustix::io::Result<usize>>,
    label_bytes: [u8; 256],
    entered: bool,
}

impl Observation {
    pub(super) fn new() -> Self {
        Self {
            metadata: None,
            mount: None,
            filesystem: None,
            label: None,
            label_bytes: [0; 256],
            entered: false,
        }
    }

    pub(super) fn observe(&mut self, file: &File) -> bool {
        if self.entered {
            return false;
        }
        self.entered = true;
        self.metadata = Some(file.metadata());
        self.mount = Some(MountId::from_fd(file.as_fd()));
        self.filesystem = Some(rustix::fs::fstatvfs(file));
        self.label = Some(rustix::fs::fgetxattr(
            file,
            "security.selinux",
            &mut self.label_bytes,
        ));
        true
    }

    pub(super) fn require(&self, label: &[u8], length: Option<u64>) -> bool {
        let Some(Ok(metadata)) = &self.metadata else {
            return false;
        };
        let expected_mode = if length.is_some() { 0o400 } else { 0o500 };
        let type_matches = match length {
            Some(length) => metadata.is_file() && metadata.len() == length && metadata.nlink() == 1,
            None => metadata.is_dir(),
        };
        let Some(Ok(length)) = self.label else {
            return false;
        };
        let Some(observed) = self.label_bytes.get(..length) else {
            return false;
        };
        let observed = observed.strip_suffix(b"\0").unwrap_or(observed);

        type_matches
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == expected_mode
            && metadata.dev() != 0
            && metadata.ino() != 0
            && matches!(self.mount, Some(Ok(_)))
            && matches!(&self.filesystem, Some(Ok(fs)) if fs.f_flag.contains(StatVfsMountFlags::RDONLY))
            && observed == label
    }

    pub(super) fn same_mount(&self, other: &Self) -> bool {
        matches!((&self.mount, &other.mount), (Some(Ok(left)), Some(Ok(right))) if left == right)
    }

    pub(super) fn same_object(&self, other: &Self) -> bool {
        let (Some(Ok(left)), Some(Ok(right))) = (&self.metadata, &other.metadata) else {
            return false;
        };
        self.same_mount(other)
            && (
                left.dev(),
                left.ino(),
                left.mode(),
                left.uid(),
                left.gid(),
                left.len(),
                left.mtime(),
                left.mtime_nsec(),
                left.ctime(),
                left.ctime_nsec(),
            ) == (
                right.dev(),
                right.ino(),
                right.mode(),
                right.uid(),
                right.gid(),
                right.len(),
                right.mtime(),
                right.mtime_nsec(),
                right.ctime(),
                right.ctime_nsec(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_observation_retains_all_reached_results_and_refuses_reentry() {
        let file = tempfile::tempfile().unwrap();
        let mut original = Observation::new();

        assert!(original.observe(&file));
        assert!(!original.require(b"foreign", Some(32)));
        assert!(original.metadata.is_some());
        assert!(original.mount.is_some());
        assert!(original.filesystem.is_some());
        assert!(original.label.is_some());
        let before = original.metadata.as_ref().unwrap().as_ref().unwrap().ino();

        assert!(!original.observe(&file));
        assert_eq!(
            original.metadata.as_ref().unwrap().as_ref().unwrap().ino(),
            before
        );
    }
}
