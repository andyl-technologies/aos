//! Retains the exact supported state-parent namespace during recovery.
//!
//! Only cache and publication directories are supported children. Unknown names
//! are unresolved, never deleted. The cache directly checks readable parent and
//! cache project attributes. Publication remains private mode 0700: its O_PATH
//! descriptor proves inode/custody identity, not FS_IOC_FSGETXATTR success. Its
//! project/inheritance observation comes from actual strict publisher Inventory
//! under the same drain context, protected by setter confinement and retained
//! provisioning guards while this unchanged child inode remains installed.

use super::{NativeCachePreparation, recovery_namespace::read_names};
use crate::{
    host_cache::NativeHostLayout, host_quota::NativeProject, quota_confinement::Installed,
};
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    sync::Arc,
};
use terrane::host::cache::HostDomainLocation;

/// Observes state namespace identity without independently proving private quota.
pub(super) struct StateParentObservation {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    confinement: Arc<Installed>,
    parent: File,
    parent_metadata: Metadata,
    cache: File,
    cache_metadata: Metadata,
    publication: File,
    publication_metadata: Metadata,
    content_uid: u32,
    state_gid: u32,
    publisher_uid: u32,
    project_id: u32,
    max_entries: usize,
}

impl StateParentObservation {
    /// Borrows actual retained state inodes for post-syncfs allocation observation.
    pub(super) fn retained_inodes(&self) -> [&File; 3] {
        [&self.parent, &self.cache, &self.publication]
    }

    /// Retains actual configured state children and rejects every unknown name.
    ///
    /// # Errors
    /// Refuses stale roots, incomplete/unknown namespaces, wrong native custody,
    /// unavailable readable project observations and replaced child inodes.
    pub(super) fn inspect(preparation: &NativeCachePreparation) -> io::Result<Self> {
        preparation.confinement.check_current()?;
        preparation.layout().recheck()?;
        let retained = preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("missing retained state parent"))?;
        let parent = File::from(openat(retained, ".", directory_flags(), Mode::empty())?);
        supported_children(&parent, preparation.config.inventory_entries)?;
        let cache_path = child(&parent, "cache")?;
        let cache_metadata = cache_path.metadata()?;
        let cache = File::from(open(
            format!("/proc/self/fd/{}", cache_path.as_raw_fd()),
            directory_flags() & !OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        if !same_identity(&cache_metadata, &cache.metadata()?) {
            return Err(invalid(
                "classified cache state directory changed during reopen",
            ));
        }
        let publication = child(&parent, "publication")?;
        let publication_metadata = publication.metadata()?;
        let parent_metadata = parent.metadata()?;
        let observed = Self {
            layout: Arc::clone(preparation.layout()),
            confinement: Arc::clone(&preparation.confinement),
            parent,
            parent_metadata,
            cache,
            cache_metadata,
            publication,
            publication_metadata,
            content_uid: preparation.config.content_uid,
            state_gid: preparation.config.state_gid,
            publisher_uid: preparation.config.publisher.identities.publish_uid,
            project_id: preparation.config.project_id,
            max_entries: preparation.config.inventory_entries,
        };
        observed.check_current()?;
        Ok(observed)
    }

    /// Rechecks exact names, unchanged child inodes and configured native custody.
    ///
    /// The private child's project binding is jointly supplied by the real
    /// publisher inspection; no ioctl is attempted on its O_PATH descriptor.
    /// Cache content mutations may change its directory timestamps/allocation,
    /// while inode, ownership, permissions and project remain fixed.
    ///
    /// # Errors
    /// Refuses new/missing/unknown names, changed state inodes/custody, stale
    /// confinement/roots and changed directly observable project assignments.
    pub(super) fn check_current(&self) -> io::Result<()> {
        self.confinement.check_current()?;
        self.layout.recheck()?;
        supported_children(&self.parent, self.max_entries)?;
        let parent = self.parent.metadata()?;
        if !same_identity(&self.parent_metadata, &parent)
            || (parent.dev(), parent.ino()) != self.layout.directory_binding("state")?
            || parent.uid() != 0
            || parent.gid() != 0
            || parent.mode() & 0o7777 != 0o755
        {
            return Err(invalid("state parent differs from retained root custody"));
        }
        let cache = child(&self.parent, "cache")?.metadata()?;
        let publication = child(&self.parent, "publication")?.metadata()?;
        if !same_identity(&self.cache_metadata, &cache)
            || !same_identity(&self.cache_metadata, &self.cache.metadata()?)
            || cache.uid() != self.content_uid
            || cache.gid() != self.state_gid
            || cache.mode() & 0o7777 != 0o2770
            || !same_identity(&self.publication_metadata, &publication)
            || !same_identity(&self.publication_metadata, &self.publication.metadata()?)
            || publication.uid() != self.publisher_uid
            || publication.mode() & 0o7777 != 0o700
            || cache.dev() != parent.dev()
            || publication.dev() != parent.dev()
        {
            return Err(invalid(
                "state child differs from retained configured custody",
            ));
        }
        for file in [&self.parent, &self.cache] {
            let project = NativeProject::inspect(file)?;
            if project.project_id != self.project_id
                || !project.inherit
                || project.device != parent.dev()
            {
                return Err(invalid(
                    "readable state directory has another project assignment",
                ));
            }
        }
        Ok(())
    }
}

fn supported_children(parent: &File, limit: usize) -> io::Result<()> {
    let names = read_names(parent, limit)?;
    if names != [OsString::from("cache"), OsString::from("publication")] {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "state parent has missing or unhandled children",
        ));
    }
    Ok(())
}

fn child(parent: &File, name: &str) -> io::Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_dir() {
        return Err(invalid("state child is not an ordinary directory"));
    }
    Ok(file)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn same_identity(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn actual_state_parent_scan_refuses_unknown_file_and_directory_siblings() {
        let mut nonce = [0; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut nonce)
            .unwrap();
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("terrane-state-parent-{suffix}"));
        std::fs::create_dir(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let _cleanup = Cleanup(path.clone());
        std::fs::create_dir(path.join("cache")).unwrap();
        std::fs::create_dir(path.join("publication")).unwrap();
        let parent = File::open(&path).unwrap();
        supported_children(&parent, 8).unwrap();

        std::fs::write(path.join("unhandled.tmp"), []).unwrap();
        assert_eq!(
            supported_children(&parent, 8).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(path.join("unhandled.tmp").exists());
        std::fs::remove_file(path.join("unhandled.tmp")).unwrap();
        std::fs::create_dir(path.join("old-policy")).unwrap();
        assert_eq!(
            supported_children(&parent, 8).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(path.join("old-policy").is_dir());
    }
}
