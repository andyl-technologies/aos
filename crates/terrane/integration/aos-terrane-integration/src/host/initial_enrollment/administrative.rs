//! Retains exact administrative ancestor membership through each native effect.

use super::model::{Custody, Entry, StatPreimage};
use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
};
use terrane_linux::host_quota::{
    NativeProject, RetainedProjectClaim, directory_children, filesystem_uuid, open_host_path,
    provision_project, set_directory_custody,
};

pub(super) struct AdministrativeDirectory {
    pub entry: Entry,
    pub descriptor: File,
    pub expected: Metadata,
    pub project: NativeProject,
    pub child_name: OsString,
    pub child_device: u64,
    pub child_inode: u64,
}

pub(super) fn stat(metadata: &Metadata) -> StatPreimage {
    StatPreimage {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
        rdev: metadata.rdev(),
        size: metadata.len(),
        blocks: metadata.blocks(),
        block_size: metadata.blksize(),
        atime: metadata.atime(),
        atime_nsec: metadata.atime_nsec(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn comparable(metadata: &Metadata) -> StatPreimage {
    let mut value = stat(metadata);
    // Reading the exact directory changes atime on some mounts. Atime is
    // retained as original history but never normalized into the phase state.
    value.atime = 0;
    value.atime_nsec = 0;
    value
}

impl AdministrativeDirectory {
    pub(super) fn check(&self) -> io::Result<()> {
        let named = open_host_path(&self.entry.path, true)?;
        if comparable(&named.metadata()?) != comparable(&self.expected)
            || comparable(&self.descriptor.metadata()?) != comparable(&self.expected)
            || NativeProject::inspect(&self.descriptor)? != self.project
        {
            return Err(io::Error::other(
                "administrative ancestor full preimage changed",
            ));
        }
        let children = directory_children(&self.descriptor)?;
        if children.len() != 1 || children[0].name != self.child_name {
            return Err(io::Error::other(
                "administrative ancestor membership changed",
            ));
        }
        let child = children[0].directory.metadata()?;
        if (child.dev(), child.ino()) != (self.child_device, self.child_inode)
            || comparable(&self.descriptor.metadata()?) != comparable(&self.expected)
            || comparable(&named.metadata()?) != comparable(&self.expected)
        {
            return Err(io::Error::other(
                "administrative child or ancestor changed during enumeration",
            ));
        }
        Ok(())
    }

    fn advance(&mut self, custody: Option<Custody>, project_id: u32) -> io::Result<()> {
        let actual = self.descriptor.metadata()?;
        let mut before = comparable(&self.expected);
        let mut after = comparable(&actual);
        // Only the actual setter's ctime and explicitly requested custody may
        // advance. Link count, membership, mtime, size and allocation stay exact.
        before.ctime = 0;
        before.ctime_nsec = 0;
        after.ctime = 0;
        after.ctime_nsec = 0;
        if let Some(custody) = custody {
            before.uid = custody.uid;
            before.gid = custody.gid;
            before.mode = (before.mode & !0o7777) | custody.mode;
        }
        let project = NativeProject::inspect(&self.descriptor)?;
        if before != after
            || project.project_id != project_id
            || !project.inherit
            || (project.device, project.inode) != (self.project.device, self.project.inode)
        {
            return Err(io::Error::other(
                "administrative setter changed an unrelated preimage field",
            ));
        }
        self.expected = actual;
        self.project = project;
        self.check()
    }

    pub(super) fn assign(
        &mut self,
        claim: &RetainedProjectClaim,
        uuid: &[u8; 16],
        project: u32,
        limit: u64,
    ) -> io::Result<()> {
        self.check()?;
        if filesystem_uuid(&self.descriptor)? != *uuid {
            return Err(io::Error::other(
                "administrative ancestor changed filesystem",
            ));
        }
        claim.verify(uuid, project)?;
        provision_project(&self.descriptor, project, limit)?;
        self.advance(None, project)?;
        self.check()?;
        set_directory_custody(&self.descriptor, 0, 0, 0o700)?;
        self.advance(
            Some(Custody {
                uid: 0,
                gid: 0,
                mode: 0o700,
            }),
            project,
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Tests use panics as assertion failures."
)]
mod tests {
    use crate::host::{OwnerConfig, RootConfig};
    use std::{collections::BTreeSet, fs, path::PathBuf};

    /// This ignored native component fixture consumes real directory events,
    /// not a forged creator receipt. It grants no enrollment or Ready credit.
    #[test]
    #[ignore = "requires a fresh root-owned disk-backed native quota fixture"]
    fn administrative_capture_rejects_late_namespace_and_metadata_mutations() {
        terrane_linux::host_quota::initial_enrollment::require_initial_host_root().unwrap();
        let root = PathBuf::from(
            std::env::var_os("TERRANE_INITIAL_ADMIN_NATIVE_ROOT")
                .expect("explicit guest fixture root"),
        );
        let administrative = root.join("admin-membership");
        let control = administrative.join("control");
        fs::create_dir(&administrative).unwrap();
        fs::create_dir(&control).unwrap();
        let owner = OwnerConfig {
            owner_id: "native-component".to_owned(),
            domain: "private:fixture".to_owned(),
            project_id: 41001,
            hard_limit_bytes: 32 * 1024 * 1024,
            allowed_client_uids: BTreeSet::from([840, 841]),
            roots: vec![RootConfig {
                role_directory: "administrative-root".to_owned(),
                path: administrative.clone(),
            }],
        };
        let captured = super::super::capture::administrative(&owner, &control).unwrap();
        captured[0].check().unwrap();

        fs::create_dir(administrative.join("unrecorded")).unwrap();
        assert!(
            captured[0].check().is_err(),
            "late uncharged sibling must refuse before claims/Ready"
        );
        fs::remove_dir(administrative.join("unrecorded")).unwrap();
        assert!(
            captured[0].check().is_err(),
            "restoring membership cannot normalize changed parent times"
        );

        drop(captured);
        fs::remove_dir(&control).unwrap();
        fs::remove_dir(&administrative).unwrap();
    }
}
