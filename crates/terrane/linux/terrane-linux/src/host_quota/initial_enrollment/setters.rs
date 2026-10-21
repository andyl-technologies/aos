//! Applies receipt-gated administrative metadata changes with tracked phases.

use super::{
    InitialCustody, InitialDirectoryKey, InitialFileKey, Key, NativeInitialHostScaffold, inspection,
};
use crate::host_quota::{
    NativeProject, NativeQuota, RetainedProjectClaim, filesystem_uuid, native,
};
use std::{io, os::unix::fs::MetadataExt, sync::Arc};

#[derive(Clone, Copy)]
enum Selection {
    Directory,
    File,
}

impl NativeInitialHostScaffold {
    /// Assigns an original regular leaf to its durably claimed finite project.
    ///
    /// The host must first durably publish its complete initial global claim
    /// and ledger. The retained claim is reverified against the actual inode's
    /// filesystem UUID and project. This never changes bytes or inode identity.
    ///
    /// # Errors
    /// Refuses foreign keys, changed preimages, links, invalid claims, reassigned
    /// owners, nonfinite quota, missing host custody and kernel failures.
    /// An uncertain effect faults the receipt for administrative recovery.
    pub fn set_file_project(
        &mut self,
        key: InitialFileKey,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
    ) -> io::Result<(NativeProject, NativeQuota)> {
        self.set_project(key.0, Selection::File, claim, project_id, hard_limit_bytes)
    }

    /// Assigns a retained directory through the strict directory provisioner.
    ///
    /// The host must durably publish its complete first claim and ledger first.
    /// Only actual successful effects advance this receipt's expected preimage.
    ///
    /// # Errors
    /// Refuses foreign keys, stale custody, claim or finite-quota mismatch and
    /// native failures. Partial progress faults the receipt for recovery.
    pub fn set_directory_project(
        &mut self,
        key: InitialDirectoryKey,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
    ) -> io::Result<(NativeProject, NativeQuota)> {
        self.set_project(
            key.0,
            Selection::Directory,
            claim,
            project_id,
            hard_limit_bytes,
        )
    }

    /// Changes an original regular leaf's ownership and mode under its claim.
    ///
    /// Durable complete first claim and ledger publication must precede this
    /// operation. The actual project and finite limit must already match.
    ///
    /// # Errors
    /// Refuses stale or foreign keys, changed bytes, hard links, claim/project
    /// mismatches, invalid modes, missing host custody and native failures.
    pub fn set_file_custody(
        &mut self,
        key: InitialFileKey,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
        custody: InitialCustody,
    ) -> io::Result<()> {
        self.set_custody(
            key.0,
            Selection::File,
            claim,
            project_id,
            hard_limit_bytes,
            custody,
        )
    }

    /// Changes a retained directory's custody through the strict generic helper.
    ///
    /// The complete initial global claim and ledger must already be durable.
    ///
    /// # Errors
    /// Refuses stale keys/preimages, claim/project/quota mismatch, invalid modes,
    /// absent host custody and native failures; uncertain effects fault receipt.
    pub fn set_directory_custody(
        &mut self,
        key: InitialDirectoryKey,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
        custody: InitialCustody,
    ) -> io::Result<()> {
        self.set_custody(
            key.0,
            Selection::Directory,
            claim,
            project_id,
            hard_limit_bytes,
            custody,
        )
    }

    fn check_key(&self, key: &Key, selection: &Selection) -> io::Result<()> {
        if !Arc::ptr_eq(&key.owner, &self.identity) || key.index >= self.entries(selection).len() {
            return Err(io::Error::other(
                "selector belongs to another initial scaffold",
            ));
        }
        self.recheck()
    }

    fn entries(&self, selection: &Selection) -> &[super::Entry] {
        match selection {
            Selection::Directory => &self.directories,
            Selection::File => &self.files,
        }
    }

    fn set_project(
        &mut self,
        key: Key,
        selection: Selection,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
    ) -> io::Result<(NativeProject, NativeQuota)> {
        self.check_key(&key, &selection)?;
        if project_id == 0 || hard_limit_bytes == 0 || !hard_limit_bytes.is_multiple_of(1024) {
            return Err(io::Error::other(
                "finite aligned initial project limit required",
            ));
        }
        let entry = &self.entries(&selection)[key.index];
        claim.verify(&filesystem_uuid(&entry.descriptor)?, project_id)?;
        if entry.current_project.project_id != 0 && entry.current_project.project_id != project_id {
            return Err(io::Error::other(
                "initial enrollment cannot reassign charge ownership",
            ));
        }
        // From here any failure may follow a physical effect. Retain the original
        // evidence and refuse further setters instead of guessing a replay phase.
        self.faulted = true;
        let entry = &self.entries(&selection)[key.index];
        match selection {
            Selection::Directory => {
                native::provision_project(&entry.descriptor, project_id, hard_limit_bytes)?
            }
            Selection::File => {
                let quota = NativeQuota::query(&entry.descriptor, project_id)?;
                if quota.hard_limit_bytes != hard_limit_bytes {
                    return Err(io::Error::other(
                        "initial file project finite limit differs",
                    ));
                }
                native::assign_project(&entry.descriptor, project_id, false)?;
                entry.descriptor.sync_all()?;
            }
        }
        let project = NativeProject::inspect(&entry.descriptor)?;
        let quota = NativeQuota::query(&entry.descriptor, project_id)?;
        if project.project_id != project_id || quota.hard_limit_bytes != hard_limit_bytes {
            return Err(io::Error::other(
                "initial project setter failed verification",
            ));
        }
        self.advance(&key, &selection, None, &project)?;
        Ok((project, quota))
    }

    fn set_custody(
        &mut self,
        key: Key,
        selection: Selection,
        claim: &RetainedProjectClaim,
        project_id: u32,
        hard_limit_bytes: u64,
        custody: InitialCustody,
    ) -> io::Result<()> {
        let InitialCustody { uid, gid, mode } = custody;
        self.check_key(&key, &selection)?;
        if mode & !0o7777 != 0 {
            return Err(io::Error::other("invalid initial custody mode"));
        }
        let entry = &self.entries(&selection)[key.index];
        let protected = entry.path.starts_with(self.control());
        let coordination = match self.binding() {
            terrane_format::gc::publication::BackendBinding::Local {
                coordination_device,
                coordination_inode,
                ..
            } => {
                (entry.original.dev(), entry.original.ino())
                    == (*coordination_device, *coordination_inode)
            }
            _ => {
                return Err(io::Error::other(
                    "initial enrollment requires local original binding",
                ));
            }
        };
        let protected_mode = match selection {
            Selection::Directory => 0o700,
            Selection::File => 0o600,
        };
        if (protected || coordination) && (uid, gid, mode) != (0, 0, protected_mode) {
            return Err(io::Error::other(
                "protected original custody must remain private host root",
            ));
        }
        claim.verify(&filesystem_uuid(&entry.descriptor)?, project_id)?;
        if entry.current_project.project_id != project_id
            || NativeQuota::query(&entry.descriptor, project_id)?.hard_limit_bytes
                != hard_limit_bytes
        {
            return Err(io::Error::other(
                "initial custody requires its actual finite claimed project",
            ));
        }
        let expected_project = entry.current_project.clone();
        self.faulted = true;
        let entry = &self.entries(&selection)[key.index];
        match selection {
            Selection::Directory => {
                crate::host_quota::set_directory_custody(&entry.descriptor, uid, gid, mode)?
            }
            Selection::File => {
                rustix::fs::fchown(
                    &entry.descriptor,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )?;
                rustix::fs::fchmod(&entry.descriptor, rustix::fs::Mode::from_raw_mode(mode))?;
                entry.descriptor.sync_all()?;
            }
        }
        self.advance(&key, &selection, Some((uid, gid, mode)), &expected_project)
    }

    fn advance(
        &mut self,
        key: &Key,
        selection: &Selection,
        custody: Option<(u32, u32, u32)>,
        expected_project: &NativeProject,
    ) -> io::Result<()> {
        let entry = &self.entries(selection)[key.index];
        let after = entry.descriptor.metadata()?;
        if (
            after.dev(),
            after.ino(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) != (
            entry.current.dev(),
            entry.current.ino(),
            entry.current.nlink(),
            entry.current.len(),
            entry.current.mtime(),
            entry.current.mtime_nsec(),
        ) {
            return Err(io::Error::other(
                "initial setter changed inode, links or content shape",
            ));
        }
        let expected = custody.unwrap_or((
            entry.current.uid(),
            entry.current.gid(),
            entry.current.mode() & 0o7777,
        ));
        if (after.uid(), after.gid(), after.mode() & 0o7777) != expected {
            return Err(io::Error::other("initial setter changed unrelated custody"));
        }
        let project = NativeProject::inspect(&entry.descriptor)?;
        if &project != expected_project {
            return Err(io::Error::other(
                "initial setter changed unrelated project attributes",
            ));
        }
        let entry = match selection {
            Selection::Directory => &mut self.directories[key.index],
            Selection::File => &mut self.files[key.index],
        };
        entry.current = after;
        entry.current_project = project;
        // Validate every name and exact original byte preimage after the actual
        // tracked event. On failure the permanently faulted receipt is retained.
        self.faulted = false;
        if let Err(error) = inspection::recheck(self) {
            self.faulted = true;
            return Err(error);
        }
        Ok(())
    }
}
