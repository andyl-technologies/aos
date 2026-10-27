//! Checks opaque quarantine observations against actual namespace and project custody.
//!
//! Quarantine bytes are never interpreted as valid content. The authenticated
//! descriptor makes native project inspection possible even when the cache
//! cannot read a publisher-owned inode through its mode0400 pathname. Encoded
//! members retain shared-content ownership and are inspected through original
//! read-only kernel handles without interpreting bytes or acquiring lifecycle tokens.

use super::NativeRecoveryInspector;
use crate::{host_cache::NativeHostLayout, host_quota::NativeProject};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::{File, Metadata},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    sync::Arc,
};
use terrane_format::identity::Descriptor;
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains an original unverified quarantine inode and its actual charge custody.
///
/// This is neither a content receipt nor a lifecycle token. It cannot authorize
/// service, restoration, retirement, pin removal or recovery completion.
pub struct NativeQuarantinedInode {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    file: File,
    name: String,
    observed: Metadata,
    project_id: u32,
}

impl NativeQuarantinedInode {
    /// Borrows the read-only unverified descriptor for native accounting.
    ///
    /// Bytes may be corrupt or unsealed and must never be served as content.
    /// Callers recheck original custody before and after their observations.
    pub fn handle(&self) -> &File {
        &self.file
    }

    /// Rechecks the original named inode, immutable observation and native project.
    ///
    /// # Errors
    /// Refuses changed native roots, names, inodes, metadata, access or projects.
    pub fn check_current(&self) -> io::Result<()> {
        self.layout.recheck()?;
        let parent = self
            .layout
            .directories
            .get("quarantine")
            .ok_or_else(|| invalid("quarantine root absent"))?;
        let named = File::from(fs::openat(
            parent,
            self.name.as_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if !same_metadata(&self.observed, &self.file.metadata()?)
            || !same_metadata(&self.observed, &named.metadata()?)
        {
            return Err(invalid("quarantined inode changed original custody"));
        }
        let flags = fs::fcntl_getfl(&self.file)?;
        let project = NativeProject::inspect(&self.file)?;
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
            || project.project_id != self.project_id
            || (project.device, project.inode) != (self.observed.dev(), self.observed.ino())
        {
            return Err(invalid(
                "quarantined inode has another access or project binding",
            ));
        }
        self.layout.recheck()
    }
}

impl NativeRecoveryInspector {
    /// Retains a shared encoded quarantine inode without interpreting its bytes.
    ///
    /// The public tag routes to a candidate and confers no publisher authority.
    /// A partial pack/index quarantine may retain either member independently;
    /// this observation never establishes the other member or valid metadata.
    ///
    /// # Errors
    /// Refuses unknown names, unsafe inode kinds, changed native custody,
    /// another configured content owner/project or stale recovery context.
    pub(in crate::host_cache) fn inspect_quarantined_encoded(
        &self,
        name: &str,
    ) -> io::Result<NativeQuarantinedInode> {
        self.check_current()?;
        check_encoded_name(name)?;
        let context = self.session.recovery_context().map_err(io::Error::other)?;
        let parent = self
            .layout
            .directories
            .get("quarantine")
            .ok_or_else(|| invalid("quarantine root absent"))?;
        // Classify first, then reopen that same kernel inode. A replaced FIFO,
        // symlink or device must never be opened through a readable pathname.
        let path = File::from(fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let observed = path.metadata()?;
        self.custody.check(&observed, false)?;
        // Rejected custody may have lost group access or write access. These
        // readable owner-only classes still supply no serving grant.
        let metadata_member = matches!(name.split('.').nth(2), Some("pack" | "idx"));
        let readable_mode = matches!(observed.mode() & 0o7777, 0o400 | 0o600 | 0o640)
            || (metadata_member && observed.mode() & 0o7777 == 0o660);
        if observed.nlink() != 1
            || !readable_mode
            || observed.dev() != self.layout.directory_binding("layout-root")?.0
        {
            return Err(invalid(
                "encoded quarantine differs from configured content custody",
            ));
        }
        let file = File::from(fs::open(
            format!("/proc/self/fd/{}", path.as_raw_fd()),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let result = NativeQuarantinedInode {
            layout: Arc::clone(&self.layout),
            file,
            name: name.to_owned(),
            observed,
            project_id: self.project_id,
        };
        result.check_current()?;
        self.session
            .check_recovery_context(&context)
            .map_err(io::Error::other)?;
        self.check_current()?;
        Ok(result)
    }

    /// Observes a publisher-owned quarantined sealed-body candidate without reading bytes.
    ///
    /// The actual authenticated publisher session must retain recovery custody.
    /// The descriptor is checked against the original domain's quarantine entry,
    /// native filesystem, configured publisher identity and quota project.
    /// The descriptor's claimed content identity and length remain unverified.
    ///
    /// # Errors
    /// Refuses invalid keys, undrained sessions, absent or unsafe quarantine
    /// entries, failed transport, changed native custody and project mismatches.
    pub fn inspect_quarantined_sealed(
        &self,
        descriptor: &Descriptor,
    ) -> io::Result<NativeQuarantinedInode> {
        self.inspect_quarantined_entry(descriptor, None)
    }

    /// Observes a legacy name or a public incarnation-tagged quarantine entry.
    ///
    /// # Errors
    /// Returns the same native custody and transport errors as sealed inspection.
    pub(in crate::host_cache) fn inspect_quarantined_entry(
        &self,
        descriptor: &Descriptor,
        incarnation: Option<[u8; 32]>,
    ) -> io::Result<NativeQuarantinedInode> {
        self.check_current()?;
        let context = self.session.recovery_context().map_err(io::Error::other)?;
        let file = self
            .session
            .inspect_quarantined_sealed(descriptor, incarnation)
            .map_err(io::Error::other)?;
        let observed = file.metadata()?;
        if !observed.is_file()
            || observed.uid() != self.publisher_uid
            || observed.nlink() != 1
            || !matches!(observed.mode() & 0o7777, 0o400 | 0o600)
            || observed.dev() != self.layout.directory_binding("layout-root")?.0
        {
            return Err(invalid(
                "quarantine reply differs from configured publisher custody",
            ));
        }
        let result = NativeQuarantinedInode {
            layout: Arc::clone(&self.layout),
            file,
            name: crate::publisher_io::quarantine_name(descriptor, incarnation.as_ref()),
            observed,
            project_id: self.project_id,
        };
        result.check_current()?;
        self.session
            .check_recovery_context(&context)
            .map_err(io::Error::other)?;
        self.check_current()?;
        Ok(result)
    }
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Recognizes only the closed generated encoded quarantine filename grammar.
fn check_encoded_name(name: &str) -> io::Result<()> {
    let mut parts = name.split('.');
    if parts.next() != Some("encoded")
        || !parts.next().is_some_and(canonical_hex)
        || !matches!(parts.next(), Some("0" | "1" | "2" | "pack" | "idx"))
        || !parts.next().is_some_and(canonical_hex)
        || parts.next().is_some()
    {
        return Err(invalid("unrecognized encoded quarantine name"));
    }
    Ok(())
}

fn canonical_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::check_encoded_name;

    #[test]
    fn encoded_quarantine_names_are_closed_routing_fields_without_content_authority() {
        let digest = "13".repeat(32);
        let tag = "24".repeat(32);
        for member in ["0", "1", "2", "pack", "idx"] {
            assert!(check_encoded_name(&format!("encoded.{digest}.{member}.{tag}")).is_ok());
        }
        for name in [
            format!("encoded.{digest}.3.{tag}"),
            format!("encoded.{digest}.00.{tag}"),
            format!("encoded.{digest}.0.{tag}.extra"),
            format!("encoded.{digest}.0"),
            format!(
                "encoded.{}.pack.{tag}",
                digest.to_uppercase().replace('1', "A")
            ),
            format!("encoded.{digest}.idx.{}", &tag[..62]),
            format!("../encoded.{digest}.0.{tag}"),
            format!("encoded.{digest}/other.0.{tag}"),
        ] {
            assert!(check_encoded_name(&name).is_err(), "{name}");
        }
    }
}
