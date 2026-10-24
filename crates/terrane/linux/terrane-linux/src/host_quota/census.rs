//! Compares distinct retained project inodes with a fresh kernel inode charge.
//!
//! Every counted inode remains open through the quota query. Excluded retired
//! identities are never counted or retained by this scan. Equality therefore
//! proves that none of those excluded identities remains charged in this
//! project, even through a descriptor or mapping outside the scanned namespace.
//! An incomplete scan can conservatively delay that proof; it cannot invent it.

use super::{NativeProject, NativeQuota, ProjectInodeBinding, ProjectInodeBirth, filesystem_uuid};
use rustix::fs::{Dir, FileType, Mode, OFlags, open, openat};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

/// Identifies an original native inode independently of any pathname.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectInode {
    /// Native filesystem device identifier.
    pub device: u64,
    /// Native inode number on that device.
    pub inode: u64,
}

/// Bounds native traversal and the descriptors retained through one observation.
#[derive(Clone, Copy, Debug)]
pub struct ProjectCensusLimits {
    /// Maximum distinct non-excluded inodes retained at once, including roots.
    /// Enumeration additionally uses at most three temporary descriptors.
    pub retained_inodes: usize,
    /// Maximum directory entries visited, including aliases and excluded names.
    pub directory_entries: usize,
    /// Maximum entry depth below each supplied retained root.
    pub depth: u32,
}

/// Records an actual quota comparison without granting physical release.
///
/// The caller must bind this observation to its original project, retired
/// inode identities and serialized maintenance operation. It must first unlink
/// those retired names and close its own backing descriptors. This observation
/// does not drain workers, retire names, alter project attributes or replace
/// current authorization. A retained reference cannot be resurrected after its
/// inode has actually stopped being charged.
pub struct NativeProjectClosure {
    filesystem_uuid: [u8; 16],
    project_id: u32,
    excluded: Vec<ProjectInode>,
    incarnations: Vec<ProjectInodeBinding>,
    retained_inodes: u64,
    quota: NativeQuota,
}

impl NativeProjectClosure {
    /// Returns the filesystem identity actually inspected during the census.
    pub const fn filesystem_uuid(&self) -> &[u8; 16] {
        &self.filesystem_uuid
    }

    /// Returns the actual nonzero project assignment of every counted inode.
    pub const fn project_id(&self) -> u32 {
        self.project_id
    }

    /// Borrows the exact original identities omitted from the retained count.
    pub fn excluded(&self) -> &[ProjectInode] {
        &self.excluded
    }

    /// Borrows the exact original incarnation bindings used by this observation.
    pub fn incarnations(&self) -> &[ProjectInodeBinding] {
        &self.incarnations
    }

    /// Returns the number of distinct non-excluded inodes held through the query.
    pub const fn retained_inodes(&self) -> u64 {
        self.retained_inodes
    }

    /// Borrows fresh complete-project charges, including unlinked kernel custody.
    pub const fn quota(&self) -> &NativeQuota {
        &self.quota
    }

    /// Reports whether no excluded inode was still charged at the observation.
    ///
    /// A false result leaves physical obligations unresolved. It does not
    /// identify which excluded inode or unrelated allocation remains charged.
    pub fn all_excluded_closed(&self) -> bool {
        self.retained_inodes == self.quota.charged_inodes
    }
}

struct Retained {
    file: File,
    identity: ProjectInode,
    directory: bool,
    depth: u32,
}

struct Census {
    project: NativeProject,
    excluded: BTreeMap<ProjectInode, BTreeSet<Option<ProjectInodeBirth>>>,
    seen: BTreeSet<ProjectInode>,
    retained: Vec<Retained>,
    limits: ProjectCensusLimits,
    visited: usize,
}

/// Observes kernel closure using bounded, original project-inode custody.
///
/// Roots are trusted retained directories, never caller-supplied remote paths.
/// They must share a nonzero project and device. The caller must prevent
/// untrusted project setters throughout the observation, as for ordinary quota
/// inspection, and supply trusted procfs for original-descriptor reopening.
/// Namespace mutation alone cannot inflate the distinct retained
/// count: open descriptors keep counted allocations charged through the query.
/// Excluded identities are checked again against each actually opened inode.
///
/// This operation requires native quota-query and directory-read privileges.
/// Missing roots or names, unsupported entries, exhaustion and incomplete
/// observations return errors without granting closure. Unrelated allocations
/// can prevent equality even after all requested retired inodes have closed.
/// No subtraction of allocation bytes or policy reservations is involved.
///
/// # Errors
/// Refuses empty or duplicate exclusions, invalid bounds, mismatched projects,
/// cross-device traversal, special files or links, changed native project
/// bindings, exhausted traversal/descriptor bounds and native inspection errors.
pub fn observe_project_closure(
    roots: &[&File],
    excluded: &[ProjectInode],
    limits: ProjectCensusLimits,
) -> io::Result<NativeProjectClosure> {
    if excluded.is_empty() || excluded.len() > limits.directory_entries {
        return Err(invalid());
    }
    let bindings: Vec<_> = excluded
        .iter()
        .map(|identity| ProjectInodeBinding {
            identity: *identity,
            birth: None,
        })
        .collect();
    observe_project_incarnation_closure(roots, &bindings, limits)
}

/// Observes closure while distinguishing replacements of original inode numbers.
///
/// Creation times must come from original retained descriptors before disclosure,
/// never from replacement paths. Missing timestamps retain legacy exclusions.
/// The same bounded traversal, held inode count and kernel quota comparison as
/// [`observe_project_closure`] apply; matching original incarnations stay omitted.
///
/// # Errors
/// Refuses invalid identities or timestamps, unavailable native creation times
/// for matching inode numbers, and every failure of [`observe_project_closure`].
pub fn observe_project_incarnation_closure(
    roots: &[&File],
    excluded: &[ProjectInodeBinding],
    limits: ProjectCensusLimits,
) -> io::Result<NativeProjectClosure> {
    let root = roots.first().ok_or_else(invalid)?;
    if roots.len() > limits.retained_inodes
        || excluded.is_empty()
        || excluded.len() > limits.directory_entries
        || limits.retained_inodes == 0
        || limits.directory_entries == 0
        || limits.depth == 0
    {
        return Err(invalid());
    }
    let project = NativeProject::inspect(root)?;
    if project.project_id == 0 || !project.inherit || !root.metadata()?.is_dir() {
        return Err(invalid());
    }
    let filesystem_uuid = filesystem_uuid(root)?;
    let mut omitted: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    for binding in excluded {
        let identity = binding.identity;
        if identity.device != project.device
            || identity.inode == 0
            || binding
                .birth
                .is_some_and(|birth| birth.nanoseconds >= 1_000_000_000)
            || !omitted.entry(identity).or_default().insert(binding.birth)
        {
            return Err(invalid());
        }
    }
    let mut census = Census {
        project,
        excluded: omitted,
        seen: BTreeSet::new(),
        retained: Vec::new(),
        limits,
        visited: 0,
    };
    for root in roots {
        let actual = NativeProject::inspect(root)?;
        if !root.metadata()?.is_dir()
            || !actual.inherit
            || actual.device != census.project.device
            || actual.project_id != census.project.project_id
        {
            return Err(invalid());
        }
        census.retain(root.try_clone()?, 0)?;
    }
    census.walk()?;

    // Retained descriptors establish a lower bound on actual charged inodes,
    // regardless of later rename/unlink. Administrative project reassignment
    // remains outside the permitted concurrent operations.
    census.check_projects()?;
    let quota = NativeQuota::query(root, census.project.project_id)?;
    census.check_projects()?;
    let retained_inodes = u64::try_from(census.retained.len()).map_err(|_| invalid())?;
    if quota.charged_inodes < retained_inodes {
        return Err(io::Error::other(
            "retained project census exceeds kernel charge",
        ));
    }
    Ok(NativeProjectClosure {
        filesystem_uuid,
        project_id: census.project.project_id,
        excluded: excluded.iter().map(|binding| binding.identity).collect(),
        incarnations: excluded.to_vec(),
        retained_inodes,
        quota,
    })
}

impl Census {
    fn omits(&self, identity: ProjectInode, file: &File) -> io::Result<bool> {
        let Some(originals) = self.excluded.get(&identity) else {
            return Ok(false);
        };
        if originals.contains(&None) {
            return Ok(true);
        }
        // Multiple draining exposures can record distinct incarnations of one
        // inode number. Omit any matching original; count only a replacement
        // whose native creation time differs from every retained obligation.
        let birth = ProjectInodeBirth::observe(file)?;
        Ok(originals.contains(&Some(birth)))
    }

    fn retain(&mut self, file: File, depth: u32) -> io::Result<()> {
        let metadata = file.metadata()?;
        let identity = ProjectInode {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        if identity.device != self.project.device {
            return Err(invalid());
        }
        if self.omits(identity, &file)? || self.seen.contains(&identity) {
            return Ok(());
        }
        if self.retained.len() >= self.limits.retained_inodes || depth > self.limits.depth {
            return Err(io::Error::other("project census custody bound exceeded"));
        }
        let directory = metadata.is_dir();
        if (!directory && !metadata.is_file())
            || NativeProject::inspect(&file)?.project_id != self.project.project_id
        {
            return Err(invalid());
        }
        self.retained.try_reserve(1).map_err(io::Error::other)?;
        self.seen.insert(identity);
        self.retained.push(Retained {
            file,
            identity,
            directory,
            depth,
        });
        Ok(())
    }

    fn walk(&mut self) -> io::Result<()> {
        let mut next = 0;
        while next < self.retained.len() {
            if self.retained[next].directory {
                self.directory(next)?;
            }
            next += 1;
        }
        Ok(())
    }

    fn directory(&mut self, parent: usize) -> io::Result<()> {
        let depth = self.retained[parent]
            .depth
            .checked_add(1)
            .ok_or_else(invalid)?;
        let mut entries = Dir::read_from(&self.retained[parent].file)?;
        for entry in &mut entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            if depth > self.limits.depth {
                return Err(io::Error::other("project census depth bound exceeded"));
            }
            if self.visited >= self.limits.directory_entries {
                return Err(io::Error::other("project census entry bound exceeded"));
            }
            self.visited += 1;
            let inode = File::from(openat(
                &self.retained[parent].file,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let before = inode.metadata()?;
            let identity = ProjectInode {
                device: before.dev(),
                inode: before.ino(),
            };
            if identity.device != self.project.device {
                return Err(invalid());
            }
            if self.omits(identity, &inode)? || self.seen.contains(&identity) {
                continue;
            }
            let kind = FileType::from_raw_mode(before.mode());
            let flags = match kind {
                FileType::Directory => OFlags::DIRECTORY,
                FileType::RegularFile => OFlags::empty(),
                _ => return Err(invalid()),
            };
            // Reopen the classified inode, never its replaceable directory name.
            // A raced name cannot redirect a read-open into a special device.
            let file = File::from(open(
                format!("/proc/self/fd/{}", inode.as_raw_fd()),
                flags | OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let after = file.metadata()?;
            if (after.dev(), after.ino(), after.mode())
                != (before.dev(), before.ino(), before.mode())
            {
                return Err(invalid());
            }
            drop(inode);
            self.retain(file, depth)?;
        }
        Ok(())
    }

    fn check_projects(&self) -> io::Result<()> {
        for retained in &self.retained {
            let actual = NativeProject::inspect(&retained.file)?;
            if actual.device != retained.identity.device
                || actual.inode != retained.identity.inode
                || actual.project_id != self.project.project_id
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid original project census",
    )
}
