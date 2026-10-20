//! Retains actual local residue descriptors without treating old bytes as authority.
//!
//! A permanent owner covers late arbitrary bodies under its canonical family
//! keys. These receipts identify physical instances; they do not certify content
//! eligibility, publication rights or a future absence.

use super::super::{FencePolicy, MetadataStamp, NativeExclusion, ParentFence, Worker};
use super::super::{absent_name, check_opened_name, open_native};
use super::recipes::Recipes;
use crate::store::native_effect::check_parents;
use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Retains one no-follow descriptor or a freshly checked absent family leaf.
pub(super) struct Leaf {
    path: PathBuf,
    parents: Vec<ParentFence>,
    owner: u32,
    present: Option<Present>,
    absent_anchor: Option<PathBuf>,
    extracted: Option<SourceStamp>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SourceStamp {
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl SourceStamp {
    fn capture(metadata: &std::fs::Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Present {
    file: File,
    stamp: MetadataStamp,
}

impl Leaf {
    /// Reports only the actual captured presence, never future continuity.
    pub(super) fn is_present(&self) -> bool {
        self.present.is_some()
    }

    /// Observes only a path whose actual parent is in the complete retained Frame.
    ///
    /// # Errors
    /// Refuses missing retained ancestry, unsafe leaves, replacements and I/O failures.
    pub(super) fn capture(
        worker: &Worker,
        recipes: &Recipes,
        path: PathBuf,
        owner: u32,
    ) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("permanent residue lacks parent"))?;
        let fence = recipes
            .ancestor(&worker.projection, parent)
            .ok_or_else(|| io::Error::other("permanent residue ancestry was not retained"))?;
        fence.check(&worker.projection.exclusions)?;
        if fence.path != parent {
            let suffix = path.strip_prefix(&fence.path).map_err(io::Error::other)?;
            let first = suffix.components().next().ok_or_else(|| {
                io::Error::other("permanent absent family lacks canonical descendant")
            })?;
            if !matches!(first, std::path::Component::Normal(_)) {
                return Err(io::Error::other(
                    "permanent absent descendant is noncanonical",
                ));
            }
            let anchor = fence.path.join(first);
            let read = recipes.exact(&worker.projection, &anchor, None)?;
            if !matches!(read.policy, FencePolicy::Payload { owner: actual } if actual == owner) {
                return Err(io::Error::other(
                    "permanent missing ancestor lacks current absence",
                ));
            }
            let leaf = Self {
                path,
                owner,
                parents: read
                    .parents
                    .iter()
                    .map(|parent| ParentFence {
                        path: parent.path.clone(),
                        stamp: parent.stamp,
                    })
                    .collect(),
                present: None,
                absent_anchor: Some(anchor),
                extracted: None,
            };
            leaf.check(&worker.projection.exclusions)?;
            return Ok(leaf);
        }
        let mut parents: Vec<_> = fence
            .parents
            .iter()
            .map(|parent| ParentFence {
                path: parent.path.clone(),
                stamp: parent.stamp,
            })
            .collect();
        parents.push(ParentFence {
            path: parent.to_owned(),
            stamp: fence.stamp,
        });
        check_parents(&path, &parents, owner)?;

        let present = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                absent_name(&path)?;
                None
            }
            Err(error) => return Err(error),
            Ok(metadata) => {
                let stamp = MetadataStamp::checked(&metadata)?;
                FencePolicy::Payload { owner }.validate(stamp)?;
                let file = open_native(&path, false)?;
                let opened = MetadataStamp::checked(&file.metadata()?)?;
                FencePolicy::Payload { owner }.validate(opened)?;
                if !opened.same_incarnation(stamp) {
                    return Err(io::Error::other("permanent residue replaced during open"));
                }
                check_opened_name(&file, &path, false)?;
                Some(Present { file, stamp })
            }
        };
        let leaf = Self {
            path,
            parents,
            owner,
            present,
            absent_anchor: None,
            extracted: None,
        };
        leaf.check(&worker.projection.exclusions)?;
        Ok(leaf)
    }

    /// Rechecks ancestry and the original descriptor/name incarnation under holds.
    ///
    /// # Errors
    /// Refuses changed ancestry, unsafe metadata, replacement or unproved absence.
    pub(super) fn check(&self, exclusions: &[NativeExclusion]) -> io::Result<()> {
        // The enclosing worker checks exclusion identity and current authority.
        // Require actual retained exclusions even when the leaf is absent.
        if exclusions.is_empty() {
            return Err(io::Error::other(
                "permanent residue lacks retained exclusion",
            ));
        }
        check_parents(self.checked_path(), &self.parents, self.owner)?;
        match &self.present {
            None => absent_name(self.checked_path())?,
            Some(present) => {
                let opened = MetadataStamp::checked(&present.file.metadata()?)?;
                let named = MetadataStamp::checked(&std::fs::symlink_metadata(&self.path)?)?;
                let policy = FencePolicy::Payload { owner: self.owner };
                policy.validate(opened)?;
                policy.validate(named)?;
                if !opened.same_incarnation(present.stamp) || !named.same_incarnation(present.stamp)
                {
                    return Err(io::Error::other("permanent residue incarnation changed"));
                }
                check_opened_name(&present.file, &self.path, false)?;
            }
        }
        check_parents(self.checked_path(), &self.parents, self.owner)
    }

    /// Borrows the observed canonical path without providing deletion permission.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows the first actually absent anchor or the actual opened leaf.
    pub(super) fn checked_path(&self) -> &Path {
        self.absent_anchor.as_deref().unwrap_or(&self.path)
    }

    /// Reads the same actually opened instance without certifying content eligibility.
    ///
    /// # Errors
    /// Refuses absence, unsafe or replaced instances, size overflow, allocation
    /// failure, short/oversized reads and filesystem failures.
    pub(super) fn read_whole(
        &mut self,
        exclusions: &[NativeExclusion],
    ) -> io::Result<(Vec<u8>, std::fs::Metadata)> {
        self.check(exclusions)?;
        let present = self.present.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "permanent extraction source absent",
            )
        })?;
        let before = present.file.metadata()?;
        let limit = before
            .len()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("permanent extraction source length overflow"))?;
        let capacity = usize::try_from(limit).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity)?;
        present.file.seek(SeekFrom::Start(0))?;
        (&mut present.file).take(limit).read_to_end(&mut bytes)?;
        let after = present.file.metadata()?;
        if u64::try_from(bytes.len()).map_err(io::Error::other)? != before.len()
            || SourceStamp::capture(&after) != SourceStamp::capture(&before)
        {
            return Err(io::Error::other(
                "permanent extraction source length changed",
            ));
        }
        self.check(exclusions)?;
        self.extracted = Some(SourceStamp::capture(&after));
        Ok((bytes, after))
    }

    /// Checks extraction-time metadata in addition to physical continuity.
    ///
    /// # Errors
    /// Refuses a missing extraction or a changed length, modification or change time.
    pub(super) fn check_source(&self, exclusions: &[NativeExclusion]) -> io::Result<()> {
        self.check(exclusions)?;
        let present = self
            .present
            .as_ref()
            .ok_or_else(|| io::Error::other("source absent"))?;
        let expected = self
            .extracted
            .ok_or_else(|| io::Error::other("source not extracted"))?;
        if SourceStamp::capture(&present.file.metadata()?) != expected
            || SourceStamp::capture(&std::fs::symlink_metadata(&self.path)?) != expected
        {
            return Err(io::Error::other("extracted source metadata changed"));
        }
        self.check(exclusions)
    }

    /// Rechecks actual absence after unlink without claiming future absence.
    ///
    /// # Errors
    /// Refuses replacement, surviving links, changed descriptor or unsafe ancestry.
    pub(super) fn check_removed(&self) -> io::Result<()> {
        check_parents(self.checked_path(), &self.parents, self.owner)?;
        absent_name(self.checked_path())?;
        if let Some(present) = &self.present {
            let stamp = MetadataStamp::checked(&present.file.metadata()?)?;
            if stamp.identity != present.stamp.identity
                || stamp.owner != present.stamp.owner
                || stamp.mode != present.stamp.mode
                || stamp.kind != present.stamp.kind
                || stamp.links != 0
            {
                return Err(io::Error::other("permanent unlinked descriptor changed"));
            }
        }
        check_parents(self.checked_path(), &self.parents, self.owner)
    }
}
