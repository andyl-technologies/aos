//! Retains an actual complete canonical local Trash candidate directory walk.
//!
//! Directory descriptors, names and modification snapshots are checked before
//! and after enumeration and again before receipt publication. Each request
//! traverses a bounded set; exact selected earlier traversal rows may cover other
//! cycles without becoming current absence or permission to delete an instance.

use super::super::{
    FencePolicy, MetadataStamp, NamedFence, NativeEffectFailure, ParentFence, Worker,
};
use crate::store::native_effect::{check_opened_name, check_parents, open_native};
use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Borrows the first original name recipe for each path in one fixed worker.
///
/// This indexes recipe selection only. Every duplicate remains in the worker's
/// projection, and every selected recipe still performs its physical checks.
struct DirectoryRecipes<'worker> {
    names: BTreeMap<&'worker Path, &'worker NamedFence>,
}

impl<'worker> DirectoryRecipes<'worker> {
    fn new(worker: &'worker Worker) -> Self {
        let mut names = BTreeMap::new();
        for name in &worker.projection.names {
            // Preserve iterator.find semantics if distinct original recipes
            // share a path. The full projection continues checking all of them.
            names.entry(name.path.as_path()).or_insert(name);
        }
        Self { names }
    }

    fn get(&self, path: &Path) -> Option<&'worker NamedFence> {
        self.names.get(path).copied()
    }
}

struct Directory {
    path: PathBuf,
    file: File,
    stamp: MetadataStamp,
    times: (i64, i64, i64, i64),
    parents: Vec<ParentFence>,
    owner: u32,
}

fn times(metadata: &Metadata) -> (i64, i64, i64, i64) {
    (
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

impl Directory {
    fn capture(
        worker: &Worker,
        recipes: &DirectoryRecipes<'_>,
        path: PathBuf,
        owner: u32,
    ) -> io::Result<Self> {
        let retained = recipes
            .get(&path)
            .ok_or_else(|| io::Error::other("candidate directory lacks retained name"))?;
        retained.check(&worker.projection.exclusions)?;
        let file = open_native(&path, true)?;
        let metadata = file.metadata()?;
        let stamp = MetadataStamp::checked(&metadata)?;
        FencePolicy::NamespaceDirectory { owner }.validate(stamp)?;
        let directory = Self {
            path,
            file,
            stamp,
            times: times(&metadata),
            parents: retained
                .parents
                .iter()
                .map(|parent| ParentFence {
                    path: parent.path.clone(),
                    stamp: parent.stamp,
                })
                .collect(),
            owner,
        };
        directory.check(worker, recipes)?;
        Ok(directory)
    }

    fn check(&self, worker: &Worker, recipes: &DirectoryRecipes<'_>) -> io::Result<()> {
        let retained = recipes
            .get(&self.path)
            .ok_or_else(|| io::Error::other("candidate directory lost retained name"))?;
        retained.check(&worker.projection.exclusions)?;
        self.check_physical()
    }

    fn check_physical(&self) -> io::Result<()> {
        check_parents(&self.path, &self.parents, self.owner)?;
        check_opened_name(&self.file, &self.path, true)?;
        let metadata = self.file.metadata()?;
        if !MetadataStamp::checked(&metadata)?.same_incarnation(self.stamp)
            || times(&metadata) != self.times
        {
            return Err(io::Error::other(
                "candidate directory changed during traversal",
            ));
        }
        check_parents(&self.path, &self.parents, self.owner)?;
        Ok(())
    }
}

/// Retains actual complete enumeration evidence without universal absence rights.
pub(super) struct CandidateWalk {
    root: PathBuf,
    trash: Option<Directory>,
    cycles: Vec<u64>,
    directories: Vec<Directory>,
    owner: u32,
    complete: bool,
    absent_parents: Vec<ParentFence>,
}

fn enumerate(path: &Path, owner: u32) -> io::Result<Vec<u64>> {
    let mut cycles = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 Trash candidate"))?;
        let cycle = text.parse::<u64>().map_err(io::Error::other)?;
        if text != cycle.to_string() || !entry.file_type()?.is_dir() {
            return Err(io::Error::other(
                "unsafe noncanonical Trash candidate directory",
            ));
        }
        let directory_path = path.join(cycle.to_string());
        let file = open_native(&directory_path, true)?;
        FencePolicy::NamespaceDirectory { owner }
            .validate(MetadataStamp::checked(&file.metadata()?)?)?;
        check_opened_name(&file, &directory_path, true)?;
        cycles.push(cycle);
    }
    cycles.sort_unstable();
    if cycles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::other("duplicate Trash candidate directory"));
    }
    Ok(cycles)
}

impl CandidateWalk {
    /// Enumerates actual canonical cycles under complete current retained inputs.
    ///
    /// # Errors
    /// Refuses unsafe directories, changed enumeration, unretained batch paths,
    /// absent-path conflicts and current-input failures.
    pub(super) fn capture(
        worker: &Worker,
        root: &Path,
        requested: &[u64],
        visited: &[u64],
        owner: u32,
    ) -> Result<Self, NativeEffectFailure> {
        worker.refresh(&[])?;
        let recipes = DirectoryRecipes::new(worker);
        let path = root.join("trash");
        let mut absent_parents = Vec::new();
        let (trash, cycles, directories) = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let trash = Directory::capture(worker, &recipes, path.clone(), owner)?;
                let cycles = enumerate(&path, owner)?;
                let mut directories = Vec::new();
                // These captures only retain physical directory evidence within
                // one read-only request. Each checks its original name recipe;
                // the enclosing refresh and final walk.check compare complete
                // current inputs around the whole traversal and re-enumeration.
                for cycle in &cycles {
                    if requested.binary_search(cycle).is_err() {
                        continue;
                    }
                    directories.push(Directory::capture(
                        worker,
                        &recipes,
                        path.join(cycle.to_string()),
                        owner,
                    )?);
                }
                trash.check(worker, &recipes)?;
                (Some(trash), cycles, directories)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let read = worker.projection.exact(&path, None)?;
                if !matches!(read.policy, FencePolicy::Payload { owner: actual } if actual == owner)
                {
                    return Err(
                        io::Error::other("absent Trash family lacks retained absence").into(),
                    );
                }
                absent_parents = read
                    .parents
                    .iter()
                    .map(|parent| ParentFence {
                        path: parent.path.clone(),
                        stamp: parent.stamp,
                    })
                    .collect();
                (None, Vec::new(), Vec::new())
            }
            Err(error) => return Err(error.into()),
        };
        let complete = cycles.iter().all(|cycle| {
            requested.binary_search(cycle).is_ok() || visited.binary_search(cycle).is_ok()
        });
        let walk = Self {
            root: root.to_owned(),
            trash,
            cycles,
            directories,
            owner,
            complete,
            absent_parents,
        };
        walk.check(worker)?;
        Ok(walk)
    }

    /// Reports current actual enumeration covered by selected prior and new traversal rows.
    pub(super) fn complete(&self) -> bool {
        self.complete
    }

    /// Rechecks original directory recipes while staging unselected proposals.
    ///
    /// This retains Trash and requested-directory descriptors, names, ancestry,
    /// policies and modification snapshots without repeating enumeration. Full
    /// traversal must be rechecked before selecting progress and through its ACK.
    ///
    /// # Errors
    /// Refuses changed retained directories or the original absent-family anchor.
    pub(super) fn check_continuity(&self) -> io::Result<()> {
        match &self.trash {
            Some(trash) => {
                trash.check_physical()?;
                for directory in &self.directories {
                    directory.check_physical()?;
                }
                trash.check_physical()?;
            }
            None => self.check_absent_family()?,
        }
        Ok(())
    }

    /// Rechecks absence against the originally captured ancestry.
    fn check_absent_family(&self) -> io::Result<()> {
        let path = self.root.join("trash");
        check_parents(&path, &self.absent_parents, self.owner)?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(io::Error::other("absent Trash family appeared")),
        }
        check_parents(&path, &self.absent_parents, self.owner)?;
        Ok(())
    }

    /// Freshly verifies traversal continuity without granting current permission.
    ///
    /// The submitting Frame independently retains exclusions and rechecks current
    /// authority around this physical check. Earlier traversal coverage is not an
    /// absence predicate and does not authorize a later residue request.
    ///
    /// # Errors
    /// Refuses changed canonical names, unsafe directories, ancestry, descriptors,
    /// modification snapshots or the actually captured absent family anchor.
    pub(super) fn check_physical(&self) -> io::Result<()> {
        let path = self.root.join("trash");
        match &self.trash {
            Some(trash) => {
                trash.check_physical()?;
                if enumerate(&path, self.owner)? != self.cycles {
                    return Err(io::Error::other(
                        "Trash candidates changed during traversal",
                    ));
                }
                for directory in &self.directories {
                    directory.check_physical()?;
                }
                trash.check_physical()?;
            }
            None => self.check_absent_family()?,
        }
        Ok(())
    }

    /// Repeats actual enumeration and descriptor continuity before completion.
    ///
    /// # Errors
    /// Refuses changed candidates, directory incarnation, timestamps or authority.
    pub(super) fn check(&self, worker: &Worker) -> Result<(), NativeEffectFailure> {
        worker.refresh(&[])?;
        let recipes = DirectoryRecipes::new(worker);
        let path = self.root.join("trash");
        match &self.trash {
            Some(trash) => {
                trash.check(worker, &recipes)?;
                if enumerate(&path, self.owner)? != self.cycles {
                    return Err(
                        io::Error::other("Trash candidates changed during traversal").into(),
                    );
                }
                for directory in &self.directories {
                    directory.check(worker, &recipes)?;
                }
                trash.check(worker, &recipes)?;
            }
            None => {
                worker.projection.exact(&path, None)?.check()?;
            }
        }
        worker.refresh(&[])?;
        Ok(())
    }
}
