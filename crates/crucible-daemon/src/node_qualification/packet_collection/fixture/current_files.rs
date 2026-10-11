//! Reads original measured readonly file revisions without rerunning callbacks.
//!
//! Actual full source/ELF bytes are streamed at issuance. The original file
//! descriptors and complete Linux identity/revision facts then remain owned.
//! A current read compares both descriptor and configured path facts, including
//! change time, before native dispatch. This is installed source liveness, not
//! an accepted class, immutable filesystem lease or adversarial root protection.

use std::{
    fs::{File, Metadata},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use super::{PacketFixtureMeasurements, measurement, refused};
use crate::node_qualification::QualificationError;

#[derive(PartialEq, Eq)]
struct Facts {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for Facts {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Original {
    path: PathBuf,
    file: File,
    facts: Facts,
}

pub(super) struct CurrentFiles {
    originals: Vec<Original>,
    process: u32,
}

impl CurrentFiles {
    pub(super) fn install(
        selected: &PacketFixtureMeasurements,
    ) -> Result<Self, QualificationError> {
        // Complete roster and serialized ownership are checked before paths,
        // files or vector slots are copied. Issuance hashes the retained fd itself.
        selected.authenticate()?;
        let mut originals = Vec::new();
        originals.try_reserve_exact(10).map_err(|_| refused())?;
        originals.push(original(&selected.peer.path, &selected.peer.content)?);
        originals.push(original(Path::new("/proc/self/exe"), &selected.host)?);
        for source in &selected.sources {
            originals.push(original(&source.path, &source.content)?);
        }
        let installed = Self {
            originals,
            process: std::process::id(),
        };
        installed.current()?;
        Ok(installed)
    }

    pub(super) fn current(&self) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.originals.len() != 10 {
            return Err(refused());
        }
        for original in &self.originals {
            let descriptor = original.file.metadata().map_err(measurement::io)?;
            let path = std::fs::metadata(&original.path).map_err(measurement::io)?;
            if !descriptor.is_file()
                || !path.is_file()
                || Facts::from(&descriptor) != original.facts
                || Facts::from(&path) != original.facts
            {
                return Err(refused());
            }
        }
        Ok(())
    }
}

fn original(
    path: &Path,
    expected: &crucible_node_contract::ContentRef,
) -> Result<Original, QualificationError> {
    let mut file = File::open(path).map_err(measurement::io)?;
    let measured = measurement::measured_file(&mut file, expected)?;
    let facts = Facts::from(&measured);
    let selected = Facts::from(&std::fs::metadata(path).map_err(measurement::io)?);
    if facts != selected {
        return Err(refused());
    }
    Ok(Original {
        path: path.to_path_buf(),
        file,
        facts,
    })
}

#[cfg(test)]
#[path = "current_files/tests.rs"]
mod tests;
