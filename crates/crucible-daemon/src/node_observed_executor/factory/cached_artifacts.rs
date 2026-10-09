//! Independently enrolled immutable inputs for read-only cache compatibility.
//!
//! The helper materializes immutable scenario bytes solely to regenerate the
//! installed profile. It creates no native world or restoration authority and
//! never changes enrollment. Missing Path entries cannot become ArchiveOnly.

use super::*;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

pub(super) struct CachedArtifacts {
    _directory: TempDir,
    registry: BTreeMap<String, InstalledIoArtifact>,
}

impl CachedArtifacts {
    pub(super) fn registry(&self) -> &BTreeMap<String, InstalledIoArtifact> {
        &self.registry
    }
}

pub(super) fn materialize(
    installed: &BTreeMap<String, InstalledIoArtifact>,
    selections: &[InstalledNodeSelection],
    scenario: &NodeScenario,
) -> Result<CachedArtifacts, NodeObservedError> {
    let mut expected = BTreeMap::new();
    for selected in selections {
        let reference = match &selected.kind {
            InstalledNodeKind::HostIo { profile } => profile.artifact(),
            InstalledNodeKind::HostScripted { profile } => profile.artifact(),
            _ => continue,
        };
        let artifact = installed
            .get(&reference.hash.digest)
            .filter(|artifact| &artifact.expected == reference)
            .ok_or_else(|| refused("cached immutable input is not independently enrolled"))?;
        if reference.length.get() > io::MAXIMUM_IO_ARTIFACT_BYTES as u64 {
            return Err(refused("cached immutable input exceeds installed capacity"));
        }
        expected.insert(reference.hash.digest.clone(), artifact.clone());
    }
    let total = expected
        .values()
        .try_fold(0u64, |total, entry| {
            total.checked_add(entry.expected.length.get())
        })
        .ok_or_else(|| refused("cached immutable byte accounting overflowed"))?;
    if expected.len() > 64 || total > 16 * 1024 * 1024 {
        return Err(refused("cached immutable closure exceeds finite capacity"));
    }
    let directory = tempfile::Builder::new()
        .prefix("crucible-cache-inputs-")
        .tempdir()
        .map_err(native)?;
    let mut registry = BTreeMap::new();
    for (key, artifact) in expected {
        match artifact.source {
            InstalledIoArtifactSource::Path(_) => {
                io::read_artifact(&artifact)?;
                registry.insert(key, artifact);
            }
            InstalledIoArtifactSource::ArchiveOnly => {
                let bytes = scenario
                    .content_bytes(&artifact.expected, io::MAXIMUM_IO_ARTIFACT_BYTES)
                    .map_err(|error| refused(&error.message))?;
                if canonical::content_ref(&bytes, &artifact.expected.media_type)?
                    != artifact.expected
                {
                    return Err(refused(
                        "cached immutable bytes differ from installed identity",
                    ));
                }
                let mut file = NamedTempFile::new_in(directory.path()).map_err(native)?;
                file.write_all(&bytes).map_err(native)?;
                file.flush().map_err(native)?;
                let (handle, path) = file.keep().map_err(native)?;
                drop(handle);
                registry.insert(key, InstalledIoArtifact::path(path, artifact.expected));
            }
        }
    }
    Ok(CachedArtifacts {
        _directory: directory,
        registry,
    })
}
