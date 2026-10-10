//! Scoped immutable source files from independently authenticated archive content.
//!
//! Archive bytes do not enroll implementation policy. This helper accepts only
//! selected references already present in the private operator catalog, checks
//! the signed original closure, and exposes temporary files to existing cold
//! native constructors without changing the installed registry or wire bytes.

use std::{collections::BTreeMap, io::Write};

use crucible::node_state::HostArchiveRecord;
use tempfile::{NamedTempFile, TempDir};

use super::{
    InstalledIoArtifact, InstalledNodeKind, InstalledNodeSelection, NodeObservedError, native,
    refused,
};

pub(super) struct ScopedArtifacts {
    // The directory outlives every pathname while native constructors copy the
    // complete immutable bytes. Native host models retain no source file handle.
    _directory: TempDir,
    registry: BTreeMap<String, InstalledIoArtifact>,
}

impl ScopedArtifacts {
    pub(super) fn registry(&self) -> &BTreeMap<String, InstalledIoArtifact> {
        &self.registry
    }
}

pub(super) fn materialize(
    installed: &BTreeMap<String, InstalledIoArtifact>,
    selections: &[InstalledNodeSelection],
    record: &HostArchiveRecord,
) -> Result<ScopedArtifacts, NodeObservedError> {
    if selections.len() > 64 {
        return Err(refused(
            "archive materialization exceeds installed selection capacity",
        ));
    }
    let mut expected = BTreeMap::new();
    for selected in selections {
        if let InstalledNodeKind::HostRecordedBlockPreserving { profile } = &selected.kind {
            for reference in [&profile.source, profile.storage.artifact()] {
                if installed
                    .get(&reference.hash.digest)
                    .is_none_or(|artifact| &artifact.expected != reference)
                    || reference.length.get() > super::io::MAXIMUM_IO_ARTIFACT_BYTES as u64
                {
                    return Err(refused(
                        "recorded cold artifact lacks bounded independent operator enrollment",
                    ));
                }
                expected.insert(reference.hash.digest.clone(), reference.clone());
            }
            continue;
        }
        let reference = match &selected.kind {
            InstalledNodeKind::HostClock | InstalledNodeKind::HostPacketReceiver { .. } => continue,
            InstalledNodeKind::HostSeededLink { profile } => &profile.program,
            InstalledNodeKind::HostFaultedLink { profile } => &profile.program,
            InstalledNodeKind::HostControlledFaultLink { profile } => &profile.program,
            InstalledNodeKind::HostIo { profile } => profile.artifact(),
            InstalledNodeKind::HostScripted { profile } => profile.artifact(),
            InstalledNodeKind::HostSemantics { profile } => &profile.program,
            InstalledNodeKind::HostConditionDebugPreserving { profile } => &profile.program,
            _ => {
                return Err(refused(
                    "archive source cannot enroll another native implementation",
                ));
            }
        };
        if installed
            .get(&reference.hash.digest)
            .is_none_or(|artifact| &artifact.expected != reference)
        {
            return Err(refused(
                "signed source artifact is not independently enrolled operator policy",
            ));
        }
        if reference.length.get() > super::io::MAXIMUM_IO_ARTIFACT_BYTES as u64 {
            return Err(refused(
                "archive source artifact exceeds its finite byte ceiling",
            ));
        }
        expected.insert(reference.hash.digest.clone(), reference.clone());
    }
    let total = expected
        .values()
        .try_fold(0u64, |total, reference| {
            total.checked_add(reference.length.get())
        })
        .ok_or_else(|| refused("archive source byte accounting overflowed"))?;
    if total > 16 * 1024 * 1024 {
        return Err(refused(
            "archive source exceeds installed immutable byte capacity",
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("crucible-archive-inputs-")
        .tempdir()
        .map_err(native)?;
    let mut registry = BTreeMap::new();
    for reference in expected.into_values() {
        let bytes = record
            .content_bytes(&reference, super::io::MAXIMUM_IO_ARTIFACT_BYTES)
            .map_err(native)?;
        let mut file = NamedTempFile::new_in(directory.path()).map_err(native)?;
        file.write_all(&bytes).map_err(native)?;
        file.flush().map_err(native)?;
        let (handle, path) = file.keep().map_err(native)?;
        drop(handle);
        registry.insert(
            reference.hash.digest.clone(),
            InstalledIoArtifact::path(path, reference),
        );
    }
    Ok(ScopedArtifacts {
        _directory: directory,
        registry,
    })
}
