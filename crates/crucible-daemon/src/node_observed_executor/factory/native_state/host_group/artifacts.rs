//! Reopens independently enrolled Script/Block artifacts from signed source bytes.
//!
//! Original pathnames may be gone. Only the operator's retained exact content
//! identities select these two artifacts; an archive cannot install a new base
//! image, script, backend or pathname policy.

use std::{collections::BTreeMap, io::Write};

use crucible::node_state::NativeArchiveRecord;
use tempfile::{NamedTempFile, TempDir};

use super::super::super::{
    InstalledIoArtifact, InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection,
    NodeObservedError, refused,
};
use super::selection::IndependentGroupSelection;

pub(in crate::node_observed_executor::factory::native_state) struct GroupArtifacts {
    _directory: TempDir,
    registry: BTreeMap<String, InstalledIoArtifact>,
}

impl GroupArtifacts {
    pub(in crate::node_observed_executor::factory::native_state) fn materialize(
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        record: &NativeArchiveRecord,
    ) -> Result<Self, NodeObservedError> {
        let selected = IndependentGroupSelection::new_preserving(selections)?;
        let InstalledNodeKind::HostScripted { profile: script } = &selected.source.kind else {
            return Err(refused("original preserving script is absent"));
        };
        let InstalledNodeKind::HostIo { profile: block } = &selected.block.kind else {
            return Err(refused("original preserving Block is absent"));
        };
        let references = [&script.script, block.artifact()];
        let mut total = 0_u64;
        for reference in references {
            total = total
                .checked_add(reference.length.get())
                .ok_or_else(|| refused("original group immutable extent overflow"))?;
            if reference.length.get() > 4 * 1024 * 1024
                || total > 8 * 1024 * 1024
                || catalog
                    .artifacts
                    .get(&reference.hash.digest)
                    .is_none_or(|artifact| &artifact.expected != reference)
            {
                return Err(refused(
                    "signed group input lacks bounded independent enrollment",
                ));
            }
        }

        let directory = tempfile::Builder::new()
            .prefix("crucible-group-source-")
            .tempdir()
            .map_err(error)?;
        let mut registry = BTreeMap::new();
        for reference in references {
            let bytes = record
                .object_bytes(reference, 4 * 1024 * 1024)
                .map_err(error)?;
            reference.verify(&bytes)?;
            let mut file = NamedTempFile::new_in(directory.path()).map_err(error)?;
            file.write_all(&bytes).map_err(error)?;
            file.flush().map_err(error)?;
            let (handle, path) = file.keep().map_err(error)?;
            drop(handle);
            registry.insert(
                reference.hash.digest.clone(),
                InstalledIoArtifact::path(path, reference.clone()),
            );
        }
        Ok(Self {
            _directory: directory,
            registry,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn registry(
        &self,
    ) -> &BTreeMap<String, InstalledIoArtifact> {
        &self.registry
    }
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
