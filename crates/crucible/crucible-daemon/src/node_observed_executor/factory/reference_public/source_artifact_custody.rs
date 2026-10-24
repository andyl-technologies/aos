//! Retains actual measured package files for private original-history archival.
//!
//! This source custody grants no execution, capture, restore or qualification.
//! Complete files stream from their original retained descriptors; later source
//! path loss cannot authorize a replacement or discard the old source bytes.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    os::unix::fs::FileExt,
};

use crucible_node_transport::ProviderError;

use super::{Artifact, InstalledPublicReferencePackage, MAXIMUM_CLOSURE_BYTES, open_regular};

pub(in crate::node_observed_executor::factory::reference_public) struct OriginalPackageSourceCustody
{
    document: Vec<u8>,
    objects: Vec<OriginalSourceArtifact>,
    archive_bytes: u64,
}

struct OriginalSourceArtifact {
    source: File,
    reference: crucible_node_format::ContentRef,
    header: Vec<u8>,
}

impl InstalledPublicReferencePackage {
    /// Opens every original measured implementation/source/runtime artifact before Child.
    pub(in crate::node_observed_executor::factory::reference_public) fn retain_original_sources(
        &self,
    ) -> Result<OriginalPackageSourceCustody, ProviderError> {
        let mut roster: BTreeMap<_, &Artifact> = BTreeMap::new();
        for artifact in self
            .manifest
            .artifacts
            .values()
            .chain(self.manifest.source_artifacts.values())
            .chain(self.runtime.objects.iter())
            .chain([
                &self.runtime.reference_graph,
                &self.runtime.build_reference_graph,
            ])
            .chain(self.runtime.build_tools.values())
        {
            if let Some(original) = roster.insert(artifact.path.clone(), artifact)
                && original.content != artifact.content
            {
                return Err(ProviderError::Correlation(
                    "original source artifact identity collision",
                ));
            }
        }
        if roster.len() > 4128 {
            return Err(ProviderError::ResourceExhausted(
                "original package source descriptor roster",
            ));
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(roster.len())
            .map_err(|_| ProviderError::ResourceExhausted("original package source reservation"))?;
        let mut archive_bytes = 0u64;
        for artifact in roster.into_values() {
            let source = open_regular(&artifact.path)
                .map_err(|error| ProviderError::Io(io::Error::other(error.to_string())))?;
            let header = serde_json::to_vec(&(&artifact.path, &artifact.content))
                .map_err(crucible_node_format::ContractError::from)?;
            archive_bytes = archive_bytes
                .checked_add(8)
                .and_then(|total| total.checked_add(header.len() as u64))
                .and_then(|total| total.checked_add(artifact.content.length.get()))
                .filter(|total| *total <= MAXIMUM_CLOSURE_BYTES + 8 * 1024 * 1024)
                .ok_or(ProviderError::ResourceExhausted(
                    "complete original source archive credit",
                ))?;
            let retained = OriginalSourceArtifact {
                source,
                reference: artifact.content.clone(),
                header,
            };
            // Authenticate these actual descriptors while no provider exists.
            // The same originals remain held on every subsequent sink attempt.
            retained.copy_original(&mut io::sink())?;
            objects.push(retained);
        }
        self.identity.verify(&self.bytes)?;
        Ok(OriginalPackageSourceCustody {
            document: self.bytes.clone(),
            objects,
            archive_bytes,
        })
    }
}

impl OriginalPackageSourceCustody {
    /// Borrows the exact original package descriptor without granting source authority.
    pub(in crate::node_observed_executor::factory::reference_public) fn document(&self) -> &[u8] {
        &self.document
    }

    /// Returns the independently bounded full original source segment extent.
    pub(in crate::node_observed_executor::factory::reference_public) fn archive_bytes(
        &self,
    ) -> u64 {
        self.archive_bytes
    }

    /// Streams and authenticates every actual retained source file into private custody.
    ///
    /// # Errors
    /// Refuses changed source extents or bytes and propagates reader or sink failures.
    pub(in crate::node_observed_executor::factory::reference_public) fn write_originals(
        &self,
        output: &mut impl Write,
    ) -> Result<(), ProviderError> {
        for object in &self.objects {
            output.write_all(&(object.header.len() as u64).to_be_bytes())?;
            output.write_all(&object.header)?;
            object.copy_original(output)?;
        }
        Ok(())
    }
}

impl OriginalSourceArtifact {
    fn copy_original(&self, output: &mut impl Write) -> Result<(), ProviderError> {
        if self.source.metadata()?.len() != self.reference.length.get() {
            return Err(ProviderError::Correlation(
                "original source descriptor extent changed",
            ));
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"CNP/1\0");
        hash.update(&(b"cnp.blob.v1".len() as u32).to_be_bytes());
        hash.update(b"cnp.blob.v1");
        hash.update(&self.reference.length.get().to_be_bytes());
        let mut buffer = [0u8; 65_536];
        let mut offset = 0u64;
        loop {
            let count = self.source.read_at(&mut buffer, offset)?;
            if count == 0 {
                break;
            }
            offset = offset
                .checked_add(count as u64)
                .filter(|length| *length <= self.reference.length.get())
                .ok_or(ProviderError::Correlation(
                    "original source extent exceeds retained commitment",
                ))?;
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        if offset != self.reference.length.get()
            || hash.finalize().to_hex().as_str() != self.reference.hash.digest
        {
            return Err(ProviderError::Correlation(
                "original source descriptor bytes changed",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Original descriptor fixture assertions intentionally fail on source drift.
// crucible-lint: allow rust-allow -- This test-only module uses assertions on private fixture effects.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn retained(path: &std::path::Path, bytes: &[u8]) -> OriginalSourceArtifact {
        std::fs::write(path, bytes).unwrap();
        let source = File::open(path).unwrap();
        let reference =
            crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")
                .unwrap();
        OriginalSourceArtifact {
            source,
            reference,
            header: b"source-only-fixture".to_vec(),
        }
    }

    #[test]
    fn original_source_descriptor_keeps_exact_bytes_after_path_loss() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original-source");
        let bytes = b"complete original source dependency\n";
        let original = retained(&path, bytes);
        std::fs::remove_file(&path).unwrap();

        let mut archived = Vec::new();
        original.copy_original(&mut archived).unwrap();

        assert!(!path.exists());
        assert_eq!(archived, bytes);
        assert_eq!(
            original.source.metadata().unwrap().len(),
            bytes.len() as u64
        );
    }

    #[test]
    fn changed_original_source_bytes_cannot_mint_complete_source_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original-source");
        let bytes = b"complete original source dependency\n";
        let original = retained(&path, bytes);
        let changed = b"changed! original source dependency\n";
        assert_eq!(changed.len(), bytes.len());
        std::fs::write(&path, changed).unwrap();

        let mut archived = Vec::new();
        assert!(original.copy_original(&mut archived).is_err());

        assert_eq!(archived, changed);
        assert_eq!(original.reference.length.get(), bytes.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), changed);
    }

    impl OriginalPackageSourceCustody {
        /// Creates a private file-sink fixture, without a package or native authority.
        pub(in crate::node_observed_executor::factory::reference_public) fn fixture_for_sink(
            path: &std::path::Path,
            bytes: &[u8],
        ) -> Self {
            std::fs::write(path, bytes).unwrap();
            let reference =
                crucible_node_format::canonical::content_ref(bytes, "application/octet-stream")
                    .unwrap();
            let header = serde_json::to_vec(&(path, &reference)).unwrap();
            let archive_bytes = 8 + header.len() as u64 + bytes.len() as u64;
            Self {
                document: b"private source-only filesystem fixture".to_vec(),
                objects: vec![OriginalSourceArtifact {
                    source: File::open(path).unwrap(),
                    reference,
                    header,
                }],
                archive_bytes,
            }
        }
    }
}
