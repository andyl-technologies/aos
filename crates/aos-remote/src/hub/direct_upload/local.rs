//! Bounded local-file adapters for the shared private staging coordinator.

use std::io::Read as _;
use std::path::PathBuf;

use aos_net::direct_upload::{
    AdmittedSource, DirectClientError, SourceWaveBudget, open_regular_source_file,
};
use aos_proto_types::direct_upload::{
    DirectDependencyPhase, DirectUploadTarget, MAX_DIRECT_BATCH_ITEMS,
};
use sha2::{Digest as _, Sha256};

use super::{DirectStageFile, DirectUploadCoordinator};

/// One caller-owned local source and its exact closed logical upload target.
#[derive(Debug)]
pub struct DirectStagePath {
    /// Caller-selected local ordinary file, never a remote/provider URL.
    pub source: PathBuf,
    /// Optional pre-inventoried exact full SHA; absent means hash this descriptor.
    pub expected_sha256: Option<String>,
    /// Original cache/publication/OCI object identity.
    pub target: DirectUploadTarget,
    /// Conservative hint, never final publication graph authority.
    pub phase: DirectDependencyPhase,
}

impl DirectUploadCoordinator {
    /// Opens and admits a bounded wave without buffering complete file bodies.
    ///
    /// The caller retains source/ancestor custody. Every source descriptor is
    /// regular and at most16 GiB; source hashes are verified again during part
    /// streaming and independently by storage-side final verification.
    ///
    /// # Errors
    /// Refuses empty/oversized waves, source/digest conflicts or staging failures.
    pub async fn stage_paths(&self, paths: Vec<DirectStagePath>) -> Result<(), DirectClientError> {
        if paths.is_empty() || paths.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Invalid);
        }
        let mut budget = SourceWaveBudget::default();
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let source_path = path.source;
            let expected = path.expected_sha256;
            let (file, size, sha) = tokio::task::spawn_blocking(move || {
                let mut file = open_regular_source_file(&source_path)
                    .map_err(|_| DirectClientError::Invalid)?;
                let metadata = file.metadata().map_err(|_| DirectClientError::Invalid)?;
                if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 * 1024 {
                    return Err(DirectClientError::Invalid);
                }
                let sha = match expected {
                    Some(sha) => sha,
                    None => {
                        let mut digest = Sha256::new();
                        let mut buffer = [0_u8; 64 * 1024];
                        let mut remaining = metadata.len();
                        while remaining > 0 {
                            let count = remaining.min(buffer.len() as u64) as usize;
                            file.read_exact(&mut buffer[..count])
                                .map_err(|_| DirectClientError::Invalid)?;
                            digest.update(&buffer[..count]);
                            remaining -= count as u64;
                        }
                        hex::encode(digest.finalize())
                    }
                };
                Ok((file, metadata.len(), sha))
            })
            .await
            .map_err(|_| DirectClientError::Invalid)??;
            if !budget
                .reserve(size, self.part_size())
                .map_err(|_| DirectClientError::Invalid)?
            {
                return Err(DirectClientError::Invalid);
            }
            let source = AdmittedSource::admit(file, size, &sha, self.part_size())
                .await
                .map_err(|_| DirectClientError::Invalid)?;
            files.push(DirectStageFile {
                target: path.target,
                source,
                phase: path.phase,
            });
        }
        self.stage(files).await
    }
}
