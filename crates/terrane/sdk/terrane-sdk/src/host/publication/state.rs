//! Persists create-once publication bindings through the existing filesystem API.
//!
//! Reconstruction manifests remain ordinary cached metadata, never this store.
//! The native command owner must retain directory custody and publisher exclusion
//! through actual filesystem worker completion even when a client disconnects.
//!
//! ```toml
//! version = 1
//! domain = "public"
//! descriptor = [132, 102]
//! verity_algorithm = 1
//! verity_digest = [0, 1]
//! ```
//!
//! The example abbreviates byte arrays. Actual descriptors use their existing
//! canonical encoding and kernel digests have the algorithm's exact length.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{PublicationClaim, PublicationState, VerityBinding};
use crate::store::LocalFs;

const MAX_RECORD: u64 = 65536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    domain: String,
    descriptor: Vec<u8>,
    verity_algorithm: u16,
    verity_digest: Vec<u8>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

pub(super) fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Stores only immutable verified bindings under a publisher-private state root.
pub struct FsPublicationState<F> {
    pub(super) fs: F,
    pub(super) directory: PathBuf,
}

impl<F: LocalFs + Sync> FsPublicationState<F> {
    /// Uses a provisioned publisher-private `state/publication` directory.
    ///
    /// The native command owner supplies independently verified directory
    /// custody. This constructor grants no ownership or create-root authority.
    pub fn new(fs: F, directory: PathBuf) -> Self {
        Self { fs, directory }
    }

    /// Removes incomplete private binding records before processing commands.
    ///
    /// The caller must retain exclusive publisher custody during this operation.
    ///
    /// # Errors
    /// Returns directory scan, removal or synchronization failures.
    pub async fn recover_temporary(&self) -> io::Result<()> {
        for path in self.fs.read_dir(&self.directory).await? {
            if path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b".binding-"))
            {
                self.fs.remove_file(&path).await?;
            }
        }
        self.fs.sync_directory(&self.directory).await
    }

    /// Returns the fixed private record path for native identity retention.
    ///
    /// This path grants no mutation authority. Native owners retain a nofollow
    /// descriptor before loading and compare the actual record before repair.
    pub fn binding_record_path(&self, claim: &PublicationClaim) -> PathBuf {
        // This digest is only an internal filename, never a content identity.
        let domain = blake3::hash(claim.domain().as_bytes());
        self.directory.join(format!(
            "{}-{}.toml",
            hexadecimal(domain.as_bytes()),
            hexadecimal(claim.descriptor().digest())
        ))
    }

    async fn load(
        &self,
        path: &Path,
        claim: &PublicationClaim,
    ) -> io::Result<Option<VerityBinding>> {
        let metadata = match self.fs.metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() || metadata.len() > MAX_RECORD {
            return Err(invalid("invalid publication binding record size or type"));
        }
        let bytes = self.fs.read_nofollow(path).await?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err(invalid("oversized publication binding"));
        }
        let record: Record =
            toml::from_str(std::str::from_utf8(&bytes).map_err(source)?).map_err(source)?;
        if record.version != 1
            || record.domain != claim.domain()
            || record.descriptor != claim.descriptor().encode()
            || !matches!(
                (record.verity_algorithm, record.verity_digest.len()),
                (1, 32) | (2, 64)
            )
        {
            return Err(invalid("publication binding context or digest mismatch"));
        }
        Ok(Some(VerityBinding {
            algorithm: record.verity_algorithm,
            digest: record.verity_digest,
        }))
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + Send + Sync> PublicationState for FsPublicationState<F> {
    async fn binding(&self, claim: &PublicationClaim) -> io::Result<Option<VerityBinding>> {
        self.load(&self.binding_record_path(claim), claim).await
    }

    async fn record(
        &mut self,
        claim: &PublicationClaim,
        binding: &VerityBinding,
    ) -> io::Result<()> {
        if !matches!((binding.algorithm, binding.digest.len()), (1, 32) | (2, 64)) {
            return Err(invalid("invalid publication kernel digest"));
        }
        let path = self.binding_record_path(claim);
        if let Some(existing) = self.load(&path, claim).await? {
            if existing != *binding {
                return Err(invalid("conflicting existing publication binding"));
            }
            self.fs.sync_file(&path).await?;
            return self.fs.sync_directory(&self.directory).await;
        }

        let record = Record {
            version: 1,
            domain: claim.domain().to_owned(),
            descriptor: claim.descriptor().encode(),
            verity_algorithm: binding.algorithm,
            verity_digest: binding.digest.clone(),
        };
        let bytes = toml::to_string(&record).map_err(source)?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err(invalid("oversized publication context"));
        }
        let random = self.fs.random_bytes(16).await?;
        let temporary = self
            .directory
            .join(format!(".binding-{}", hexadecimal(&random)));
        self.fs.write_new(&temporary, bytes.as_bytes()).await?;
        self.fs.sync_file(&temporary).await?;
        match self.fs.rename_no_replace(&temporary, &path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if self.load(&path, claim).await?.as_ref() != Some(binding) {
                    return Err(invalid("concurrent conflicting publication binding"));
                }
                self.fs.remove_file(&temporary).await?;
            }
            Err(error) => return Err(error),
        }
        self.fs.sync_file(&path).await?;
        self.fs.sync_directory(&self.directory).await
    }
}
