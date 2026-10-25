//! Composes a GC-only native repository from configured public verification files.

use super::LocalOpenError;
use crate::{
    bucket::{BucketBinding, FileBucket},
    config::Config,
    repository::{
        LocalMaintenanceIdentity, LocalRepositoryLocation, MetadataValidator, Repository,
    },
    role::Role,
    store::{Clock, LocalFs},
};

impl Config {
    /// Reopens an existing local repository for the selected GC role.
    ///
    /// Only an exact native file-bucket leaf is supported. Explicit trusted
    /// policy and all public issuer files are checked before repository access.
    /// The host token, exposure tokens and private authority seeds are never
    /// opened. This constructs neither a collector lease nor a GC service;
    /// original authenticated collection and role confinement remain separate.
    /// The keyring must match the protected installed Guard configuration;
    /// reopening cannot install a key rotation or alter retirement policy.
    ///
    /// # Errors
    /// Rejects non-GC or conflicting roles, unsupported store expressions,
    /// missing or invalid trusted configuration, unsafe public-key files and
    /// every existing protected maintenance-reopen failure.
    pub async fn open_local_maintenance<F, C>(
        &self,
        selected_role: Role,
        fs: F,
        clock: C,
    ) -> Result<Repository<FileBucket<F, C, MetadataValidator>, C, F>, LocalOpenError>
    where
        F: LocalFs + BucketBinding + Clone + Sync + 'static,
        C: Clock + BucketBinding + Clone + Sync + 'static,
        FileBucket<F, C, MetadataValidator>: Sync,
    {
        let role = self
            .select_role(Some(selected_role))
            .map_err(LocalOpenError::Role)?;
        if role != Role::Gc {
            return Err(LocalOpenError::WrongRole(role));
        }
        let expression = self.store();
        if expression.name() != "bucket" || !expression.children().is_empty() {
            return Err(LocalOpenError::UnsupportedStore);
        }
        let [url] = expression.arguments() else {
            return Err(LocalOpenError::UnsupportedStore);
        };
        if !url.starts_with("file:///") {
            return Err(LocalOpenError::UnsupportedStore);
        }
        let trusted = self
            .local_repository()
            .ok_or(LocalOpenError::MissingConfiguration)?;
        trusted.validate().map_err(LocalOpenError::Configuration)?;
        let location =
            LocalRepositoryLocation::from_file_url(url, trusted.authority_directory.clone().into())
                .map_err(LocalOpenError::Repository)?;
        let policy = trusted.policy(self.locality())?;
        let identity = LocalMaintenanceIdentity {
            issuer_keys: self
                .tokens()
                .load_issuer_keys(trusted.owner_uid)
                .map_err(LocalOpenError::IssuerKeys)?,
            owner_uid: trusted.owner_uid,
        };
        let repository =
            Repository::open_local_maintenance(&location, &identity, policy, fs, clock)
                .await
                .map_err(LocalOpenError::Repository)?;
        repository
            .validate_store_leaf(expression)
            .map_err(LocalOpenError::Capabilities)?;
        Ok(repository)
    }
}
