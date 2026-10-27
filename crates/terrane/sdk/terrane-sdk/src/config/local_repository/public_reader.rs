//! Composes read-only Serve from explicit public keys and a supplied startup Read.

use super::LocalOpenError;
use crate::{
    bucket::{BucketBinding, FileBucket},
    config::Config,
    repository::{LocalReaderIdentity, LocalRepositoryLocation, MetadataValidator, Repository},
    role::Role,
    store::{Clock, LocalFs},
};

impl Config {
    /// Reopens configured native Serve without loading private credentials.
    ///
    /// Only an exact file-bucket leaf is supported. Public issuer locators come
    /// from `tokens.issuer_public_keys`; the startup capability is supplied
    /// explicitly by the trusted caller. Neither `tokens.host_token`, exposure
    /// token locators nor the instance's signing seeds and token are opened.
    /// The capability must authorize the configured current reference through
    /// its existing protected native history. It grants no later request right.
    ///
    /// This constructs no listener or exposure and grants no authoring or
    /// collection authority. Process filesystem confinement remains separate.
    ///
    /// # Errors
    /// Rejects non-Serve or conflicting roles, unsupported store expressions,
    /// missing trusted configuration, invalid public-key files, incompatible
    /// native state and every failed startup Read or Original check.
    pub async fn open_local_reader<F, C>(
        &self,
        selected_role: Role,
        token: &[u8],
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
        if role != Role::Serve {
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
        let identity = LocalReaderIdentity {
            issuer_keys: self
                .tokens()
                .load_issuer_keys(trusted.owner_uid)
                .map_err(LocalOpenError::IssuerKeys)?,
            owner_uid: trusted.owner_uid,
        };
        let repository = Repository::open_local_reader(
            &location,
            &identity,
            trusted.policy(self.locality())?,
            &trusted.current_reference,
            token,
            fs,
            clock,
        )
        .await
        .map_err(LocalOpenError::Repository)?;
        repository
            .validate_store_leaf(expression)
            .map_err(LocalOpenError::Capabilities)?;
        Ok(repository)
    }
}
