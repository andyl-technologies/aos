//! Composes the existing trusted local reopen path for the explicit serve role.

use std::fmt;
use terrane_format::{auth::Verb, refs::Locality};

use super::{TrustedAclVerb, TrustedLocalRepository};
use crate::config::{Config, ConfigError};
use crate::{
    bucket::{BucketBinding, FileBucket},
    repository::{
        LocalAuthorityIdentity, LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator,
        Repository,
    },
    role::{Role, RoleError},
    store::{Clock, LocalFs},
};

/// Reports unavailable local composition separately from existing-state failures.
#[derive(Debug)]
pub enum LocalOpenError {
    /// Requires an explicit trusted local configuration; no identity is inferred.
    MissingConfiguration,
    /// Refuses a store shape without opening any configured authority files.
    UnsupportedStore,
    /// Refuses roles that do not own the repository or private authority.
    WrongRole(Role),
    /// Preserves explicit role selection mismatch or absence.
    Role(RoleError),
    /// Rejects invalid trusted policy without manufacturing replacements.
    Configuration(ConfigError),
    /// Preserves the existing T1 protected reopen and authorization failures.
    Repository(crate::repository::Error),
}

impl Config {
    /// Reopens a strict local file-bucket repository owned by the serve role.
    ///
    /// Only an exact leaf `bucket(file:///...)` is supported. This factory does
    /// not implement routed stores or host-cache composition. It returns no
    /// instance signing authority; exposure credentials must be independently
    /// resolved and passed to `PreparedExposures::prepare`.
    ///
    /// # Errors
    /// Rejects non-serve invocations, missing explicit trust, unsupported store
    /// shapes before authority I/O, and every existing protected reopen failure.
    pub async fn open_local_repository<F, C>(
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
        let identity = LocalAuthorityIdentity {
            issuer: trusted.issuer.clone(),
            key_id: trusted.key_id.clone(),
            owner_uid: trusted.owner_uid,
        };
        let (repository, authority) = Repository::open_local(
            &location,
            &identity,
            trusted.policy(self.locality())?,
            &trusted.current_reference,
            fs,
            clock,
        )
        .await
        .map_err(LocalOpenError::Repository)?;
        drop(authority);
        Ok(repository)
    }
}

impl TrustedLocalRepository {
    fn policy(
        &self,
        locality: &crate::config::host::Locality,
    ) -> Result<LocalRepositoryPolicy, LocalOpenError> {
        let label = |value: &str| (!value.is_empty()).then(|| value.to_owned());
        let acl = self
            .acl
            .iter()
            .map(|entry| {
                let mask = entry.verbs.iter().fold(0, |mask, verb| {
                    mask | match verb {
                        TrustedAclVerb::Read => Verb::Read as u8,
                        TrustedAclVerb::Fork => Verb::Fork as u8,
                        TrustedAclVerb::Commit => Verb::Commit as u8,
                        TrustedAclVerb::Tag => Verb::Tag as u8,
                        TrustedAclVerb::Admin => Verb::Admin as u8,
                    }
                });
                (entry.principal.clone(), mask)
            })
            .collect();
        Ok(LocalRepositoryPolicy {
            store_name: self.store_name.clone(),
            domain: self.domain.clone(),
            default_private_domain: self.default_private_domain.clone(),
            acl,
            locality: Locality {
                region: label(&locality.region),
                zone: label(&locality.zone),
                host: label(&locality.host),
            },
            timing: self
                .timing
                .validated()
                .map_err(LocalOpenError::Configuration)?,
            policy_authority: self.policy_authority.clone(),
            // These properties are initialization-only. This factory never
            // initializes or replaces the existing signed root or genesis.
            bootstrap_properties: Vec::new(),
        })
    }
}

impl fmt::Display for LocalOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfiguration => {
                formatter.write_str("trusted local repository configuration is required")
            }
            Self::UnsupportedStore => {
                formatter.write_str("only an exact local file-bucket leaf is supported")
            }
            Self::WrongRole(role) => write!(
                formatter,
                "role {role} cannot open private local repository authority"
            ),
            Self::Role(error) => fmt::Display::fmt(error, formatter),
            Self::Configuration(error) => fmt::Display::fmt(error, formatter),
            Self::Repository(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for LocalOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Role(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::MissingConfiguration | Self::UnsupportedStore | Self::WrongRole(_) => None,
        }
    }
}
