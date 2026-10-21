//! Opens configured signing authority solely for an explicitly selected serve role.

use std::{fmt, path::Path};

use crate::{
    config::{Config, ConfigError},
    role::{Role, RoleError},
    workload::{MintError, StaticKeyIssuer},
};

/// Reports role, configuration and actual private-key opening failures.
#[derive(Debug)]
pub enum IssuerOpenError {
    /// Rejects absent or conflicting process-role selection.
    Role(RoleError),
    /// Refuses private issuer authority in another process role.
    WrongRole(Role),
    /// No trusted issuer is configured under the requested local name.
    MissingIssuer,
    /// Rejects invalid trusted configuration before private-file I/O.
    Configuration(ConfigError),
    /// Preserves actual private-file, public-key match and lifetime failures.
    Issuer(MintError),
}

impl Config {
    /// Opens one configured native workload issuer for the selected serve role.
    ///
    /// Role checks precede private-file access. The raw seed must satisfy the
    /// issuer's descriptor checks and match its independently configured public
    /// key. Opening does not authenticate any remote caller or job claim.
    ///
    /// # Errors
    /// Rejects missing or conflicting roles, non-serve invocations, an unknown
    /// issuer, invalid policy and every actual private-key opening failure.
    pub fn open_static_workload_issuer(
        &self,
        name: &str,
        selected_role: Role,
    ) -> Result<StaticKeyIssuer, IssuerOpenError> {
        let role = self
            .select_role(Some(selected_role))
            .map_err(IssuerOpenError::Role)?;
        if role != Role::Serve {
            return Err(IssuerOpenError::WrongRole(role));
        }
        let configured = self
            .static_workload_issuers()
            .get(name)
            .ok_or(IssuerOpenError::MissingIssuer)?;
        configured
            .validate()
            .map_err(IssuerOpenError::Configuration)?;
        let policy = configured
            .policy()
            .map_err(IssuerOpenError::Configuration)?;
        StaticKeyIssuer::open(
            Path::new(&configured.signing_key_file),
            configured.owner_uid,
            policy,
        )
        .map_err(IssuerOpenError::Issuer)
    }
}

impl fmt::Display for IssuerOpenError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role(error) => error.fmt(output),
            Self::WrongRole(role) => {
                write!(output, "role {role} cannot open workload signing authority")
            }
            Self::MissingIssuer => output.write_str("static workload issuer is not configured"),
            Self::Configuration(error) => error.fmt(output),
            Self::Issuer(error) => error.fmt(output),
        }
    }
}

impl std::error::Error for IssuerOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Role(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::Issuer(error) => Some(error),
            Self::WrongRole(_) | Self::MissingIssuer => None,
        }
    }
}
