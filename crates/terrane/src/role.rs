//! Selects isolated process roles without starting unavailable services.
//!
//! Names follow ARCH-10 and CRATE-15. Dispatch deliberately fails until a role's
//! runtime is implemented, so parsing a role cannot acknowledge work it did not do.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

/// Selects one process invocation from the specification's role vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Serves the repository and protocol exposures.
    Serve,
    /// Coordinates kernel realizer exposures.
    Realize,
    /// Handles one FUSE connection without network access.
    FuseWorker,
    /// Publishes sealed backing objects.
    Publish,
    /// Collects unreachable content under a singleton lease.
    Gc,
    /// Executes a tree job.
    Job,
}

impl Role {
    /// Lists every role selectable by one binary (ARCH-10, CRATE-15).
    pub const ALL: [Self; 6] = [
        Self::Serve,
        Self::Realize,
        Self::FuseWorker,
        Self::Publish,
        Self::Gc,
        Self::Job,
    ];

    /// Returns the registered configuration name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Serve => "serve",
            Self::Realize => "realize",
            Self::FuseWorker => "fuse-worker",
            Self::Publish => "publish",
            Self::Gc => "gc",
            Self::Job => "job",
        }
    }

    /// Refuses dispatch until this role's runtime is implemented.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::Unavailable`] for every role in the foundation build.
    pub fn run(self) -> Result<(), RoleError> {
        Err(RoleError::Unavailable(self))
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = RoleError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == name)
            .ok_or_else(|| RoleError::Unknown(name.to_owned()))
    }
}

/// Describes role selection or dispatch failures.
#[derive(Debug, Eq, PartialEq)]
pub enum RoleError {
    /// Rejects a name outside the closed role vocabulary.
    Unknown(String),
    /// Reports a role whose runtime has not been implemented.
    Unavailable(Role),
    /// Rejects an invocation selecting a role different from its configuration.
    Mismatch {
        /// Names the role required by configuration.
        configured: Role,
        /// Names the role requested by the command line.
        requested: Role,
    },
}

impl fmt::Display for RoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(formatter, "unknown role {name:?}"),
            Self::Mismatch {
                configured,
                requested,
            } => {
                write!(
                    formatter,
                    "requested role {requested} differs from configured role {configured}"
                )
            }
            Self::Unavailable(role) => {
                write!(
                    formatter,
                    "role {role} runtime is unavailable in this foundation build"
                )
            }
        }
    }
}

impl std::error::Error for RoleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_registered_roles_parse_and_refuse_unimplemented_runtime() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
            assert_eq!(role.run(), Err(RoleError::Unavailable(role)));
        }
    }

    #[test]
    fn unknown_roles_are_rejected() {
        assert!(matches!(
            "mount-broker".parse::<Role>(),
            Err(RoleError::Unknown(_))
        ));
    }
}
