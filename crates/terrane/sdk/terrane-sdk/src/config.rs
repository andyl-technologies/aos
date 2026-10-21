//! Loads role and store-expression syntax without opening backends.
//!
//! The loader accepts specification 26 exposure tables and the shared role
//! configuration. Parsing validates syntax and compiled surface availability;
//! repository authorization and schema preparation must succeed before startup.
//! A syntax check grants no authority and starts no service.
//!
//! ```toml
//! role = "serve"
//! store = "guard(policy=warehouse)(bucket(file:///var/lib/terrane))"
//! ```

use std::fmt;

use serde::Deserialize;

use crate::role::{Role, RoleError};

pub mod exposure;
pub mod expression;
pub mod host;
pub mod local_repository;
pub mod token;
pub mod workload;

/// Holds parsed foundation configuration without backend credentials or I/O.
#[derive(Debug)]
pub struct Config {
    role: Option<Role>,
    exposures: Vec<exposure::ConfiguredExposure>,
    locality: host::Locality,
    host_tier: Option<host::HostTier>,
    local_repository: Option<local_repository::TrustedLocalRepository>,
    tokens: token::Tokens,
    static_workload_issuers: std::collections::BTreeMap<String, workload::StaticWorkloadIssuer>,
    store: expression::StoreExpression,
}

impl Config {
    /// Parses the specification's TOML vocabulary and store-expression syntax.
    ///
    /// Unavailable surfaces and malformed exposure records reject the complete
    /// configuration. Parsing does not claim token or schema authorization.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed TOML, unknown keys or roles, invalid
    /// store syntax, invalid static workload issuer policy, unsupported host-tier
    /// wipe policies, or any exposure naming a missing surface or view policy.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input).map_err(ConfigError::Toml)?;
        let store = expression::StoreExpression::parse(&raw.store).map_err(ConfigError::Store)?;

        let exposures = exposure::parse(raw.expose)?;
        if let Some(host) = &raw.host_tier {
            host.validate()?;
        }
        raw.tokens.validate()?;
        workload::validate(&raw.static_workload_issuers)?;
        if let Some(local) = &raw.local_repository {
            local.validate()?;
        }

        Ok(Self {
            role: raw.role,
            exposures,
            locality: raw.locality,
            host_tier: raw.host_tier,
            local_repository: raw.local_repository,
            tokens: raw.tokens,
            static_workload_issuers: raw.static_workload_issuers,
            store,
        })
    }

    /// Returns the sole process role selected by this invocation.
    pub const fn role(&self) -> Option<Role> {
        self.role
    }

    /// Validates an optional command-line role against the configured role.
    ///
    /// Returning the configured role keeps one invocation confined to its
    /// selected responsibility; command-line arguments cannot broaden it.
    ///
    /// # Errors
    ///
    /// Returns [`RoleError::Mismatch`] when the requested role differs from
    /// the configured role, or [`RoleError::Missing`] when neither source selects one.
    pub fn select_role(&self, requested: Option<Role>) -> Result<Role, RoleError> {
        match (self.role, requested) {
            (Some(configured), Some(requested)) if configured != requested => {
                Err(RoleError::Mismatch {
                    configured,
                    requested,
                })
            }
            (Some(role), _) | (None, Some(role)) => Ok(role),
            (None, None) => Err(RoleError::Missing),
        }
    }

    /// Returns exposures in configuration order, without opening their endpoints.
    pub fn exposures(&self) -> &[exposure::ConfiguredExposure] {
        &self.exposures
    }

    /// Returns the configured topology labels.
    pub fn locality(&self) -> &host::Locality {
        &self.locality
    }

    /// Returns optional host-tier policy without claiming runtime availability.
    pub fn host_tier(&self) -> Option<&host::HostTier> {
        self.host_tier.as_ref()
    }

    /// Returns explicit trust inputs for strict local reopening, when configured.
    pub fn local_repository(&self) -> Option<&local_repository::TrustedLocalRepository> {
        self.local_repository.as_ref()
    }

    /// Returns configured credential locators without reading their secrets.
    pub fn tokens(&self) -> &token::Tokens {
        &self.tokens
    }

    /// Returns trusted static issuer configuration without reading signing keys.
    pub fn static_workload_issuers(
        &self,
    ) -> &std::collections::BTreeMap<String, workload::StaticWorkloadIssuer> {
        &self.static_workload_issuers
    }

    /// Returns the immutable, parsed store-expression tree (ARCH-6).
    pub fn store(&self) -> &expression::StoreExpression {
        &self.store
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    role: Option<Role>,
    store: String,
    #[serde(default)]
    expose: Vec<exposure::RawExposure>,
    #[serde(default)]
    locality: host::Locality,
    host_tier: Option<host::HostTier>,
    local_repository: Option<local_repository::TrustedLocalRepository>,
    #[serde(default)]
    tokens: token::Tokens,
    #[serde(default)]
    static_workload_issuers: std::collections::BTreeMap<String, workload::StaticWorkloadIssuer>,
}

pub(super) fn absolute_path(path: &str) -> bool {
    std::path::Path::new(path).is_absolute()
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "." | ".."))
        && !path.contains("//")
        && (path == "/" || !path.ends_with('/'))
}

/// Describes failures to load the entire foundation configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Rejects an invalid whole-configuration invariant.
    Invalid(&'static str),
    /// Preserves malformed view selector diagnostics.
    View(crate::surface::ViewError),
    /// Preserves TOML diagnostics, including unknown keys and role names.
    Toml(toml::de::Error),
    /// Preserves store-expression syntax diagnostics.
    Store(expression::ExpressionError),
    /// Names a surface that this build cannot serve (ARCH-10, SURF-9).
    UnavailableSurface(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid configuration: {message}"),
            Self::View(error) => write!(formatter, "invalid view: {error}"),
            Self::Toml(error) => write!(formatter, "invalid configuration: {error}"),
            Self::Store(error) => write!(formatter, "invalid store expression: {error}"),
            Self::UnavailableSurface(surface) => {
                write!(
                    formatter,
                    "surface {surface:?} is unavailable in this build"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::View(error) => Some(error),
            Self::UnavailableSurface(_) | Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn each_role_loads_through_the_same_vocabulary() {
        for role in Role::ALL {
            let text = format!("role = '{role}'\nstore = 'bucket(file:///tmp/store)'\n");
            assert_eq!(
                Config::parse(&text).expect("valid syntax").role(),
                Some(role)
            );
        }
    }

    #[test]
    fn rejects_unknown_keys_and_unavailable_surfaces() {
        assert!(Config::parse("role = 'serve'\nstore = 'disk(/tmp)'\nsecret = 'x'").is_err());

        let input = "role = 'realize'\nstore = 'disk(/tmp)'\n[[expose]]\nid = 'root'\nview = 'refs/heads/main'\nsurface = 'fuse'\nat = '/tmp/view'\ntoken = 'file:/tmp/token'";
        assert!(
            matches!(Config::parse(input), Err(ConfigError::UnavailableSurface(name)) if name == "fuse")
        );
    }

    #[test]
    fn sealed_host_tiers_reject_zero_wipe_for_every_role() {
        for role in Role::ALL {
            for domain in ["public", "private:owner"] {
                let input = format!(
                    "role = '{role}'\n\
                     store = 'disk(/var/lib/terrane)'\n\
                     [host_tier]\n\
                     path = '/var/lib/terrane'\n\
                     size_bytes = 1048576\n\
                     reassembly = 'never'\n\
                     [host_tier.domains.'{domain}']\n\
                     path = '/var/lib/terrane/domain'\n\
                     wipe = 'zero'\n"
                );

                assert!(
                    matches!(
                        Config::parse(&input),
                        Err(ConfigError::Invalid(
                            "sealed host tiers cannot honor wipe=zero"
                        ))
                    ),
                    "role {role} must refuse zero-wipe for {domain}"
                );

                let supported = input.replace("wipe = 'zero'", "wipe = 'none'");
                assert!(
                    Config::parse(&supported).is_ok(),
                    "role {role} must accept explicit no-wipe for {domain}"
                );
            }
        }
    }
}
