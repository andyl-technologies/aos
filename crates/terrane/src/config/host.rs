//! Parses host-tier placement and policy without opening host storage.
//!
//! ```toml
//! [host_tier]
//! path = "/var/lib/terrane"
//! size_bytes = 1073741824
//! reassembly = "never"
//! [host_tier.domains.public]
//! path = "/var/lib/terrane/public"
//! wipe = "none"
//! ```

use super::ConfigError;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Labels the configured placement of this instance.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Locality {
    /// Region label, empty when unspecified.
    #[serde(default)]
    pub region: String,
    /// Zone label, empty when unspecified.
    #[serde(default)]
    pub zone: String,
    /// Host label, empty when unspecified.
    #[serde(default)]
    pub host: String,
}

/// Holds host-tier syntax without claiming that runtime policy is available.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTier {
    /// Absolute host storage directory.
    pub path: String,
    /// Positive exact storage quota in bytes.
    pub size_bytes: u64,
    /// Supported trunk reassembly policy.
    pub reassembly: Reassembly,
    /// Explicit canonical disclosure-domain directories.
    #[serde(default)]
    pub domains: BTreeMap<String, DomainDirectory>,
}

/// Selects trunk host-tier reassembly behavior.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Reassembly {
    /// Retains chunks without assembling complete objects.
    Never,
    /// Assembles complete objects whenever admitted.
    Always,
}

/// Holds one domain's path and requested deletion policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainDirectory {
    /// Absolute directory dedicated to this domain.
    pub path: String,
    /// Requested wipe policy; parsing grants no runtime qualification.
    pub wipe: Wipe,
}

/// Selects a registered trunk wipe policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Wipe {
    /// Deletes without overwriting.
    None,
    /// Requests overwrite before deletion; availability is checked at runtime.
    Zero,
}

impl HostTier {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !super::absolute_path(&self.path) || self.size_bytes == 0 {
            return Err(ConfigError::Invalid(
                "host tier requires an absolute path and positive size_bytes",
            ));
        }
        let mut paths = std::collections::BTreeSet::new();
        for (domain, directory) in &self.domains {
            let canonical = terrane_core::properties::Domain::parse(domain).is_ok();
            if !canonical
                || !super::absolute_path(&directory.path)
                || !paths.insert(&directory.path)
            {
                return Err(ConfigError::Invalid(
                    "invalid or duplicate domain directory",
                ));
            }
        }
        Ok(())
    }
}
