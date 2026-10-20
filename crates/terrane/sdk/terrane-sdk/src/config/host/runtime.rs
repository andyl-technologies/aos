//! Parses explicit publisher and quota locators without opening privileged services.
//!
//! These records select operator inputs. Runtime startup separately requires the
//! relevant records and authenticates retained paths, process identities and
//! quota observations; parsing never creates publication or quota authority.
//!
//! ```toml
//! [host_tier.publisher]
//! socket_path = "/run/terrane-publish/publisher.sock"
//! serve_uid = 1001
//! publish_uid = 1002
//! content_uid = 1001
//! content_gid = 1003
//! max_connections = 32
//! [host_tier.quota]
//! socket_path = "/run/terrane-host-helper/quota.sock"
//! configuration_epoch = "00000000000000000000000000000001"
//! [host_tier.domains.public.publisher]
//! retirement_grace_ms = 30000
//! chunk_profile = "cdc-1m"
//! chunk_seed = "0000000000000000000000000000000000000000000000000000000000000001"
//! ```

use serde::{Deserialize, Deserializer};
use terrane_format::chunking::ChunkProfile;

use crate::config::ConfigError;

/// Holds explicitly configured local publisher listener and identity inputs.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    /// Absolute Unix listener path, independent of request packets.
    pub socket_path: String,
    /// Expected kernel identity of the serving peer.
    pub serve_uid: u32,
    /// Required identity of the local publishing process.
    pub publish_uid: u32,
    /// Owner of encoded cache content directories and files.
    pub content_uid: u32,
    /// Shared content group selected by the operator.
    pub content_gid: u32,
    /// Positive concurrent connection bound, at most 1024.
    pub max_connections: usize,
}

/// Holds one domain's explicit publication profile and retirement interval.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainPublisher {
    /// Positive retirement grace in milliseconds, at most 300000.
    pub retirement_grace_ms: u64,
    /// Registered chunk profile name; currently only `cdc-1m` is supported.
    pub chunk_profile: String,
    /// Actual 32-byte chunk seed, represented by 64 lowercase hex digits in TOML.
    #[serde(deserialize_with = "deserialize_hex")]
    pub chunk_seed: [u8; 32],
}

/// Holds quota helper locators without accepting caller-supplied quota evidence.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    /// Absolute Unix socket path to the authenticated native host-root helper.
    pub socket_path: String,
    /// Exact helper configuration epoch, represented by 32 lowercase hex digits.
    #[serde(deserialize_with = "deserialize_hex")]
    pub configuration_epoch: [u8; 16],
}

impl Publisher {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let identities = [
            self.serve_uid,
            self.publish_uid,
            self.content_uid,
            self.content_gid,
        ];
        if !socket_path(&self.socket_path)
            || identities.contains(&u32::MAX)
            || self.serve_uid == self.publish_uid
            || self.content_uid == self.publish_uid
            || !(1..=1024).contains(&self.max_connections)
        {
            return Err(ConfigError::Invalid(
                "invalid publisher endpoint, identities or connection bound",
            ));
        }
        Ok(())
    }
}

impl DomainPublisher {
    /// Constructs the actual registered chunk profile from the configured seed.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile name is unsupported. No default profile
    /// or seed is substituted, including for manually constructed records.
    pub fn profile(&self) -> Result<ChunkProfile, ConfigError> {
        if self.chunk_profile != "cdc-1m" {
            return Err(ConfigError::Invalid("unsupported publisher chunk profile"));
        }
        Ok(ChunkProfile::cdc_1m(self.chunk_seed))
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=300_000).contains(&self.retirement_grace_ms) {
            return Err(ConfigError::Invalid(
                "publisher retirement grace must be 1..300000 milliseconds",
            ));
        }
        self.profile()?;
        Ok(())
    }
}

impl Quota {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !socket_path(&self.socket_path) {
            return Err(ConfigError::Invalid("invalid quota helper socket path"));
        }
        Ok(())
    }
}

fn socket_path(path: &str) -> bool {
    crate::config::absolute_path(path) && path != "/"
}

fn deserialize_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom(
            "expected fixed-length lowercase hexadecimal",
        ));
    }

    let mut bytes = [0; N];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (output, pair) in bytes.iter_mut().zip(pairs) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *output = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}
