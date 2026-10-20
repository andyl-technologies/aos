//! Validated retained HMAC keys for delivery URL reservations.

use std::collections::BTreeSet;

use anyhow::Context as _;
use aos_hub_db::db::Database;
use base64::Engine as _;
/// One externally managed URL-reservation HMAC key version.
#[derive(Clone)]
pub struct RouteReservationKey {
    /// Positive immutable key version persisted with reservations.
    pub version: i64,
    /// Secret HMAC key bytes.
    pub secret: Vec<u8>,
    /// Whether new reservations use this version.
    pub active: bool,
}

/// Supplies the active and retained URL-reservation keys to both Hub runtimes.
pub trait RouteReservationKeyring: aos_hub_db::backend::BackendBounds {
    /// Returns a complete point-in-time keyring snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when secret configuration cannot be loaded safely.
    fn snapshot(&self) -> anyhow::Result<Vec<RouteReservationKey>>;
}

/// Validated in-memory keyring loaded by a runtime from its secret provider.
pub struct ConfiguredRouteReservationKeyring {
    keys: Vec<RouteReservationKey>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RouteReservationKeyringManifest {
    active_version: i64,
    keys: Vec<RouteReservationKeyManifestEntry>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RouteReservationKeyManifestEntry {
    version: i64,
    key_base64: String,
}

impl ConfiguredRouteReservationKeyring {
    /// Parses and validates the shared native/Worker secret manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON/base64, duplicate or non-positive
    /// versions, an absent active version, or a key shorter than 32 bytes.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let manifest: RouteReservationKeyringManifest =
            serde_json::from_str(json).context("decoding route reservation keyring")?;
        anyhow::ensure!(
            manifest.active_version > 0,
            "activeVersion must be positive"
        );
        anyhow::ensure!(!manifest.keys.is_empty(), "at least one key is required");
        let mut versions = BTreeSet::new();
        let mut keys = Vec::with_capacity(manifest.keys.len());
        for entry in manifest.keys {
            anyhow::ensure!(entry.version > 0, "key versions must be positive");
            anyhow::ensure!(versions.insert(entry.version), "duplicate key version");
            let secret = base64::engine::general_purpose::STANDARD
                .decode(entry.key_base64)
                .context("decoding route reservation key")?;
            anyhow::ensure!(
                secret.len() >= 32,
                "route reservation keys must be at least 32 bytes"
            );
            keys.push(RouteReservationKey {
                version: entry.version,
                secret,
                active: entry.version == manifest.active_version,
            });
        }
        anyhow::ensure!(
            versions.contains(&manifest.active_version),
            "activeVersion does not identify a retained key"
        );
        keys.sort_by_key(|key| key.version);
        Ok(Self { keys })
    }

    /// Fails closed when storage references a key version absent from this keyring.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or for any missing retained key.
    pub async fn validate_referenced_versions(&self, db: &Database) -> anyhow::Result<()> {
        let referenced = db.route_reservation_key_versions().await?;
        let missing = self.missing_referenced_versions(&referenced);
        anyhow::ensure!(
            missing.is_empty(),
            "route reservation keyring is missing referenced versions: {missing:?}"
        );
        Ok(())
    }

    /// Returns persisted key versions that are absent from this keyring.
    pub(super) fn missing_referenced_versions(&self, referenced: &[i64]) -> Vec<i64> {
        let configured = self
            .keys
            .iter()
            .map(|key| key.version)
            .collect::<BTreeSet<_>>();
        referenced
            .iter()
            .copied()
            .filter(|version| !configured.contains(version))
            .collect()
    }
}

impl RouteReservationKeyring for ConfiguredRouteReservationKeyring {
    fn snapshot(&self) -> anyhow::Result<Vec<RouteReservationKey>> {
        Ok(self.keys.clone())
    }
}
