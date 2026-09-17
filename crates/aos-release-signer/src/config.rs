//! Deployment configuration for the file-backed signing adapter.
//!
//! The configuration is a JSON document kept outside the source repository
//! and the Nix store. It maps public key ids to private key files and states
//! which signer roles each key may serve. Every path must be absolute. The
//! adapter refuses a configuration or private key that other users could
//! modify or read.
//!
//! ```json
//! {
//!   "schema_version": "aos.release.file-signer-config/v1",
//!   "provider_revision": "andyl-testing-file-signer-v1",
//!   "registries": ["andyl/testing"],
//!   "tools": {
//!     "openssl": "/nix/store/...-openssl-3.5.0/bin/openssl",
//!     "sbsign": "/nix/store/...-sbsigntools-0.9.5/bin/sbsign"
//!   },
//!   "keys": [
//!     {
//!       "key_id": "andyl-testing-release-evidence-v1",
//!       "roles": ["release-evidence"],
//!       "verification_identity": "andyl-testing-release-evidence-v1",
//!       "material": {
//!         "kind": "ed25519-pkcs8-pem",
//!         "private_key": "/var/lib/aos-release/keys/release-evidence.pem"
//!       }
//!     },
//!     {
//!       "key_id": "testing-v1",
//!       "roles": ["registry"],
//!       "verification_identity": "testing-v1",
//!       "material": {
//!         "kind": "openssh-ed25519",
//!         "private_key": "/var/lib/aos-release/keys/testing-v1",
//!         "trust_line": "andyl-testing:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAI..."
//!       }
//!     },
//!     {
//!       "key_id": "andyl-testing-secure-boot-db-v1",
//!       "roles": ["secure-boot-db"],
//!       "verification_identity": "andyl-testing-secure-boot-db-v1",
//!       "material": {
//!         "kind": "rsa-x509",
//!         "private_key": "/var/lib/aos-release/keys/db.key",
//!         "certificate": "/var/lib/aos-release/keys/db.crt"
//!       }
//!     },
//!     {
//!       "key_id": "andyl-testing-pcr-policy-v1",
//!       "roles": ["pcr-policy"],
//!       "verification_identity": "andyl-testing-pcr-policy-v1",
//!       "material": {
//!         "kind": "rsa-public-pem",
//!         "private_key": "/var/lib/aos-release/keys/pcr.key",
//!         "public_key": "/var/lib/aos-release/keys/pcr.pem"
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! Verification material digests reported to the coordinator are computed
//! over the exact bytes of the `certificate`, `public_key`, or `trust_line`
//! named here, so those files must be byte-identical to the public copies the
//! coordinator and image assembly pin independently.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::require_identifier;
use aos_release::registry::registry_policy;
use aos_release::signing::SignerRole;
use serde::{Deserialize, Serialize};

/// Exact configuration schema identifier.
pub const CONFIG_SCHEMA_V1: &str = "aos.release.file-signer-config/v1";

/// Environment variable naming the configuration file when no flag is given.
pub const CONFIG_ENVIRONMENT_VARIABLE: &str = "AOS_RELEASE_SIGNER_CONFIG";

/// Complete adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerConfigV1 {
    /// Exact configuration schema identifier.
    pub schema_version: String,
    /// Provider policy revision every request must name.
    pub provider_revision: String,
    /// Canonical registries this adapter is willing to sign for.
    pub registries: Vec<String>,
    /// Absolute paths of the external tools used by transforming operations.
    #[serde(default)]
    pub tools: ToolPaths,
    /// Keys the adapter may use, one entry per public key id.
    pub keys: Vec<KeyEntry>,
}

/// Executables used for PE/COFF and kernel-module transformations.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPaths {
    /// OpenSSL command-line tool used for CMS module signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openssl: Option<PathBuf>,
    /// `sbsign` from sbsigntools used for Authenticode signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbsign: Option<PathBuf>,
}

/// One key the adapter may apply to a closed set of roles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// Stable public key id named by release plans and signing requests.
    pub key_id: String,
    /// Signer roles this key may serve.
    pub roles: Vec<SignerRole>,
    /// Public identity string the coordinator pins with `--verification-identity`.
    pub verification_identity: String,
    /// Private key location and public material used for verification digests.
    pub material: KeyMaterial,
}

/// Private-key encoding and the matching public material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeyMaterial {
    /// PKCS#8 PEM Ed25519 private key; the public key is derived from it.
    Ed25519Pkcs8Pem {
        /// Absolute path of the private key PEM.
        private_key: PathBuf,
    },
    /// OpenSSH Ed25519 private key used for SSHSIG operations.
    OpensshEd25519 {
        /// Absolute path of the unencrypted OpenSSH private key.
        private_key: PathBuf,
        /// Exact `alias:Ed25519:<base64>` trust line committed in the roster.
        trust_line: String,
    },
    /// RSA private key whose public identity is an X.509 certificate.
    RsaX509 {
        /// Absolute path of the RSA private key PEM (PKCS#8 or PKCS#1).
        private_key: PathBuf,
        /// Absolute path of the PEM certificate embedded by the image assembly.
        certificate: PathBuf,
    },
    /// RSA private key whose public identity is a bare SubjectPublicKeyInfo PEM.
    RsaPublicPem {
        /// Absolute path of the RSA private key PEM (PKCS#8 or PKCS#1).
        private_key: PathBuf,
        /// Absolute path of the public key PEM embedded by the image assembly.
        public_key: PathBuf,
    },
}

impl KeyMaterial {
    /// Returns the private key path for permission checks.
    #[must_use]
    pub fn private_key(&self) -> &Path {
        match self {
            Self::Ed25519Pkcs8Pem { private_key }
            | Self::OpensshEd25519 { private_key, .. }
            | Self::RsaX509 { private_key, .. }
            | Self::RsaPublicPem { private_key, .. } => private_key,
        }
    }

    /// Returns the public file whose exact bytes identify this key, if any.
    #[must_use]
    pub fn public_file(&self) -> Option<&Path> {
        match self {
            Self::RsaX509 { certificate, .. } => Some(certificate),
            Self::RsaPublicPem { public_key, .. } => Some(public_key),
            Self::Ed25519Pkcs8Pem { .. } | Self::OpensshEd25519 { .. } => None,
        }
    }
}

impl SignerConfigV1 {
    /// Loads and validates the configuration named by a flag or the environment.
    ///
    /// # Errors
    ///
    /// Returns an error when neither source names a file, the file is not an
    /// absolute single-link regular file owned by the caller with no group or
    /// world write permission, or its contents fail [`Self::validate`].
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let path =
            match explicit {
                Some(path) => path.to_path_buf(),
                None => PathBuf::from(std::env::var_os(CONFIG_ENVIRONMENT_VARIABLE).with_context(
                    || format!("set {CONFIG_ENVIRONMENT_VARIABLE} or pass --config"),
                )?),
            };
        require_private_file(&path, "signer configuration", false)?;
        let bytes = fs::read(&path)
            .with_context(|| format!("reading signer configuration {}", path.display()))?;
        let config: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing signer configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates identifiers, registries, paths, and key file permissions.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, malformed identifiers, an
    /// unauthorized registry, a duplicated key id, a key without roles, a
    /// relative path, or a private key readable or writable by other users.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_V1 {
            bail!("unsupported signer configuration schema");
        }
        require_identifier(&self.provider_revision, "provider revision")?;
        if self.registries.is_empty() {
            bail!("signer configuration must authorize at least one registry");
        }
        for registry in &self.registries {
            registry_policy(registry)?;
        }
        for tool in [&self.tools.openssl, &self.tools.sbsign]
            .into_iter()
            .flatten()
        {
            if !tool.is_absolute() {
                bail!("signer tool path must be absolute: {}", tool.display());
            }
        }

        if self.keys.is_empty() {
            bail!("signer configuration names no keys");
        }
        let mut seen = BTreeMap::new();
        for entry in &self.keys {
            require_identifier(&entry.key_id, "signer key id")?;
            require_identifier(&entry.verification_identity, "verification identity")?;
            if entry.roles.is_empty() {
                bail!("signer key {} serves no role", entry.key_id);
            }
            if seen.insert(entry.key_id.as_str(), ()).is_some() {
                bail!("signer configuration repeats key id {}", entry.key_id);
            }
            require_private_file(entry.material.private_key(), "private key", true)?;
            if let Some(public) = entry.material.public_file() {
                if !public.is_absolute() {
                    bail!(
                        "public material path must be absolute: {}",
                        public.display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Finds the entry for a key id.
    #[must_use]
    pub fn key(&self, key_id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|entry| entry.key_id == key_id)
    }

    /// Returns the configured executable for a transforming tool.
    ///
    /// # Errors
    ///
    /// Returns an error when the tool is not configured or is not an
    /// absolute regular file.
    pub fn tool(&self, name: &str) -> Result<&Path> {
        let path = match name {
            "openssl" => self.tools.openssl.as_deref(),
            "sbsign" => self.tools.sbsign.as_deref(),
            _ => None,
        }
        .with_context(|| format!("signer configuration does not name the {name} tool"))?;
        let metadata = path
            .metadata()
            .with_context(|| format!("inspecting {name} at {}", path.display()))?;
        if !metadata.is_file() {
            bail!("{name} tool is not a regular file: {}", path.display());
        }
        Ok(path)
    }
}

/// Requires an absolute, single-link regular file that other users cannot alter.
///
/// Private keys additionally reject any group or world read permission.
fn require_private_file(path: &Path, label: &str, secret: bool) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute: {}", path.display());
    }
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!(
            "{label} must be a single-link regular file: {}",
            path.display()
        );
    }
    let forbidden = if secret { 0o077 } else { 0o022 };
    if metadata.mode() & forbidden != 0 {
        bail!("{label} has permissive mode bits: {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(private_key: &Path) -> SignerConfigV1 {
        SignerConfigV1 {
            schema_version: CONFIG_SCHEMA_V1.into(),
            provider_revision: "test-provider-v1".into(),
            registries: vec!["andyl/testing".into()],
            tools: ToolPaths::default(),
            keys: vec![KeyEntry {
                key_id: "evidence-v1".into(),
                roles: vec![SignerRole::ReleaseEvidence],
                verification_identity: "evidence-v1".into(),
                material: KeyMaterial::Ed25519Pkcs8Pem {
                    private_key: private_key.to_path_buf(),
                },
            }],
        }
    }

    fn private_file(dir: &Path, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = dir.join("key.pem");
        fs::write(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn accepts_a_private_owner_only_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = private_file(dir.path(), 0o600);
        assert!(config(&key).validate().is_ok());
    }

    #[test]
    fn rejects_group_readable_keys_and_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let key = private_file(dir.path(), 0o640);
        assert!(config(&key).validate().is_err());

        fs::set_permissions(&key, {
            use std::os::unix::fs::PermissionsExt as _;
            fs::Permissions::from_mode(0o600)
        })
        .unwrap();
        let mut duplicated = config(&key);
        duplicated.keys.push(duplicated.keys[0].clone());
        assert!(duplicated.validate().is_err());
    }

    #[test]
    fn rejects_relative_paths_and_unknown_registries() {
        let dir = tempfile::tempdir().unwrap();
        let key = private_file(dir.path(), 0o600);
        let mut relative = config(&key);
        relative.keys[0].material = KeyMaterial::Ed25519Pkcs8Pem {
            private_key: PathBuf::from("relative.pem"),
        };
        assert!(relative.validate().is_err());

        let mut registry = config(&key);
        registry.registries = vec!["not a registry".into()];
        assert!(registry.validate().is_err());
    }

    #[test]
    fn material_kinds_round_trip_through_json() {
        let material = KeyMaterial::RsaX509 {
            private_key: "/keys/db.key".into(),
            certificate: "/keys/db.crt".into(),
        };
        let json = serde_json::to_string(&material).unwrap();
        assert!(json.contains("\"kind\":\"rsa-x509\""));
        let parsed: KeyMaterial = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, material);
    }
}
