//! Private-key loading and the public identities reported for each key.
//!
//! Every loaded key carries the exact public bytes whose SHA-256 the
//! coordinator compares against independently pinned material: the raw
//! 32-byte Ed25519 public key, the committed OpenSSH trust line, an X.509
//! certificate PEM, or a bare SubjectPublicKeyInfo PEM.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use ssh_key::PrivateKey;

use crate::config::KeyMaterial;

/// A private key resolved from configuration together with its public identity.
pub enum LoadedKey {
    /// Ed25519 key used for detached request-digest and raw payload signatures.
    Ed25519(SigningKey),
    /// OpenSSH Ed25519 key used for SSHSIG signatures.
    Openssh {
        /// Parsed unencrypted private key.
        key: PrivateKey,
        /// Exact roster trust line identifying the key.
        trust_line: String,
    },
    /// RSA key whose public identity is a file the image assembly embeds.
    Rsa {
        /// Parsed private key.
        key: RsaPrivateKey,
        /// Absolute path of the PEM private key, for external tools.
        private_key_path: PathBuf,
        /// Absolute path of the certificate or public key PEM.
        public_path: PathBuf,
        /// Whether `public_path` is an X.509 certificate rather than a bare key.
        certificate: bool,
    },
}

impl LoadedKey {
    /// Loads and checks the key described by one configuration entry.
    ///
    /// # Errors
    ///
    /// Returns an error when a file cannot be read or parsed, an OpenSSH key
    /// is encrypted or not Ed25519, or the configured trust line does not
    /// match the key.
    pub fn load(material: &KeyMaterial) -> Result<Self> {
        match material {
            KeyMaterial::Ed25519Pkcs8Pem { private_key } => {
                let der = read_pem_body(private_key, "PRIVATE KEY")?;
                let key = SigningKey::from_pkcs8_der(&der)
                    .with_context(|| format!("parsing {}", private_key.display()))?;
                Ok(Self::Ed25519(key))
            }
            KeyMaterial::OpensshEd25519 {
                private_key,
                trust_line,
            } => {
                let pem = read_text(private_key, "OpenSSH private key")?;
                let key = PrivateKey::from_openssh(pem.trim())
                    .with_context(|| format!("parsing {}", private_key.display()))?;
                if key.is_encrypted() {
                    bail!("OpenSSH key {} is encrypted", private_key.display());
                }
                if key.algorithm() != ssh_key::Algorithm::Ed25519 {
                    bail!("OpenSSH key {} is not Ed25519", private_key.display());
                }
                require_trust_line_match(&key, trust_line)?;
                Ok(Self::Openssh {
                    key,
                    trust_line: trust_line.clone(),
                })
            }
            KeyMaterial::RsaX509 {
                private_key,
                certificate,
            } => Ok(Self::Rsa {
                key: read_rsa(private_key)?,
                private_key_path: private_key.clone(),
                public_path: certificate.clone(),
                certificate: true,
            }),
            KeyMaterial::RsaPublicPem {
                private_key,
                public_key,
            } => Ok(Self::Rsa {
                key: read_rsa(private_key)?,
                private_key_path: private_key.clone(),
                public_path: public_key.clone(),
                certificate: false,
            }),
        }
    }

    /// Returns the digest of the public material the coordinator pins.
    ///
    /// # Errors
    ///
    /// Returns an error when the public file cannot be read.
    pub fn verification_material_digest(&self) -> Result<Sha256Digest> {
        Ok(match self {
            Self::Ed25519(key) => Sha256Digest::of_bytes(key.verifying_key().to_bytes()),
            Self::Openssh { trust_line, .. } => Sha256Digest::of_bytes(trust_line.as_bytes()),
            Self::Rsa { public_path, .. } => {
                Sha256Digest::of_bytes(fs::read(public_path).with_context(|| {
                    format!("reading public material {}", public_path.display())
                })?)
            }
        })
    }

    /// Describes the public half for operator inspection.
    #[must_use]
    pub fn public_summary(&self) -> String {
        match self {
            Self::Ed25519(key) => format!(
                "ed25519 {}",
                base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
            ),
            Self::Openssh { trust_line, .. } => format!("openssh {trust_line}"),
            Self::Rsa {
                public_path,
                certificate,
                ..
            } => format!(
                "rsa {} {}",
                if *certificate {
                    "certificate"
                } else {
                    "public-key"
                },
                public_path.display()
            ),
        }
    }
}

fn read_text(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading {label} {}", path.display()))
}

/// Decodes the base64 body of a single PEM block with the given label.
///
/// PEM parsing is done here rather than through the key crates so the
/// adapter does not depend on optional `pem` features being unified into
/// the workspace build.
fn read_pem_body(path: &Path, label: &str) -> Result<Vec<u8>> {
    let text = read_text(path, &format!("{label} PEM"))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .with_context(|| format!("{} lacks a {label} PEM block", path.display()))?
        + begin.len();
    let stop = text[start..]
        .find(&end)
        .with_context(|| format!("{} has an unterminated {label} PEM block", path.display()))?;
    let body: String = text[start..start + stop].lines().map(str::trim).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .with_context(|| format!("decoding {label} PEM in {}", path.display()))
}

fn read_rsa(path: &Path) -> Result<RsaPrivateKey> {
    let pem = read_text(path, "RSA private key")?;
    let key = if pem.contains("BEGIN RSA PRIVATE KEY") {
        let der = read_pem_body(path, "RSA PRIVATE KEY")?;
        RsaPrivateKey::from_pkcs1_der(&der).map_err(anyhow::Error::from)
    } else {
        let der = read_pem_body(path, "PRIVATE KEY")?;
        RsaPrivateKey::from_pkcs8_der(&der).map_err(anyhow::Error::from)
    };
    key.with_context(|| format!("parsing RSA private key {}", path.display()))
}

/// Requires the configured trust line to carry exactly this key's public blob.
fn require_trust_line_match(key: &PrivateKey, trust_line: &str) -> Result<()> {
    let openssh = key
        .public_key()
        .to_openssh()
        .context("encoding OpenSSH public key")?;
    let blob = openssh
        .split_whitespace()
        .nth(1)
        .context("OpenSSH public key has no key material")?;
    let mut parts = trust_line.splitn(3, ':');
    let (alias, algorithm, material) = (parts.next(), parts.next(), parts.next());
    match (alias, algorithm, material) {
        (Some(alias), Some("Ed25519"), Some(material)) if !alias.is_empty() && material == blob => {
            Ok(())
        }
        _ => bail!("trust line does not name this OpenSSH key as <alias>:Ed25519:<blob>"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    /// RFC 8410 PKCS#8 prefix for a 32-byte Ed25519 seed.
    const PKCS8_ED25519_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    /// Writes a PKCS#8 PEM for a fixed seed and returns its path.
    pub(crate) fn write_ed25519_pem(dir: &Path, seed: [u8; 32]) -> PathBuf {
        let mut der = PKCS8_ED25519_PREFIX.to_vec();
        der.extend(seed);
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let path = dir.join(format!("ed25519-{}.pem", seed[0]));
        fs::write(
            &path,
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
        )
        .unwrap();
        path
    }

    /// Writes an OpenSSH private key for a fixed seed and returns its path and blob.
    pub(crate) fn write_openssh_key(dir: &Path, seed: [u8; 32]) -> (PathBuf, String) {
        let keypair = Ed25519Keypair::from_seed(&seed);
        let key = PrivateKey::new(KeypairData::Ed25519(keypair), "test").unwrap();
        let path = dir.join(format!("openssh-{}", seed[0]));
        fs::write(
            &path,
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let blob = key
            .public_key()
            .to_openssh()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        (path, blob)
    }

    #[test]
    fn loads_a_pkcs8_ed25519_key() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [3_u8; 32];
        let path = write_ed25519_pem(dir.path(), seed);
        let expected = SigningKey::from_bytes(&seed);

        let loaded = LoadedKey::load(&KeyMaterial::Ed25519Pkcs8Pem { private_key: path }).unwrap();
        assert_eq!(
            loaded.verification_material_digest().unwrap(),
            Sha256Digest::of_bytes(expected.verifying_key().to_bytes())
        );
        let LoadedKey::Ed25519(loaded) = loaded else {
            panic!("expected Ed25519 key");
        };
        assert_eq!(loaded.verifying_key(), expected.verifying_key());
    }

    #[test]
    fn openssh_keys_require_a_matching_trust_line() {
        let dir = tempfile::tempdir().unwrap();
        let (path, blob) = write_openssh_key(dir.path(), [5_u8; 32]);

        let matching = KeyMaterial::OpensshEd25519 {
            private_key: path.clone(),
            trust_line: format!("alias:Ed25519:{blob}"),
        };
        let loaded = LoadedKey::load(&matching).unwrap();
        assert_eq!(
            loaded.verification_material_digest().unwrap(),
            Sha256Digest::of_bytes(format!("alias:Ed25519:{blob}").as_bytes())
        );

        let mismatched = KeyMaterial::OpensshEd25519 {
            private_key: path,
            trust_line: "alias:Ed25519:AAAA".into(),
        };
        assert!(LoadedKey::load(&mismatched).is_err());
    }
}
