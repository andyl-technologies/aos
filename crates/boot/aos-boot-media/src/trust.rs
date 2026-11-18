//! Applies an immutable Secure Boot db certificate snapshot to boot artifacts.
//!
//! A boot environment carries the currently signing db certificate together
//! with every configured rotation-overlap certificate as one PEM bundle.
//! Verification succeeds only when one complete certificate authorizes the
//! artifact; a malformed bundle is rejected rather than partially consumed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{MediaError, Tools};

const MAX_TRUST_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_ACTIVE_CERTIFICATES: usize = 32;
const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// Identifies a db certificate bundle and a private scratch directory.
#[derive(Clone, Debug)]
pub struct DbTrust {
    /// PEM bundle of every authorized db certificate.
    pub bundle: PathBuf,
    /// Root-owned scratch directory for staged certificates and public keys.
    pub work_dir: PathBuf,
}

impl DbTrust {
    /// Verifies one UKI's Authenticode signature against the db snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Rejected`] when no certificate authorizes the UKI,
    /// and other variants for a malformed bundle or a failed helper.
    pub fn verify_uki(&self, tools: &Tools, uki: &Path) -> Result<(), MediaError> {
        for (index, certificate) in self.active_certificates()?.iter().enumerate() {
            let certificate_path = self.write_certificate(index, certificate)?;
            validate_certificate(tools, &certificate_path)?;
            let output = Command::new(&tools.sbverify)
                .arg("--cert")
                .arg(&certificate_path)
                .arg(uki)
                .output()
                .map_err(|error| MediaError::Helper(format!("cannot execute sbverify: {error}")))?;
            if output.status.success() {
                return Ok(());
            }
        }
        Err(MediaError::Rejected(
            "artifact is not authorized by the active Secure Boot db set".into(),
        ))
    }

    /// Verifies a detached SHA-256 signature over `data` against the db snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Rejected`] when no certificate's public key
    /// verifies the signature, and other variants for a malformed bundle or a
    /// failed helper.
    pub fn verify_detached_signature(
        &self,
        tools: &Tools,
        data: &Path,
        signature: &Path,
    ) -> Result<(), MediaError> {
        for (index, certificate) in self.active_certificates()?.iter().enumerate() {
            let certificate_path = self.write_certificate(index, certificate)?;
            let public_key = self.work_dir.join(format!("active-db-{index}.pub"));
            let extraction = Command::new(&tools.openssl)
                .args(["x509", "-pubkey", "-noout", "-in"])
                .arg(&certificate_path)
                .output()
                .map_err(|error| MediaError::Helper(format!("cannot execute openssl: {error}")))?;
            if !extraction.status.success() {
                return Err(MediaError::Rejected(
                    "active db certificate cannot be parsed by openssl".into(),
                ));
            }
            fs::write(&public_key, extraction.stdout)?;

            let verification = Command::new(&tools.openssl)
                .args(["dgst", "-sha256", "-verify"])
                .arg(&public_key)
                .arg("-signature")
                .arg(signature)
                .arg(data)
                .output()
                .map_err(|error| MediaError::Helper(format!("cannot execute openssl: {error}")))?;
            if verification.status.success() {
                return Ok(());
            }
        }
        Err(MediaError::Rejected(
            "signature is not authorized by the active Secure Boot db set".into(),
        ))
    }

    fn active_certificates(&self) -> Result<Vec<String>, MediaError> {
        let metadata = fs::metadata(&self.bundle)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TRUST_BUNDLE_BYTES {
            return Err(MediaError::Rejected(
                "authorized db trust bundle is empty, oversized, or not a regular file".into(),
            ));
        }
        let bundle = fs::read_to_string(&self.bundle)?;
        parse_certificates(&bundle).map_err(MediaError::Rejected)
    }

    fn write_certificate(&self, index: usize, certificate: &str) -> Result<PathBuf, MediaError> {
        fs::create_dir_all(&self.work_dir)?;
        let path = self.work_dir.join(format!("active-db-{index}.crt"));
        fs::write(&path, certificate)?;
        Ok(path)
    }
}

/// Splits a PEM bundle into complete certificates, rejecting any stray data.
///
/// # Errors
///
/// Returns a reason when the bundle is empty, contains data outside a
/// certificate, has an unterminated certificate, or exceeds the certificate
/// count bound.
pub fn parse_certificates(bundle: &str) -> Result<Vec<String>, String> {
    let mut remaining = bundle;
    let mut certificates = Vec::new();
    loop {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        if !remaining.starts_with(BEGIN_CERTIFICATE) {
            return Err("active db trust bundle contains data outside a PEM certificate".into());
        }
        let end_offset = remaining.find(END_CERTIFICATE).ok_or_else(|| {
            "active db trust bundle contains an unterminated certificate".to_string()
        })? + END_CERTIFICATE.len();
        certificates.push(format!("{}\n", &remaining[..end_offset]));
        if certificates.len() > MAX_ACTIVE_CERTIFICATES {
            return Err("active db trust bundle contains too many certificates".into());
        }
        remaining = &remaining[end_offset..];
    }
    if certificates.is_empty() {
        return Err("active db trust bundle contains no certificates".into());
    }
    Ok(certificates)
}

fn validate_certificate(tools: &Tools, certificate: &Path) -> Result<(), MediaError> {
    let output = Command::new(&tools.openssl)
        .args(["x509", "-noout", "-in"])
        .arg(certificate)
        .output()
        .map_err(|error| MediaError::Helper(format!("cannot execute openssl: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(MediaError::Rejected(
            "active db trust bundle contains an invalid X.509 certificate".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_certificates;

    const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";

    #[test]
    fn accepts_an_ordered_certificate_set() {
        let bundle = format!("\n{CERTIFICATE}\n{CERTIFICATE}");
        assert_eq!(parse_certificates(&bundle).map(|certs| certs.len()), Ok(2));
    }

    #[test]
    fn rejects_trailing_or_unterminated_data() {
        assert!(parse_certificates(&format!("{CERTIFICATE}junk")).is_err());
        assert!(parse_certificates("-----BEGIN CERTIFICATE-----\n").is_err());
    }
}
