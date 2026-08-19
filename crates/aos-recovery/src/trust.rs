//! Applies the immutable Secure Boot db trust snapshot inside recovery.
//!
//! The recovery initrd carries the currently signing db certificate together
//! with every configured rotation-overlap db certificate. Verification succeeds only
//! when one complete PEM certificate authorizes the artifact; malformed trust
//! bundles are rejected rather than partially consumed.

use std::fs;
use std::path::Path;
use std::process::Command;

const AUTHORIZED_DB_CERTS: &str = "/etc/aos/trust/authorized-db-certs.pem";
const WORK_DIR: &str = "/run/aos-recovery";
const MAX_TRUST_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_ACTIVE_CERTIFICATES: usize = 32;
const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// Verifies one UKI against the immutable configured db snapshot.
pub(crate) fn verify_uki(uki: &Path) -> Result<(), String> {
    for (index, certificate) in active_certificates()?.iter().enumerate() {
        let certificate_path = write_certificate(index, certificate)?;
        validate_certificate(&certificate_path)?;
        let output = Command::new("/bin/sbverify")
            .arg("--cert")
            .arg(&certificate_path)
            .arg(uki)
            .output()
            .map_err(|error| format!("cannot execute sbverify: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
    }
    Err("artifact is not authorized by the active Secure Boot db set".into())
}

/// Verifies a detached SHA-256 signature against the configured db snapshot.
pub(crate) fn verify_detached_signature(data: &Path, signature: &Path) -> Result<(), String> {
    for (index, certificate) in active_certificates()?.iter().enumerate() {
        let certificate_path = write_certificate(index, certificate)?;
        let public_key = Path::new(WORK_DIR).join(format!("active-db-{index}.pub"));
        let extraction = Command::new("/bin/openssl")
            .args(["x509", "-pubkey", "-noout", "-in"])
            .arg(&certificate_path)
            .output()
            .map_err(|error| format!("cannot execute openssl: {error}"))?;
        if !extraction.status.success() {
            return Err("active db certificate cannot be parsed by openssl".into());
        }
        fs::write(&public_key, extraction.stdout)
            .map_err(|error| format!("cannot stage active db public key: {error}"))?;

        let verification = Command::new("/bin/openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&public_key)
            .arg("-signature")
            .arg(signature)
            .arg(data)
            .output()
            .map_err(|error| format!("cannot execute openssl: {error}"))?;
        if verification.status.success() {
            return Ok(());
        }
    }
    Err("signature is not authorized by the active Secure Boot db set".into())
}

fn active_certificates() -> Result<Vec<String>, String> {
    let metadata = fs::metadata(AUTHORIZED_DB_CERTS)
        .map_err(|error| format!("cannot inspect authorized db trust bundle: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TRUST_BUNDLE_BYTES {
        return Err("authorized db trust bundle is empty, oversized, or not a regular file".into());
    }
    let bundle = fs::read_to_string(AUTHORIZED_DB_CERTS)
        .map_err(|error| format!("cannot read authorized db trust bundle: {error}"))?;
    parse_certificates(&bundle)
}

fn parse_certificates(bundle: &str) -> Result<Vec<String>, String> {
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

fn write_certificate(index: usize, certificate: &str) -> Result<std::path::PathBuf, String> {
    fs::create_dir_all(WORK_DIR)
        .map_err(|error| format!("cannot create recovery work directory: {error}"))?;
    let path = Path::new(WORK_DIR).join(format!("active-db-{index}.crt"));
    fs::write(&path, certificate)
        .map_err(|error| format!("cannot stage active db certificate: {error}"))?;
    Ok(path)
}

fn validate_certificate(certificate: &Path) -> Result<(), String> {
    let output = Command::new("/bin/openssl")
        .args(["x509", "-noout", "-in"])
        .arg(certificate)
        .output()
        .map_err(|error| format!("cannot execute openssl: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err("active db trust bundle contains an invalid X.509 certificate".into())
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
