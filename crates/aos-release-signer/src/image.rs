//! Transforming operations for Linux image finalization.
//!
//! Authenticode and kernel-module signatures are produced with the AOS-built
//! `sbsign` and `openssl` tools named in the configuration; PCR policies are
//! signed in-process. Every transform writes into a private temporary
//! directory and returns the complete signed bytes, which the coordinator
//! digests and verifies independently before installing them.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use hex::ToHex as _;
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePublicKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::sign::rsa_sha256_sign;

/// Trailer that Linux expects after an appended module signature.
const MODULE_SIGNATURE_MAGIC: &[u8] = b"~Module signature appended~\n";

/// `PKEY_ID_PKCS7` in the kernel's `module_signature.id_type` field.
const PKEY_ID_PKCS7: u8 = 2;

/// Signs one PE/COFF image with Authenticode through `sbsign`.
///
/// # Errors
///
/// Returns an error when the temporary directory or files cannot be created,
/// `sbsign` fails, or it produces no output.
pub fn sign_pe(sbsign: &Path, key: &Path, certificate: &Path, unsigned: &[u8]) -> Result<Vec<u8>> {
    let scratch = tempfile::Builder::new()
        .prefix("aos-release-signer-pe-")
        .tempdir()
        .context("creating Authenticode scratch directory")?;
    let input = scratch.path().join("unsigned.efi");
    let output = scratch.path().join("signed.efi");
    fs::write(&input, unsigned)?;

    run_tool(
        sbsign,
        &[
            "--key",
            path_text(key)?,
            "--cert",
            path_text(certificate)?,
            "--output",
            path_text(&output)?,
            path_text(&input)?,
        ],
    )?;
    let signed = fs::read(&output).context("reading sbsign output")?;
    if signed.len() <= unsigned.len() {
        bail!("sbsign produced an output no larger than its input");
    }
    Ok(signed)
}

/// Appends a detached CMS signature to a kernel module in the Linux format.
///
/// The PKCS#7 object is produced by `openssl cms` with the same flags the
/// kernel's `sign-file` uses: binary, detached, no certificates, no signed
/// attributes, and no SMIME capabilities.
///
/// # Errors
///
/// Returns an error when the temporary files cannot be created, `openssl`
/// fails, or the signature is empty or larger than the 32-bit length field.
pub fn sign_kernel_module(
    openssl: &Path,
    key: &Path,
    certificate: &Path,
    module: &[u8],
) -> Result<Vec<u8>> {
    let scratch = tempfile::Builder::new()
        .prefix("aos-release-signer-module-")
        .tempdir()
        .context("creating module scratch directory")?;
    let input = scratch.path().join("module.ko");
    let signature = scratch.path().join("module.p7s");
    fs::write(&input, module)?;

    run_tool(
        openssl,
        &[
            "cms",
            "-sign",
            "-binary",
            "-nocerts",
            "-noattr",
            "-nosmimecap",
            "-md",
            "sha256",
            "-outform",
            "DER",
            "-signer",
            path_text(certificate)?,
            "-inkey",
            path_text(key)?,
            "-in",
            path_text(&input)?,
            "-out",
            path_text(&signature)?,
        ],
    )?;
    let pkcs7 = fs::read(&signature).context("reading CMS signature")?;
    append_module_signature(module, &pkcs7)
}

/// Builds `module || pkcs7 || module_signature header || magic`.
pub(crate) fn append_module_signature(module: &[u8], pkcs7: &[u8]) -> Result<Vec<u8>> {
    if pkcs7.is_empty() {
        bail!("module signature is empty");
    }
    let signature_length =
        u32::try_from(pkcs7.len()).context("module signature exceeds the 32-bit length field")?;
    let mut signed =
        Vec::with_capacity(module.len() + pkcs7.len() + 12 + MODULE_SIGNATURE_MAGIC.len());
    signed.extend_from_slice(module);
    signed.extend_from_slice(pkcs7);
    // struct module_signature: algo, hash, id_type, signer_len, key_id_len,
    // three padding bytes, then the big-endian signature length.
    signed.extend_from_slice(&[0, 0, PKEY_ID_PKCS7, 0, 0, 0, 0, 0]);
    signed.extend_from_slice(&signature_length.to_be_bytes());
    signed.extend_from_slice(MODULE_SIGNATURE_MAGIC);
    Ok(signed)
}

/// Unsigned `systemd-measure policy-digest` document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    sha256: Vec<PolicyRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    pcrs: Vec<u8>,
    pol: String,
}

/// Signed `.pcrsig` document consumed by systemd and the finalizer.
#[derive(Serialize)]
struct SignedPolicyDocument {
    sha256: Vec<SignedPolicyRecord>,
}

#[derive(Serialize)]
struct SignedPolicyRecord {
    pcrs: Vec<u8>,
    pkfp: String,
    pol: String,
    sig: String,
}

/// Signs every policy digest in a measured-boot policy document.
///
/// Each 32-byte policy is signed with RSA PKCS#1 v1.5 over SHA-256, the
/// scheme `systemd-measure sign` uses and `openssl dgst -sha256 -verify`
/// accepts. The public-key fingerprint is the SHA-256 of the DER-encoded
/// SubjectPublicKeyInfo, matching `openssl pkey -pubin -outform DER`.
///
/// # Errors
///
/// Returns an error for a noncanonical or malformed policy document, a
/// policy digest that is not 32 bytes, or a public key that cannot be encoded.
pub fn sign_pcr_policy(key: &RsaPrivateKey, payload: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine as _;

    canonical::require_canonical(payload, "PCR policy document")?;
    let policy: PolicyDocument = canonical::from_slice(payload, "PCR policy document")?;
    if policy.sha256.is_empty() {
        bail!("PCR policy document selects no policies");
    }
    let public_der = key
        .to_public_key()
        .to_public_key_der()
        .context("encoding PCR public key")?;
    let fingerprint: String = Sha256::digest(public_der.as_bytes()).encode_hex();

    let mut signed = Vec::with_capacity(policy.sha256.len());
    for record in policy.sha256 {
        let policy_bytes = hex::decode(&record.pol).context("decoding PCR policy digest")?;
        if policy_bytes.len() != 32 {
            bail!("PCR policy digest must be 32 bytes");
        }
        let signature = rsa_sha256_sign(key, &policy_bytes);
        signed.push(SignedPolicyRecord {
            pcrs: record.pcrs,
            pkfp: fingerprint.clone(),
            pol: record.pol,
            sig: base64::engine::general_purpose::STANDARD.encode(signature),
        });
    }
    canonical::to_vec(&SignedPolicyDocument { sha256: signed })
}

/// Runs one external tool with a cleared environment and captured diagnostics.
fn run_tool(executable: &Path, arguments: &[&str]) -> Result<()> {
    let output = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("running {}", executable.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed with {}: {}",
            executable.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("signer scratch path is not UTF-8")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn module_signature_trailer_matches_the_kernel_layout() {
        let module = b"ELF module bytes";
        let pkcs7 = vec![0x30, 0x82, 0x01, 0x00];

        let signed = append_module_signature(module, &pkcs7).unwrap();

        assert!(signed.starts_with(module));
        assert!(signed.ends_with(MODULE_SIGNATURE_MAGIC));
        let header_start = signed.len() - MODULE_SIGNATURE_MAGIC.len() - 12;
        let header = &signed[header_start..header_start + 12];
        assert_eq!(header[2], PKEY_ID_PKCS7);
        assert_eq!(&header[8..12], &(pkcs7.len() as u32).to_be_bytes());
        assert_eq!(&signed[module.len()..header_start], pkcs7.as_slice());
        assert!(append_module_signature(module, &[]).is_err());
    }

    #[test]
    fn pcr_policy_signatures_verify_with_the_public_key() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier as _;

        let key = test_rsa_key();
        let policy = b"{\"sha256\":[{\"pcrs\":[11],\"pol\":\"".to_vec();
        let mut document = policy;
        document.extend(b"00".repeat(32));
        document.extend(b"\"}]}");

        let signed = sign_pcr_policy(&key, &document).unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        let record = &parsed["sha256"][0];
        assert_eq!(record["pcrs"], serde_json::json!([11]));
        let expected_fingerprint: String =
            Sha256::digest(key.to_public_key().to_public_key_der().unwrap().as_bytes())
                .encode_hex();
        assert_eq!(record["pkfp"], serde_json::json!(expected_fingerprint));
        let signature = base64::engine::general_purpose::STANDARD
            .decode(record["sig"].as_str().unwrap())
            .unwrap();
        VerifyingKey::<Sha256>::new(key.to_public_key())
            .verify(
                &[0_u8; 32],
                &Signature::try_from(signature.as_slice()).unwrap(),
            )
            .unwrap();
        assert!(sign_pcr_policy(&key, b"{\"sha256\":[]}").is_err());
    }

    /// Deterministic 1024-bit test key; generation is too slow for unit tests.
    fn test_rsa_key() -> RsaPrivateKey {
        use rsa::traits::PrivateKeyParts as _;

        let mut rng = DeterministicRng([0x5a; 32]);
        let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        assert!(!key.primes().is_empty());
        key
    }

    /// Minimal counter-based RNG so the test does not depend on the `rand` crate.
    struct DeterministicRng([u8; 32]);

    impl rsa::rand_core::RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(32) {
                self.0 = Sha256::digest(self.0).into();
                chunk.copy_from_slice(&self.0[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rsa::rand_core::CryptoRng for DeterministicRng {}
}
