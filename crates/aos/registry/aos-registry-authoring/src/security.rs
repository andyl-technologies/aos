//! Loads producer signing keys and creates OpenSSH detached signatures.
//!
//! Registry consumers accept public trust anchors and verify signatures through
//! `aos_registry_client::security`; they do not load production private keys.

use anyhow::{Context, Result};
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use std::{fs, path::Path};

/// Reads an unencrypted OpenSSH private key, tolerating surrounding whitespace
/// the way `ssh-keygen` does.
///
/// # Errors
///
/// Returns an error when the file cannot be read or does not contain an
/// unencrypted OpenSSH private key.
fn read_openssh_private_key(key_path: &Path) -> Result<PrivateKey> {
    let contents = fs::read_to_string(key_path)
        .with_context(|| format!("reading signing key {}", key_path.display()))?;
    PrivateKey::from_openssh(contents.trim())
        .with_context(|| format!("reading signing key {}", key_path.display()))
}

/// Derives the base64 SSH wire-format public key of an OpenSSH Ed25519 private
/// key — the `<base64>` field of a `ssh-ed25519 <base64>` line, which is the
/// material a `registry:Ed25519:<base64>` trust line carries.
///
/// # Errors
///
/// Returns an error when the key cannot be read, is not Ed25519, or cannot be
/// encoded.
pub fn public_ed25519_blob(key_path: &Path) -> Result<String> {
    let key = read_openssh_private_key(key_path)?;
    let public = key.public_key();
    if public.algorithm() != ssh_key::Algorithm::Ed25519 {
        anyhow::bail!("unsupported signing key type; registry keys must be Ed25519");
    }
    let openssh = public.to_openssh().context("encoding public key")?;
    openssh
        .split_whitespace()
        .nth(1)
        .map(ToString::to_string)
        .context("public key has no key material")
}

/// Signs an arbitrary payload with an OpenSSH Ed25519 private key.
///
/// Produces an armored SSHSIG over `payload` in `namespace` — the same
/// OpenSSH format (`-----BEGIN SSH SIGNATURE-----`) that `ssh-keygen -Y sign`
/// emits and that the verification helpers above accept.
///
/// # Errors
///
/// Returns an error when the private key cannot be read, is not an unencrypted
/// OpenSSH key, or signing fails.
pub fn sign_payload_signature(key_path: &Path, namespace: &str, payload: &[u8]) -> Result<String> {
    let key = read_openssh_private_key(key_path)?;
    let signature = key
        .sign(namespace, HashAlg::Sha512, payload)
        .context("creating SSH signature")?;
    signature
        .to_pem(LineEnding::LF)
        .context("encoding SSH signature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A valid key with a non-canonical tail must still be read. The most
    /// common offender is the double trailing newline `op item get ... |
    /// jq -r .value` produces (1Password stores the key already newline-
    /// terminated and `jq -r` appends a second one), but trailing spaces and
    /// CRLF are equally fatal to the strict `ssh-key` reader. Both the
    /// public-key derivation and the signing path trim before parsing.
    ///
    /// Regression test for the `keys register` / signing "PEM error in
    /// pre-encapsulation boundary" failure introduced when the `ssh-keygen -y`
    /// shell-out was replaced with the in-process reader.
    #[test]
    fn reads_openssh_key_with_noncanonical_trailing_whitespace() {
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([23_u8; 32]);
        let canonical = keypair.to_openssh_private_key("louis");
        // The writer emits exactly one trailing newline; the bug only appears
        // once something perturbs that tail.
        assert!(canonical.ends_with("-----\n") && !canonical.ends_with("-----\n\n"));

        let expected_blob = keypair.public_key_base64();
        let temp = TempDir::new().unwrap();

        for (label, contents) in [
            ("double newline (jq -r)", format!("{canonical}\n")),
            ("trailing spaces", format!("{canonical}   ")),
            ("crlf blank line", format!("{canonical}\r\n\r\n")),
            ("no trailing newline", canonical.trim_end().to_string()),
        ] {
            let path = temp.path().join("key");
            fs::write(&path, &contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }

            let blob = public_ed25519_blob(&path)
                .unwrap_or_else(|err| panic!("public_ed25519_blob failed for {label}: {err:#}"));
            assert_eq!(blob, expected_blob, "wrong blob for {label}");

            // The signing path reads the same key; it must tolerate the tail too.
            sign_payload_signature(&path, "git", b"payload")
                .unwrap_or_else(|err| panic!("sign_payload_signature failed for {label}: {err:#}"));
        }
    }
}
