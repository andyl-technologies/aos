//! OpenSSH Ed25519 keypair generation and serialization.
//!
//! Registry maintainer keys are ordinary OpenSSH Ed25519 keys: git signs
//! tags and commits with them (`gpg.format=ssh`), and clients verify
//! signatures against the SSH wire-format public key blob embedded in
//! `registry:Ed25519:<base64>` trust-key lines. This module produces both
//! halves without shelling out to `ssh-keygen`, so key generation works on
//! minimal hosts.

use base64::Engine;
use rand::RngCore;

/// An Ed25519 keypair held as raw seed and public-key bytes.
///
/// The private half never leaves this struct except through
/// [`Ed25519Keypair::to_openssh_private_key`], which renders the standard
/// unencrypted `OPENSSH PRIVATE KEY` PEM format understood by git and
/// OpenSSH.
pub struct Ed25519Keypair {
    seed: [u8; 32],
    public_key: [u8; 32],
}

impl Ed25519Keypair {
    /// Generate a fresh keypair from the thread-local CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0_u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Construct the keypair deterministically from a 32-byte Ed25519 seed.
    ///
    /// Intended for tests and fixtures that need reproducible keys; real
    /// keys should come from [`Ed25519Keypair::generate`].
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self { seed, public_key }
    }

    /// The SSH wire-format public key blob (`ssh-ed25519` + key bytes).
    ///
    /// This is the value OpenSSH base64-encodes as the second field of a
    /// `.pub` file.
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        push_ssh_string(&mut blob, b"ssh-ed25519");
        push_ssh_string(&mut blob, &self.public_key);
        blob
    }

    /// The base64-encoded SSH public key blob.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_key_blob())
    }

    /// The `registry:Ed25519:<base64>` trust-key line for this keypair.
    ///
    /// This is the form accepted by `keys.toml`, `trusted-keys.d` files,
    /// and `[registry.signing] public_key`.
    pub fn trust_key_line(&self, registry: &str) -> String {
        format!("{registry}:Ed25519:{}", self.public_key_base64())
    }

    /// Render the private key in unencrypted OpenSSH PEM format.
    ///
    /// The output is accepted by `git -c gpg.format=ssh` and `ssh-keygen`.
    /// `comment` becomes the key comment (conventionally the key id or the
    /// maintainer's address).
    pub fn to_openssh_private_key(&self, comment: &str) -> String {
        let public_blob = self.public_key_blob();
        let mut private_key = Vec::new();
        private_key.extend_from_slice(&self.seed);
        private_key.extend_from_slice(&self.public_key);

        // Identical "checkint" values mark the (absent) decryption as
        // successful; OpenSSH requires the pair to match.
        let checkint = rand::rng().next_u32();
        let mut private = Vec::new();
        push_u32(&mut private, checkint);
        push_u32(&mut private, checkint);
        push_ssh_string(&mut private, b"ssh-ed25519");
        push_ssh_string(&mut private, &self.public_key);
        push_ssh_string(&mut private, &private_key);
        push_ssh_string(&mut private, comment.as_bytes());
        // Pad the private section to the 8-byte block size of the "none"
        // cipher with the sequence 1, 2, 3, ...
        let mut pad = 1_u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad = pad.wrapping_add(1);
        }

        let mut blob = b"openssh-key-v1\0".to_vec();
        push_ssh_string(&mut blob, b"none");
        push_ssh_string(&mut blob, b"none");
        push_ssh_string(&mut blob, b"");
        push_u32(&mut blob, 1);
        push_ssh_string(&mut blob, &public_blob);
        push_ssh_string(&mut blob, &private);

        let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
        let mut out = "-----BEGIN OPENSSH PRIVATE KEY-----\n".to_string();
        for chunk in encoded.as_bytes().chunks(70) {
            // Base64 output is pure ASCII, so byte-wise chunking cannot
            // split a character.
            out.extend(chunk.iter().map(|&byte| byte as char));
            out.push('\n');
        }
        out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        out
    }
}

fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::parse_signing_key;

    #[test]
    fn trust_key_line_parses() {
        let keypair = Ed25519Keypair::from_seed([3_u8; 32]);
        let line = keypair.trust_key_line("core");
        let (registry, algorithm, public_key) = parse_signing_key(&line).unwrap();
        assert_eq!(registry, "core");
        assert_eq!(algorithm, "Ed25519");
        assert_eq!(public_key, keypair.public_key_base64());
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = Ed25519Keypair::generate();
        let b = Ed25519Keypair::generate();
        assert_ne!(a.public_key_base64(), b.public_key_base64());
    }

    #[test]
    fn private_key_pem_round_trips_through_ssh_keygen_format() {
        let keypair = Ed25519Keypair::from_seed([5_u8; 32]);
        let pem = keypair.to_openssh_private_key("test-key");
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        // The embedded blob decodes and starts with the magic string.
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let blob = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        assert!(blob.starts_with(b"openssh-key-v1\0"));
    }
}
