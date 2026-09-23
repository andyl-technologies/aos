//! Sealed launch-only OpenSSH trust credential for the guest PID 1 bootstrap.
//!
//! ```text
//! AOSGTR01 || runtime[104] || private_len:u32be || private[private_len]
//!          || host_public_len:u16be || host_public[host_public_len]
//!          || ca_public_len:u16be || ca_public[ca_public_len]
//!          || SHA256(previous bytes)[32]
//! ```
//!
//! The credential is delivered only as a fully sealed memfd at guest FD 5.
//! Its public keys are independently pinned by the protected Host before
//! construction; this format does not make a Host-selected key trustworthy.

use ssh_key::{Algorithm, PrivateKey, PublicKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::model::AgentRuntimeBindingV1;
use crate::protected_entry::encode_agent_runtime_binding_v1;

const MAGIC: &[u8; 8] = b"AOSGTR01";
const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 128;
const FIXED_BYTES: usize = 8 + 104 + 4 + 2 + 2 + 32;

/// Maximum size of one sealed guest attach-trust credential.
pub const MAX_GUEST_ATTACH_TRUST_BYTES: usize =
    FIXED_BYTES + MAX_PRIVATE_KEY_BYTES + 2 * MAX_PUBLIC_KEY_BYTES;

/// Holds exact runtime-bound OpenSSH trust material before protected install.
pub struct GuestAttachTrustRecordV1 {
    runtime: [u8; 104],
    private_key: Zeroizing<Vec<u8>>,
    host_public_key: Vec<u8>,
    trusted_ca_public_key: Vec<u8>,
}

impl GuestAttachTrustRecordV1 {
    /// Validates unencrypted Ed25519 key material and binds it to one runtime.
    ///
    /// The caller must compare both public keys to an independent protected
    /// trust pin before sealing and delivering this record to the guest.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, noncanonical, encrypted, mismatched,
    /// or non-Ed25519 key material.
    pub fn new(
        runtime: AgentRuntimeBindingV1,
        private_key: Vec<u8>,
        host_public_key: Vec<u8>,
        trusted_ca_public_key: Vec<u8>,
    ) -> Result<Self, GuestAttachTrustErrorV1> {
        let record = Self {
            runtime: encode_agent_runtime_binding_v1(runtime),
            private_key: Zeroizing::new(private_key),
            host_public_key,
            trusted_ca_public_key,
        };
        record.validate()?;
        Ok(record)
    }

    /// Decodes a checksum-protected canonical credential from a sealed mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed lengths, checksum mismatch, or invalid
    /// OpenSSH key material.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestAttachTrustErrorV1> {
        if bytes.len() < FIXED_BYTES || bytes.len() > MAX_GUEST_ATTACH_TRUST_BYTES {
            return Err(GuestAttachTrustErrorV1::InvalidRecord);
        }
        let payload_length = bytes.len() - 32;
        let checksum: [u8; 32] = Sha256::digest(&bytes[..payload_length]).into();
        if bytes[..8] != *MAGIC || bytes[payload_length..] != checksum {
            return Err(GuestAttachTrustErrorV1::InvalidRecord);
        }

        let runtime: [u8; 104] = bytes[8..112]
            .try_into()
            .map_err(|_| GuestAttachTrustErrorV1::InvalidRecord)?;
        let mut cursor = 112;
        let private_length = read_length(bytes, &mut cursor, 4)?;
        let private_key = read_field(bytes, &mut cursor, private_length)?.to_vec();
        let host_public_length = read_length(bytes, &mut cursor, 2)?;
        let host_public_key = read_field(bytes, &mut cursor, host_public_length)?.to_vec();
        let ca_public_length = read_length(bytes, &mut cursor, 2)?;
        let trusted_ca_public_key = read_field(bytes, &mut cursor, ca_public_length)?.to_vec();
        if cursor != payload_length {
            return Err(GuestAttachTrustErrorV1::InvalidRecord);
        }

        let record = Self {
            runtime,
            private_key: Zeroizing::new(private_key),
            host_public_key,
            trusted_ca_public_key,
        };
        record.validate()?;
        if record.encode().as_slice() != bytes {
            return Err(GuestAttachTrustErrorV1::InvalidRecord);
        }
        Ok(record)
    }

    /// Encodes the canonical credential for a fully sealed FD 5 memfd.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            FIXED_BYTES
                + self.private_key.len()
                + self.host_public_key.len()
                + self.trusted_ca_public_key.len(),
        ));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.runtime);
        bytes.extend_from_slice(&(self.private_key.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.private_key);
        bytes.extend_from_slice(&(self.host_public_key.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.host_public_key);
        bytes.extend_from_slice(&(self.trusted_ca_public_key.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.trusted_ca_public_key);
        let checksum: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Returns the exact runtime prefix that must match sealed FD 4.
    #[must_use]
    pub const fn runtime_bytes(&self) -> &[u8; 104] {
        &self.runtime
    }

    /// Returns the private OpenSSH host key only for fixed guest installation.
    #[must_use]
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// Returns the canonical host public key for fixed guest installation.
    #[must_use]
    pub fn host_public_key_bytes(&self) -> &[u8] {
        &self.host_public_key
    }

    /// Returns the canonical trusted user-CA key for fixed guest installation.
    #[must_use]
    pub fn trusted_ca_public_key_bytes(&self) -> &[u8] {
        &self.trusted_ca_public_key
    }

    fn validate(&self) -> Result<(), GuestAttachTrustErrorV1> {
        if self.private_key.is_empty()
            || self.private_key.len() > MAX_PRIVATE_KEY_BYTES
            || self.host_public_key.is_empty()
            || self.host_public_key.len() > MAX_PUBLIC_KEY_BYTES
            || self.trusted_ca_public_key.is_empty()
            || self.trusted_ca_public_key.len() > MAX_PUBLIC_KEY_BYTES
        {
            return Err(GuestAttachTrustErrorV1::InvalidKey);
        }

        let private = PrivateKey::from_openssh(&self.private_key)
            .map_err(|_| GuestAttachTrustErrorV1::InvalidKey)?;
        let host_public = canonical_public_key(&self.host_public_key)?;
        canonical_public_key(&self.trusted_ca_public_key)?;
        if private.is_encrypted()
            || private.algorithm() != Algorithm::Ed25519
            || private.public_key().key_data() != host_public.key_data()
        {
            return Err(GuestAttachTrustErrorV1::InvalidKey);
        }
        Ok(())
    }
}

fn canonical_public_key(bytes: &[u8]) -> Result<PublicKey, GuestAttachTrustErrorV1> {
    let text = std::str::from_utf8(bytes).map_err(|_| GuestAttachTrustErrorV1::InvalidKey)?;
    let key = PublicKey::from_openssh(text).map_err(|_| GuestAttachTrustErrorV1::InvalidKey)?;
    if key.algorithm() != Algorithm::Ed25519
        || !key.comment().is_empty()
        || key.to_openssh().map_err(|_| GuestAttachTrustErrorV1::InvalidKey)? != text
    {
        return Err(GuestAttachTrustErrorV1::InvalidKey);
    }
    Ok(key)
}

fn read_length(
    bytes: &[u8],
    cursor: &mut usize,
    width: usize,
) -> Result<usize, GuestAttachTrustErrorV1> {
    let field = read_field(bytes, cursor, width)?;
    Ok(match width {
        2 => u16::from_be_bytes([field[0], field[1]]) as usize,
        4 => u32::from_be_bytes([field[0], field[1], field[2], field[3]]) as usize,
        _ => return Err(GuestAttachTrustErrorV1::InvalidRecord),
    })
}

fn read_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], GuestAttachTrustErrorV1> {
    let end = cursor
        .checked_add(length)
        .ok_or(GuestAttachTrustErrorV1::InvalidRecord)?;
    let field = bytes
        .get(*cursor..end)
        .ok_or(GuestAttachTrustErrorV1::InvalidRecord)?;
    *cursor = end;
    Ok(field)
}

/// Reports invalid sealed guest attach-trust material.
#[derive(Debug, thiserror::Error)]
pub enum GuestAttachTrustErrorV1 {
    /// The length, checksum, or canonical encoding is invalid.
    #[error("guest attach-trust credential is invalid")]
    InvalidRecord,
    /// The OpenSSH key material is invalid or inconsistent.
    #[error("guest attach-trust key material is invalid")]
    InvalidKey,
}
