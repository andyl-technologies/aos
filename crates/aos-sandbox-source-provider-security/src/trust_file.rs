//! Fixed protected SourceProvider trust snapshot.
//!
//! ```text
//! AOSPTRS1 || version:u16be=1 || reserved[6]=0 ||
//! trust-generation:u64be || trust-digest[32] ||
//! revocation-generation:u64be || revocation-digest[32] ||
//! authority-count:u16be || key-count:u16be || reserved[4]=0 ||
//! authority-record[80]* || key-record[184]*
//! ```
//!
//! Counts and exact length are checked before allocation. Record order is the
//! protocol trust-set order; rebuilding the protocol value recomputes and
//! verifies its digest.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS, MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS,
    SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityTrustV1, SourceProviderAuthorityV1,
    SourceProviderKeyTrustStateV1, SourceProviderKeyTrustV1, SourceProviderKeyUsageV1,
    SourceProviderTrustSetV1,
};

use crate::SourceProviderSecurityError;
use crate::manifest::{decode_signer, read_array, read_i64, read_u16, read_u64, require_zero};

/// Exact fixed header length of an `AOSPTRS1` record.
pub const SOURCE_PROVIDER_TRUST_HEADER_BYTES: usize = 104;
/// Exact authority-record length.
pub const SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES: usize = 80;
/// Exact signing-key-record length.
pub const SOURCE_PROVIDER_TRUST_KEY_BYTES: usize = 184;
/// Largest canonical protected trust record.
pub const MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES: usize = SOURCE_PROVIDER_TRUST_HEADER_BYTES
    + MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS * SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES
    + MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS * SOURCE_PROVIDER_TRUST_KEY_BYTES;

const MAGIC: &[u8; 8] = b"AOSPTRS1";

/// Holds one decoded trust file and its protocol trust model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderTrustFileV1 {
    trust_set: SourceProviderTrustSetV1,
    exact: Vec<u8>,
}

impl SourceProviderTrustFileV1 {
    /// Decodes a canonical protected trust file without granting provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for a malformed header, invalid
    /// count or exact length, noncanonical record, or digest mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceProviderSecurityError> {
        if bytes.len() < SOURCE_PROVIDER_TRUST_HEADER_BYTES
            || bytes.len() > MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES
            || &bytes[..8] != MAGIC
            || read_u16(bytes, 8)? != 1
        {
            return Err(SourceProviderSecurityError::format("trust", "header"));
        }
        require_zero(bytes, 10, 16, "trust", "header reserved")?;
        require_zero(bytes, 100, 104, "trust", "count reserved")?;

        let authority_count = usize::from(read_u16(bytes, 96)?);
        let key_count = usize::from(read_u16(bytes, 98)?);
        if authority_count == 0
            || authority_count > MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS
            || key_count == 0
            || key_count > MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS
        {
            return Err(SourceProviderSecurityError::format("trust", "counts"));
        }
        let authority_bytes = authority_count
            .checked_mul(SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES)
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        let key_bytes = key_count
            .checked_mul(SOURCE_PROVIDER_TRUST_KEY_BYTES)
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        let exact_length = SOURCE_PROVIDER_TRUST_HEADER_BYTES
            .checked_add(authority_bytes)
            .and_then(|length| length.checked_add(key_bytes))
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        if bytes.len() != exact_length {
            return Err(SourceProviderSecurityError::format("trust", "length"));
        }

        let mut authorities = Vec::with_capacity(authority_count);
        for index in 0..authority_count {
            let offset =
                SOURCE_PROVIDER_TRUST_HEADER_BYTES + index * SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES;
            authorities.push(decode_authority(&bytes[offset..offset + 80])?);
        }
        let key_offset = SOURCE_PROVIDER_TRUST_HEADER_BYTES + authority_bytes;
        let mut keys = Vec::with_capacity(key_count);
        for index in 0..key_count {
            let offset = key_offset + index * SOURCE_PROVIDER_TRUST_KEY_BYTES;
            keys.push(decode_key(&bytes[offset..offset + 184])?);
        }

        let trust_set = SourceProviderTrustSetV1::new(
            read_u64(bytes, 16)?,
            ObjectDigest::from_bytes(read_array(bytes, 24)?),
            read_u64(bytes, 56)?,
            ObjectDigest::from_bytes(read_array(bytes, 64)?),
            authorities,
            keys,
        )
        .map_err(|_| SourceProviderSecurityError::format("trust", "protocol model"))?;
        Ok(Self {
            trust_set,
            exact: bytes.to_vec(),
        })
    }

    /// Returns the exact canonical protected trust-file bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.exact.clone()
    }

    /// Returns the reconstructed canonical protocol trust set.
    #[must_use]
    pub const fn trust_set(&self) -> &SourceProviderTrustSetV1 {
        &self.trust_set
    }
}

fn decode_authority(
    bytes: &[u8],
) -> Result<SourceProviderAuthorityTrustV1, SourceProviderSecurityError> {
    require_zero(bytes, 73, 80, "trust authority", "reserved")?;
    let state = match bytes[72] {
        1 => SourceProviderAuthorityTrustStateV1::Trusted,
        2 => SourceProviderAuthorityTrustStateV1::Revoked,
        _ => {
            return Err(SourceProviderSecurityError::format(
                "trust authority",
                "state",
            ));
        }
    };
    let authority = SourceProviderAuthorityV1::new(
        read_array(bytes, 0)?,
        read_u64(bytes, 16)?,
        ObjectDigest::from_bytes(read_array(bytes, 24)?),
    )
    .map_err(|_| SourceProviderSecurityError::format("trust authority", "identity"))?;
    SourceProviderAuthorityTrustV1::new(
        authority,
        read_i64(bytes, 56)?,
        read_i64(bytes, 64)?,
        state,
    )
    .map_err(|_| SourceProviderSecurityError::format("trust authority", "interval"))
}

fn decode_key(bytes: &[u8]) -> Result<SourceProviderKeyTrustV1, SourceProviderSecurityError> {
    require_zero(bytes, 169, 176, "trust key", "reserved")?;
    let state = match bytes[168] {
        1 => SourceProviderKeyTrustStateV1::Eligible,
        2 => SourceProviderKeyTrustStateV1::Superseded,
        3 => SourceProviderKeyTrustStateV1::Revoked,
        _ => return Err(SourceProviderSecurityError::format("trust key", "state")),
    };
    let usage = match bytes[112] {
        1 => SourceProviderKeyUsageV1::RootMountHello,
        2 => SourceProviderKeyUsageV1::ProviderHello,
        3 => SourceProviderKeyUsageV1::RootMountRecord,
        4 => SourceProviderKeyUsageV1::ProviderOutcome,
        _ => return Err(SourceProviderSecurityError::format("trust key", "usage")),
    };
    let signer = decode_signer(&bytes[..120], usage)?;
    SourceProviderKeyTrustV1::new(
        signer,
        read_array(bytes, 120)?,
        read_i64(bytes, 152)?,
        read_i64(bytes, 160)?,
        state,
        read_u64(bytes, 176)?,
    )
    .map_err(|_| SourceProviderSecurityError::format("trust key", "protocol model"))
}
