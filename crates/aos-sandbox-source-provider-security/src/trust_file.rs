//! Fixed protected SourceProvider trust snapshot and authenticated head chain.
//!
//! ```text
//! AOSPTRS2 || version:u16be=2 || reserved[6]=0 ||
//! trust-generation:u64be || trust-digest[32] ||
//! revocation-generation:u64be || revocation-digest[32] ||
//! authority-count:u16be || key-count:u16be || history-count:u16be || reserved[2]=0 ||
//! authority-record[160]* || key-record[344]* || trust-head-link[160]*
//!
//! authority-record := protocol-authority-record[80] || state-effective-head[80]
//!
//! key-record := protocol-key-record[184] || issuance-trust-generation:u64be ||
//!   issuance-trust-digest[32] || issuance-revocation-generation:u64be ||
//!   issuance-revocation-digest[32] || earliest-deactivation-head[80]
//!
//! earliest-deactivation-head := trust-generation:u64be || trust-digest[32] ||
//!   revocation-generation:u64be || revocation-digest[32]
//!
//! trust-head-link := trust-generation:u64be || trust-digest[32] ||
//!   revocation-generation:u64be || revocation-digest[32] ||
//!   predecessor-trust-generation:u64be || predecessor-trust-digest[32] ||
//!   predecessor-revocation-generation:u64be || predecessor-revocation-digest[32]
//! ```
//!
//! Counts and exact length are checked before allocation. Record order is the
//! protocol trust-set order. The protected manifest authenticates the complete
//! file, including the unique predecessor chain, while rebuilding the current
//! protocol value independently recomputes and verifies its head digest.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS, MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS,
    SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityTrustV1, SourceProviderAuthorityV1,
    SourceProviderKeyTrustStateV1, SourceProviderKeyTrustV1, SourceProviderKeyUsageV1,
    SourceProviderSigningKeyV1, SourceProviderTrustSetV1,
};

use crate::SourceProviderSecurityError;
use crate::manifest::{decode_signer, read_array, read_i64, read_u16, read_u64, require_zero};

/// Exact fixed header length of an `AOSPTRS2` record.
pub const SOURCE_PROVIDER_TRUST_HEADER_BYTES: usize = 104;
/// Exact authority-record length.
pub const SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES: usize = 160;
/// Exact signing-key-record length, including immutable issuance heads.
pub const SOURCE_PROVIDER_TRUST_KEY_BYTES: usize = 344;
/// Exact authenticated trust-head-link length.
pub const SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES: usize = 160;
/// Maximum authenticated trust heads retained in one protected snapshot.
pub const MAXIMUM_SOURCE_PROVIDER_TRUST_HEADS: usize = 256;
/// Largest canonical protected trust record.
pub const MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES: usize = SOURCE_PROVIDER_TRUST_HEADER_BYTES
    + MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS * SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES
    + MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS * SOURCE_PROVIDER_TRUST_KEY_BYTES
    + MAXIMUM_SOURCE_PROVIDER_TRUST_HEADS * SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES;

const MAGIC: &[u8; 8] = b"AOSPTRS2";

type ProtectedTrustHead = (u64, ObjectDigest, u64, ObjectDigest);

/// Describes one manifest-authenticated trust/revocation head and predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedTrustHeadLinkV2 {
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    predecessor_trust_generation: u64,
    predecessor_trust_digest: ObjectDigest,
    predecessor_revocation_generation: u64,
    predecessor_revocation_digest: ObjectDigest,
}

/// Holds one decoded trust file and its protocol trust model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderTrustFileV1 {
    trust_set: SourceProviderTrustSetV1,
    authority_state_heads: Vec<(SourceProviderAuthorityV1, ProtectedTrustHead)>,
    key_history: Vec<(
        SourceProviderSigningKeyV1,
        ProtectedTrustHead,
        ProtectedTrustHead,
    )>,
    history: Vec<ProtectedTrustHeadLinkV2>,
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
            || read_u16(bytes, 8)? != 2
        {
            return Err(SourceProviderSecurityError::format("trust", "header"));
        }
        require_zero(bytes, 10, 16, "trust", "header reserved")?;
        require_zero(bytes, 102, 104, "trust", "count reserved")?;

        let authority_count = usize::from(read_u16(bytes, 96)?);
        let key_count = usize::from(read_u16(bytes, 98)?);
        let history_count = usize::from(read_u16(bytes, 100)?);
        if authority_count == 0
            || authority_count > MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS
            || key_count == 0
            || key_count > MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS
            || history_count == 0
            || history_count > MAXIMUM_SOURCE_PROVIDER_TRUST_HEADS
        {
            return Err(SourceProviderSecurityError::format("trust", "counts"));
        }
        let authority_bytes = authority_count
            .checked_mul(SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES)
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        let key_bytes = key_count
            .checked_mul(SOURCE_PROVIDER_TRUST_KEY_BYTES)
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        let history_bytes = history_count
            .checked_mul(SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES)
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        let exact_length = SOURCE_PROVIDER_TRUST_HEADER_BYTES
            .checked_add(authority_bytes)
            .and_then(|length| length.checked_add(key_bytes))
            .and_then(|length| length.checked_add(history_bytes))
            .ok_or(SourceProviderSecurityError::format("trust", "length"))?;
        if bytes.len() != exact_length {
            return Err(SourceProviderSecurityError::format("trust", "length"));
        }

        let mut authorities = Vec::with_capacity(authority_count);
        let mut authority_state_heads = Vec::with_capacity(authority_count);
        for index in 0..authority_count {
            let offset =
                SOURCE_PROVIDER_TRUST_HEADER_BYTES + index * SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES;
            let record = &bytes[offset..offset + SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES];
            let authority = decode_authority(&record[..80])?;
            authority_state_heads.push((authority.authority().clone(), decode_head(record, 80)?));
            authorities.push(authority);
        }
        let key_offset = SOURCE_PROVIDER_TRUST_HEADER_BYTES + authority_bytes;
        let mut keys = Vec::with_capacity(key_count);
        let mut key_history = Vec::with_capacity(key_count);
        for index in 0..key_count {
            let offset = key_offset + index * SOURCE_PROVIDER_TRUST_KEY_BYTES;
            let record = &bytes[offset..offset + SOURCE_PROVIDER_TRUST_KEY_BYTES];
            let key = decode_key(&record[..184])?;
            let issuance_head = decode_head(record, 184)?;
            let earliest_deactivation_head = decode_head(record, 264)?;
            key_history.push((
                key.signer().clone(),
                issuance_head,
                earliest_deactivation_head,
            ));
            keys.push(key);
        }
        let history_offset = key_offset + key_bytes;
        let mut history = Vec::with_capacity(history_count);
        for index in 0..history_count {
            let offset = history_offset + index * SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES;
            history.push(decode_trust_head_link(
                &bytes[offset..offset + SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES],
            )?);
        }
        validate_trust_history(&history)?;
        if authority_state_heads
            .iter()
            .any(|(_, effective)| !history.iter().any(|head| head.head() == *effective))
            || key_history.iter().any(|(_, issuance, effective)| {
                !history.iter().any(|head| head.head() == *issuance)
                    || !history.iter().any(|head| head.head() == *effective)
            })
        {
            return Err(SourceProviderSecurityError::format(
                "trust",
                "key issuance head",
            ));
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
        for key in trust_set.keys() {
            let (_, issuance, effective) = key_history
                .iter()
                .find(|(signer, _, _)| signer == key.signer())
                .ok_or(SourceProviderSecurityError::format("trust", "key history"))?;
            let issuance_index = history.iter().position(|head| head.head() == *issuance);
            let effective_index = history.iter().position(|head| head.head() == *effective);
            let valid_epoch = matches!(
                (issuance_index, effective_index),
                (Some(left), Some(right)) if left <= right
            );
            let valid_state_epoch = match key.state() {
                SourceProviderKeyTrustStateV1::Eligible => issuance == effective,
                SourceProviderKeyTrustStateV1::Superseded
                | SourceProviderKeyTrustStateV1::Revoked => issuance != effective,
            };
            if !valid_epoch || !valid_state_epoch {
                return Err(SourceProviderSecurityError::format(
                    "trust",
                    "key state epoch",
                ));
            }
        }
        let current = history
            .last()
            .ok_or(SourceProviderSecurityError::format("trust", "history"))?;
        if current.head()
            != (
                trust_set.trust_generation(),
                trust_set.trust_digest(),
                trust_set.revocation_generation(),
                trust_set.revocation_digest(),
            )
        {
            return Err(SourceProviderSecurityError::format(
                "trust",
                "current history head",
            ));
        }
        Ok(Self {
            trust_set,
            authority_state_heads,
            key_history,
            history,
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

    /// Returns the complete protected, oldest-to-newest trust-head chain.
    #[must_use]
    pub fn history(&self) -> &[ProtectedTrustHeadLinkV2] {
        &self.history
    }

    /// Resolves one signing-key identity to its issuance and current-state epochs.
    #[must_use]
    pub fn key_history(
        &self,
        signer: &SourceProviderSigningKeyV1,
    ) -> Option<(
        (u64, ObjectDigest, u64, ObjectDigest),
        (u64, ObjectDigest, u64, ObjectDigest),
    )> {
        self.key_history
            .iter()
            .find(|(candidate, _, _)| candidate == signer)
            .map(|(_, issuance, effective)| (*issuance, *effective))
    }

    /// Resolves one authority identity to its authenticated current-state epoch.
    #[must_use]
    pub fn authority_state_head(
        &self,
        authority: &SourceProviderAuthorityV1,
    ) -> Option<(u64, ObjectDigest, u64, ObjectDigest)> {
        self.authority_state_heads
            .iter()
            .find(|(candidate, _)| candidate == authority)
            .map(|(_, head)| *head)
    }
}

impl ProtectedTrustHeadLinkV2 {
    /// Returns this link's trust and revocation heads.
    #[must_use]
    pub const fn head(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.trust_generation,
            self.trust_digest,
            self.revocation_generation,
            self.revocation_digest,
        )
    }

    /// Returns this link's exact predecessor heads, or all zeroes for genesis.
    #[must_use]
    pub const fn predecessor(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.predecessor_trust_generation,
            self.predecessor_trust_digest,
            self.predecessor_revocation_generation,
            self.predecessor_revocation_digest,
        )
    }
}

fn decode_trust_head_link(
    bytes: &[u8],
) -> Result<ProtectedTrustHeadLinkV2, SourceProviderSecurityError> {
    Ok(ProtectedTrustHeadLinkV2 {
        trust_generation: read_u64(bytes, 0)?,
        trust_digest: ObjectDigest::from_bytes(read_array(bytes, 8)?),
        revocation_generation: read_u64(bytes, 40)?,
        revocation_digest: ObjectDigest::from_bytes(read_array(bytes, 48)?),
        predecessor_trust_generation: read_u64(bytes, 80)?,
        predecessor_trust_digest: ObjectDigest::from_bytes(read_array(bytes, 88)?),
        predecessor_revocation_generation: read_u64(bytes, 120)?,
        predecessor_revocation_digest: ObjectDigest::from_bytes(read_array(bytes, 128)?),
    })
}

fn decode_head(
    bytes: &[u8],
    offset: usize,
) -> Result<ProtectedTrustHead, SourceProviderSecurityError> {
    Ok((
        read_u64(bytes, offset)?,
        ObjectDigest::from_bytes(read_array(bytes, offset + 8)?),
        read_u64(bytes, offset + 40)?,
        ObjectDigest::from_bytes(read_array(bytes, offset + 48)?),
    ))
}

fn validate_trust_history(
    history: &[ProtectedTrustHeadLinkV2],
) -> Result<(), SourceProviderSecurityError> {
    let zero = ObjectDigest::from_bytes([0; 32]);
    for (index, link) in history.iter().enumerate() {
        let (trust_generation, trust_digest, revocation_generation, revocation_digest) =
            link.head();
        if trust_generation == 0
            || trust_digest == zero
            || revocation_generation == 0
            || revocation_digest == zero
        {
            return Err(SourceProviderSecurityError::format("trust", "history head"));
        }
        let expected_predecessor = if index == 0 {
            (0, zero, 0, zero)
        } else {
            history[index - 1].head()
        };
        if link.predecessor() != expected_predecessor {
            return Err(SourceProviderSecurityError::format(
                "trust",
                "history predecessor",
            ));
        }
        if index > 0 {
            let (prior_trust, _, prior_revocation, _) = expected_predecessor;
            if trust_generation < prior_trust
                || revocation_generation < prior_revocation
                || (trust_generation == prior_trust && revocation_generation == prior_revocation)
            {
                return Err(SourceProviderSecurityError::format(
                    "trust",
                    "history generation",
                ));
            }
        }
    }
    Ok(())
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
        5 => SourceProviderKeyUsageV1::CatalogPublisher,
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
