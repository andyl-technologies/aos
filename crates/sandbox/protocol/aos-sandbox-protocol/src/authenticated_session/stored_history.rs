//! Canonical historical stored-session DATA, without protected provenance.
//!
//! ```text
//! ordinary key: AOSBSJ01 | protocol:u8
//! Recover Inventory18 key: AOSBRI01 | Storage protocol:u8
//! Stop cleanup key: AOSBHS01 | Host protocol:u8
//! NoApply cleanup key: AOSBHN01 | Host protocol:u8
//! value: AOSBSJ01 | version:u16be=2/3 | protocol:u8 | endpoint:u8 |
//! generation:u64be | stable-endpoint[32] | publication[32] | catalog[32] |
//! history-head[32] | history-length:u32be | canonical durable history |
//! (V3: checkpoint-length:u32be | canonical AOSBSCP1) | sha256[32]
//! ```
//!
//! Shape and cryptographic self-consistency do not establish a live session,
//! required floor, policy currentness, protected journal or resend authority.
//! Concrete owners independently source pins and actual original archives.

use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES, BrokerSessionDurableEndpointV1,
    BrokerSessionDurableHistoryV1, BrokerSessionProtocolV1,
};
use sha2::{Digest as _, Sha256};

mod capture;

pub use capture::{StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryEncodeCaptureV1};

use super::historical_checkpoint::{self, HistoricalCheckpointErrorV1, HistoricalSessionCheckpointV1};

/// Reports malformed or inconsistent canonical historical stored-session DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoredBrokerSessionHistoryErrorV1 {
    /// The original closed carrier could not be decoded or reproduced.
    #[error("invalid historical stored Broker Session Authentication carrier")]
    Invalid,
}

impl From<HistoricalCheckpointErrorV1> for StoredBrokerSessionHistoryErrorV1 {
    fn from(_: HistoricalCheckpointErrorV1) -> Self {
        Self::Invalid
    }
}

/// Exact protocol-key prefix, without journal-namespace authority.
pub const KEY_MAGIC: &[u8; 8] = b"AOSBSJ01";
/// Names the distinct Inventory18-only Recover head in the same protected file.
///
/// This key never replaces the ordinary head or settles its uncertainty.
pub const OPERATOR_RECOVER_KEY_MAGIC_V1: &[u8; 8] = b"AOSBRI01";

/// Names the separate fresh Host Stop cleanup head without replacing old Stop.
pub const HOST_STOP_CLEANUP_KEY_MAGIC_V1: &[u8; 8] = b"AOSBHS01";

/// Names the separate fresh Host NoApply cleanup head without adopting old C18.
pub const HOST_NO_APPLY_CLEANUP_KEY_MAGIC_V1: &[u8; 8] = b"AOSBHN01";

/// Distinguishes finite canonical row purposes without granting journal authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StoredBrokerSessionPurposeDataV2 {
    /// The established ordinary protocol head.
    #[default]
    Ordinary,
    /// The separate signed Inventory18-only OperatorRecover observation head.
    OperatorRecoverInventory,
    /// The fresh Host Stop cleanup head, restricted to methods 1 and 3.
    HostStopCleanup,
    /// The fresh Host NoApply cleanup head, restricted to methods 42 and 43.
    HostNoApplyCleanup,
}

/// Classifies a complete canonical protocol key as passive format DATA.
///
/// # Errors
/// Rejects unknown prefixes/codes and a purpose with the wrong protocol.
pub fn classify_protocol_key_v2(key: &[u8])
    -> Result<(StoredBrokerSessionPurposeDataV2, BrokerSessionProtocolV1), StoredBrokerSessionHistoryErrorV1>
{
    if key.len() != CANONICAL_PROTOCOL_KEY_BYTES_V1 {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let protocol = decode_protocol(key[8])?;
    let purpose = if key.starts_with(KEY_MAGIC) {
        StoredBrokerSessionPurposeDataV2::Ordinary
    } else if key.starts_with(OPERATOR_RECOVER_KEY_MAGIC_V1) && protocol == BrokerSessionProtocolV1::Storage {
        StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory
    } else if key.starts_with(HOST_STOP_CLEANUP_KEY_MAGIC_V1) && protocol == BrokerSessionProtocolV1::Host {
        StoredBrokerSessionPurposeDataV2::HostStopCleanup
    } else if key.starts_with(HOST_NO_APPLY_CLEANUP_KEY_MAGIC_V1) && protocol == BrokerSessionProtocolV1::Host {
        StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup
    } else {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    };
    Ok((purpose, protocol))
}

/// Produces the fixed Recover Inventory18 key as comparison DATA.
#[must_use]
pub fn canonical_operator_recover_inventory_key_v1() -> Vec<u8> {
    protocol_key_for_purpose_v2(BrokerSessionProtocolV1::Storage,
        StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory)
}

fn protocol_key_for_purpose_v2(protocol: BrokerSessionProtocolV1,
    purpose: StoredBrokerSessionPurposeDataV2,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(CANONICAL_PROTOCOL_KEY_BYTES_V1);
    key.extend_from_slice(match purpose {
        StoredBrokerSessionPurposeDataV2::Ordinary => KEY_MAGIC,
        StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory => OPERATOR_RECOVER_KEY_MAGIC_V1,
        StoredBrokerSessionPurposeDataV2::HostStopCleanup => HOST_STOP_CLEANUP_KEY_MAGIC_V1,
        StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => HOST_NO_APPLY_CLEANUP_KEY_MAGIC_V1,
    });
    key.push(protocol_code(protocol));
    key
}

/// Produces the separate fresh Host Stop cleanup key as comparison DATA.
#[must_use]
pub fn canonical_host_stop_cleanup_key_v1() -> Vec<u8> {
    protocol_key_for_purpose_v2(BrokerSessionProtocolV1::Host,
        StoredBrokerSessionPurposeDataV2::HostStopCleanup)
}

/// Produces the separate fresh Host NoApply cleanup key as comparison DATA.
#[must_use]
pub fn canonical_host_no_apply_cleanup_key_v1() -> Vec<u8> {
    protocol_key_for_purpose_v2(BrokerSessionProtocolV1::Host,
        StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup)
}
/// Exact stored-session value prefix.
pub const VALUE_MAGIC: &[u8; 8] = b"AOSBSJ01";
/// Original carrier version without signed historical hello evidence.
pub const VALUE_VERSION_V2: u16 = 2;
/// Original carrier version retaining signed historical hello evidence.
pub const VALUE_VERSION_V3: u16 = 3;
/// Minimum complete V2 carrier bytes, including its digest.
pub const VALUE_FIXED_BYTES_V2: usize = 184;
/// Minimum complete V3 carrier bytes, including checkpoint length and digest.
pub const VALUE_FIXED_BYTES_V3: usize = 188;
/// Complete stored-carrier digest width.
pub const VALUE_DIGEST_BYTES: usize = 32;
const VALUE_DOMAIN_V2: &[u8] = b"aos.sandbox.broker-session.protected-history.v2\0";
const VALUE_DOMAIN_V3: &[u8] = b"aos.sandbox.broker-session.protected-history.v3\0";

/// Retains portable historical comparison fields, never a protected owner cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBrokerSessionHistoryV1 {
    /// Closed signed protocol selected by the original carrier.
    pub protocol: BrokerSessionProtocolV1,
    /// Original client or broker endpoint direction.
    pub endpoint: BrokerSessionDurableEndpointV1,
    /// Nonzero original protected-snapshot generation, as comparison DATA.
    pub generation: u64,
    /// Original stable endpoint identity; independently sourced custody required.
    pub stable_endpoint_identity: [u8; 32],
    /// Original endpoint publication comparison commitment.
    pub endpoint_publication: [u8; 32],
    /// Original catalog comparison commitment, not current policy authority.
    pub current_catalog: [u8; 32],
    /// Exact durable history head comparison commitment.
    pub current_head: [u8; 32],
    /// Exact bounded canonical durable history, including full signed packets.
    pub history: Vec<u8>,
    /// V3 signed hello/context evidence; absent for original V2 data.
    pub checkpoint: Option<HistoricalSessionCheckpointV1>,
}

impl StoredBrokerSessionHistoryV1 {
    /// Decodes the complete canonical durable history without granting custody.
    ///
    /// # Errors
    /// Rejects malformed, discontinuous or oversized historical records.
    pub fn history_model(
        &self,
    ) -> Result<BrokerSessionDurableHistoryV1, StoredBrokerSessionHistoryErrorV1> {
        BrokerSessionDurableHistoryV1::decode(&self.history)
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)
    }

    /// Borrows historical fields without copying history or checkpoint bytes.
    #[must_use]
    pub fn as_view(&self) -> StoredBrokerSessionHistoryViewV1<'_> {
        StoredBrokerSessionHistoryViewV1 {
            protocol: self.protocol,
            endpoint: self.endpoint,
            generation: self.generation,
            stable_endpoint_identity: self.stable_endpoint_identity,
            endpoint_publication: self.endpoint_publication,
            current_catalog: self.current_catalog,
            current_head: self.current_head,
            history: &self.history,
            checkpoint: self.checkpoint.as_ref(),
        }
    }

    /// Encodes canonical historical DATA, never a protected current head.
    ///
    /// # Errors
    /// Rejects malformed history, checkpoint linkage, zero bindings or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1> {
        self.as_view().encode()
    }

    /// Decodes one exact V2 or V3 carrier without granting provenance.
    ///
    /// V2 remains V2 and cannot establish original signed-session provenance.
    ///
    /// # Errors
    /// Rejects malformed keys, closed codes, lengths, nested data or digest.
    pub fn decode(key: &[u8], value: &[u8]) -> Result<Self, StoredBrokerSessionHistoryErrorV1> {
        capture::decode_engine(key, value, None)
    }
}

/// Borrows historical comparison DATA without copying its bounded payloads.
///
/// This view grants no protected journal, live session, floor or currentness.
/// All fields remain nonauthorizing comparison data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredBrokerSessionHistoryViewV1<'history> {
    /// Closed signed protocol selected by the original carrier.
    pub protocol: BrokerSessionProtocolV1,
    /// Original client or broker endpoint direction.
    pub endpoint: BrokerSessionDurableEndpointV1,
    /// Nonzero original protected-snapshot generation, as comparison DATA.
    pub generation: u64,
    /// Original stable endpoint identity; independently sourced custody required.
    pub stable_endpoint_identity: [u8; 32],
    /// Original endpoint publication comparison commitment.
    pub endpoint_publication: [u8; 32],
    /// Original catalog comparison commitment, not current policy authority.
    pub current_catalog: [u8; 32],
    /// Exact durable history head comparison commitment.
    pub current_head: [u8; 32],
    /// Exact bounded canonical durable history, including full signed packets.
    pub history: &'history [u8],
    /// V3 signed hello/context evidence; absent for original V2 data.
    pub checkpoint: Option<&'history HistoricalSessionCheckpointV1>,
}

impl StoredBrokerSessionHistoryViewV1<'_> {
    /// Encodes canonical historical DATA, never a protected current head.
    ///
    /// # Errors
    /// Rejects malformed history, checkpoint linkage, zero bindings or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1> {
        capture::encode_engine(self, None, StoredBrokerSessionPurposeDataV2::Ordinary)
    }

    /// Encodes only signed Inventory18-only Recover history as passive DATA.
    ///
    /// # Errors
    /// Rejects a missing signed checkpoint, a different profile/method, or any
    /// existing canonical history, linkage, length, or checksum error.
    pub fn encode_operator_recover_inventory_v1(&self)
        -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1>
    {
        capture::encode_engine(self, None, StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory)
    }

    /// Encodes only the signed fresh Host Stop cleanup history as passive DATA.
    ///
    /// # Errors
    /// Rejects a different signed profile, ordinary Stop body, missing checkpoint,
    /// or any shared canonical history, linkage, length or checksum error.
    pub fn encode_host_stop_cleanup_v1(&self)
        -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1>
    {
        capture::encode_engine(self, None, StoredBrokerSessionPurposeDataV2::HostStopCleanup)
    }

    /// Encodes only the signed fresh Host NoApply cleanup history as passive DATA.
    ///
    /// # Errors
    /// Rejects a different signed profile, methods outside 42/43, missing signed
    /// checkpoint, forbidden ordinary authorization, or any shared history error.
    pub fn encode_host_no_apply_cleanup_v1(&self)
        -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1>
    {
        capture::encode_engine(self, None, StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup)
    }
}

/// Computes the sole canonical protocol-row key, without journal authority.
#[must_use]
pub fn canonical_protocol_key_v1(protocol: BrokerSessionProtocolV1) -> Vec<u8> {
    protocol_key_for_purpose_v2(protocol, StoredBrokerSessionPurposeDataV2::Ordinary)
}

fn protocol_code(protocol: BrokerSessionProtocolV1) -> u8 {
    protocol.code()
}

fn decode_protocol(code: u8) -> Result<BrokerSessionProtocolV1, StoredBrokerSessionHistoryErrorV1> {
    BrokerSessionProtocolV1::from_code(code)
        .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)
}

fn endpoint_code(endpoint: BrokerSessionDurableEndpointV1) -> u8 {
    match endpoint {
        BrokerSessionDurableEndpointV1::Client => 1,
        BrokerSessionDurableEndpointV1::Broker => 2,
    }
}

fn decode_endpoint(
    code: u8,
) -> Result<BrokerSessionDurableEndpointV1, StoredBrokerSessionHistoryErrorV1> {
    match code {
        1 => Ok(BrokerSessionDurableEndpointV1::Client),
        2 => Ok(BrokerSessionDurableEndpointV1::Broker),
        _ => Err(StoredBrokerSessionHistoryErrorV1::Invalid),
    }
}

fn value_digest(value_without_digest: &[u8], version: u16) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(if version == VALUE_VERSION_V3 {
        VALUE_DOMAIN_V3
    } else {
        VALUE_DOMAIN_V2
    });
    digest.update(value_without_digest);
    digest.finalize().into()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, StoredBrokerSessionHistoryErrorV1> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, StoredBrokerSessionHistoryErrorV1> {
    bytes
        .get(offset)
        .copied()
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, StoredBrokerSessionHistoryErrorV1> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, StoredBrokerSessionHistoryErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StoredBrokerSessionHistoryErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;

    bytes
        .get(offset..end)
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
        .try_into()
        .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_adapter_preserves_invalid_history_errors_for_unknown_codes() {
        assert_eq!(protocol_code(BrokerSessionProtocolV1::Nix), 6);
        assert_eq!(decode_protocol(6).unwrap(), BrokerSessionProtocolV1::Nix);

        for code in std::iter::once(0).chain(7..=u8::MAX) {
            assert_eq!(
                decode_protocol(code),
                Err(StoredBrokerSessionHistoryErrorV1::Invalid)
            );
        }
    }

    #[test]
    fn borrowed_view_retains_history_allocation_and_same_encoding_failure() {
        // This is deliberately malformed historical DATA, not a signed fixture
        // or protected owner. It checks borrowing and error compatibility only.
        let stored = StoredBrokerSessionHistoryV1 {
            protocol: BrokerSessionProtocolV1::Nix,
            endpoint: BrokerSessionDurableEndpointV1::Client,
            generation: 1,
            stable_endpoint_identity: [1; 32],
            endpoint_publication: [2; 32],
            current_catalog: [3; 32],
            current_head: [4; 32],
            history: b"invalid-history".to_vec(),
            checkpoint: None,
        };

        let view = stored.as_view();
        assert!(std::ptr::eq(view.history.as_ptr(), stored.history.as_ptr()));
        assert_eq!(view.history.len(), stored.history.len());
        assert_eq!(view.encode(), stored.encode());
        assert!(view.encode().is_err());
    }

    #[test]
    fn canonical_keys_preserve_closed_original_protocol_codes() {
        let protocols = [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Storage,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
            BrokerSessionProtocolV1::MountFuse,
            BrokerSessionProtocolV1::Nix,
        ];

        for (index, protocol) in protocols.into_iter().enumerate() {
            let key = canonical_protocol_key_v1(protocol);
            assert_eq!(&key[..8], KEY_MAGIC);
            assert_eq!(usize::from(key[8]), index + 1);
            assert_eq!(decode_protocol(key[8]).unwrap(), protocol);
        }

        assert!(decode_protocol(0).is_err());
        assert!(decode_protocol(7).is_err());
    }

    #[test]
    fn recover_key_is_disjoint_fixed_storage_and_rejects_unknown_purposes() {
        let recover = canonical_operator_recover_inventory_key_v1();
        assert_eq!(classify_protocol_key_v2(&recover).unwrap(),
            (StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory, BrokerSessionProtocolV1::Storage));
        assert_ne!(recover, canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage));
        for protocol in [BrokerSessionProtocolV1::Host, BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network, BrokerSessionProtocolV1::MountFuse,
            BrokerSessionProtocolV1::Nix] {
            let mut cross_role = recover.clone();
            cross_role[8] = protocol_code(protocol);
            assert!(classify_protocol_key_v2(&cross_role).is_err());
        }
        let mut unknown = recover.clone();
        unknown[7] = b'2';
        assert!(classify_protocol_key_v2(&unknown).is_err());
        assert!(classify_protocol_key_v2(&recover[..8]).is_err());
        let mut trailing = recover;
        trailing.push(0);
        assert!(classify_protocol_key_v2(&trailing).is_err());
    }

    #[test]
    fn host_cleanup_keys_cannot_alias_ordinary_or_cross_their_protocol() {
        let stop = canonical_host_stop_cleanup_key_v1();
        let no_apply = canonical_host_no_apply_cleanup_key_v1();
        let ordinary = canonical_protocol_key_v1(BrokerSessionProtocolV1::Host);
        assert_ne!(stop, no_apply);
        assert_ne!(stop, ordinary);
        assert_ne!(no_apply, ordinary);

        for (key, purpose) in [
            (stop, StoredBrokerSessionPurposeDataV2::HostStopCleanup),
            (no_apply, StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup),
        ] {
            assert_eq!(classify_protocol_key_v2(&key).unwrap(),
                (purpose, BrokerSessionProtocolV1::Host));
            for protocol in [BrokerSessionProtocolV1::Storage, BrokerSessionProtocolV1::Mount,
                BrokerSessionProtocolV1::Network, BrokerSessionProtocolV1::MountFuse,
                BrokerSessionProtocolV1::Nix] {
                let mut cross_role = key.clone();
                cross_role[8] = protocol_code(protocol);
                assert!(classify_protocol_key_v2(&cross_role).is_err());
            }
            assert!(classify_protocol_key_v2(&key[..8]).is_err());
            let mut trailing = key;
            trailing.push(0);
            assert!(classify_protocol_key_v2(&trailing).is_err());
        }
    }

    #[test]
    fn checked_reader_rejects_wrapping_or_truncated_offsets() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(read_array::<2>(&bytes, 1).unwrap(), [2, 3]);
        assert!(read_array::<2>(&bytes, usize::MAX).is_err());
        assert!(read_array::<2>(&bytes, 3).is_err());
    }

    #[test]
    fn both_original_versions_reject_oversized_nested_history_without_rewrite() {
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Nix);

        for (version, fixed_bytes) in [
            (VALUE_VERSION_V2, VALUE_FIXED_BYTES_V2),
            (VALUE_VERSION_V3, VALUE_FIXED_BYTES_V3),
        ] {
            let mut value = vec![0; fixed_bytes];
            value[..8].copy_from_slice(VALUE_MAGIC);
            value[8..10].copy_from_slice(&version.to_be_bytes());
            value[10] = protocol_code(BrokerSessionProtocolV1::Nix);
            value[11] = endpoint_code(BrokerSessionDurableEndpointV1::Client);
            value[148..152].copy_from_slice(&u32::MAX.to_be_bytes());

            assert!(StoredBrokerSessionHistoryV1::decode(&key, &value).is_err());
            assert_eq!(read_u16(&value, 8).unwrap(), version);
        }
    }
}

const CANONICAL_PROTOCOL_KEY_BYTES_V1: usize = 9;

/// Reports the actual canonical key encoder's fixed allocated byte capacity.
#[must_use]
pub const fn canonical_protocol_key_receiving_bytes_v1() -> usize { CANONICAL_PROTOCOL_KEY_BYTES_V1 }
