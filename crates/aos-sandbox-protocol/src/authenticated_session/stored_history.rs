//! Canonical historical stored-session DATA, without protected provenance.
//!
//! ```text
//! key: AOSBSJ01 | protocol:u8
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
        if value.len() < VALUE_FIXED_BYTES_V2
            || value.len()
                > VALUE_FIXED_BYTES_V3
                    .checked_add(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)
                    .and_then(|size| size.checked_add(historical_checkpoint::MAXIMUM_BYTES))
                    .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
            || value.get(..8) != Some(VALUE_MAGIC.as_slice())
        {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let version = read_u16(value, 8)?;
        if !matches!(version, VALUE_VERSION_V2 | VALUE_VERSION_V3) {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let protocol = decode_protocol(read_u8(value, 10)?)?;
        let endpoint = decode_endpoint(read_u8(value, 11)?)?;
        if key != canonical_protocol_key_v1(protocol) {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let generation = read_u64(value, 12)?;
        let stable_endpoint_identity = read_array(value, 20)?;
        let endpoint_publication = read_array(value, 52)?;
        let current_catalog = read_array(value, 84)?;
        let current_head = read_array(value, 116)?;
        let history_length = usize::try_from(read_u32(value, 148)?)
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let history_end = 152usize
            .checked_add(history_length)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let (checkpoint, digest_start) = if version == VALUE_VERSION_V3 {
            let length = usize::try_from(read_u32(value, history_end)?)
                .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
            if length == 0 || length > historical_checkpoint::MAXIMUM_BYTES {
                return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
            }
            let start = history_end
                .checked_add(4)
                .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
            let end = start
                .checked_add(length)
                .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
            let checkpoint = HistoricalSessionCheckpointV1::decode(
                value
                    .get(start..end)
                    .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?,
            )?;
            (Some(checkpoint), end)
        } else {
            (None, history_end)
        };
        let digest_end = digest_start
            .checked_add(VALUE_DIGEST_BYTES)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        if history_length == 0
            || history_length > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || digest_end != value.len()
            || read_array::<32>(value, digest_start)?
                != value_digest(&value[..digest_start], version)
        {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let history = value
            .get(152..history_end)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
            .to_vec();
        let stored = Self {
            protocol,
            endpoint,
            generation,
            stable_endpoint_identity,
            endpoint_publication,
            current_catalog,
            current_head,
            history,
            checkpoint,
        };
        if stored.encode()? != value {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        Ok(stored)
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
        let model = BrokerSessionDurableHistoryV1::decode(self.history)
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let head = model
            .head()
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        if let Some(checkpoint) = self.checkpoint {
            let transcript = checkpoint.verify()?;
            if transcript.protocol() != self.protocol
                || model.records().iter().any(|record| {
                    record.session_binding() != transcript.session_binding()
                        || record.protected_bindings().protected_context()
                            != checkpoint.context().protected_context_digest()
                        || record.protected_bindings().endpoint_publication()
                            != self.endpoint_publication
                })
            {
                return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
            }
        }
        if self.generation == 0
            || self.endpoint_publication.iter().all(|byte| *byte == 0)
            || self.stable_endpoint_identity.iter().all(|byte| *byte == 0)
            || self.current_catalog.iter().all(|byte| *byte == 0)
            || model.head_commitment() != self.current_head
            || head.protocol() != self.protocol
            || head.endpoint() != self.endpoint
        {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let history_length = u32::try_from(self.history.len())
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let checkpoint = self
            .checkpoint
            .map(HistoricalSessionCheckpointV1::encode)
            .transpose()?;
        let checkpoint_length = checkpoint.as_ref().map_or(0, Vec::len);
        let version = if checkpoint.is_some() {
            VALUE_VERSION_V3
        } else {
            VALUE_VERSION_V2
        };
        let capacity = VALUE_FIXED_BYTES_V3
            .checked_add(self.history.len())
            .and_then(|size| size.checked_add(checkpoint_length))
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        if self.history.len() > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || checkpoint_length > historical_checkpoint::MAXIMUM_BYTES
        {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let mut value = Vec::with_capacity(capacity);
        value.extend_from_slice(VALUE_MAGIC);
        value.extend_from_slice(&version.to_be_bytes());
        value.push(protocol_code(self.protocol));
        value.push(endpoint_code(self.endpoint));
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.stable_endpoint_identity);
        value.extend_from_slice(&self.endpoint_publication);
        value.extend_from_slice(&self.current_catalog);
        value.extend_from_slice(&self.current_head);
        value.extend_from_slice(&history_length.to_be_bytes());
        value.extend_from_slice(self.history);
        if let Some(checkpoint) = checkpoint {
            let length = u32::try_from(checkpoint.len())
                .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
            value.extend_from_slice(&length.to_be_bytes());
            value.extend_from_slice(&checkpoint);
        }
        let digest = value_digest(&value, version);
        value.extend_from_slice(&digest);
        Ok(value)
    }
}

/// Computes the sole canonical protocol-row key, without journal authority.
#[must_use]
pub fn canonical_protocol_key_v1(protocol: BrokerSessionProtocolV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.extend_from_slice(KEY_MAGIC);
    key.push(protocol_code(protocol));
    key
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
