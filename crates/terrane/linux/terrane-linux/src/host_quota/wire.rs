//! Owns the strict host-quota-local-v1 protobuf representation.
//!
//! ```text
//! QuotaQuery(version=1, request_id, epoch[16], owner_id, domain)
//! QuotaObservation(echo, sequence, result, live quota, complete roots)
//! ```

use prost::Message;
use std::io;

/// Carries the registered QuotaQuery message.
#[derive(Clone, PartialEq, Message)]
pub struct QuotaQuery {
    /// Carries the protocol `version` field.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Carries the protocol `request_id` field.
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// Carries the protocol `configuration_epoch` field.
    #[prost(bytes, tag = "3")]
    pub configuration_epoch: Vec<u8>,
    /// Carries the protocol `owner_id` field.
    #[prost(string, tag = "4")]
    pub owner_id: String,
    /// Carries the protocol `domain` field.
    #[prost(string, tag = "5")]
    pub domain: String,
}

/// Carries the registered QuotaRoot message.
#[derive(Clone, PartialEq, Message)]
pub struct QuotaRoot {
    /// Carries the protocol `role_directory` field.
    #[prost(string, tag = "1")]
    pub role_directory: String,
    /// Carries the protocol `device` field.
    #[prost(uint64, tag = "2")]
    pub device: u64,
    /// Carries the protocol `inode` field.
    #[prost(uint64, tag = "3")]
    pub inode: u64,
    /// Carries the protocol `project_inherit` field.
    #[prost(bool, tag = "4")]
    pub project_inherit: bool,
}

/// Carries the registered QuotaObservation message.
#[derive(Clone, PartialEq, Message)]
pub struct QuotaObservation {
    /// Carries the protocol `version` field.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Carries the protocol `request_id` field.
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// Carries the protocol `configuration_epoch` field.
    #[prost(bytes, tag = "3")]
    pub configuration_epoch: Vec<u8>,
    /// Carries the protocol `owner_id` field.
    #[prost(string, tag = "4")]
    pub owner_id: String,
    /// Carries the protocol `domain` field.
    #[prost(string, tag = "5")]
    pub domain: String,
    /// Carries the protocol `query_sequence` field.
    #[prost(uint64, tag = "6")]
    pub query_sequence: u64,
    /// Carries the protocol `result` field.
    #[prost(int32, tag = "7")]
    pub result: i32,
    /// Carries the protocol `filesystem_uuid` field.
    #[prost(bytes, tag = "8")]
    pub filesystem_uuid: Vec<u8>,
    /// Carries the protocol `project_id` field.
    #[prost(uint32, tag = "9")]
    pub project_id: u32,
    /// Carries the protocol `accounting` field.
    #[prost(bool, tag = "10")]
    pub accounting: bool,
    /// Carries the protocol `enforcement` field.
    #[prost(bool, tag = "11")]
    pub enforcement: bool,
    /// Carries the protocol `hard_limit_bytes` field.
    #[prost(uint64, tag = "12")]
    pub hard_limit_bytes: u64,
    /// Carries the protocol `charged_reserved_bytes` field.
    #[prost(uint64, tag = "13")]
    pub charged_reserved_bytes: u64,
    /// Carries the protocol `hard_inode_limit` field.
    #[prost(uint64, tag = "14")]
    pub hard_inode_limit: u64,
    /// Carries the protocol `charged_inodes` field.
    #[prost(uint64, tag = "15")]
    pub charged_inodes: u64,
    /// Carries the protocol `roots` field.
    #[prost(message, repeated, tag = "16")]
    pub roots: Vec<QuotaRoot>,
    /// Carries the protocol `tier_charge_budget_bytes` field.
    #[prost(uint64, tag = "17")]
    pub tier_charge_budget_bytes: u64,
    /// Carries the protocol `configured_limit_sum_bytes` field.
    #[prost(uint64, tag = "18")]
    pub configured_limit_sum_bytes: u64,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid host quota packet")
}

fn varint(bytes: &[u8], cursor: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or_else(invalid)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(invalid());
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(invalid())
}

fn field_mask(bytes: &[u8]) -> io::Result<u64> {
    let mut mask = 0u64;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let key = varint(bytes, &mut cursor)?;
        mask |= 1u64 << (key >> 3);
        if key & 7 == 0 {
            varint(bytes, &mut cursor)?;
        } else {
            let length = usize::try_from(varint(bytes, &mut cursor)?).map_err(|_| invalid())?;
            cursor = cursor
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(invalid)?;
        }
    }
    Ok(mask)
}

fn strict(bytes: &[u8], shapes: &[u8], repeated: usize) -> io::Result<()> {
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    let mut cursor = 0;
    let mut seen = 0u64;
    while cursor < bytes.len() {
        let key = varint(bytes, &mut cursor)?;
        let field = usize::try_from(key >> 3).map_err(|_| invalid())?;
        if field == 0 || field > shapes.len() || key & 7 != u64::from(shapes[field - 1]) {
            return Err(invalid());
        }
        let bit = 1u64 << field;
        if seen & bit != 0 && field != repeated {
            return Err(invalid());
        }
        seen |= bit;
        if key & 7 == 0 {
            let value = varint(bytes, &mut cursor)?;
            if ((shapes.len() == 5 && field == 1)
                || (shapes.len() == 18 && [1, 7, 9].contains(&field)))
                && value > u64::from(u32::MAX)
            {
                return Err(invalid());
            }
            if ((shapes.len() == 4 && field == 4)
                || (shapes.len() == 18 && [10, 11].contains(&field)))
                && value > 1
            {
                return Err(invalid());
            }
        } else {
            let length = usize::try_from(varint(bytes, &mut cursor)?).map_err(|_| invalid())?;
            let end = cursor
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(invalid)?;
            if field == repeated {
                strict(&bytes[cursor..end], &[2, 0, 0, 0], 0)?;
            }
            cursor = end;
        }
    }
    Ok(())
}

impl QuotaQuery {
    /// Decodes one bounded packet while rejecting schema extensions and ambiguity.
    ///
    /// # Errors
    /// Returns an error for malformed, unknown, duplicate or missing fields.
    pub fn decode_strict(bytes: &[u8]) -> io::Result<Self> {
        strict(bytes, &[0, 0, 2, 2, 2], 0)?;
        let query = Self::decode(bytes).map_err(|_| invalid())?;
        if query.version != 1
            || query.request_id == 0
            || query.configuration_epoch.len() != 16
            || query.owner_id.is_empty()
            || query.owner_id.len() > 256
            || query.domain.is_empty()
            || query.domain.len() > 256
        {
            return Err(invalid());
        }
        terrane_format::properties::Domain::parse(&query.domain).map_err(|_| invalid())?;
        Ok(query)
    }
}

impl QuotaObservation {
    /// Decodes one bounded response with a closed field vocabulary.
    ///
    /// # Errors
    /// Returns an error for malformed fields or invalid observation bounds.
    pub fn decode_strict(bytes: &[u8]) -> io::Result<Self> {
        strict(
            bytes,
            &[0, 0, 2, 2, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
            16,
        )?;
        let value = Self::decode(bytes).map_err(|_| invalid())?;
        if value.result != 0 && field_mask(bytes)? & !0xfe != 0 {
            return Err(invalid());
        }
        if value.version != 1
            || value.request_id == 0
            || value.configuration_epoch.len() != 16
            || value.query_sequence == 0
            || !(0..=5).contains(&value.result)
            || value.roots.len() > 32
        {
            return Err(invalid());
        }
        terrane_format::properties::Domain::parse(&value.domain).map_err(|_| invalid())?;
        if value.owner_id.is_empty() || value.owner_id.len() > 256 || value.domain.len() > 256 {
            return Err(invalid());
        }
        if value.result == 0 {
            if value.filesystem_uuid.len() != 16
                || value.project_id == 0
                || !value.accounting
                || !value.enforcement
                || value.hard_limit_bytes == 0
                || value.roots.is_empty()
                || value.configured_limit_sum_bytes > value.tier_charge_budget_bytes
            {
                return Err(invalid());
            }
        } else if !value.filesystem_uuid.is_empty()
            || value.project_id != 0
            || value.accounting
            || value.enforcement
            || value.hard_limit_bytes != 0
            || value.charged_reserved_bytes != 0
            || value.hard_inode_limit != 0
            || value.charged_inodes != 0
            || !value.roots.is_empty()
            || value.tier_charge_budget_bytes != 0
            || value.configured_limit_sum_bytes != 0
        {
            return Err(invalid());
        }
        if value.result == 0 {
            let mut labels = std::collections::BTreeSet::new();
            let mut identities = std::collections::BTreeSet::new();
            if !(super::ROOT_LABELS.len()..=super::ROOT_LABELS.len() + 1)
                .contains(&value.roots.len())
                || value.configured_limit_sum_bytes < value.hard_limit_bytes
                || value.roots.iter().any(|root| {
                    !root.project_inherit
                        || (!super::ROOT_LABELS.contains(&root.role_directory.as_str())
                            && root.role_directory != "administrative-root")
                        || !labels.insert(&root.role_directory)
                        || !identities.insert((root.device, root.inode))
                })
            {
                return Err(invalid());
            }
            if !super::ROOT_LABELS
                .iter()
                .all(|label| labels.iter().any(|actual| actual.as_str() == *label))
            {
                return Err(invalid());
            }
        }
        Ok(value)
    }
}
