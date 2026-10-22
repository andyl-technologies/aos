//! Encodes canonical version 2 project-census requests on the host quota socket.
//!
//! ```text
//! CensusQuery(version=2, request_id, epoch[16], owner_id, domain, excluded[])
//! CensusObservation(echo, sequence, result, quota_v1, excluded[], retained_count)
//! ```
//!
//! These diagnostic messages carry no native authority. Only an authenticated
//! helper client may construct verified census evidence. Version 1 quota packets
//! keep their original closed schema and decoder.

use super::{ProjectInode, QuotaObservation, QuotaQuery};
use prost::Message;
use std::{collections::BTreeSet, io};

/// Bounds original identities in one descriptor-free census request.
pub const MAX_CENSUS_EXCLUSIONS: usize = 512;

/// Identifies an inode omitted from a retained project census under every alias.
#[derive(Clone, PartialEq, Message)]
pub struct CensusInode {
    /// Nonzero original device identity, without a client-selected pathname.
    #[prost(uint64, tag = "1")]
    pub device: u64,
    /// Nonzero original inode number on that device.
    #[prost(uint64, tag = "2")]
    pub inode: u64,
}

impl From<ProjectInode> for CensusInode {
    fn from(value: ProjectInode) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
        }
    }
}

impl From<&CensusInode> for ProjectInode {
    fn from(value: &CensusInode) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
        }
    }
}

/// Requests read-only census of an authenticated, host-configured charge owner.
#[derive(Clone, PartialEq, Message)]
pub struct CensusQuery {
    /// Protocol discriminator, exactly 2.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Nonzero client-wide request identity.
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// Exact 16-byte protected host configuration epoch.
    #[prost(bytes, tag = "3")]
    pub configuration_epoch: Vec<u8>,
    /// Host-configured charge owner identifier.
    #[prost(string, tag = "4")]
    pub owner_id: String,
    /// Canonical disclosure domain authorized for the actual peer UID.
    #[prost(string, tag = "5")]
    pub domain: String,
    /// Nonempty, bounded, distinct original inode identities to omit.
    #[prost(message, repeated, tag = "6")]
    pub excluded: Vec<CensusInode>,
}

impl CensusQuery {
    /// Decodes only the canonical encoding of the closed version 2 query schema.
    ///
    /// # Errors
    /// Refuses oversized packets, unknown or duplicate fields, noncanonical
    /// encodings, invalid correlation, empty or duplicate original identities.
    pub fn decode_strict(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = canonical(bytes)?;
        QuotaQuery::decode_strict(&value.quota_query().encode_to_vec())?;
        if value.version != 2 {
            return Err(invalid());
        }
        identities(&value.excluded)?;
        Ok(value)
    }

    pub(super) fn quota_query(&self) -> QuotaQuery {
        QuotaQuery {
            version: 1,
            request_id: self.request_id,
            configuration_epoch: self.configuration_epoch.clone(),
            owner_id: self.owner_id.clone(),
            domain: self.domain.clone(),
        }
    }
}

/// Carries an actual helper census observation, separate from release authority.
#[derive(Clone, PartialEq, Message)]
pub struct CensusObservation {
    /// Protocol discriminator, exactly 2.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Echoed client-wide request identity.
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// Actual protected helper configuration epoch.
    #[prost(bytes, tag = "3")]
    pub configuration_epoch: Vec<u8>,
    /// Echoed configured owner identifier.
    #[prost(string, tag = "4")]
    pub owner_id: String,
    /// Echoed canonical disclosure domain.
    #[prost(string, tag = "5")]
    pub domain: String,
    /// Nonzero, increasing per-connection sequence.
    #[prost(uint64, tag = "6")]
    pub query_sequence: u64,
    /// Existing quota result code; nonzero results carry correlation alone.
    #[prost(int32, tag = "7")]
    pub result: i32,
    /// Complete partition evidence with charges queried while counted inodes are held.
    #[prost(message, optional, tag = "8")]
    pub quota: Option<QuotaObservation>,
    /// Exact ordered echo of the original identities omitted from that census.
    #[prost(message, repeated, tag = "9")]
    pub excluded: Vec<CensusInode>,
    /// Distinct non-excluded inodes held through the actual quota observation.
    #[prost(uint64, tag = "10")]
    pub retained_inodes: u64,
}

impl CensusObservation {
    /// Decodes a canonical closed response without accepting bare wire authority.
    ///
    /// # Errors
    /// Refuses malformed correlation, invalid partition evidence, excessive
    /// retained counts, ambiguous identities and evidence on an error response.
    pub fn decode_strict(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = canonical(bytes)?;
        let correlation = QuotaObservation {
            version: 1,
            request_id: value.request_id,
            configuration_epoch: value.configuration_epoch.clone(),
            owner_id: value.owner_id.clone(),
            domain: value.domain.clone(),
            query_sequence: value.query_sequence,
            result: if value.result == 0 { 4 } else { value.result },
            ..QuotaObservation::default()
        };
        QuotaObservation::decode_strict(&correlation.encode_to_vec())?;
        if value.version != 2 {
            return Err(invalid());
        }
        if value.result != 0 {
            if value.quota.is_some() || !value.excluded.is_empty() || value.retained_inodes != 0 {
                return Err(invalid());
            }
            return Ok(value);
        }

        identities(&value.excluded)?;
        let quota = value.quota.as_ref().ok_or_else(invalid)?;
        QuotaObservation::decode_strict(&quota.encode_to_vec())?;
        let root = quota.roots.first().ok_or_else(invalid)?;
        if quota.result != 0
            || quota.request_id != value.request_id
            || quota.configuration_epoch != value.configuration_epoch
            || quota.owner_id != value.owner_id
            || quota.domain != value.domain
            || quota.query_sequence != value.query_sequence
            || value.retained_inodes == 0
            || value.retained_inodes > quota.charged_inodes
            || root.device == 0
            || quota
                .roots
                .iter()
                .any(|entry| entry.device != root.device || entry.inode == 0)
            || value
                .excluded
                .iter()
                .any(|inode| inode.device != root.device)
        {
            return Err(invalid());
        }
        Ok(value)
    }
}

fn identities(inodes: &[CensusInode]) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    if inodes.is_empty() || inodes.len() > MAX_CENSUS_EXCLUSIONS {
        return Err(invalid());
    }
    if inodes.iter().any(|inode| {
        inode.device == 0 || inode.inode == 0 || !seen.insert((inode.device, inode.inode))
    }) {
        return Err(invalid());
    }
    Ok(())
}

fn canonical<M: Message + Default>(bytes: &[u8]) -> io::Result<M> {
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    let value = M::decode(bytes).map_err(|_| invalid())?;
    if value.encode_to_vec() != bytes {
        return Err(invalid());
    }
    Ok(value)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid host census packet")
}
