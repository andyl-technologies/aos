//! Encodes canonical version 2 and 3 project-census requests on the host quota socket.
//!
//! ```text
//! CensusQuery(version=2|3, request_id, epoch[16], owner_id, domain, excluded[])
//! v2: excluded(device, inode); v3: excluded(device, inode, optional birth(sec, ns))
//! CensusObservation(echo, sequence, result, quota_v1, excluded[], retained_count)
//! ```
//!
//! These diagnostic messages carry no native authority. Only an authenticated
//! helper client may construct verified census evidence. Version 1 quota packets
//! keep their original closed schema and decoder.

use super::{ProjectInode, ProjectInodeBinding, ProjectInodeBirth, QuotaObservation, QuotaQuery};
use prost::Message;
use std::{collections::BTreeSet, io};

/// Bounds original identities in one descriptor-free census request.
///
/// Every encoded request and response must also fit the unchanged 16 KiB packet
/// bound. Large incarnation lists can reach that byte bound before this count.
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
    /// Original creation time in version 3; forbidden in version 2.
    #[prost(message, optional, tag = "3")]
    pub birth: Option<CensusBirth>,
}

/// Carries an original inode creation timestamp in the version 3 schema.
#[derive(Clone, PartialEq, Message)]
pub struct CensusBirth {
    /// Signed creation seconds since the Unix epoch.
    #[prost(sint64, tag = "1")]
    pub seconds: i64,
    /// Fractional creation nanoseconds, strictly below one billion.
    #[prost(uint32, tag = "2")]
    pub nanoseconds: u32,
}

impl From<ProjectInode> for CensusInode {
    fn from(value: ProjectInode) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            birth: None,
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

impl From<ProjectInodeBinding> for CensusInode {
    fn from(value: ProjectInodeBinding) -> Self {
        Self {
            device: value.identity.device,
            inode: value.identity.inode,
            birth: value.birth.map(|birth| CensusBirth {
                seconds: birth.seconds,
                nanoseconds: birth.nanoseconds,
            }),
        }
    }
}

impl From<&CensusInode> for ProjectInodeBinding {
    fn from(value: &CensusInode) -> Self {
        Self {
            identity: ProjectInode::from(value),
            birth: value.birth.as_ref().map(|birth| ProjectInodeBirth {
                seconds: birth.seconds,
                nanoseconds: birth.nanoseconds,
            }),
        }
    }
}

/// Requests read-only census of an authenticated, host-configured charge owner.
#[derive(Clone, PartialEq, Message)]
pub struct CensusQuery {
    /// Protocol discriminator: 2 for raw inode numbers, 3 for incarnation bindings.
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
    /// Nonempty, bounded, distinct original identities to omit.
    ///
    /// Version 3 permits several creation times for the same inode number;
    /// matching any original excludes it. An absent timestamp excludes every
    /// incarnation of that number conservatively.
    #[prost(message, repeated, tag = "6")]
    pub excluded: Vec<CensusInode>,
}

impl CensusQuery {
    /// Decodes the canonical encoding of the explicitly versioned closed schema.
    ///
    /// # Errors
    /// Refuses oversized packets, unknown or duplicate fields, noncanonical
    /// encodings, invalid correlation, empty or duplicate original identities.
    pub fn decode_strict(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = canonical(bytes)?;
        QuotaQuery::decode_strict(&value.quota_query().encode_to_vec())?;
        if !matches!(value.version, 2 | 3) {
            return Err(invalid());
        }
        identities(value.version, &value.excluded)?;
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
    /// Protocol discriminator: 2 for raw inode numbers, 3 for incarnation bindings.
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
        if !matches!(value.version, 2 | 3) {
            return Err(invalid());
        }
        if value.result != 0 {
            if value.quota.is_some() || !value.excluded.is_empty() || value.retained_inodes != 0 {
                return Err(invalid());
            }
            return Ok(value);
        }

        identities(value.version, &value.excluded)?;
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

fn identities(version: u32, inodes: &[CensusInode]) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    if inodes.is_empty()
        || inodes.len() > MAX_CENSUS_EXCLUSIONS
        || (version == 3 && inodes.iter().all(|inode| inode.birth.is_none()))
    {
        return Err(invalid());
    }
    if inodes.iter().any(|inode| {
        inode.device == 0
            || inode.inode == 0
            || (version == 2 && inode.birth.is_some())
            || inode
                .birth
                .as_ref()
                .is_some_and(|birth| birth.nanoseconds >= 1_000_000_000)
            || !seen.insert((
                inode.device,
                inode.inode,
                inode
                    .birth
                    .as_ref()
                    .map(|birth| (birth.seconds, birth.nanoseconds)),
            ))
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
