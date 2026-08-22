//! Canonical scheduler-owned network continuation codec.
//!
//! The format records every directed link snapshot, symmetric-link RNG
//! cursor, and exact signal-fault wakeup in deterministic identity order.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use crate::{LinkId, NetworkLinkDirection};

use super::{SchedulerNetworkCheckpoint, SchedulerNetworkLinkCheckpoint};

impl SchedulerNetworkCheckpoint {
    /// Encodes every scheduler-owned directed link and shared RNG cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] when link identities are
    /// duplicated or out of order, a collection exceeds its hard bound, or one
    /// of the complete device-owned link snapshots is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SchedulerNetworkCheckpointCodecError> {
        self.canonical_bytes_with_limit(
            u64::try_from(HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX),
        )
    }

    /// Encodes the scheduler network continuation under an authored byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] under the same
    /// conditions as [`Self::canonical_bytes`], and when the representation or
    /// a nested link snapshot exceeds `maximum`.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, SchedulerNetworkCheckpointCodecError> {
        validate_scheduler_network_checkpoint(self)?;
        let configured = scheduler_network_configured(maximum);
        let encoded_length = scheduler_network_encoded_length(self, configured)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_length).map_err(|_| {
            scheduler_network_aggregate_resource(
                "scheduler network checkpoint bytes",
                0,
                encoded_length,
                configured,
            )
        })?;
        bytes.extend_from_slice(SCHEDULER_NETWORK_CHECKPOINT_MAGIC);
        write_scheduler_network_count(&mut bytes, self.links.len(), "directed links")?;
        for link in &self.links {
            write_scheduler_network_string(&mut bytes, &link.link.name)?;
            bytes.push(match link.direction {
                NetworkLinkDirection::EndpointAToEndpointB => 1,
                NetworkLinkDirection::EndpointBToEndpointA => 2,
            });
            write_scheduler_network_blob(
                &mut bytes,
                &link
                    .state
                    .canonical_bytes_with_limit(u64::try_from(configured).unwrap_or(u64::MAX))
                    .map_err(map_link_snapshot_error)?,
            )?;
        }
        write_scheduler_network_count(&mut bytes, self.rng_positions.len(), "RNG positions")?;
        for (link, position) in &self.rng_positions {
            write_scheduler_network_string(&mut bytes, &link.name)?;
            bytes.extend_from_slice(&position.to_le_bytes());
        }
        match self.signal_fault_wakeup_nanos {
            Some(wakeup) => {
                bytes.push(1);
                bytes.extend_from_slice(&wakeup.to_le_bytes());
            }
            None => bytes.push(0),
        }
        Ok(bytes)
    }

    /// Decodes and validates every scheduler-owned network continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] for unsupported,
    /// malformed, over-limit, duplicated, out-of-order, invalid nested, or
    /// trailing state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SchedulerNetworkCheckpointCodecError> {
        Self::from_canonical_bytes_with_limit(
            bytes,
            u64::try_from(HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX),
        )
    }

    /// Decodes a scheduler network continuation under an authored byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] under the same
    /// conditions as [`Self::from_canonical_bytes`], and before decoding when
    /// `bytes` exceeds `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, SchedulerNetworkCheckpointCodecError> {
        let configured = scheduler_network_configured(maximum);
        if bytes.len() > configured {
            return Err(scheduler_network_aggregate_resource(
                "scheduler network checkpoint bytes",
                0,
                bytes.len(),
                configured,
            ));
        }
        let mut reader = SchedulerNetworkCheckpointReader::new(bytes)?;
        let link_count = reader.count("directed links")?;
        let mut links = Vec::new();
        links.try_reserve_exact(link_count).map_err(|_| {
            scheduler_network_resource(
                "directed links",
                0,
                link_count,
                HARD_SCHEDULER_NETWORK_LINKS,
            )
        })?;
        for _ in 0..link_count {
            let link = LinkId::from_name(reader.string("link identity")?);
            let direction = match reader.byte("link direction")? {
                1 => NetworkLinkDirection::EndpointAToEndpointB,
                2 => NetworkLinkDirection::EndpointBToEndpointA,
                _ => {
                    return Err(SchedulerNetworkCheckpointCodecError::Malformed(
                        "link direction",
                    ));
                }
            };
            let state = crucible_device::LinkSnapshot::from_canonical_bytes_with_limit(
                reader.blob("link snapshot")?,
                u64::try_from(configured).unwrap_or(u64::MAX),
            )
            .map_err(map_link_snapshot_error)?;
            links.push(SchedulerNetworkLinkCheckpoint {
                link,
                direction,
                state,
            });
        }
        let rng_count = reader.count("RNG positions")?;
        let mut rng_positions = BTreeMap::new();
        for _ in 0..rng_count {
            let link = LinkId::from_name(reader.string("RNG link identity")?);
            let position = reader.u64("RNG position")?;
            if rng_positions.insert(link, position).is_some() {
                return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
            }
        }
        let signal_fault_wakeup_nanos = match reader.byte("fault wakeup tag")? {
            0 => None,
            1 => Some(reader.u64("fault wakeup")?),
            _ => {
                return Err(SchedulerNetworkCheckpointCodecError::Malformed(
                    "fault wakeup tag",
                ));
            }
        };
        reader.finish()?;
        let checkpoint = Self {
            links,
            rng_positions,
            signal_fault_wakeup_nanos,
        };
        validate_scheduler_network_checkpoint(&checkpoint)?;
        if checkpoint.canonical_bytes_with_limit(maximum)?.as_slice() != bytes {
            return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
        }
        Ok(checkpoint)
    }
}

const SCHEDULER_NETWORK_CHECKPOINT_MAGIC: &[u8] = b"crucible.scheduler-network.v1\0";
const HARD_SCHEDULER_NETWORK_LINKS: usize = 65_536;
const HARD_SCHEDULER_NETWORK_BLOB_BYTES: usize = 1 << 30;
const HARD_SCHEDULER_NETWORK_NAME_BYTES: usize = 4_096;
const HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024 * 1024;

/// Failure to encode or decode scheduler-owned network continuation state.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SchedulerNetworkCheckpointCodecError {
    /// The stored format version is unsupported.
    #[error("unsupported scheduler network checkpoint version")]
    Version,
    /// A field is truncated, invalid UTF-8, or has an unknown tag.
    #[error("malformed scheduler network checkpoint field `{0}`")]
    Malformed(&'static str),
    /// A representation or allocation exceeds its active resource ceiling.
    #[error(
        "scheduler network checkpoint `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Field whose bound was exceeded.
        field: &'static str,
        /// Units already retained by the operation.
        current: u64,
        /// Additional units requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// Link identities are duplicated, out of order, or have noncanonical bytes.
    #[error("noncanonical scheduler network checkpoint")]
    Noncanonical,
    /// A device-owned directed-link checkpoint is invalid.
    #[error(transparent)]
    Link(#[from] crucible_device::LinkSnapshotCodecError),
}

fn scheduler_network_encoded_length(
    checkpoint: &SchedulerNetworkCheckpoint,
    configured: usize,
) -> Result<usize, SchedulerNetworkCheckpointCodecError> {
    let mut length = SCHEDULER_NETWORK_CHECKPOINT_MAGIC.len();
    scheduler_network_add_length(&mut length, size_of::<u32>(), configured)?;
    for link in &checkpoint.links {
        scheduler_network_add_length(&mut length, size_of::<u32>(), configured)?;
        scheduler_network_add_length(&mut length, link.link.name.len(), configured)?;
        scheduler_network_add_length(&mut length, size_of::<u8>(), configured)?;
        let state_length = link
            .state
            .canonical_length_with_limit(u64::try_from(configured).unwrap_or(u64::MAX))
            .map_err(map_link_snapshot_error)?;
        scheduler_network_add_length(&mut length, size_of::<u32>(), configured)?;
        scheduler_network_add_length(&mut length, state_length, configured)?;
    }
    scheduler_network_add_length(&mut length, size_of::<u32>(), configured)?;
    for link in checkpoint.rng_positions.keys() {
        scheduler_network_add_length(&mut length, size_of::<u32>(), configured)?;
        scheduler_network_add_length(&mut length, link.name.len(), configured)?;
        scheduler_network_add_length(&mut length, size_of::<u64>(), configured)?;
    }
    scheduler_network_add_length(&mut length, size_of::<u8>(), configured)?;
    if checkpoint.signal_fault_wakeup_nanos.is_some() {
        scheduler_network_add_length(&mut length, size_of::<u64>(), configured)?;
    }
    Ok(length)
}

fn scheduler_network_add_length(
    current: &mut usize,
    requested: usize,
    configured: usize,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    let total = current.checked_add(requested).ok_or_else(|| {
        scheduler_network_aggregate_resource(
            "scheduler network checkpoint bytes",
            *current,
            requested,
            configured,
        )
    })?;
    if total > configured || total > HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES {
        return Err(scheduler_network_aggregate_resource(
            "scheduler network checkpoint bytes",
            *current,
            requested,
            configured,
        ));
    }
    *current = total;
    Ok(())
}

fn scheduler_network_configured(maximum: u64) -> usize {
    let hard = u64::try_from(HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX);
    usize::try_from(maximum.min(hard)).unwrap_or(usize::MAX)
}

fn scheduler_network_aggregate_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    configured: usize,
) -> SchedulerNetworkCheckpointCodecError {
    SchedulerNetworkCheckpointCodecError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: u64::try_from(configured).unwrap_or(u64::MAX),
        hard: u64::try_from(HARD_SCHEDULER_NETWORK_CHECKPOINT_BYTES).unwrap_or(u64::MAX),
    }
}

fn scheduler_network_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    hard: usize,
) -> SchedulerNetworkCheckpointCodecError {
    SchedulerNetworkCheckpointCodecError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: u64::try_from(hard).unwrap_or(u64::MAX),
        hard: u64::try_from(hard).unwrap_or(u64::MAX),
    }
}

fn map_link_snapshot_error(
    error: crucible_device::LinkSnapshotCodecError,
) -> SchedulerNetworkCheckpointCodecError {
    match error {
        crucible_device::LinkSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        error => SchedulerNetworkCheckpointCodecError::Link(error),
    }
}

fn validate_scheduler_network_checkpoint(
    checkpoint: &SchedulerNetworkCheckpoint,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if checkpoint.links.len() > HARD_SCHEDULER_NETWORK_LINKS
        || checkpoint.rng_positions.len() > HARD_SCHEDULER_NETWORK_LINKS
    {
        return Err(scheduler_network_resource(
            "link count",
            0,
            checkpoint.links.len().max(checkpoint.rng_positions.len()),
            HARD_SCHEDULER_NETWORK_LINKS,
        ));
    }
    let mut previous: Option<(&LinkId, NetworkLinkDirection)> = None;
    for link in &checkpoint.links {
        if link.link.name.is_empty()
            || link.link.name.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES
            || previous
                .as_ref()
                .is_some_and(|prior| prior >= &(&link.link, link.direction))
        {
            return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
        }
        previous = Some((&link.link, link.direction));
    }
    if checkpoint
        .rng_positions
        .keys()
        .any(|link| link.name.is_empty() || link.name.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES)
    {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    let directed = checkpoint
        .links
        .iter()
        .map(|link| &link.link)
        .collect::<BTreeSet<_>>();
    if directed != checkpoint.rng_positions.keys().collect::<BTreeSet<_>>() {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    Ok(())
}

fn write_scheduler_network_count(
    bytes: &mut Vec<u8>,
    count: usize,
    field: &'static str,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if count > HARD_SCHEDULER_NETWORK_LINKS {
        return Err(scheduler_network_resource(
            field,
            0,
            count,
            HARD_SCHEDULER_NETWORK_LINKS,
        ));
    }
    bytes.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| scheduler_network_resource(field, 0, count, HARD_SCHEDULER_NETWORK_LINKS))?
            .to_le_bytes(),
    );
    Ok(())
}

fn write_scheduler_network_string(
    bytes: &mut Vec<u8>,
    value: &str,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if value.is_empty() || value.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    write_scheduler_network_blob(bytes, value.as_bytes())
}

fn write_scheduler_network_blob(
    bytes: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if value.len() > HARD_SCHEDULER_NETWORK_BLOB_BYTES {
        return Err(scheduler_network_resource(
            "blob",
            0,
            value.len(),
            HARD_SCHEDULER_NETWORK_BLOB_BYTES,
        ));
    }
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| {
                scheduler_network_resource(
                    "blob",
                    0,
                    value.len(),
                    HARD_SCHEDULER_NETWORK_BLOB_BYTES,
                )
            })?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value);
    Ok(())
}

struct SchedulerNetworkCheckpointReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SchedulerNetworkCheckpointReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, SchedulerNetworkCheckpointCodecError> {
        let bytes = bytes
            .strip_prefix(SCHEDULER_NETWORK_CHECKPOINT_MAGIC)
            .ok_or(SchedulerNetworkCheckpointCodecError::Version)?;
        Ok(Self { bytes, offset: 0 })
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SchedulerNetworkCheckpointCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?
            .try_into()
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, SchedulerNetworkCheckpointCodecError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SchedulerNetworkCheckpointCodecError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SchedulerNetworkCheckpointCodecError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn count(
        &mut self,
        field: &'static str,
    ) -> Result<usize, SchedulerNetworkCheckpointCodecError> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        if count > HARD_SCHEDULER_NETWORK_LINKS {
            return Err(scheduler_network_resource(
                field,
                0,
                count,
                HARD_SCHEDULER_NETWORK_LINKS,
            ));
        }
        Ok(count)
    }

    fn blob(
        &mut self,
        field: &'static str,
    ) -> Result<&'a [u8], SchedulerNetworkCheckpointCodecError> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        if length > HARD_SCHEDULER_NETWORK_BLOB_BYTES {
            return Err(scheduler_network_resource(
                field,
                0,
                length,
                HARD_SCHEDULER_NETWORK_BLOB_BYTES,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn string(
        &mut self,
        field: &'static str,
    ) -> Result<String, SchedulerNetworkCheckpointCodecError> {
        let bytes = self.blob(field)?;
        if bytes.is_empty() || bytes.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES {
            return Err(SchedulerNetworkCheckpointCodecError::Malformed(field));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))
    }

    fn finish(self) -> Result<(), SchedulerNetworkCheckpointCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SchedulerNetworkCheckpointCodecError::Noncanonical)
        }
    }
}
