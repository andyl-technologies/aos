//! Durable directed-link snapshots and canonical codecs.

use super::*;

mod codec_support;

use codec_support::*;

/// The device half of a network link's `MaterializedState` ([IO-23], [IO-26]).
///
/// Captures the link's clock cursor, base latency, floor, effective fault table,
/// sequence counter, pending-recompute flag, RNG cursor, and the
/// in-flight deliveries. The active fault set is part of the captured state so a
/// fork resumes with identical link behavior (deferred wiring in CS-IO-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSnapshot {
    /// The link's current (consumer-frontier) icount at snapshot time.
    pub current_icount: u64,
    /// The fixed virtual-time shift in bits.
    pub shift_bits: u8,
    /// The source node id stamped into delivery keys.
    pub src_node: u32,
    /// The link's base latency in virtual nanoseconds.
    pub base_latency_ns: u64,
    /// The strictly-positive minimum link-latency floor.
    pub floor_ns: u64,
    /// The effective fault table active at snapshot time.
    pub faults: LinkFaults,
    /// The next per-frame sequence number.
    pub next_seq: u32,
    /// Whether a lookahead recompute was pending at snapshot time.
    pub lookahead_recompute_pending: bool,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    pub rng_position: u64,
    /// The in-flight deliveries, in delivery order.
    pub inflight: Vec<PendingResponse>,
}

impl LinkSnapshot {
    /// Returns the in-flight deliveries captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.inflight
    }

    /// Encodes the complete directed-link continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`LinkSnapshotCodecError`] when the snapshot violates the live
    /// link invariants or a bounded collection or frame payload is too large.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinkSnapshotCodecError> {
        self.canonical_bytes_with_limit(u64::try_from(HARD_LINK_SNAPSHOT_BYTES).unwrap_or(u64::MAX))
    }

    /// Encodes the directed-link continuation under an authored byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`LinkSnapshotCodecError`] under the same conditions as
    /// [`Self::canonical_bytes`], and when the representation exceeds `maximum`.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, LinkSnapshotCodecError> {
        let encoded_length = self.canonical_length_with_limit(maximum)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_length).map_err(|_| {
            link_snapshot_resource(
                "link snapshot bytes",
                0,
                encoded_length,
                link_snapshot_configured(maximum),
                HARD_LINK_SNAPSHOT_BYTES,
            )
        })?;
        bytes.extend_from_slice(LINK_SNAPSHOT_MAGIC);
        put_link_u64(&mut bytes, self.current_icount);
        bytes.push(self.shift_bits);
        put_link_u32(&mut bytes, self.src_node);
        put_link_u64(&mut bytes, self.base_latency_ns);
        put_link_u64(&mut bytes, self.floor_ns);
        bytes.push(u8::from(self.faults.partitioned));
        put_link_u64(&mut bytes, self.faults.added_latency_ns);
        put_link_u64(&mut bytes, self.faults.jitter_window_ns);
        put_link_u64(&mut bytes, self.faults.reorder_window_ns);
        write_link_count(&mut bytes, self.faults.bandwidth_bits_per_sec.len())?;
        for value in &self.faults.bandwidth_bits_per_sec {
            put_link_u64(&mut bytes, *value);
        }
        write_probability(&mut bytes, self.faults.loss);
        write_link_count(&mut bytes, self.faults.additional_loss.len())?;
        for probability in &self.faults.additional_loss {
            write_probability(&mut bytes, *probability);
        }
        write_probability(&mut bytes, self.faults.duplicate);
        put_link_u64(&mut bytes, self.faults.duplicate_gap_ns);
        write_probability(&mut bytes, self.faults.corrupt);
        write_link_count(&mut bytes, self.faults.corruption_strategies.len())?;
        for strategy in &self.faults.corruption_strategies {
            match strategy {
                LinkCorruptionStrategy::BitFlip { max_bits } => {
                    bytes.push(1);
                    put_link_u32(&mut bytes, *max_bits);
                }
                LinkCorruptionStrategy::FieldMutation => bytes.push(2),
                LinkCorruptionStrategy::Truncation { max_bytes } => {
                    bytes.push(3);
                    put_link_u64(&mut bytes, *max_bytes);
                }
            }
        }
        put_link_u32(&mut bytes, self.next_seq);
        bytes.push(u8::from(self.lookahead_recompute_pending));
        put_link_u64(&mut bytes, self.rng_position);
        write_link_count(&mut bytes, self.inflight.len())?;
        for pending in &self.inflight {
            put_link_u64(&mut bytes, pending.key.delivery_icount);
            put_link_u32(&mut bytes, pending.key.src_node);
            put_link_u32(&mut bytes, pending.key.seq);
            put_link_u32(&mut bytes, pending.response.request_id);
            bytes.push(match pending.response.status {
                ResponseStatus::Ok => 1,
                ResponseStatus::Error => 2,
            });
            write_link_blob(&mut bytes, &pending.response.payload)?;
        }
        if bytes.len() != encoded_length {
            return Err(LinkSnapshotCodecError::Noncanonical);
        }
        Ok(bytes)
    }

    /// Returns the exact canonical representation length under an authored bound.
    ///
    /// # Errors
    ///
    /// Returns [`LinkSnapshotCodecError`] when the snapshot is invalid, a field
    /// is over its bound, or the representation exceeds `maximum`.
    pub fn canonical_length_with_limit(
        &self,
        maximum: u64,
    ) -> Result<usize, LinkSnapshotCodecError> {
        validate_link_snapshot(self)?;
        link_snapshot_encoded_length(self, maximum)
    }

    /// Decodes and validates one complete directed-link continuation.
    ///
    /// # Errors
    ///
    /// Returns [`LinkSnapshotCodecError`] for unsupported versions, malformed
    /// or over-limit values, noncanonical ordering, invalid live-link state, or
    /// trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinkSnapshotCodecError> {
        Self::from_canonical_bytes_with_limit(
            bytes,
            u64::try_from(HARD_LINK_SNAPSHOT_BYTES).unwrap_or(u64::MAX),
        )
    }

    /// Decodes a directed-link continuation under an authored byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`LinkSnapshotCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, LinkSnapshotCodecError> {
        let configured = link_snapshot_configured(maximum);
        if bytes.len() > configured {
            return Err(link_snapshot_resource(
                "link snapshot bytes",
                0,
                bytes.len(),
                configured,
                HARD_LINK_SNAPSHOT_BYTES,
            ));
        }
        let mut reader = LinkSnapshotReader::new(bytes)?;
        let current_icount = reader.u64("current icount")?;
        let shift_bits = reader.byte("shift bits")?;
        let src_node = reader.u32("source node")?;
        let base_latency_ns = reader.u64("base latency")?;
        let floor_ns = reader.u64("latency floor")?;
        let partitioned = reader.boolean("partitioned")?;
        let added_latency_ns = reader.u64("added latency")?;
        let jitter_window_ns = reader.u64("jitter window")?;
        let reorder_window_ns = reader.u64("reorder window")?;
        let bandwidth_count = reader.count("bandwidth caps")?;
        let mut bandwidth_bits_per_sec = link_snapshot_vector("bandwidth caps", bandwidth_count)?;
        for _ in 0..bandwidth_count {
            bandwidth_bits_per_sec.push(reader.u64("bandwidth cap")?);
        }
        let loss = reader.probability("loss probability")?;
        let loss_count = reader.count("additional loss probabilities")?;
        let mut additional_loss =
            link_snapshot_vector("additional loss probabilities", loss_count)?;
        for _ in 0..loss_count {
            additional_loss.push(reader.probability("additional loss probability")?);
        }
        let duplicate = reader.probability("duplicate probability")?;
        let duplicate_gap_ns = reader.u64("duplicate gap")?;
        let corrupt = reader.probability("corruption probability")?;
        let corruption_count = reader.count("corruption strategies")?;
        let mut corruption_strategies =
            link_snapshot_vector("corruption strategies", corruption_count)?;
        for _ in 0..corruption_count {
            corruption_strategies.push(match reader.byte("corruption strategy")? {
                1 => LinkCorruptionStrategy::BitFlip {
                    max_bits: reader.u32("bit-flip count")?,
                },
                2 => LinkCorruptionStrategy::FieldMutation,
                3 => LinkCorruptionStrategy::Truncation {
                    max_bytes: reader.u64("truncation length")?,
                },
                _ => return Err(LinkSnapshotCodecError::Malformed("corruption strategy")),
            });
        }
        let next_seq = reader.u32("next sequence")?;
        let lookahead_recompute_pending = reader.boolean("lookahead recompute")?;
        let rng_position = reader.u64("RNG position")?;
        let inflight_count = reader.count("in-flight frames")?;
        let mut inflight = link_snapshot_vector("in-flight frames", inflight_count)?;
        for _ in 0..inflight_count {
            let delivery_icount = reader.u64("delivery icount")?;
            let pending_src_node = reader.u32("delivery source")?;
            let sequence = reader.u32("delivery sequence")?;
            let request_id = reader.u32("frame identity")?;
            let status = match reader.byte("response status")? {
                1 => ResponseStatus::Ok,
                2 => ResponseStatus::Error,
                _ => return Err(LinkSnapshotCodecError::Malformed("response status")),
            };
            let payload_bytes = reader.blob("frame payload")?;
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(payload_bytes.len())
                .map_err(|_| {
                    link_snapshot_resource(
                        "frame payload",
                        0,
                        payload_bytes.len(),
                        crucible_shmem::MAX_FRAME_DATA,
                        crucible_shmem::MAX_FRAME_DATA,
                    )
                })?;
            payload.extend_from_slice(payload_bytes);
            inflight.push(PendingResponse::from_parts(
                delivery_icount,
                pending_src_node,
                sequence,
                Response::new(request_id, status, payload),
            ));
        }
        reader.finish()?;
        let snapshot = Self {
            current_icount,
            shift_bits,
            src_node,
            base_latency_ns,
            floor_ns,
            faults: LinkFaults {
                partitioned,
                added_latency_ns,
                jitter_window_ns,
                reorder_window_ns,
                bandwidth_bits_per_sec,
                loss,
                additional_loss,
                duplicate,
                duplicate_gap_ns,
                corrupt,
                corruption_strategies,
            },
            next_seq,
            lookahead_recompute_pending,
            rng_position,
            inflight,
        };
        validate_link_snapshot(&snapshot)?;
        if snapshot.canonical_bytes_with_limit(maximum)?.as_slice() != bytes {
            return Err(LinkSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

const LINK_SNAPSHOT_MAGIC: &[u8] = b"crucible.link-snapshot.v1\0";
const HARD_LINK_SNAPSHOT_ENTRIES: usize = 65_536;
const HARD_LINK_SNAPSHOT_BYTES: usize = 1 << 30;

/// Failure to encode or decode a durable directed-link continuation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkSnapshotCodecError {
    /// The stored format version is unsupported.
    #[error("unsupported link snapshot version")]
    Version,
    /// A field is truncated or carries an unknown tag.
    #[error("malformed link snapshot field `{0}`")]
    Malformed(&'static str),
    /// A representation or allocation exceeds its active resource ceiling.
    #[error(
        "link snapshot `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
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
    /// The stored representation is not canonical.
    #[error("noncanonical link snapshot")]
    Noncanonical,
    /// The decoded state violates a live network-link invariant.
    #[error("invalid live link snapshot: {0}")]
    Device(String),
}

fn validate_link_snapshot(snapshot: &LinkSnapshot) -> Result<(), LinkSnapshotCodecError> {
    if snapshot.inflight.len() > HARD_LINK_SNAPSHOT_ENTRIES
        || snapshot.faults.bandwidth_bits_per_sec.len() > HARD_LINK_SNAPSHOT_ENTRIES
        || snapshot.faults.additional_loss.len() > HARD_LINK_SNAPSHOT_ENTRIES
        || snapshot.faults.corruption_strategies.len() > HARD_LINK_SNAPSHOT_ENTRIES
    {
        return Err(link_snapshot_resource(
            "snapshot entries",
            0,
            snapshot
                .inflight
                .len()
                .max(snapshot.faults.bandwidth_bits_per_sec.len())
                .max(snapshot.faults.additional_loss.len())
                .max(snapshot.faults.corruption_strategies.len()),
            HARD_LINK_SNAPSHOT_ENTRIES,
            HARD_LINK_SNAPSHOT_ENTRIES,
        ));
    }
    if snapshot
        .inflight
        .iter()
        .any(|pending| pending.response.payload.len() > crucible_shmem::MAX_FRAME_DATA)
    {
        let requested = snapshot
            .inflight
            .iter()
            .map(|pending| pending.response.payload.len())
            .max()
            .unwrap_or(0);
        return Err(link_snapshot_resource(
            "frame payload",
            0,
            requested,
            crucible_shmem::MAX_FRAME_DATA,
            crucible_shmem::MAX_FRAME_DATA,
        ));
    }
    if snapshot
        .inflight
        .iter()
        .any(|pending| pending.key.src_node != snapshot.src_node)
    {
        return Err(LinkSnapshotCodecError::Device(String::from(
            "in-flight frame source differs from link source",
        )));
    }
    if snapshot
        .inflight
        .windows(2)
        .any(|pair| pair[0].key > pair[1].key)
    {
        return Err(LinkSnapshotCodecError::Noncanonical);
    }
    let normalized = NetLink::restore(snapshot)
        .map_err(|error| LinkSnapshotCodecError::Device(error.to_string()))?
        .snapshot();
    if normalized != *snapshot {
        return Err(LinkSnapshotCodecError::Noncanonical);
    }
    Ok(())
}

fn write_probability(bytes: &mut Vec<u8>, probability: crate::fault::Probability) {
    put_link_u64(bytes, probability.numerator);
    put_link_u64(bytes, probability.denominator);
}

fn write_link_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), LinkSnapshotCodecError> {
    if count > HARD_LINK_SNAPSHOT_ENTRIES {
        return Err(link_snapshot_resource(
            "snapshot entries",
            0,
            count,
            HARD_LINK_SNAPSHOT_ENTRIES,
            HARD_LINK_SNAPSHOT_ENTRIES,
        ));
    }
    let count = u32::try_from(count).map_err(|_| {
        link_snapshot_resource(
            "snapshot entries",
            0,
            count,
            HARD_LINK_SNAPSHOT_ENTRIES,
            HARD_LINK_SNAPSHOT_ENTRIES,
        )
    })?;
    put_link_u32(bytes, count);
    Ok(())
}

fn write_link_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), LinkSnapshotCodecError> {
    if value.len() > crucible_shmem::MAX_FRAME_DATA {
        return Err(link_snapshot_resource(
            "frame payload",
            0,
            value.len(),
            crucible_shmem::MAX_FRAME_DATA,
            crucible_shmem::MAX_FRAME_DATA,
        ));
    }
    put_link_u32(
        bytes,
        u32::try_from(value.len()).map_err(|_| {
            link_snapshot_resource(
                "frame payload",
                0,
                value.len(),
                crucible_shmem::MAX_FRAME_DATA,
                crucible_shmem::MAX_FRAME_DATA,
            )
        })?,
    );
    bytes.extend_from_slice(value);
    Ok(())
}

fn put_link_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_link_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

struct LinkSnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LinkSnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, LinkSnapshotCodecError> {
        let body = bytes
            .strip_prefix(LINK_SNAPSHOT_MAGIC)
            .ok_or(LinkSnapshotCodecError::Version)?;
        Ok(Self {
            bytes: body,
            offset: 0,
        })
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], LinkSnapshotCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(LinkSnapshotCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(LinkSnapshotCodecError::Malformed(field))?
            .try_into()
            .map_err(|_| LinkSnapshotCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, LinkSnapshotCodecError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn boolean(&mut self, field: &'static str) -> Result<bool, LinkSnapshotCodecError> {
        match self.byte(field)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(LinkSnapshotCodecError::Malformed(field)),
        }
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, LinkSnapshotCodecError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, LinkSnapshotCodecError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn probability(
        &mut self,
        field: &'static str,
    ) -> Result<crate::fault::Probability, LinkSnapshotCodecError> {
        Ok(crate::fault::Probability::new(
            self.u64(field)?,
            self.u64(field)?,
        ))
    }

    fn count(&mut self, field: &'static str) -> Result<usize, LinkSnapshotCodecError> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| LinkSnapshotCodecError::Malformed(field))?;
        if count > HARD_LINK_SNAPSHOT_ENTRIES {
            return Err(link_snapshot_resource(
                field,
                0,
                count,
                HARD_LINK_SNAPSHOT_ENTRIES,
                HARD_LINK_SNAPSHOT_ENTRIES,
            ));
        }
        Ok(count)
    }

    fn blob(&mut self, field: &'static str) -> Result<&'a [u8], LinkSnapshotCodecError> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| LinkSnapshotCodecError::Malformed(field))?;
        if length > crucible_shmem::MAX_FRAME_DATA {
            return Err(link_snapshot_resource(
                field,
                0,
                length,
                crucible_shmem::MAX_FRAME_DATA,
                crucible_shmem::MAX_FRAME_DATA,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(LinkSnapshotCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(LinkSnapshotCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), LinkSnapshotCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(LinkSnapshotCodecError::Noncanonical)
        }
    }
}
