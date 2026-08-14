//! Durable 9p device snapshots and canonical codecs.

use super::*;

/// The device half of a 9p sub-node's `MaterializedState` ([IO-19], [IO-23]).
///
/// Holds the uniform-core snapshot (clock, rings, in-flight responses), the
/// server's fid table and negotiated `msize`, the latency model (part of the
/// `World`, [IO-22]), exact directives, visibility continuation, and session
/// identity. It **never** holds
/// the served tree bytes ([TEMP-9]); restore re-supplies the content-addressed
/// tree, whose open caches are pure functions of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepSnapshot {
    /// The uniform-core snapshot: clock, rings, in-flight responses.
    pub core: IoCoreSnapshot,
    /// The protocol server snapshot: the fid table and negotiated `msize`.
    pub server: NinepServerSnapshot,
    /// The latency model parameters, restored so post-restore completion icounts
    /// match an uninterrupted run ([IO-22]).
    pub latency: NinepLatency,
    /// Whether every compute requires an authenticated request directive.
    pub require_fault_directives: bool,
    /// Installed directives not yet consumed by their exact requests.
    pub directives: BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
    /// Committed-versus-visible object versions and frontiers.
    pub visibility: NinepVisibilityState,
    /// Fids bound to scenario-owned object versions outside the immutable tree.
    pub virtual_fids: BTreeMap<u32, NinepVirtualFid>,
    /// Monotone negotiated-session identity for per-session visibility.
    pub session_epoch: u64,
}

const NINEP_SNAPSHOT_MAGIC: &[u8] = b"crucible.ninep-snapshot.v1\0";
const MAX_NINEP_SNAPSHOT_BYTES: usize = 536_870_912;
const MAX_NINEP_FIDS: usize = 1_048_576;
const MAX_NINEP_DIRECTIVES: usize = 1_048_576;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepSnapshotWire {
    core: Vec<u8>,
    server: NinepServerSnapshot,
    latency: [u64; 3],
    require_fault_directives: bool,
    directives: Vec<(NinepRequestIdentity, ResolvedNinepRequestDirective)>,
    visibility: NinepVisibilityState,
    virtual_fids: Vec<(u32, NinepVirtualFid)>,
    session_epoch: u64,
}

impl NinepSnapshot {
    /// Returns the in-flight responses captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.core.inflight
    }

    /// Returns the captured fid table as `(fid, entry)` pairs in fid order.
    #[must_use]
    pub fn fids(&self) -> &[(u32, super::super::server::FidEntry)] {
        &self.server.fids
    }

    /// Encodes the complete 9p continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`NinepSnapshotCodecError`] for invalid nested state or an
    /// over-limit serialized checkpoint.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, NinepSnapshotCodecError> {
        validate_ninep_snapshot(self)?;
        let wire = NinepSnapshotWire {
            core: self
                .core
                .canonical_bytes()
                .map_err(|_| NinepSnapshotCodecError::Nested)?,
            server: self.server.clone(),
            latency: [
                self.latency.control_ns,
                self.latency.data_ns,
                self.latency.per_byte_ns,
            ],
            require_fault_directives: self.require_fault_directives,
            directives: self
                .directives
                .iter()
                .map(|(identity, directive)| (*identity, directive.clone()))
                .collect(),
            visibility: self.visibility.clone(),
            virtual_fids: self
                .virtual_fids
                .iter()
                .map(|(fid, binding)| (*fid, binding.clone()))
                .collect(),
            session_epoch: self.session_epoch,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| NinepSnapshotCodecError::Malformed)?;
        if payload.len() > MAX_NINEP_SNAPSHOT_BYTES {
            return Err(NinepSnapshotCodecError::Limit);
        }
        let mut bytes = Vec::with_capacity(NINEP_SNAPSHOT_MAGIC.len() + payload.len());
        bytes.extend_from_slice(NINEP_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes and validates a complete 9p continuation.
    ///
    /// # Errors
    ///
    /// Returns [`NinepSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NinepSnapshotCodecError> {
        let payload = bytes
            .strip_prefix(NINEP_SNAPSHOT_MAGIC)
            .ok_or(NinepSnapshotCodecError::Version)?;
        if payload.len() > MAX_NINEP_SNAPSHOT_BYTES {
            return Err(NinepSnapshotCodecError::Limit);
        }
        let wire: NinepSnapshotWire =
            ciborium::de::from_reader(payload).map_err(|_| NinepSnapshotCodecError::Malformed)?;
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes(&wire.core)
                .map_err(|_| NinepSnapshotCodecError::Nested)?,
            server: wire.server,
            latency: NinepLatency::new(wire.latency[0], wire.latency[1], wire.latency[2]),
            require_fault_directives: wire.require_fault_directives,
            directives: collect_strict(wire.directives)?,
            visibility: wire.visibility,
            virtual_fids: collect_strict(wire.virtual_fids)?,
            session_epoch: wire.session_epoch,
        };
        validate_ninep_snapshot(&snapshot)?;
        if snapshot.to_canonical_bytes()?.as_slice() != bytes {
            return Err(NinepSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

/// Failure to encode or authenticate a complete 9p snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NinepSnapshotCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported 9p snapshot version")]
    Version,
    /// The snapshot cannot be serialized or decoded.
    #[error("malformed 9p snapshot")]
    Malformed,
    /// A nested continuation is invalid.
    #[error("invalid nested 9p snapshot state")]
    Nested,
    /// The snapshot violates protocol or state invariants.
    #[error("invalid 9p snapshot state")]
    Invalid,
    /// The snapshot exceeds a compiled resource ceiling.
    #[error("9p snapshot exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical 9p snapshot")]
    Noncanonical,
}

fn collect_strict<K: Ord, V>(
    entries: Vec<(K, V)>,
) -> Result<BTreeMap<K, V>, NinepSnapshotCodecError> {
    if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(NinepSnapshotCodecError::Noncanonical);
    }
    Ok(entries.into_iter().collect())
}

fn validate_ninep_snapshot(snapshot: &NinepSnapshot) -> Result<(), NinepSnapshotCodecError> {
    snapshot
        .core
        .canonical_bytes()
        .map_err(|_| NinepSnapshotCodecError::Nested)?;
    snapshot
        .visibility
        .validate()
        .map_err(|_| NinepSnapshotCodecError::Invalid)?;
    if snapshot.server.msize < MIN_MSIZE
        || snapshot.server.msize > MAX_MSIZE
        || snapshot.server.fids.len() > MAX_NINEP_FIDS
        || snapshot
            .server
            .fids
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        || snapshot.directives.len() > MAX_NINEP_DIRECTIVES
        || snapshot.virtual_fids.len() > MAX_NINEP_FIDS
    {
        return Err(NinepSnapshotCodecError::Invalid);
    }
    for (_, entry) in &snapshot.server.fids {
        if entry.path.iter().any(|component| {
            component.is_empty() || component == "." || component == ".." || component.contains('/')
        }) {
            return Err(NinepSnapshotCodecError::Invalid);
        }
    }
    for (identity, directive) in &snapshot.directives {
        if identity != &directive.identity
            || matches!(directive.result, NinepResultDirective::Errno(0))
        {
            return Err(NinepSnapshotCodecError::Invalid);
        }
        if let NinepResultDirective::Stale(object) | NinepResultDirective::Misdirected(object) =
            &directive.result
        {
            object
                .validate()
                .map_err(|_| NinepSnapshotCodecError::Invalid)?;
        }
    }
    for binding in snapshot.virtual_fids.values() {
        binding
            .validate()
            .map_err(|_| NinepSnapshotCodecError::Invalid)?;
    }
    Ok(())
}
