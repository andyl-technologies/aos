//! Durable 9p device snapshots and canonical codecs.

use super::*;
use crate::ninep::HARD_NINEP_OBJECT_VERSIONS;
use crate::ninep::server::{FidEntry, FidState};
use crate::snapshot_codec::{
    BoundedVec, SnapshotEncodeError, SnapshotResourceError, admit_input, encode_prefixed,
    map_decode_error,
};
use crate::subnode::IoCoreSnapshotCodecError;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

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

const NINEP_SNAPSHOT_MAGIC: &[u8] = b"crucible.ninep-snapshot.v2\0";
/// Compiled byte ceiling for one 9p device snapshot.
pub const MAX_NINEP_SNAPSHOT_BYTES: u64 = 536_870_912;
const MAX_NINEP_FIDS: u64 = 1_048_576;
const MAX_NINEP_DIRECTIVES: u64 = 1_048_576;
const MAX_NINEP_PATH_COMPONENTS: u64 = 1_048_576;

type SnapshotBytes = BoundedVec<u8, MAX_NINEP_SNAPSHOT_BYTES>;
type SnapshotFids = BoundedVec<(u32, FidEntryWire), MAX_NINEP_FIDS>;
type SnapshotPath = BoundedVec<String, MAX_NINEP_PATH_COMPONENTS>;
type SnapshotDirectives =
    BoundedVec<(NinepRequestIdentity, ResolvedNinepRequestDirective), MAX_NINEP_DIRECTIVES>;
type SnapshotVirtualFids = BoundedVec<(u32, NinepVirtualFid), MAX_NINEP_FIDS>;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepSnapshotWire {
    core: SnapshotBytes,
    server: NinepServerWire,
    latency: [u64; 3],
    require_fault_directives: bool,
    directives: SnapshotDirectives,
    visibility: NinepVisibilityState,
    virtual_fids: SnapshotVirtualFids,
    session_epoch: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepServerWire {
    msize: u32,
    negotiated: bool,
    fids: SnapshotFids,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FidEntryWire {
    path: SnapshotPath,
    state: FidState,
}

#[derive(Serialize)]
struct NinepSnapshotEncodeWire<'a> {
    core: SnapshotBytes,
    server: NinepServerEncodeWire<'a>,
    latency: [u64; 3],
    require_fault_directives: bool,
    directives: SnapshotDirectivesRef<'a>,
    visibility: &'a NinepVisibilityState,
    virtual_fids: SnapshotVirtualFidsRef<'a>,
    session_epoch: u64,
}

#[derive(Serialize)]
struct NinepServerEncodeWire<'a> {
    msize: u32,
    negotiated: bool,
    fids: SnapshotFidsRef<'a>,
}

struct SnapshotFidsRef<'a>(&'a [(u32, FidEntry)]);

impl Serialize for SnapshotFidsRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (fid, entry) in self.0 {
            sequence.serialize_element(&(
                *fid,
                FidEntryEncodeWire {
                    path: &entry.path,
                    state: entry.state,
                },
            ))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct FidEntryEncodeWire<'a> {
    path: &'a [String],
    state: FidState,
}

struct SnapshotDirectivesRef<'a>(&'a BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>);

impl Serialize for SnapshotDirectivesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (identity, directive) in self.0 {
            sequence.serialize_element(&(*identity, directive))?;
        }
        sequence.end()
    }
}

struct SnapshotVirtualFidsRef<'a>(&'a BTreeMap<u32, NinepVirtualFid>);

impl Serialize for SnapshotVirtualFidsRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (fid, binding) in self.0 {
            sequence.serialize_element(&(*fid, binding))?;
        }
        sequence.end()
    }
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
        self.to_canonical_bytes_with_limit(MAX_NINEP_SNAPSHOT_BYTES)
    }

    /// Encodes the snapshot under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NinepSnapshotCodecError`] under the same conditions as
    /// [`Self::to_canonical_bytes`], and when the representation exceeds
    /// `maximum`.
    pub fn to_canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, NinepSnapshotCodecError> {
        admit_ninep_snapshot_resources(self)?;
        validate_ninep_snapshot(self)?;
        let wire = NinepSnapshotEncodeWire {
            core: bounded_bytes(
                self.core.canonical_bytes().map_err(map_io_core_error)?,
                "9p I/O core bytes",
            )?,
            server: NinepServerEncodeWire {
                msize: self.server.msize,
                negotiated: self.server.negotiated,
                fids: SnapshotFidsRef(&self.server.fids),
            },
            latency: [
                self.latency.control_ns,
                self.latency.data_ns,
                self.latency.per_byte_ns,
            ],
            require_fault_directives: self.require_fault_directives,
            directives: SnapshotDirectivesRef(&self.directives),
            visibility: &self.visibility,
            virtual_fids: SnapshotVirtualFidsRef(&self.virtual_fids),
            session_epoch: self.session_epoch,
        };
        encode_prefixed(
            &wire,
            NINEP_SNAPSHOT_MAGIC,
            "9p snapshot bytes",
            maximum,
            MAX_NINEP_SNAPSHOT_BYTES,
        )
        .map_err(map_encode_error)
    }

    /// Decodes and validates a complete 9p continuation.
    ///
    /// # Errors
    ///
    /// Returns [`NinepSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NinepSnapshotCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, MAX_NINEP_SNAPSHOT_BYTES)
    }

    /// Decodes the snapshot under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NinepSnapshotCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, NinepSnapshotCodecError> {
        let payload = bytes
            .strip_prefix(NINEP_SNAPSHOT_MAGIC)
            .ok_or(NinepSnapshotCodecError::Version)?;
        admit_input(
            bytes,
            "9p snapshot bytes",
            maximum,
            MAX_NINEP_SNAPSHOT_BYTES,
        )
        .map_err(map_resource_error)?;
        let wire: NinepSnapshotWire = ciborium::de::from_reader(payload).map_err(|error| {
            map_decode_error(error).map_or(NinepSnapshotCodecError::Malformed, map_resource_error)
        })?;
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes(wire.core.as_slice())
                .map_err(map_io_core_error)?,
            server: decode_server(wire.server)?,
            latency: NinepLatency::new(wire.latency[0], wire.latency[1], wire.latency[2]),
            require_fault_directives: wire.require_fault_directives,
            directives: collect_strict(wire.directives.into_inner())?,
            visibility: wire.visibility,
            virtual_fids: collect_strict(wire.virtual_fids.into_inner())?,
            session_epoch: wire.session_epoch,
        };
        admit_ninep_snapshot_resources(&snapshot)?;
        validate_ninep_snapshot(&snapshot)?;
        if snapshot.to_canonical_bytes_with_limit(maximum)?.as_slice() != bytes {
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
    /// The snapshot exceeds a configured or compiled resource ceiling.
    #[error(
        "9p snapshot resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Resource field that rejected the operation.
        field: &'static str,
        /// Bytes or entries already retained by the operation.
        current: u64,
        /// Additional bytes or entries requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
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

fn decode_server(wire: NinepServerWire) -> Result<NinepServerSnapshot, NinepSnapshotCodecError> {
    Ok(NinepServerSnapshot {
        msize: wire.msize,
        negotiated: wire.negotiated,
        fids: wire
            .fids
            .into_inner()
            .into_iter()
            .map(|(fid, entry)| {
                (
                    fid,
                    FidEntry {
                        path: entry.path.into_inner(),
                        state: entry.state,
                    },
                )
            })
            .collect(),
    })
}

fn bounded_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SnapshotBytes, NinepSnapshotCodecError> {
    SnapshotBytes::new(bytes, field).map_err(map_resource_error)
}

fn map_encode_error(error: SnapshotEncodeError) -> NinepSnapshotCodecError {
    match error {
        SnapshotEncodeError::Malformed => NinepSnapshotCodecError::Malformed,
        SnapshotEncodeError::Resource(error) => map_resource_error(error),
    }
}

fn map_resource_error(error: SnapshotResourceError) -> NinepSnapshotCodecError {
    NinepSnapshotCodecError::ResourceLimit {
        field: error.field,
        current: error.current,
        requested: error.requested,
        configured: error.configured,
        hard: error.hard,
    }
}

fn map_io_core_error(error: IoCoreSnapshotCodecError) -> NinepSnapshotCodecError {
    match error {
        IoCoreSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => NinepSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        _ => NinepSnapshotCodecError::Nested,
    }
}

fn resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    hard: u64,
) -> NinepSnapshotCodecError {
    NinepSnapshotCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured: hard,
        hard,
    }
}

fn validate_ninep_snapshot(snapshot: &NinepSnapshot) -> Result<(), NinepSnapshotCodecError> {
    snapshot.core.canonical_bytes().map_err(map_io_core_error)?;
    snapshot
        .visibility
        .validate()
        .map_err(|_| NinepSnapshotCodecError::Invalid)?;
    if snapshot.server.msize < MIN_MSIZE
        || snapshot.server.msize > MAX_MSIZE
        || snapshot
            .server
            .fids
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
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

fn admit_ninep_snapshot_resources(snapshot: &NinepSnapshot) -> Result<(), NinepSnapshotCodecError> {
    for (field, count, hard) in [
        ("9p server fids", snapshot.server.fids.len(), MAX_NINEP_FIDS),
        (
            "9p directives",
            snapshot.directives.len(),
            MAX_NINEP_DIRECTIVES,
        ),
        (
            "9p virtual fids",
            snapshot.virtual_fids.len(),
            MAX_NINEP_FIDS,
        ),
    ] {
        admit_collection_count(field, count, hard)?;
    }
    for (_, entry) in &snapshot.server.fids {
        admit_collection_count(
            "9p fid path components",
            entry.path.len(),
            MAX_NINEP_PATH_COMPONENTS,
        )?;
    }
    for count in snapshot.visibility.checkpoint_collection_counts() {
        admit_collection_count(
            "9p visibility entries",
            count,
            HARD_NINEP_OBJECT_VERSIONS as u64,
        )?;
    }
    Ok(())
}

fn admit_collection_count(
    field: &'static str,
    count: usize,
    hard: u64,
) -> Result<(), NinepSnapshotCodecError> {
    let requested = u64::try_from(count).unwrap_or(u64::MAX);
    if requested > hard {
        return Err(resource_limit(field, 0, requested, hard));
    }
    Ok(())
}
