//! Canonical wire representation of the version 6 capture manifest body.
//!
//! The body holds only bounded descriptors. Every byte string that can be
//! large is a leaf named by its digest and length, and every side log and
//! side trace is its segment references:
//!
//! ```text
//! CaptureManifestWire { schema_version, reproduction, observed_signature,
//!                       finding_fingerprint, model_reproduction: Leaf,
//!                       recipe, deployment, selected_side, sides,
//!                       campaign_replay_closure: Closure, lifecycle_objects }
//! Closure { root: Leaf, frames: [Leaf] }           // replay-closure root and frames
//! Leaf    { digest: bytes[32], length: u64 }       // trace content ID v1
//! Segment { digest: bytes[32], first_sequence, entry_count, encoded_bytes }
//! Trace   { mode, work_items, records, chain, segments: [TraceSegment] }
//! TraceSegment { digest: bytes[32], first_item, item_count, records,
//!                encoded_bytes }                   // trace content ID v1
//! ```

use super::*;
use crucible_cas::content_store::{ContentId, ObjectKind};
use serde::de::{Deserializer, Visitor};
use serde::{Serializer, de};

use crucible::model::{
    FaultReplayMode, RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA, ResolvedEffectTraceManifest,
    ResolvedEffectTraceSegmentRef,
};

use crate::{ATTEMPT_LOG_SEGMENT_SCHEMA, AttemptLogSegmentRef};

const MAX_CBOR_NESTING_DEPTH: usize = 128;

/// Trace schema version of every non-segment capture leaf.
pub(super) const CAPTURE_LEAF_SCHEMA_VERSION: u32 = 1;

pub(super) struct ByteBuf(pub(super) Vec<u8>);

impl Serialize for ByteBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ByteBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(ByteBufVisitor)
    }
}

struct ByteBufVisitor;

impl<'de> Visitor<'de> for ByteBufVisitor {
    type Value = ByteBuf;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a definite-length CBOR byte string")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ByteBuf(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(ByteBuf(value))
    }
}

/// Rejects hostile container declarations before Serde can reserve storage.
pub(super) fn preflight_canonical_cbor(bytes: &[u8]) -> Result<(), ()> {
    let mut position = 0;
    scan_cbor_item(bytes, &mut position, 0)?;
    if position != bytes.len() {
        return Err(());
    }
    Ok(())
}

fn scan_cbor_item(bytes: &[u8], position: &mut usize, depth: usize) -> Result<(), ()> {
    if depth > MAX_CBOR_NESTING_DEPTH {
        return Err(());
    }
    let initial = *bytes.get(*position).ok_or(())?;
    *position = position.checked_add(1).ok_or(())?;
    let major = initial >> 5;
    let additional = initial & 0x1f;

    match major {
        0 | 1 => {
            read_cbor_argument(bytes, position, additional)?;
        }
        2 | 3 => {
            let length = usize::try_from(read_cbor_argument(bytes, position, additional)?)
                .map_err(|_| ())?;
            *position = position
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(())?;
        }
        4 => {
            let count = usize::try_from(read_cbor_argument(bytes, position, additional)?)
                .map_err(|_| ())?;
            if count > bytes.len().saturating_sub(*position) {
                return Err(());
            }
            for _ in 0..count {
                scan_cbor_item(bytes, position, depth + 1)?;
            }
        }
        5 => {
            let count = usize::try_from(read_cbor_argument(bytes, position, additional)?)
                .map_err(|_| ())?;
            let items = count.checked_mul(2).ok_or(())?;
            if items > bytes.len().saturating_sub(*position) {
                return Err(());
            }
            for _ in 0..items {
                scan_cbor_item(bytes, position, depth + 1)?;
            }
        }
        6 => {
            read_cbor_argument(bytes, position, additional)?;
            scan_cbor_item(bytes, position, depth + 1)?;
        }
        7 => {
            read_cbor_argument(bytes, position, additional)?;
        }
        _ => return Err(()),
    }
    Ok(())
}

fn read_cbor_argument(bytes: &[u8], position: &mut usize, additional: u8) -> Result<u64, ()> {
    let width = match additional {
        0..=23 => return Ok(u64::from(additional)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(()),
    };
    let end = position
        .checked_add(width)
        .filter(|end| *end <= bytes.len())
        .ok_or(())?;
    let mut encoded = [0_u8; 8];
    encoded[8 - width..].copy_from_slice(&bytes[*position..end]);
    *position = end;
    Ok(u64::from_be_bytes(encoded))
}

/// Complete bounded body of one version 6 capture manifest.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureManifestWire {
    pub(super) schema_version: u32,
    pub(super) reproduction: ReproductionArtifactId,
    pub(super) observed_signature: ByteBuf,
    pub(super) finding_fingerprint: ContentHash,
    pub(super) model_reproduction: LeafWire,
    pub(super) recipe: FindingProductionReplayRecipe,
    pub(super) deployment: DeploymentWire,
    pub(super) selected_side: FindingProductionReplaySelectedSide,
    pub(super) sides: Vec<SideWire>,
    pub(super) campaign_replay_closure: ReplayClosureWire,
    pub(super) lifecycle_objects: Vec<LifecycleObjectWire>,
}

/// The campaign replay closure's root leaf and its frame leaves, in order.
///
/// Frames grow with the replayed run and are at most 64 MiB each; the body
/// holds only their descriptors.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayClosureWire {
    pub(super) root: LeafWire,
    pub(super) frames: Vec<LeafWire>,
}

/// One trace leaf named by its content digest and exact length.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeafWire {
    digest: ByteBuf,
    pub(super) length: u64,
}

impl LeafWire {
    pub(super) fn new(id: ContentId, length: u64) -> Self {
        Self {
            digest: ByteBuf(id.digest().to_vec()),
            length,
        }
    }

    /// Rebuilds the trace leaf identity the digest names.
    pub(super) fn id(&self) -> Result<ContentId, FindingProductionReplayCaptureError> {
        trace_id(&self.digest, CAPTURE_LEAF_SCHEMA_VERSION)
    }
}

/// One attempt-log segment reference of a side log.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SegmentWire {
    digest: ByteBuf,
    first_sequence: u64,
    entry_count: u64,
    encoded_bytes: u64,
}

impl From<&AttemptLogSegmentRef> for SegmentWire {
    fn from(segment: &AttemptLogSegmentRef) -> Self {
        Self {
            digest: ByteBuf(segment.id.digest().to_vec()),
            first_sequence: segment.first_sequence,
            entry_count: segment.entry_count,
            encoded_bytes: segment.encoded_bytes,
        }
    }
}

impl SegmentWire {
    pub(super) fn segment(
        &self,
    ) -> Result<AttemptLogSegmentRef, FindingProductionReplayCaptureError> {
        Ok(AttemptLogSegmentRef {
            id: trace_id(&self.digest, ATTEMPT_LOG_SEGMENT_SCHEMA)?,
            first_sequence: self.first_sequence,
            entry_count: self.entry_count,
            encoded_bytes: self.encoded_bytes,
        })
    }
}

fn trace_id(
    digest: &ByteBuf,
    schema_version: u32,
) -> Result<ContentId, FindingProductionReplayCaptureError> {
    let digest: [u8; 32] = digest.0.as_slice().try_into().map_err(|_| {
        FindingProductionReplayCaptureError::InvalidManifest {
            reason: "leaf digest",
        }
    })?;
    Ok(ContentId::from_parts(
        ObjectKind::Trace,
        schema_version,
        digest,
    ))
}

/// A side log's manifest: its totals and ordered segment references.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventLogWire {
    pub(super) entry_count: u64,
    pub(super) chain: ContentHash,
    pub(super) segments: Vec<SegmentWire>,
}

/// One resolved-effect trace segment reference of a side trace.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TraceSegmentWire {
    digest: ByteBuf,
    first_item: u64,
    item_count: u64,
    records: u64,
    encoded_bytes: u64,
}

impl From<&ResolvedEffectTraceSegmentRef> for TraceSegmentWire {
    fn from(segment: &ResolvedEffectTraceSegmentRef) -> Self {
        Self {
            digest: ByteBuf(segment.id.digest().to_vec()),
            first_item: segment.first_item,
            item_count: segment.item_count,
            records: segment.records,
            encoded_bytes: segment.encoded_bytes,
        }
    }
}

impl TraceSegmentWire {
    pub(super) fn segment(
        &self,
    ) -> Result<ResolvedEffectTraceSegmentRef, FindingProductionReplayCaptureError> {
        Ok(ResolvedEffectTraceSegmentRef {
            id: trace_id(&self.digest, RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA)?,
            first_item: self.first_item,
            item_count: self.item_count,
            records: self.records,
            encoded_bytes: self.encoded_bytes,
        })
    }
}

/// A side trace's manifest: its replay mode, totals, chain, and ordered
/// segment references.
///
/// The fields are those of the trace's version 4 manifest, so the decoder
/// rebuilds that manifest from the segment references and requires the
/// recorded totals and chain to match the ones the references derive.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EffectTraceWire {
    pub(super) mode: FaultReplayMode,
    pub(super) work_items: u64,
    pub(super) records: u64,
    pub(super) chain: ContentHash,
    pub(super) segments: Vec<TraceSegmentWire>,
}

impl From<&ResolvedEffectTraceManifest> for EffectTraceWire {
    fn from(manifest: &ResolvedEffectTraceManifest) -> Self {
        Self {
            mode: manifest.mode(),
            work_items: manifest.work_items(),
            records: manifest.records(),
            chain: manifest.chain(),
            segments: manifest
                .segments()
                .iter()
                .map(TraceSegmentWire::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SideWire {
    pub(super) outcome: FindingProductionReplayTerminalOutcome,
    pub(super) completed_quanta: u64,
    pub(super) frontier_ticks: u64,
    pub(super) event_log: EventLogWire,
    pub(super) terminal_fingerprints: Vec<FingerprintWire>,
    pub(super) resolved_effect_trace: Option<EffectTraceWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentWire {
    pub(super) runtime: FindingProductionReplayRuntimeIdentity,
    pub(super) root_image_format: FindingProductionReplayRootImageFormat,
    pub(super) guest_assets: Vec<GuestAssetsWire>,
    pub(super) initrd: Option<AssetWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuestAssetsWire {
    pub(super) architecture: ArchitectureWire,
    pub(super) kernel: AssetWire,
    pub(super) root_image: AssetWire,
    pub(super) kernel_cmdline_prefix: Option<String>,
}

/// One guest asset: its BLAKE3 identity and the leaf holding its bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssetWire {
    pub(super) identity: ContentHash,
    pub(super) leaf: LeafWire,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ArchitectureWire {
    X86_64,
    Aarch64,
}

impl From<VmArchitecture> for ArchitectureWire {
    fn from(value: VmArchitecture) -> Self {
        match value {
            VmArchitecture::X86_64 => Self::X86_64,
            VmArchitecture::Aarch64 => Self::Aarch64,
        }
    }
}

impl From<ArchitectureWire> for VmArchitecture {
    fn from(value: ArchitectureWire) -> Self {
        match value {
            ArchitectureWire::X86_64 => Self::X86_64,
            ArchitectureWire::Aarch64 => Self::Aarch64,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FingerprintWire {
    node: String,
    at_ticks: u64,
    hash: ContentHash,
}

impl From<&FingerprintSample> for FingerprintWire {
    fn from(value: &FingerprintSample) -> Self {
        Self {
            node: value.node.name.clone(),
            at_ticks: value.at.ticks,
            hash: value.fingerprint.hash,
        }
    }
}

impl From<FingerprintWire> for FingerprintSample {
    fn from(value: FingerprintWire) -> Self {
        Self {
            node: NodeId { name: value.node },
            at: VirtualTime {
                ticks: value.at_ticks,
            },
            fingerprint: crucible::ExecutionFingerprint { hash: value.hash },
        }
    }
}

/// One lifecycle object: its BLAKE3 identity and the leaf holding its bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleObjectWire {
    pub(super) identity: ContentHash,
    pub(super) leaf: LeafWire,
}

pub(super) struct BoundedVecWriter {
    bytes: Vec<u8>,
    limit: u64,
    limit_exceeded: bool,
}

impl BoundedVecWriter {
    pub(super) fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            limit_exceeded: false,
        }
    }

    pub(super) const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    pub(super) fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for BoundedVecWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let current = u64::try_from(self.bytes.len())
            .map_err(|_| std::io::Error::other("encoded size cannot be represented"))?;
        let requested = u64::try_from(buffer.len())
            .map_err(|_| std::io::Error::other("write size cannot be represented"))?;
        if current
            .checked_add(requested)
            .is_none_or(|next| next > self.limit)
        {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("encoded size limit exceeded"));
        }
        self.bytes
            .try_reserve(buffer.len())
            .map_err(|_| std::io::Error::other("reserve encoded capture"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
