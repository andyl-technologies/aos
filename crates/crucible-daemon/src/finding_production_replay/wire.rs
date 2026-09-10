//! Canonical wire representation and bounded encoding writers.
//!
//! The codec owns the following versioned outer layout:
//!
//! ```text
//! CaptureWire { schema_version, reproduction, observed_signature,
//!               finding_fingerprint, model_reproduction, recipe, deployment,
//!               selected_side, sides, campaign_replay_closure,
//!               lifecycle_objects }
//! ```

use super::*;
use serde::de::{Deserializer, Visitor};
use serde::{Serializer, de};

const MAX_CBOR_NESTING_DEPTH: usize = 128;

struct ByteBuf(Vec<u8>);

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

struct BytesRef<'a>(&'a [u8]);

impl Serialize for BytesRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0)
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

#[derive(Serialize, Deserialize)]
pub(super) struct CaptureWire {
    pub(super) schema_version: u32,
    reproduction: ReproductionArtifactId,
    observed_signature: ByteBuf,
    finding_fingerprint: ContentHash,
    model_reproduction: ByteBuf,
    recipe: FindingProductionReplayRecipe,
    deployment: DeploymentWire,
    selected_side: FindingProductionReplaySelectedSide,
    sides: Vec<ExecutionSideWire>,
    campaign_replay_closure: ByteBuf,
    lifecycle_objects: Vec<LifecycleObjectWire>,
}

#[derive(Serialize)]
pub(super) struct CaptureWireRef<'a> {
    schema_version: u32,
    reproduction: ReproductionArtifactId,
    observed_signature: ByteBuf,
    finding_fingerprint: ContentHash,
    model_reproduction: BytesRef<'a>,
    recipe: FindingProductionReplayRecipe,
    deployment: DeploymentWireRef<'a>,
    selected_side: FindingProductionReplaySelectedSide,
    sides: Vec<ExecutionSideWireRef<'a>>,
    campaign_replay_closure: BytesRef<'a>,
    lifecycle_objects: Vec<LifecycleObjectWireRef<'a>>,
}

impl<'a> From<&'a FindingProductionReplayCapture> for CaptureWireRef<'a> {
    fn from(value: &'a FindingProductionReplayCapture) -> Self {
        Self {
            schema_version: FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION,
            reproduction: value.reproduction,
            observed_signature: ByteBuf(value.observed_signature.canonical_bytes()),
            finding_fingerprint: value.finding_fingerprint,
            model_reproduction: BytesRef(&value.model_reproduction),
            recipe: value.shared_context.recipe,
            deployment: DeploymentWireRef::from(&value.shared_context.deployment),
            selected_side: value.selected_side,
            sides: value.sides.iter().map(ExecutionSideWireRef::from).collect(),
            campaign_replay_closure: BytesRef(&value.campaign_replay_closure),
            lifecycle_objects: value
                .shared_context
                .lifecycle_objects
                .iter()
                .map(|(identity, bytes)| LifecycleObjectWireRef {
                    identity,
                    bytes: BytesRef(bytes),
                })
                .collect(),
        }
    }
}

impl TryFrom<CaptureWire> for FindingProductionReplayCapture {
    type Error = FindingProductionReplayCaptureError;

    fn try_from(value: CaptureWire) -> Result<Self, Self::Error> {
        let mut lifecycle_objects = BTreeMap::new();
        for object in value.lifecycle_objects {
            if lifecycle_objects
                .insert(object.identity, object.bytes.0)
                .is_some()
            {
                return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
            }
        }
        Ok(Self {
            reproduction: value.reproduction,
            observed_signature: FindingSignature::from_canonical_bytes(&value.observed_signature.0)
                .map_err(FindingProductionReplayCaptureError::Campaign)?,
            finding_fingerprint: value.finding_fingerprint,
            model_reproduction: value.model_reproduction.0.into(),
            shared_context: Arc::new(FindingProductionReplaySharedContext {
                recipe: value.recipe,
                deployment: FindingProductionReplayDeployment::from(value.deployment),
                lifecycle_objects,
            }),
            selected_side: value.selected_side,
            sides: value
                .sides
                .into_iter()
                .map(FindingProductionReplayExecutionSide::from)
                .collect::<Vec<_>>()
                .into(),
            campaign_replay_closure: value.campaign_replay_closure.0.into(),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct DeploymentWire {
    runtime: FindingProductionReplayRuntimeIdentity,
    root_image_format: FindingProductionReplayRootImageFormat,
    guest_assets: Vec<GuestAssetsWire>,
    initrd: Option<AssetWire>,
}

impl From<DeploymentWire> for FindingProductionReplayDeployment {
    fn from(value: DeploymentWire) -> Self {
        Self {
            runtime: value.runtime,
            root_image_format: value.root_image_format,
            guest_assets: value
                .guest_assets
                .into_iter()
                .map(FindingProductionReplayGuestAssets::from)
                .collect(),
            initrd: value.initrd.map(FindingProductionReplayAsset::from),
        }
    }
}

#[derive(Serialize)]
struct DeploymentWireRef<'a> {
    runtime: &'a FindingProductionReplayRuntimeIdentity,
    root_image_format: FindingProductionReplayRootImageFormat,
    guest_assets: Vec<GuestAssetsWireRef<'a>>,
    initrd: Option<AssetWireRef<'a>>,
}

impl<'a> From<&'a FindingProductionReplayDeployment> for DeploymentWireRef<'a> {
    fn from(value: &'a FindingProductionReplayDeployment) -> Self {
        Self {
            runtime: &value.runtime,
            root_image_format: value.root_image_format,
            guest_assets: value
                .guest_assets
                .iter()
                .map(GuestAssetsWireRef::from)
                .collect(),
            initrd: value.initrd.as_ref().map(AssetWireRef::from),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct GuestAssetsWire {
    architecture: ArchitectureWire,
    kernel: AssetWire,
    root_image: AssetWire,
    kernel_cmdline_prefix: Option<String>,
}

impl From<GuestAssetsWire> for FindingProductionReplayGuestAssets {
    fn from(value: GuestAssetsWire) -> Self {
        Self {
            architecture: value.architecture.into(),
            kernel: value.kernel.into(),
            root_image: value.root_image.into(),
            kernel_cmdline_prefix: value.kernel_cmdline_prefix,
        }
    }
}

#[derive(Serialize)]
struct GuestAssetsWireRef<'a> {
    architecture: ArchitectureWire,
    kernel: AssetWireRef<'a>,
    root_image: AssetWireRef<'a>,
    kernel_cmdline_prefix: Option<&'a str>,
}

impl<'a> From<&'a FindingProductionReplayGuestAssets> for GuestAssetsWireRef<'a> {
    fn from(value: &'a FindingProductionReplayGuestAssets) -> Self {
        Self {
            architecture: value.architecture.into(),
            kernel: AssetWireRef::from(&value.kernel),
            root_image: AssetWireRef::from(&value.root_image),
            kernel_cmdline_prefix: value.kernel_cmdline_prefix.as_deref(),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ArchitectureWire {
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
struct AssetWire {
    identity: ContentHash,
    bytes: ByteBuf,
}

impl From<AssetWire> for FindingProductionReplayAsset {
    fn from(value: AssetWire) -> Self {
        Self {
            identity: value.identity,
            bytes: value.bytes.0.into(),
        }
    }
}

#[derive(Serialize)]
struct AssetWireRef<'a> {
    identity: ContentHash,
    bytes: BytesRef<'a>,
}

impl<'a> From<&'a FindingProductionReplayAsset> for AssetWireRef<'a> {
    fn from(value: &'a FindingProductionReplayAsset) -> Self {
        Self {
            identity: value.identity,
            bytes: BytesRef(&value.bytes),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ExecutionSideWire {
    outcome: FindingProductionReplayTerminalOutcome,
    completed_quanta: u64,
    frontier_ticks: u64,
    event_log: Vec<SchedulerEventLogEntry>,
    terminal_fingerprints: Vec<FingerprintWire>,
    resolved_effect_trace: Option<ByteBuf>,
}

#[derive(Serialize)]
struct ExecutionSideWireRef<'a> {
    outcome: FindingProductionReplayTerminalOutcome,
    completed_quanta: u64,
    frontier_ticks: u64,
    event_log: &'a [SchedulerEventLogEntry],
    terminal_fingerprints: Vec<FingerprintWireRef<'a>>,
    resolved_effect_trace: Option<BytesRef<'a>>,
}

impl<'a> From<&'a FindingProductionReplayExecutionSide> for ExecutionSideWireRef<'a> {
    fn from(value: &'a FindingProductionReplayExecutionSide) -> Self {
        Self {
            outcome: value.outcome,
            completed_quanta: value.completed_quanta,
            frontier_ticks: value.frontier.ticks,
            event_log: &value.event_log,
            terminal_fingerprints: value
                .terminal_fingerprints
                .iter()
                .map(FingerprintWireRef::from)
                .collect(),
            resolved_effect_trace: value.resolved_effect_trace.as_deref().map(BytesRef),
        }
    }
}

impl From<ExecutionSideWire> for FindingProductionReplayExecutionSide {
    fn from(value: ExecutionSideWire) -> Self {
        Self {
            outcome: value.outcome,
            completed_quanta: value.completed_quanta,
            frontier: VirtualTime {
                ticks: value.frontier_ticks,
            },
            event_log: value.event_log,
            terminal_fingerprints: value
                .terminal_fingerprints
                .into_iter()
                .map(FingerprintSample::from)
                .collect(),
            resolved_effect_trace: value.resolved_effect_trace.map(|bytes| bytes.0),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FingerprintWire {
    node: String,
    at_ticks: u64,
    hash: ContentHash,
}

#[derive(Serialize)]
struct FingerprintWireRef<'a> {
    node: &'a str,
    at_ticks: u64,
    hash: ContentHash,
}

impl<'a> From<&'a FingerprintSample> for FingerprintWireRef<'a> {
    fn from(value: &'a FingerprintSample) -> Self {
        Self {
            node: &value.node.name,
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

#[derive(Serialize, Deserialize)]
struct LifecycleObjectWire {
    identity: ContentHash,
    bytes: ByteBuf,
}

#[derive(Serialize)]
struct LifecycleObjectWireRef<'a> {
    identity: &'a ContentHash,
    bytes: BytesRef<'a>,
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

pub(super) struct BoundedHashWriter {
    hasher: blake3::Hasher,
    written: u64,
    limit: u64,
    limit_exceeded: bool,
}

impl BoundedHashWriter {
    pub(super) fn new(limit: u64) -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            written: 0,
            limit,
            limit_exceeded: false,
        }
    }

    pub(super) const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    pub(super) fn finish(self) -> ContentHash {
        ContentHash {
            bytes: *self.hasher.finalize().as_bytes(),
        }
    }
}

impl std::io::Write for BoundedHashWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let requested = u64::try_from(buffer.len())
            .map_err(|_| std::io::Error::other("hash write size cannot be represented"))?;
        let Some(next) = self.written.checked_add(requested) else {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("encoded size limit exceeded"));
        };
        if next > self.limit {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("encoded size limit exceeded"));
        }
        self.hasher.update(buffer);
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct CanonicalComparisonWriter<'a> {
    expected: &'a [u8],
    position: usize,
    written: u64,
    limit: u64,
    mismatch: bool,
    limit_exceeded: bool,
}

impl<'a> CanonicalComparisonWriter<'a> {
    pub(super) const fn new(expected: &'a [u8], limit: u64) -> Self {
        Self {
            expected,
            position: 0,
            written: 0,
            limit,
            mismatch: false,
            limit_exceeded: false,
        }
    }

    pub(super) const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    pub(super) fn matches(&self) -> bool {
        !self.mismatch && self.position == self.expected.len()
    }
}

impl std::io::Write for CanonicalComparisonWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let requested = u64::try_from(buffer.len())
            .map_err(|_| std::io::Error::other("comparison size cannot be represented"))?;
        let Some(next_written) = self.written.checked_add(requested) else {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("encoded size limit exceeded"));
        };
        if next_written > self.limit {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("encoded size limit exceeded"));
        }
        let next_position = self.position.saturating_add(buffer.len());
        if next_position > self.expected.len()
            || self.expected[self.position..next_position] != *buffer
        {
            self.mismatch = true;
        }
        self.position = next_position;
        self.written = next_written;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
