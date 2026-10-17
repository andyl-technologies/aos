//! Publication and loading of version 4 capture manifests.
//!
//! [`FindingProductionReplayCapture::prepare_objects`] derives the manifest
//! envelope and every leaf without writing anything. Leaf bytes are read from
//! the capture's shared in-memory content, or from a side's segment stores,
//! only when a backend copies them, so preparing a capture never builds a
//! buffer the size of the capture.
//! [`FindingProductionReplayCapture::from_objects`] decodes a published
//! manifest, checks that its children are exactly the leaves its body names,
//! and reads the static leaves under fixed or scenario-derived bounds. Side
//! logs stay segment references served by the supplied leaf handles.
//!
//! ```text
//! child role               leaf content                          read bound
//! model-reproduction       compact model reproduction            32 MiB
//! campaign-replay-closure  canonical guarded replay closure      128 MiB
//! resolved-effect-trace    one side's resolved-effect trace      64 MiB
//! guest-asset              kernel, root image, or initrd bytes   scenario guest-asset bytes
//! lifecycle-object         signal artifact or World base image   scenario lifecycle bytes
//! event-log-segment        one attempt-log segment               16 MiB, streamed
//! ```
//!
//! Every leaf is a trace object of schema version 1 whose identity derives
//! from its bytes, and the envelope is an exact manifest of schema version 4.

use std::io::{self, Cursor, Read};

use crucible_campaign::FindingReplayCaptureEvidenceId;
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{BlobHandle, BlobSource, ObjectKind, StoreError};

use super::wire::{
    ArchitectureWire, AssetWire, BoundedVecWriter, ByteBuf, CAPTURE_LEAF_SCHEMA_VERSION,
    CaptureManifestWire, DeploymentWire, EventLogWire, FingerprintWire, GuestAssetsWire, LeafWire,
    LifecycleObjectWire, SegmentWire, SideWire, preflight_canonical_cbor,
};
use super::*;
use crate::qemu_campaign_lifecycle::MAX_REPLAY_CLOSURE_BYTES;
use crate::{
    AttemptLogManifest, AttemptLogSegmentRef, AttemptLogSegmentSource, AttemptLogSegmentSources,
    MAX_ATTEMPT_LOG_SEGMENT_BYTES, MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
};

/// Schema name of the version 4 capture manifest envelope.
pub const FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA: &str =
    "crucible.executor.finding-production-replay-capture";

/// Largest encoded capture manifest, children and body together.
///
/// This is the generic content-envelope bound, which is also the ordinary
/// component-message bound. The body holds at most two side manifests of
/// 4,095 segment references each plus the scenario-bounded leaf lists, so
/// the bound does not grow with the replayed run.
pub const MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// Largest model reproduction leaf, the campaign artifact payload ceiling.
const MAX_MODEL_REPRODUCTION_LEAF_BYTES: u64 = MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES as u64;

/// Semantic role of one capture manifest child.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingProductionReplayLeafRole {
    /// The compact model reproduction the replay executed.
    ModelReproduction,
    /// The canonical guarded campaign replay closure.
    CampaignReplayClosure,
    /// One side's canonical resolved-effect trace.
    ResolvedEffectTrace,
    /// One guest kernel, root image, or initrd.
    GuestAsset,
    /// One signal artifact or World I/O base image.
    LifecycleObject,
    /// One attempt-log segment of a side's scheduler log.
    EventLogSegment,
}

impl FindingProductionReplayLeafRole {
    /// Returns the stable envelope child role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelReproduction => "model-reproduction",
            Self::CampaignReplayClosure => "campaign-replay-closure",
            Self::ResolvedEffectTrace => "resolved-effect-trace",
            Self::GuestAsset => "guest-asset",
            Self::LifecycleObject => "lifecycle-object",
            Self::EventLogSegment => "event-log-segment",
        }
    }

    /// Parses a stable envelope child role.
    #[must_use]
    pub fn from_role(role: &str) -> Option<Self> {
        [
            Self::ModelReproduction,
            Self::CampaignReplayClosure,
            Self::ResolvedEffectTrace,
            Self::GuestAsset,
            Self::LifecycleObject,
            Self::EventLogSegment,
        ]
        .into_iter()
        .find(|candidate| candidate.as_str() == role)
    }

    /// Returns whether the leaf's size grows with the replayed run.
    ///
    /// Only side-log segments do; every other leaf is fixed by the scenario
    /// or by a constant format bound.
    #[must_use]
    pub const fn is_run_length(self) -> bool {
        matches!(self, Self::EventLogSegment)
    }
}

/// One content-addressed leaf of a capture, ready to be copied by a backend.
#[derive(Clone)]
pub struct FindingProductionReplayLeaf {
    role: FindingProductionReplayLeafRole,
    length: u64,
    source: BlobHandle,
}

impl std::fmt::Debug for FindingProductionReplayLeaf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingProductionReplayLeaf")
            .field("role", &self.role)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

impl FindingProductionReplayLeaf {
    /// Returns the leaf's role; a run-length role when any reference is one.
    #[must_use]
    pub const fn role(&self) -> FindingProductionReplayLeafRole {
        self.role
    }

    /// Returns the exact leaf length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns a reopenable source of the leaf bytes.
    ///
    /// Opening the source reads the bytes from the capture's shared content
    /// or from a side's segment store; nothing is buffered beforehand.
    #[must_use]
    pub const fn source(&self) -> &BlobHandle {
        &self.source
    }
}

/// The manifest and every leaf of one capture, derived without any write.
#[derive(Clone)]
pub struct FindingProductionReplayCaptureObjects {
    root: FindingReplayCaptureEvidenceId,
    manifest: Arc<[u8]>,
    leaves: BTreeMap<ContentId, FindingProductionReplayLeaf>,
}

impl std::fmt::Debug for FindingProductionReplayCaptureObjects {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingProductionReplayCaptureObjects")
            .field("root", &self.root)
            .field("manifest_bytes", &self.manifest.len())
            .field("leaves", &self.leaves.len())
            .finish()
    }
}

impl FindingProductionReplayCaptureObjects {
    /// Returns the manifest identity that names the complete capture.
    #[must_use]
    pub const fn root(&self) -> FindingReplayCaptureEvidenceId {
        self.root
    }

    /// Returns the canonical manifest envelope bytes.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns a reopenable source of the manifest envelope bytes.
    #[must_use]
    pub fn manifest_source(&self) -> BlobHandle {
        BlobHandle::new(Arc::new(SharedBytesSource(SharedBytes::Owned(Arc::clone(
            &self.manifest,
        )))))
    }

    /// Returns every distinct leaf the manifest references, by identity.
    #[must_use]
    pub const fn leaves(&self) -> &BTreeMap<ContentId, FindingProductionReplayLeaf> {
        &self.leaves
    }
}

/// Decodes a capture manifest envelope and checks it names `root`.
///
/// Only the envelope framing, identity, and schema are checked here. A
/// publication store uses the children to preflight leaf presence and
/// allowances before [`FindingProductionReplayCapture::from_objects`]
/// authenticates the body.
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when the bytes exceed the
/// manifest bound, are not a canonical envelope, derive another identity, or
/// carry another schema.
pub fn decode_finding_production_replay_manifest(
    root: FindingReplayCaptureEvidenceId,
    bytes: &[u8],
) -> Result<ContentEnvelope, FindingProductionReplayCaptureError> {
    if bytes.len() as u64 > MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-manifest-bytes",
        });
    }
    let envelope = ContentEnvelope::from_canonical_bytes(bytes)
        .map_err(FindingProductionReplayCaptureError::Envelope)?;
    if envelope.schema_name() != FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA {
        return Err(FindingProductionReplayCaptureError::InvalidManifest { reason: "schema" });
    }
    if envelope.schema_version() != FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION {
        return Err(FindingProductionReplayCaptureError::UnsupportedSchema {
            actual: envelope.schema_version(),
        });
    }
    if envelope.content_id(ObjectKind::ExactManifest) != root.content_id() {
        return Err(FindingProductionReplayCaptureError::InvalidManifest {
            reason: "manifest identity",
        });
    }
    Ok(envelope)
}

impl FindingProductionReplayCapture {
    /// Derives the manifest and every leaf for publication without writing.
    ///
    /// The capture was authenticated when it was built, so nothing is
    /// revalidated here. Equal leaves of different roles or sides appear once
    /// in [`FindingProductionReplayCaptureObjects::leaves`].
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] when the manifest
    /// cannot be encoded within [`MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES`]
    /// or its identity is not a capture evidence identity.
    pub fn prepare_objects(
        &self,
    ) -> Result<FindingProductionReplayCaptureObjects, FindingProductionReplayCaptureError> {
        let mut leaves = LeafSet::default();
        let leaf_ids = self.shared_context.leaf_ids();

        let model_reproduction = leaves.insert_bytes(
            FindingProductionReplayLeafRole::ModelReproduction,
            SharedBytes::Owned(Arc::clone(&self.model_reproduction)),
            None,
        )?;
        let campaign_replay_closure = leaves.insert_bytes(
            FindingProductionReplayLeafRole::CampaignReplayClosure,
            SharedBytes::Owned(Arc::clone(&self.campaign_replay_closure)),
            None,
        )?;
        let deployment = deployment_wire(&self.shared_context.deployment, leaf_ids, &mut leaves)?;
        let mut lifecycle_objects = Vec::with_capacity(self.shared_context.lifecycle_objects.len());
        for identity in self.shared_context.lifecycle_objects.keys() {
            let leaf = leaves.insert_bytes(
                FindingProductionReplayLeafRole::LifecycleObject,
                SharedBytes::LifecycleObject {
                    context: Arc::clone(&self.shared_context),
                    identity: *identity,
                },
                leaf_ids.get(identity).copied(),
            )?;
            lifecycle_objects.push(LifecycleObjectWire {
                identity: *identity,
                leaf,
            });
        }
        let sides = self
            .sides
            .iter()
            .map(|side| side_wire(side, &mut leaves))
            .collect::<Result<Vec<_>, _>>()?;

        let body = CaptureManifestWire {
            schema_version: FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION,
            reproduction: self.reproduction,
            observed_signature: ByteBuf(self.observed_signature.canonical_bytes()),
            finding_fingerprint: self.finding_fingerprint,
            model_reproduction,
            recipe: self.shared_context.recipe,
            deployment,
            selected_side: self.selected_side,
            sides,
            campaign_replay_closure,
            lifecycle_objects,
        };
        let envelope = encode_manifest(&body, leaves.children)?;
        let root = FindingReplayCaptureEvidenceId::from_manifest_content_id(
            envelope.content_id(ObjectKind::ExactManifest),
        )
        .map_err(FindingProductionReplayCaptureError::Campaign)?;

        Ok(FindingProductionReplayCaptureObjects {
            root,
            manifest: envelope.canonical_bytes().into(),
            leaves: leaves.leaves,
        })
    }

    /// Decodes and authenticates a published capture from its objects.
    ///
    /// `leaves` supplies a handle for every child the manifest names; side
    /// logs keep reading their segments through those handles, one segment at
    /// a time. Static leaves are read whole under their bounds and `limits`.
    /// The decoded capture is then authenticated exactly as a freshly
    /// captured one, which streams every side log once.
    ///
    /// # Errors
    ///
    /// Returns [`FindingProductionReplayCaptureError`] for a malformed,
    /// noncanonical, or oversized manifest, children that differ from the
    /// leaves the body names, a missing, mislabeled, or corrupt leaf, or a
    /// capture that fails authentication.
    pub fn from_objects(
        root: FindingReplayCaptureEvidenceId,
        manifest: &[u8],
        leaves: &BTreeMap<ContentId, BlobHandle>,
        limits: FindingProductionReplayCaptureLimits,
    ) -> Result<Self, FindingProductionReplayCaptureError> {
        let envelope = decode_finding_production_replay_manifest(root, manifest)?;
        let body = decode_manifest_body(envelope.body())?;
        if manifest_children(&body)? != *envelope.children() {
            return Err(FindingProductionReplayCaptureError::InvalidManifest {
                reason: "children differ from the leaves the body names",
            });
        }

        let reader = LeafReader { leaves };
        let model_reproduction =
            reader.read(&body.model_reproduction, MAX_MODEL_REPRODUCTION_LEAF_BYTES)?;
        let campaign_replay_closure = reader.read(
            &body.campaign_replay_closure,
            MAX_REPLAY_CLOSURE_BYTES as u64,
        )?;
        let mut leaf_ids = BTreeMap::new();
        let deployment = read_deployment(&reader, body.deployment, limits, &mut leaf_ids)?;
        let lifecycle_objects =
            read_lifecycle_objects(&reader, body.lifecycle_objects, limits, &mut leaf_ids)?;
        let sides = body
            .sides
            .into_iter()
            .map(|side| read_side(&reader, side))
            .collect::<Result<Vec<_>, _>>()?;

        let shared_context = FindingProductionReplaySharedContext::from_validated_parts(
            body.recipe,
            deployment,
            lifecycle_objects,
        );
        // Every identity was rederived from the bytes just read.
        let _ = shared_context.leaf_ids.set(leaf_ids);
        let capture = Self {
            reproduction: body.reproduction,
            observed_signature: FindingSignature::from_canonical_bytes(&body.observed_signature.0)
                .map_err(FindingProductionReplayCaptureError::Campaign)?,
            finding_fingerprint: body.finding_fingerprint,
            model_reproduction: model_reproduction.into(),
            shared_context: Arc::new(shared_context),
            selected_side: body.selected_side,
            sides: sides.into(),
            campaign_replay_closure: campaign_replay_closure.into(),
        };
        capture.validate(limits)?;
        Ok(capture)
    }
}

impl FindingProductionReplaySharedContext {
    /// Returns the publication leaf identity of every asset and object.
    fn leaf_ids(&self) -> &BTreeMap<ContentHash, ContentId> {
        self.leaf_ids.get_or_init(|| {
            let assets = self
                .deployment
                .guest_assets
                .iter()
                .flat_map(|assets| [&assets.kernel, &assets.root_image])
                .chain(self.deployment.initrd.iter())
                .map(|asset| (asset.identity, leaf_id(&asset.bytes)));
            let objects = self
                .lifecycle_objects
                .iter()
                .map(|(identity, bytes)| (*identity, leaf_id(bytes)));
            assets.chain(objects).collect()
        })
    }
}

/// Derives the trace identity of one non-segment leaf.
fn leaf_id(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, CAPTURE_LEAF_SCHEMA_VERSION, bytes)
}

/// Distinct leaves and role-tagged children accumulated for one manifest.
#[derive(Default)]
struct LeafSet {
    leaves: BTreeMap<ContentId, FindingProductionReplayLeaf>,
    children: BTreeSet<ContentChild>,
}

impl LeafSet {
    /// Adds one shared byte leaf, hashing it unless `known_id` names it.
    fn insert_bytes(
        &mut self,
        role: FindingProductionReplayLeafRole,
        bytes: SharedBytes,
        known_id: Option<ContentId>,
    ) -> Result<LeafWire, FindingProductionReplayCaptureError> {
        let id = known_id.unwrap_or_else(|| leaf_id(bytes.as_slice()));
        let length = bytes.as_slice().len() as u64;
        let source = BlobHandle::new(Arc::new(SharedBytesSource(bytes)));
        self.insert(role, id, length, source)?;
        Ok(LeafWire::new(id, length))
    }

    /// Adds one side-log segment, read from `segments` only when copied.
    fn insert_segment(
        &mut self,
        segment: AttemptLogSegmentRef,
        segments: &AttemptLogSegmentSources,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        let source = BlobHandle::new(Arc::new(SegmentLeafSource {
            segment,
            segments: segments.clone(),
        }));
        self.insert(
            FindingProductionReplayLeafRole::EventLogSegment,
            segment.id,
            segment.encoded_bytes,
            source,
        )
    }

    fn insert(
        &mut self,
        role: FindingProductionReplayLeafRole,
        id: ContentId,
        length: u64,
        source: BlobHandle,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        self.children.insert(
            ContentChild::new(role.as_str(), id)
                .map_err(FindingProductionReplayCaptureError::Envelope)?,
        );
        let leaf = self
            .leaves
            .entry(id)
            .or_insert(FindingProductionReplayLeaf {
                role,
                length,
                source,
            });
        // Equal bytes referenced as both a segment and a static leaf are
        // charged as run-length evidence.
        if role.is_run_length() {
            leaf.role = role;
        }
        Ok(())
    }
}

fn deployment_wire(
    deployment: &FindingProductionReplayDeployment,
    leaf_ids: &BTreeMap<ContentHash, ContentId>,
    leaves: &mut LeafSet,
) -> Result<DeploymentWire, FindingProductionReplayCaptureError> {
    let mut asset = |asset: &FindingProductionReplayAsset| {
        let leaf = leaves.insert_bytes(
            FindingProductionReplayLeafRole::GuestAsset,
            SharedBytes::Owned(Arc::clone(&asset.bytes)),
            leaf_ids.get(&asset.identity).copied(),
        )?;
        Ok::<_, FindingProductionReplayCaptureError>(AssetWire {
            identity: asset.identity,
            leaf,
        })
    };
    let mut guest_assets = Vec::with_capacity(deployment.guest_assets.len());
    for assets in &deployment.guest_assets {
        guest_assets.push(GuestAssetsWire {
            architecture: ArchitectureWire::from(assets.architecture),
            kernel: asset(&assets.kernel)?,
            root_image: asset(&assets.root_image)?,
            kernel_cmdline_prefix: assets.kernel_cmdline_prefix.clone(),
        });
    }
    let initrd = deployment.initrd.as_ref().map(&mut asset).transpose()?;

    Ok(DeploymentWire {
        runtime: deployment.runtime.clone(),
        root_image_format: deployment.root_image_format,
        guest_assets,
        initrd,
    })
}

fn side_wire(
    side: &FindingProductionReplayExecutionSide,
    leaves: &mut LeafSet,
) -> Result<SideWire, FindingProductionReplayCaptureError> {
    let manifest = side.event_log.manifest();
    for segment in manifest.segments() {
        leaves.insert_segment(*segment, side.event_log.segments())?;
    }
    let resolved_effect_trace = side
        .resolved_effect_trace
        .as_ref()
        .map(|trace| {
            leaves.insert_bytes(
                FindingProductionReplayLeafRole::ResolvedEffectTrace,
                SharedBytes::Owned(Arc::clone(trace)),
                None,
            )
        })
        .transpose()?;

    Ok(SideWire {
        outcome: side.outcome,
        completed_quanta: side.completed_quanta,
        frontier_ticks: side.frontier.ticks,
        event_log: EventLogWire {
            entry_count: manifest.entry_count(),
            chain: manifest.chain(),
            segments: manifest.segments().iter().map(SegmentWire::from).collect(),
        },
        terminal_fingerprints: side
            .terminal_fingerprints
            .iter()
            .map(FingerprintWire::from)
            .collect(),
        resolved_effect_trace,
    })
}

fn encode_manifest(
    body: &CaptureManifestWire,
    children: BTreeSet<ContentChild>,
) -> Result<ContentEnvelope, FindingProductionReplayCaptureError> {
    let mut writer = BoundedVecWriter::new(MAX_FINDING_PRODUCTION_REPLAY_MANIFEST_BYTES);
    if let Err(error) = ciborium::into_writer(body, &mut writer) {
        if writer.limit_exceeded() {
            return Err(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-manifest-bytes",
            });
        }
        return Err(FindingProductionReplayCaptureError::Encode(error));
    }
    ContentEnvelope::new(
        FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA,
        FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION,
        children,
        writer.into_inner(),
    )
    .map_err(FindingProductionReplayCaptureError::Envelope)
}

/// Decodes the bounded body and requires its exact canonical encoding.
pub(super) fn decode_manifest_body(
    bytes: &[u8],
) -> Result<CaptureManifestWire, FindingProductionReplayCaptureError> {
    preflight_canonical_cbor(bytes)
        .map_err(|()| FindingProductionReplayCaptureError::DecodeBounds)?;
    let body: CaptureManifestWire =
        ciborium::from_reader(bytes).map_err(FindingProductionReplayCaptureError::Decode)?;
    if body.schema_version != FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION {
        return Err(FindingProductionReplayCaptureError::UnsupportedSchema {
            actual: body.schema_version,
        });
    }

    let mut reencoded = BoundedVecWriter::new(bytes.len() as u64);
    if ciborium::into_writer(&body, &mut reencoded).is_err() || reencoded.into_inner() != bytes {
        return Err(FindingProductionReplayCaptureError::Noncanonical);
    }
    Ok(body)
}

/// Returns the exact role-tagged children the body names.
fn manifest_children(
    body: &CaptureManifestWire,
) -> Result<BTreeSet<ContentChild>, FindingProductionReplayCaptureError> {
    let mut children = BTreeSet::new();
    let mut child = |role: FindingProductionReplayLeafRole, id: ContentId| {
        children.insert(
            ContentChild::new(role.as_str(), id)
                .map_err(FindingProductionReplayCaptureError::Envelope)?,
        );
        Ok::<_, FindingProductionReplayCaptureError>(())
    };

    child(
        FindingProductionReplayLeafRole::ModelReproduction,
        body.model_reproduction.id()?,
    )?;
    child(
        FindingProductionReplayLeafRole::CampaignReplayClosure,
        body.campaign_replay_closure.id()?,
    )?;
    for assets in &body.deployment.guest_assets {
        for asset in [&assets.kernel, &assets.root_image] {
            child(
                FindingProductionReplayLeafRole::GuestAsset,
                asset.leaf.id()?,
            )?;
        }
    }
    if let Some(initrd) = &body.deployment.initrd {
        child(
            FindingProductionReplayLeafRole::GuestAsset,
            initrd.leaf.id()?,
        )?;
    }
    for object in &body.lifecycle_objects {
        child(
            FindingProductionReplayLeafRole::LifecycleObject,
            object.leaf.id()?,
        )?;
    }
    for side in &body.sides {
        for segment in &side.event_log.segments {
            child(
                FindingProductionReplayLeafRole::EventLogSegment,
                segment.segment()?.id,
            )?;
        }
        if let Some(trace) = &side.resolved_effect_trace {
            child(
                FindingProductionReplayLeafRole::ResolvedEffectTrace,
                trace.id()?,
            )?;
        }
    }
    Ok(children)
}

/// Bounded, authenticated reads of manifest leaves.
struct LeafReader<'a> {
    leaves: &'a BTreeMap<ContentId, BlobHandle>,
}

impl LeafReader<'_> {
    /// Returns the handle for `id` after checking its declared length.
    fn handle(
        &self,
        id: ContentId,
        length: u64,
    ) -> Result<&BlobHandle, FindingProductionReplayCaptureError> {
        let handle = self
            .leaves
            .get(&id)
            .ok_or(FindingProductionReplayCaptureError::MissingLeaf { id })?;
        if handle.logical_length() != length {
            return Err(FindingProductionReplayCaptureError::InvalidManifest {
                reason: "leaf length",
            });
        }
        Ok(handle)
    }

    /// Reads one static leaf whole, refusing it before any read when its
    /// declared length exceeds `bound`.
    fn read(
        &self,
        leaf: &LeafWire,
        bound: u64,
    ) -> Result<Vec<u8>, FindingProductionReplayCaptureError> {
        if leaf.length > bound {
            return Err(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-leaf-bytes",
            });
        }
        let id = leaf.id()?;
        let bytes = self
            .handle(id, leaf.length)?
            .read_all(leaf.length)
            .map_err(FindingProductionReplayCaptureError::LeafStore)?;
        // A repository handle authenticates at EOF; rederiving the identity
        // keeps any other leaf source fail-closed as well.
        if leaf_id(&bytes) != id {
            return Err(FindingProductionReplayCaptureError::LeafStore(
                StoreError::Corrupt { id },
            ));
        }
        Ok(bytes)
    }
}

fn read_deployment(
    reader: &LeafReader<'_>,
    wire: DeploymentWire,
    limits: FindingProductionReplayCaptureLimits,
    leaf_ids: &mut BTreeMap<ContentHash, ContentId>,
) -> Result<FindingProductionReplayDeployment, FindingProductionReplayCaptureError> {
    let mut read = BTreeMap::<ContentId, FindingProductionReplayAsset>::new();
    let mut retained_bytes = 0_u64;
    let mut asset = |wire: AssetWire| {
        let id = wire.leaf.id()?;
        if let Some(asset) = read.get(&id) {
            if asset.identity != wire.identity {
                return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
            }
            return Ok(asset.clone());
        }
        retained_bytes = charge_bytes(
            retained_bytes,
            usize::try_from(wire.leaf.length).unwrap_or(usize::MAX),
            limits.max_guest_asset_bytes,
            "finding-production-replay-guest-asset-bytes",
        )?;
        let bytes = reader.read(&wire.leaf, limits.max_guest_asset_bytes)?;
        if ContentHash::from_bytes(&bytes) != wire.identity {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
        let asset = FindingProductionReplayAsset {
            identity: wire.identity,
            bytes: bytes.into(),
        };
        leaf_ids.insert(wire.identity, id);
        read.insert(id, asset.clone());
        Ok(asset)
    };

    let mut guest_assets = Vec::with_capacity(wire.guest_assets.len());
    for assets in wire.guest_assets {
        guest_assets.push(FindingProductionReplayGuestAssets {
            architecture: assets.architecture.into(),
            kernel: asset(assets.kernel)?,
            root_image: asset(assets.root_image)?,
            kernel_cmdline_prefix: assets.kernel_cmdline_prefix,
        });
    }
    let initrd = wire.initrd.map(&mut asset).transpose()?;

    Ok(FindingProductionReplayDeployment {
        runtime: wire.runtime,
        root_image_format: wire.root_image_format,
        guest_assets,
        initrd,
    })
}

fn read_lifecycle_objects(
    reader: &LeafReader<'_>,
    wire: Vec<LifecycleObjectWire>,
    limits: FindingProductionReplayCaptureLimits,
    leaf_ids: &mut BTreeMap<ContentHash, ContentId>,
) -> Result<BTreeMap<ContentHash, Vec<u8>>, FindingProductionReplayCaptureError> {
    if wire.len() > limits.max_lifecycle_objects {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-object-count",
        });
    }
    let mut objects = BTreeMap::new();
    let mut retained_bytes = 0_u64;
    for object in wire {
        // Canonical order is strictly ascending identity, so a repeated or
        // reordered object is rejected before its bytes are read.
        if objects
            .last_key_value()
            .is_some_and(|(previous, _)| *previous >= object.identity)
        {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
        retained_bytes = charge_bytes(
            retained_bytes,
            usize::try_from(object.leaf.length).unwrap_or(usize::MAX),
            limits.max_lifecycle_bytes,
            "finding-production-replay-lifecycle-bytes",
        )?;
        let bytes = reader.read(&object.leaf, limits.max_lifecycle_bytes)?;
        if ContentHash::from_bytes(&bytes) != object.identity {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
        leaf_ids.insert(object.identity, object.leaf.id()?);
        objects.insert(object.identity, bytes);
    }
    Ok(objects)
}

fn read_side(
    reader: &LeafReader<'_>,
    wire: SideWire,
) -> Result<FindingProductionReplayExecutionSide, FindingProductionReplayCaptureError> {
    let segments = wire
        .event_log
        .segments
        .iter()
        .map(SegmentWire::segment)
        .collect::<Result<Vec<_>, _>>()?;
    let mut handles = BTreeMap::new();
    for segment in &segments {
        handles.insert(
            segment.id,
            reader.handle(segment.id, segment.encoded_bytes)?.clone(),
        );
    }
    let manifest =
        AttemptLogManifest::from_parts(segments, wire.event_log.entry_count, wire.event_log.chain)
            .map_err(|_| FindingProductionReplayCaptureError::InvalidManifest {
                reason: "side event log",
            })?;
    let mut sources = AttemptLogSegmentSources::default();
    sources.push(Arc::new(LeafSegmentSource { handles }));

    let resolved_effect_trace = wire
        .resolved_effect_trace
        .as_ref()
        .map(|leaf| {
            reader.read(
                leaf,
                super::MAX_FINDING_PRODUCTION_REPLAY_TRACE_BUNDLE_BYTES,
            )
        })
        .transpose()?
        .map(Arc::from);
    FindingProductionReplayExecutionSide::from_parts(
        wire.outcome,
        wire.completed_quanta,
        VirtualTime {
            ticks: wire.frontier_ticks,
        },
        FindingProductionReplayEventLog::new(manifest, sources),
        wire.terminal_fingerprints
            .into_iter()
            .map(FingerprintSample::from)
            .collect(),
        resolved_effect_trace,
    )
}

/// Shared immutable bytes a leaf source reads without copying them first.
#[derive(Clone)]
enum SharedBytes {
    /// Bytes owned through their own reference count.
    Owned(Arc<[u8]>),
    /// One lifecycle object inside a shared replay context.
    LifecycleObject {
        context: Arc<FindingProductionReplaySharedContext>,
        identity: ContentHash,
    },
}

impl SharedBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            // A context never loses an object, so absence cannot occur; an
            // empty read would fail the backend's length and identity checks.
            Self::LifecycleObject { context, identity } => context
                .lifecycle_objects
                .get(identity)
                .map_or(&[][..], Vec::as_slice),
        }
    }
}

struct SharedBytesSource(SharedBytes);

impl BlobSource for SharedBytesSource {
    fn logical_length(&self) -> u64 {
        self.0.as_slice().len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(SharedBytesReader {
            bytes: self.0.clone(),
            position: 0,
        }))
    }
}

struct SharedBytesReader {
    bytes: SharedBytes,
    position: usize,
}

impl Read for SharedBytesReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .bytes
            .as_slice()
            .get(self.position..)
            .unwrap_or_default();
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        Ok(count)
    }
}

/// One side-log segment read from the side's stores when it is copied.
struct SegmentLeafSource {
    segment: AttemptLogSegmentRef,
    segments: AttemptLogSegmentSources,
}

impl BlobSource for SegmentLeafSource {
    fn logical_length(&self) -> u64 {
        self.segment.encoded_bytes
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes =
            self.segments
                .segment(self.segment.id)
                .map_err(|source| StoreError::StreamIo {
                    operation: "read-finding-replay-segment",
                    source,
                })?;
        Ok(Box::new(Cursor::new(bytes)))
    }
}

/// Serves a loaded side log's segments from their published leaf handles.
struct LeafSegmentSource {
    handles: BTreeMap<ContentId, BlobHandle>,
}

impl AttemptLogSegmentSource for LeafSegmentSource {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let handle = self.handles.get(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "finding replay segment leaf absent",
            )
        })?;
        handle
            .read_all(MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64)
            .map_err(io::Error::other)
    }
}
