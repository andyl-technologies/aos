//! Releases records returned by typed Hub persistence operations.

/// One sysroot disk image attached to a platform artifact.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ImageDetail {
    /// Image format (e.g. `qcow2`, `raw`).
    pub format: String,
    /// Store path of the image.
    pub store_path: String,
    /// NAR hash of the image.
    #[serde(default)]
    pub nar_hash: String,
    /// NAR size of the image in bytes.
    #[serde(default)]
    pub nar_size: u64,
    /// Required signed direct-delivery contract.
    pub delivery: aos_registry_format::manifest::ImageDelivery,
}

/// One signed direct-delivery image projected from the rebuildable registry index.
#[derive(Debug, Clone)]
pub struct IndexedSystemImage {
    /// Signed sysroot package name.
    pub package: String,
    /// Signed immutable package release.
    pub release: String,
    /// Signed platform triple.
    pub platform: String,
    /// Signed disk encoding name.
    pub format: String,
    /// Canonical Nix store path of the image artifact.
    pub store_path: String,
    /// Signed hash of the image artifact's uncompressed NAR.
    pub nar_hash: String,
    /// Signed byte size of the image artifact's uncompressed NAR.
    pub nar_size: u64,
    /// Complete signed direct-delivery contract.
    pub delivery: aos_registry_format::manifest::ImageDelivery,
}

/// Signed role of an immutable image-related delivery object.
#[derive(Debug, Clone)]
pub enum IndexedSystemImageObject {
    /// Directly downloadable encoded disk bytes.
    Disk(IndexedSystemImage),
    /// Canonical per-encoding `image-info.json` bytes.
    ImageInfo(IndexedSystemImage),
}

/// Exact placement evidence for one signed registry image object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryImageObject {
    /// Canonical content-addressed surface key.
    pub object_key: String,
    /// Lowercase hexadecimal SHA-256 observed from storage.
    pub sha256: String,
    /// Exact observed byte size.
    pub byte_size: i64,
    /// Strong backend version observed for the exact verified object handle.
    pub strong_etag: String,
}

/// One channel with partition rollout summary.
#[derive(Debug, Clone)]
pub struct ChannelSummary {
    /// Channel name.
    pub name: String,
    /// Newest release any partition targets.
    pub frontier: Option<String>,
    /// Partition targets by bucket (0..=255); `None` = unassigned.
    pub partitions: Vec<Option<String>>,
}

/// One verified release row.
#[derive(Debug, Clone)]
pub struct ReleaseRow {
    /// Release version.
    pub semver: String,
    /// Tag object id.
    pub tag_oid: String,
    /// Release commit id.
    pub commit_oid: String,
    /// Trusted key (base64) that signed the tag.
    pub signer: Option<String>,
    /// Tagger timestamp, Unix seconds.
    pub tagged_at: Option<i64>,
    /// Whether the per-release `objects/info/packs` listing exists on the
    /// surface (the release ships a full pack).
    pub pack_present: bool,
}

/// One immutable artifact belonging to a verified release snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReleaseSnapshotArtifact {
    /// Package owning the artifact.
    pub package_name: String,
    /// Package version owning the artifact.
    pub package_version: String,
    /// Platform triple.
    pub platform: String,
    /// Artifact role: `output`, `image`, or `source_derivation`.
    pub artifact_kind: String,
    /// Full Nix store path.
    pub store_path: String,
    /// Store-path hash component.
    pub store_hash: String,
}

/// A verified, complete, immutable release artifact snapshot.
#[derive(Debug, Clone)]
pub struct ReleaseArtifactSnapshot {
    /// Release tag spelling.
    pub release_tag: String,
    /// Commit named by the verified release tag.
    pub source_commit: String,
    /// Verified tag object id.
    pub verified_tag_oid: String,
    /// Canonical digest over all ordered artifact identities.
    pub manifest_digest: String,
    /// Complete artifact set, including a valid empty set.
    pub artifacts: Vec<ReleaseSnapshotArtifact>,
    /// Signed container root carried by this release, when present.
    pub container_release: Option<ContainerReleaseRootSnapshot>,
}

/// One OCI root bound to an exact signed AOS release sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerReleaseRootSnapshot {
    /// Registry-local OCI repository name.
    pub repository: String,
    /// Logical AOS container definition name.
    pub container_name: String,
    /// Exact publishable OCI index digest.
    pub index_digest: String,
    /// Exact OCI index media type.
    pub index_media_type: String,
    /// Exact OCI index byte length.
    pub index_size: u64,
    /// SHA-256 of the exact committed `containers/v1/index.json` bytes.
    pub catalog_digest: String,
    /// AOS package identity carried by the signed release sidecar.
    pub package_name: String,
    /// Complete signed Nix closure projection.
    pub closure_members: Vec<ContainerReleaseClosureMemberSnapshot>,
    /// Independently verified closure-layer measurements.
    pub layers: Vec<ContainerReleaseLayerSnapshot>,
    /// Complete signed evidence-role projection.
    pub evidence: Vec<ContainerReleaseEvidenceSnapshot>,
    /// Exact placement observations for the index, every platform manifest,
    /// and every signed evidence referrer required by the release sidecar.
    pub required_descriptors: Vec<VerifiedContainerReleaseDescriptor>,
}

/// One Nix closure member verified from signed OCI evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerReleaseClosureMemberSnapshot {
    /// Full Nix store path.
    pub store_path: String,
    /// Exact NAR hash.
    pub nar_hash: String,
    /// Uncompressed NAR byte length.
    pub nar_size: u64,
    /// Image layer containing this path.
    pub layer_digest: String,
    /// Whether the path is one of the release closure's direct roots.
    pub direct: bool,
}

/// One signed closure-layer identity and exact size projection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerReleaseLayerSnapshot {
    /// Signed closure group name.
    pub name: String,
    /// Compressed layer digest.
    pub digest: String,
    /// Uncompressed layer DiffID.
    pub diff_id: String,
    /// Exact compressed byte length.
    pub compressed_size: u64,
    /// Exact uncompressed byte length.
    pub uncompressed_size: u64,
}

/// One evidence role carried by a verified OCI referrer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerReleaseEvidenceSnapshot {
    /// Stable evidence role.
    pub kind: String,
    /// Exact evidence payload digest.
    pub digest: String,
    /// Exact evidence payload media type.
    pub media_type: String,
    /// OCI referrer manifest digest carrying the payload.
    pub referrer_digest: String,
}

/// Signed role of one OCI descriptor required by a container release root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerReleaseDescriptorRole {
    /// Publishable multi-platform image index.
    Index,
    /// Runnable manifest for one declared platform.
    PlatformManifest,
    /// Nix runtime-closure evidence manifest.
    NixClosure,
    /// Static ability-contract evidence manifest.
    Abilities,
    /// SPDX software-bill-of-materials evidence manifest.
    Sbom,
    /// Corresponding-source evidence manifest.
    Source,
    /// Full-closure license evidence manifest.
    License,
    /// In-toto provenance evidence manifest.
    Provenance,
    /// Producer-signature evidence manifest.
    Signature,
}

/// One signed OCI descriptor and the exact physical observation that admitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContainerReleaseDescriptor {
    /// Signed role assigned to the descriptor by the release sidecar.
    pub role: ContainerReleaseDescriptorRole,
    /// Canonical `sha256:<hex>` content digest.
    pub digest: String,
    /// Exact descriptor media type.
    pub media_type: String,
    /// Exact descriptor byte length.
    pub byte_size: u64,
    /// Backing logical surface-object identity.
    pub surface_object_id: i64,
    /// Logical object revision against which the observation was recorded.
    pub object_resource_version: i64,
    /// Physical placement carrying the observed bytes.
    pub placement_id: i64,
    /// Placement desired-topology revision observed during validation.
    pub placement_resource_version: i64,
    /// Placement controller-observation revision observed during validation.
    pub placement_observation_version: i64,
    /// Inventory generation that observed the exact bytes.
    pub observed_inventory_generation: i64,
    /// Time at which the exact object observation was recorded.
    pub observed_at: i64,
    /// Strong backend entity tag for the observed object version.
    pub strong_etag: String,
}

/// One image catalog authenticated by an exact signed release tag.
#[derive(Debug, Clone)]
pub struct ReleaseImageSnapshot {
    /// Release tag spelling exposed to consumers.
    pub release_tag: String,
    /// Commit named by the verified release tag.
    pub source_commit: String,
    /// Verified signed tag object id.
    pub verified_tag_oid: String,
    /// Canonical digest bound by the publication receipt.
    pub catalog_digest: String,
    /// Images in this catalog whose signed release identity matches the tag.
    pub images: Vec<IndexedSystemImage>,
}

impl ContainerReleaseDescriptorRole {
    pub(in crate::db) fn as_str(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::PlatformManifest => "platform_manifest",
            Self::NixClosure => "nix_closure",
            Self::Abilities => "abilities",
            Self::Sbom => "sbom",
            Self::Source => "source",
            Self::License => "license",
            Self::Provenance => "provenance",
            Self::Signature => "signature",
        }
    }
}
