//! Authentication and retention contracts for published ability packages.
//!
//! Registry metadata records the exact canonical package manifest and a full
//! Nix closure catalog for every distinct artifact reference. This module
//! validates that untrusted catalog before signature and live-store checks
//! construct the opaque [`VerifiedAbilityPackage`] consumed by native runtime
//! adapters.
//!
//! A realized companion stores its canonical manifest and descriptor-addressed
//! interface documents at these paths:
//!
//! ```text
//! <abilities-store-path>/package.json
//! <abilities-store-path>/interfaces/<interface-descriptor-hex>.json
//! ```
//!
//! Registry metadata records the exact manifest identity and complete closure
//! catalog for every referenced artifact. A dedicated DSSE statement
//! authenticates those commitments together with the package coordinate and
//! companion NAR. The following JSON is a metadata excerpt; angle-bracketed
//! digest values are placeholders:
//!
//! ```json
//! {"manifest_sha256":"sha256:<64 hex digits>","package_digest":"sha256:<64 hex digits>","artifacts":[{"content":"sha256:<64 hex digits>","closure_digest":"sha256:<64 hex digits>"}],"provenance":"provenance/<package>.ability.intoto.jsonl"}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aos_ability_model::document::PlatformIdentity;
use aos_ability_model::{
    AbilityActivationMode, ArtifactReference, HandlerDescriptor, ImplementationKind, LocalKey,
    PackageDocument, ProviderImplementation, VersionedDocument,
};
use aos_contract::Sha256Digest;
use serde::Serialize;

use crate::types::{
    AbilityArtifactRetentionMeta, AbilityClosureMemberMeta, AbilityPackageMeta, PackageMeta,
    validate_attestation_provenance_ref,
};

mod catalog;
pub(crate) mod retention;

pub use catalog::VerifiedAbilityPlanningCatalog;
pub use retention::NativeAbilityRetentionVerifier;

const CLOSURE_DIGEST_DOMAIN: &str = "aos.ability.closure/v1";
const RETENTION_DIGEST_DOMAIN: &str = "aos.ability.retention/v1";
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE: &str = "https://andyl.com/aos/ability-package-provenance/v1";
const BUILD_TYPE: &str = "https://andyl.com/aos/apr-ability-publish/v1";

/// Borrows the primary package identity bound by ability provenance.
pub(crate) struct AbilityPackageCoordinate<'a> {
    pub(crate) name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) store_path: &'a str,
    pub(crate) nar_hash: &'a str,
}

/// Verifies the actual store objects retained by ability metadata.
pub(crate) trait AbilityRetentionVerifier {
    /// Checks the companion and every complete artifact closure against the
    /// live Nix store.
    ///
    /// # Errors
    ///
    /// Returns an error when any object, NAR identity, size, direct reference,
    /// transitive member, or closure edge differs from the signed catalog.
    fn verify_retention(&self, retention: &VerifiedAbilityRetentionManifest) -> Result<()>;
}

/// Holds one structurally verified retention catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAbilityRetentionManifest {
    companion_store_path: String,
    companion_nar_hash: Sha256Digest,
    companion_nar_size: u64,
    companion_references: Vec<String>,
    artifacts: Vec<AbilityArtifactRetentionMeta>,
}

impl VerifiedAbilityRetentionManifest {
    /// Returns the exact ability companion store path.
    #[must_use]
    pub fn companion_store_path(&self) -> &str {
        &self.companion_store_path
    }

    /// Returns the companion output's exact NAR identity.
    #[must_use]
    pub const fn companion_nar_hash(&self) -> Sha256Digest {
        self.companion_nar_hash
    }

    /// Returns the companion output's uncompressed NAR size.
    #[must_use]
    pub const fn companion_nar_size(&self) -> u64 {
        self.companion_nar_size
    }

    /// Returns the companion output's sorted direct store references.
    #[must_use]
    pub fn companion_references(&self) -> &[String] {
        &self.companion_references
    }

    /// Returns exact artifact catalogs in canonical content order.
    #[must_use]
    pub fn artifacts(&self) -> &[AbilityArtifactRetentionMeta] {
        &self.artifacts
    }
}

/// Holds one terminal provider and handler resolved from the same verified package.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedTerminalHandler<'a> {
    provider: &'a ProviderImplementation,
    handler: &'a HandlerDescriptor,
}

impl<'a> VerifiedTerminalHandler<'a> {
    /// Returns the exact provider implementation descriptor.
    #[must_use]
    pub const fn provider(&self) -> &'a ProviderImplementation {
        self.provider
    }

    /// Returns the handler linked by that provider implementation.
    #[must_use]
    pub const fn handler(&self) -> &'a HandlerDescriptor {
        self.handler
    }
}

/// Carries an authenticated package document and its exact retention evidence.
///
/// Fields are private and the module exposes no public constructor. Dedicated
/// provenance verification and live-store equality checks are the only paths
/// that may construct this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAbilityPackage {
    package: PackageDocument,
    manifest_sha256: Sha256Digest,
    package_digest: Sha256Digest,
    package_name: String,
    package_version: String,
    platform: String,
    activation_mode: AbilityActivationMode,
    artifacts: Vec<ArtifactReference>,
    retention: VerifiedAbilityRetentionManifest,
}

/// Owns the complete authenticated ability catalog admitted to one runtime session.
///
/// Construction deduplicates byte-for-byte equivalent package seals and
/// rejects conflicting seals for one registry package coordinate. Runtime
/// callers can therefore resolve packages and artifacts without falling back
/// to unauthenticated plan-bundle documents.
#[derive(Clone, Debug, Default)]
pub struct VerifiedAbilityPackageSet {
    packages: Vec<VerifiedAbilityPackage>,
    coordinates: BTreeMap<(String, String, String), usize>,
    artifacts: BTreeMap<Sha256Digest, ArtifactReference>,
}

impl VerifiedAbilityPackageSet {
    /// Constructs one deterministic set from independently verified packages.
    ///
    /// Equivalent duplicate seals are coalesced. A coordinate or artifact
    /// content identity that resolves to differing authenticated metadata is
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when duplicate package coordinates or artifact content
    /// identities carry conflicting commitments.
    pub fn from_verified(mut packages: Vec<VerifiedAbilityPackage>) -> Result<Self> {
        packages.sort_by(|left, right| {
            left.package_name
                .cmp(&right.package_name)
                .then_with(|| left.package_version.cmp(&right.package_version))
                .then_with(|| left.platform.cmp(&right.platform))
        });

        let mut canonical = Vec::<VerifiedAbilityPackage>::with_capacity(packages.len());
        let mut coordinates = BTreeMap::new();
        let mut artifacts = BTreeMap::<Sha256Digest, ArtifactReference>::new();
        for package in packages {
            let coordinate = (
                package.package_name.clone(),
                package.package_version.clone(),
                package.platform.clone(),
            );
            if let Some(index) = coordinates.get(&coordinate).copied() {
                if canonical[index] != package {
                    bail!(
                        "conflicting verified ability package {}@{} ({})",
                        coordinate.0,
                        coordinate.1,
                        coordinate.2
                    );
                }
                continue;
            }

            for artifact in &package.artifacts {
                if let Some(existing) = artifacts.get(&artifact.content) {
                    if existing != artifact {
                        bail!("conflicting verified ability artifact {}", artifact.content);
                    }
                } else {
                    artifacts.insert(artifact.content, artifact.clone());
                }
            }

            let index = canonical.len();
            coordinates.insert(coordinate, index);
            canonical.push(package);
        }

        Ok(Self {
            packages: canonical,
            coordinates,
            artifacts,
        })
    }

    /// Returns packages in canonical coordinate order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &VerifiedAbilityPackage> {
        self.packages.iter()
    }

    /// Returns the exact authenticated package at one release coordinate.
    #[must_use]
    pub fn get(
        &self,
        name: &str,
        version: &str,
        platform: &str,
    ) -> Option<&VerifiedAbilityPackage> {
        let coordinate = (name.to_string(), version.to_string(), platform.to_string());
        self.coordinates
            .get(&coordinate)
            .map(|index| &self.packages[*index])
    }

    /// Checks portable plan inputs against this authenticated package set.
    ///
    /// # Errors
    ///
    /// Returns an error when any package document or required runtime artifact
    /// lacks an exact authenticated counterpart in this set.
    pub fn verify_plan_inputs(
        &self,
        platform: &PlatformIdentity,
        packages: &[PackageDocument],
        artifacts: &[ArtifactReference],
    ) -> Result<()> {
        let platform = format!(
            "{}-{}",
            platform.architecture.as_str(),
            platform.system.as_str()
        );
        let mut admitted_artifacts = BTreeMap::new();
        for package in packages {
            let digest = package
                .content_digest()
                .context("computing plan ability package digest")?;
            let candidate = self.packages.iter().find(|candidate| {
                candidate.platform == platform
                    && candidate.package_digest == digest
                    && candidate.package == *package
            });
            let Some(candidate) = candidate else {
                bail!(
                    "plan ability package {}@{} for {platform} is absent from the authenticated package set",
                    package.package.name.as_str(),
                    package.package.version
                );
            };
            for artifact in &candidate.artifacts {
                if self.artifacts.get(&artifact.content) != Some(artifact) {
                    bail!(
                        "authenticated ability artifact index disagrees for {}",
                        artifact.content
                    );
                }
                admitted_artifacts.insert(artifact.content, artifact);
            }
        }
        for artifact in artifacts {
            if admitted_artifacts.get(&artifact.content).copied() != Some(artifact) {
                bail!(
                    "plan ability artifact {} is absent from the authenticated selected packages",
                    artifact.content
                );
            }
        }
        Ok(())
    }

    /// Rechecks every authenticated retention catalog against the live store.
    ///
    /// # Errors
    ///
    /// Returns an error when any companion or retained artifact closure no
    /// longer matches its authenticated catalog.
    pub(crate) fn verify_live_retention(
        &self,
        verifier: &impl AbilityRetentionVerifier,
    ) -> Result<()> {
        for package in &self.packages {
            verifier.verify_retention(&package.retention)?;
        }
        Ok(())
    }

    /// Rechecks every authenticated retention catalog against the live Nix store.
    ///
    /// This can be called again immediately before planning or execution when a
    /// package set has remained resident since its original admission.
    ///
    /// # Errors
    ///
    /// Returns an error when any companion or retained artifact closure no
    /// longer matches its authenticated catalog.
    pub fn reverify_live_retention(&self) -> Result<()> {
        self.verify_live_retention(&NativeAbilityRetentionVerifier::new())
    }
}

impl VerifiedAbilityPackage {
    /// Returns the exact canonical package document.
    #[must_use]
    pub const fn package(&self) -> &PackageDocument {
        &self.package
    }

    /// Returns the SHA-256 identity of the exact canonical manifest bytes.
    #[must_use]
    pub const fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    /// Returns the package document's domain-separated semantic identity.
    #[must_use]
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    /// Returns the authenticated registry package name.
    #[must_use]
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// Returns the authenticated registry package version.
    #[must_use]
    pub fn package_version(&self) -> &str {
        &self.package_version
    }

    /// Returns the authenticated release platform.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// Returns the signed activation ownership mode.
    #[must_use]
    pub const fn activation_mode(&self) -> AbilityActivationMode {
        self.activation_mode
    }

    /// Returns every distinct package artifact in canonical content order.
    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactReference] {
        &self.artifacts
    }

    /// Returns the exact companion and complete artifact closure catalogs.
    #[must_use]
    pub const fn retention_manifest(&self) -> &VerifiedAbilityRetentionManifest {
        &self.retention
    }

    /// Resolves a terminal handler through one exact provider descriptor.
    ///
    /// The result is present only when the descriptor identifies a provider in
    /// this package, that provider declares the same terminal handler key, the
    /// handler is present in the package catalog, and both records bind the
    /// same exact artifact.
    #[must_use]
    pub fn resolve_terminal_handler(
        &self,
        descriptor: Sha256Digest,
        handler_key: &LocalKey,
    ) -> Option<VerifiedTerminalHandler<'_>> {
        let provider = self
            .package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.descriptor_digest().ok() == Some(descriptor))?;
        let ImplementationKind::TerminalHandler { handler } = &provider.implementation else {
            return None;
        };
        if handler != handler_key {
            return None;
        }

        let handler = self.package.implementation.handlers.get(handler_key)?;
        (provider.artifact == handler.artifact)
            .then_some(VerifiedTerminalHandler { provider, handler })
    }
}

/// Verifies one signed ability manifest and its live retention catalog.
///
/// The returned package is the native runtime's sealed admission token. The
/// caller must supply trusted registry keys and a verifier backed by the live
/// Nix store; metadata-only callers cannot construct it.
///
/// # Errors
///
/// Returns an error when metadata validation, exact canonical decoding,
/// package association, dedicated provenance verification, artifact catalog
/// equality, or live-store retention verification fails.
pub(crate) fn verify_ability_package(
    package_meta: &PackageMeta,
    manifest_bytes: &[u8],
    provenance_jsonl: &str,
    registry_name: &str,
    trusted_keys: &[crate::provenance::TrustedProvenanceKey],
    retention_verifier: &impl AbilityRetentionVerifier,
) -> Result<VerifiedAbilityPackage> {
    let ability = package_meta
        .ability
        .as_ref()
        .context("package does not declare ability metadata")?;
    validate_ability_package_meta(ability)?;

    if manifest_bytes.len() as u64 != ability.manifest_size {
        bail!(
            "ability manifest byte length {} does not match signed size {}",
            manifest_bytes.len(),
            ability.manifest_size
        );
    }
    let manifest_sha256 = Sha256Digest::of_bytes(manifest_bytes);
    let recorded_manifest =
        validate_sha256_identity("ability manifest_sha256", &ability.manifest_sha256)?;
    if manifest_sha256 != recorded_manifest {
        bail!("ability manifest exact-byte digest does not match registry metadata");
    }

    let package = decode_package_manifest(manifest_bytes)?;
    if package.package.name.as_str() != package_meta.name {
        bail!(
            "ability manifest package '{}' does not match registry package '{}'",
            package.package.name.as_str(),
            package_meta.name
        );
    }
    if package.package.version != package_meta.version {
        bail!(
            "ability manifest version '{}' does not match registry version '{}'",
            package.package.version,
            package_meta.version
        );
    }
    let primary_nar_hash = canonical_nar_hash(&package_meta.nar_hash)?;
    if package.package.payload.store_path != package_meta.store_path
        || package.package.payload.nar_hash.to_string() != primary_nar_hash
    {
        bail!(
            "ability manifest payload does not match primary package {}",
            package_meta.store_path
        );
    }
    let package_digest = package
        .content_digest()
        .context("computing ability package semantic digest")?;
    let recorded_package =
        validate_sha256_identity("ability package_digest", &ability.package_digest)?;
    if package_digest != recorded_package {
        bail!("ability package semantic digest does not match registry metadata");
    }
    if activation_mode_name(package.activation_mode) != ability.activation_mode {
        bail!("ability package activation mode does not match registry metadata");
    }

    let artifacts = collect_distinct_artifacts(&package)?;
    verify_artifact_catalog(&artifacts, &ability.artifacts)?;
    verify_ability_provenance(
        package_meta,
        ability,
        provenance_jsonl,
        registry_name,
        trusted_keys,
    )?;

    let retention = VerifiedAbilityRetentionManifest {
        companion_store_path: ability.store_path.clone(),
        companion_nar_hash: validate_sha256_identity(
            "ability companion NAR hash",
            &ability.nar_hash,
        )?,
        companion_nar_size: ability.nar_size,
        companion_references: ability.references.clone(),
        artifacts: ability.artifacts.clone(),
    };
    retention_verifier.verify_retention(&retention)?;

    let activation_mode = package.activation_mode;
    Ok(VerifiedAbilityPackage {
        package,
        manifest_sha256,
        package_digest,
        package_name: package_meta.name.clone(),
        package_version: package_meta.version.clone(),
        platform: package_meta.platform.clone(),
        activation_mode,
        artifacts,
        retention,
    })
}

/// Validates and seals retention metadata for native live-store tests.
#[cfg(test)]
pub(crate) fn seal_test_retention_manifest(
    ability: &AbilityPackageMeta,
) -> Result<VerifiedAbilityRetentionManifest> {
    validate_ability_package_meta(ability)?;
    Ok(VerifiedAbilityRetentionManifest {
        companion_store_path: ability.store_path.clone(),
        companion_nar_hash: validate_sha256_identity(
            "ability companion NAR hash",
            &ability.nar_hash,
        )?,
        companion_nar_size: ability.nar_size,
        companion_references: ability.references.clone(),
        artifacts: ability.artifacts.clone(),
    })
}

fn verify_artifact_catalog(
    artifacts: &[ArtifactReference],
    retention: &[AbilityArtifactRetentionMeta],
) -> Result<()> {
    if artifacts.len() != retention.len() {
        bail!(
            "ability retention catalog has {} artifacts, expected {}",
            retention.len(),
            artifacts.len()
        );
    }
    for (artifact, retained) in artifacts.iter().zip(retention) {
        if artifact.content
            != validate_sha256_identity("ability artifact content", &retained.content)?
            || artifact.store_path != retained.store_path
            || artifact.nar_hash
                != validate_sha256_identity("ability artifact NAR hash", &retained.nar_hash)?
            || artifact.closure
                != validate_sha256_identity(
                    "ability artifact closure digest",
                    &retained.closure_digest,
                )?
        {
            bail!(
                "ability retention catalog does not match artifact {}",
                artifact.content
            );
        }
    }
    Ok(())
}

pub(crate) fn decode_package_manifest(bytes: &[u8]) -> Result<PackageDocument> {
    let supported_features =
        BTreeSet::from([aos_ability_model::RequiredFeature::new("abilities-v1")
            .context("constructing the built-in ability feature")?]);
    aos_ability_model::decode_canonical::<PackageDocument>(
        bytes,
        aos_ability_model::ABILITY_LIMITS_V1,
        &supported_features,
    )
    .context("decoding canonical ability package manifest")
}

/// Reads the bounded regular `package.json` from an exact companion store root.
///
/// # Errors
///
/// Returns an error when the companion path is not canonical, `package.json`
/// is absent, is a symlink or another non-regular file, or its size is outside
/// the RFC-0022 document bound.
pub(crate) fn read_package_manifest(store_path: &str) -> Result<Vec<u8>> {
    validate_store_root(store_path, "ability companion store path")?;
    let path = Path::new(store_path).join("package.json");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("opening ability manifest {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading ability manifest metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("ability manifest is not a regular file: {}", path.display());
    }
    let limit = aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes;
    if metadata.len() == 0 || metadata.len() > limit {
        bail!(
            "ability manifest size {} is outside 1..={limit}",
            metadata.len()
        );
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading ability manifest {}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        bail!(
            "ability manifest changed while it was read: {}",
            path.display()
        );
    }
    Ok(bytes)
}

pub(crate) fn activation_mode_name(mode: AbilityActivationMode) -> &'static str {
    match mode {
        AbilityActivationMode::ContractsOnly => "contracts-only",
        AbilityActivationMode::StructuredEffects => "structured-effects",
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AbilityRetentionBinding<'a> {
    store_path: &'a str,
    nar_hash: &'a str,
    nar_size: u64,
    references: &'a [String],
    artifacts: &'a [AbilityArtifactRetentionMeta],
}

pub(crate) fn ability_retention_digest(ability: &AbilityPackageMeta) -> Result<Sha256Digest> {
    validate_ability_package_meta(ability)?;
    Sha256Digest::of_canonical(
        RETENTION_DIGEST_DOMAIN,
        &AbilityRetentionBinding {
            store_path: &ability.store_path,
            nar_hash: &ability.nar_hash,
            nar_size: ability.nar_size,
            references: &ability.references,
            artifacts: &ability.artifacts,
        },
    )
    .context("computing ability retention digest")
}

pub(crate) fn ability_provenance_statement(
    coordinate: &AbilityPackageCoordinate<'_>,
    ability: &AbilityPackageMeta,
    registry_name: &str,
    key_id: &str,
) -> Result<serde_json::Value> {
    validate_ability_package_meta(ability)?;
    if key_id.is_empty() {
        bail!("ability provenance key id cannot be empty");
    }
    let primary_nar_hash = canonical_nar_hash(coordinate.nar_hash)?;
    let retention_digest = ability_retention_digest(ability)?;
    let manifest_subject = format!(
        "aos:ability-manifest:{}:{}:{}",
        coordinate.name, coordinate.version, coordinate.platform
    );
    let package_subject = format!(
        "aos:ability-package:{}:{}:{}",
        coordinate.name, coordinate.version, coordinate.platform
    );
    let retention_subject = format!(
        "aos:ability-retention:{}:{}:{}",
        coordinate.name, coordinate.version, coordinate.platform
    );
    let dependencies = ability
        .artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "uri": artifact.store_path,
                "digest": crate::provenance::digest_map(&artifact.nar_hash),
                "closureDigest": crate::provenance::digest_map(&artifact.closure_digest),
            })
        })
        .collect::<Vec<_>>();

    Ok(serde_json::json!({
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": coordinate.store_path,
                "digest": crate::provenance::digest_map(&primary_nar_hash),
            },
            {
                "name": ability.store_path,
                "digest": crate::provenance::digest_map(&ability.nar_hash),
            },
            {
                "name": manifest_subject,
                "digest": crate::provenance::digest_map(&ability.manifest_sha256),
            },
            {
                "name": package_subject,
                "digest": crate::provenance::digest_map(&ability.package_digest),
            },
            {
                "name": retention_subject,
                "digest": crate::provenance::digest_map(&retention_digest.to_string()),
            },
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "package": coordinate.name,
                    "version": coordinate.version,
                    "platform": coordinate.platform,
                    "storePath": coordinate.store_path,
                    "abilityStorePath": ability.store_path,
                    "activationMode": ability.activation_mode,
                    "provenance": ability.provenance,
                },
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": crate::provenance::builder_id(registry_name, key_id),
                },
            },
        },
    }))
}

/// Verifies the dedicated ability statement against metadata and an active key.
///
/// # Errors
///
/// Returns an error when the envelope, signer, statement, package coordinate,
/// or retention binding differs from authenticated registry metadata.
pub(crate) fn verify_ability_provenance(
    package_meta: &PackageMeta,
    ability: &AbilityPackageMeta,
    provenance_jsonl: &str,
    registry_name: &str,
    trusted_keys: &[crate::provenance::TrustedProvenanceKey],
) -> Result<String> {
    let (statement, key_id) =
        crate::provenance::verify_statement_dsse_jsonl(provenance_jsonl, trusted_keys)
            .context("verifying ability provenance DSSE")?;
    if trusted_keys
        .iter()
        .any(|trusted| trusted.key_id == key_id && trusted.retired_before_sequence.is_some())
    {
        bail!(
            "ability provenance key '{key_id}' is retired; dedicated ability statements require an active key"
        );
    }
    let coordinate = AbilityPackageCoordinate {
        name: &package_meta.name,
        version: &package_meta.version,
        platform: &package_meta.platform,
        store_path: &package_meta.store_path,
        nar_hash: &package_meta.nar_hash,
    };
    let expected = ability_provenance_statement(&coordinate, ability, registry_name, &key_id)?;
    if statement != expected {
        bail!("ability provenance statement does not exactly match registry metadata");
    }
    Ok(key_id)
}

/// Validates authenticated metadata for an RFC-0022 ability companion.
///
/// This structural validation checks the signed catalog itself. The package
/// verifier separately compares each catalog with the live Nix store closure
/// before constructing [`VerifiedAbilityPackage`].
///
/// # Errors
///
/// Returns an error when a digest, store path, size, feature mode, provenance
/// reference, ordering invariant, aggregate bound, or artifact closure catalog
/// is malformed or internally inconsistent.
pub fn validate_ability_package_meta(ability: &AbilityPackageMeta) -> Result<()> {
    validate_store_root(&ability.store_path, "ability companion store path")?;
    validate_sha256_identity("ability companion NAR hash", &ability.nar_hash)?;
    if ability.nar_size == 0 {
        bail!(
            "ability companion '{}' has zero NAR size",
            ability.store_path
        );
    }

    validate_aggregate_catalog_bound(ability)?;
    validate_sorted_store_hashes(&ability.store_path, &ability.references)?;
    validate_sha256_identity("ability manifest_sha256", &ability.manifest_sha256)?;
    validate_sha256_identity("ability package_digest", &ability.package_digest)?;
    if ability.manifest_size == 0
        || ability.manifest_size > aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes
    {
        bail!(
            "ability manifest size {} is outside 1..={}",
            ability.manifest_size,
            aos_ability_model::ABILITY_LIMITS_V1.max_document_bytes
        );
    }
    if !matches!(
        ability.activation_mode.as_str(),
        "contracts-only" | "structured-effects"
    ) {
        bail!(
            "ability activation mode '{}' is unsupported",
            ability.activation_mode
        );
    }
    validate_attestation_provenance_ref(&ability.provenance)
        .context("validating ability provenance reference")?;

    let mut previous_content = None;
    let mut artifact_paths = BTreeSet::new();
    for artifact in &ability.artifacts {
        let content = validate_sha256_identity("ability artifact content", &artifact.content)?;
        if previous_content.is_some_and(|previous| previous >= content) {
            bail!("ability artifacts are not in unique canonical content order");
        }
        previous_content = Some(content);

        validate_store_root(&artifact.store_path, "ability artifact store path")?;
        if !artifact_paths.insert(&artifact.store_path) {
            bail!(
                "ability artifact store path '{}' appears more than once",
                artifact.store_path
            );
        }
        validate_sha256_identity("ability artifact NAR hash", &artifact.nar_hash)?;
        if artifact.nar_size == 0 {
            bail!(
                "ability artifact '{}' has zero NAR size",
                artifact.store_path
            );
        }
        let recorded_closure =
            validate_sha256_identity("ability artifact closure digest", &artifact.closure_digest)?;

        validate_ability_closure(artifact)?;
        let computed_closure = Sha256Digest::of_canonical(CLOSURE_DIGEST_DOMAIN, &artifact.closure)
            .context("computing ability artifact closure digest")?;
        if recorded_closure != computed_closure {
            bail!(
                "ability artifact '{}' closure digest does not match its catalog",
                artifact.store_path
            );
        }
    }

    Ok(())
}

fn validate_aggregate_catalog_bound(ability: &AbilityPackageMeta) -> Result<()> {
    let mut items = ability.references.len();
    items = items
        .checked_add(ability.artifacts.len())
        .context("ability retention catalog item count overflowed")?;
    for artifact in &ability.artifacts {
        items = items
            .checked_add(artifact.closure.len())
            .context("ability retention catalog item count overflowed")?;
        for member in &artifact.closure {
            items = items
                .checked_add(member.references.len())
                .context("ability retention catalog item count overflowed")?;
        }
    }
    let limit = aos_ability_model::ABILITY_LIMITS_V1.max_collection_items as usize;
    if items > limit {
        bail!("ability retention catalog has {items} items, exceeding the limit {limit}");
    }
    Ok(())
}

fn validate_ability_closure(artifact: &AbilityArtifactRetentionMeta) -> Result<()> {
    if artifact.closure.is_empty() {
        bail!(
            "ability artifact '{}' has an empty closure",
            artifact.store_path
        );
    }

    let mut previous_member: Option<&AbilityClosureMemberMeta> = None;
    let mut member_paths = BTreeSet::new();
    let mut member_hashes = BTreeSet::new();
    let mut root_matches = 0_u8;
    for member in &artifact.closure {
        if previous_member.is_some_and(|previous| previous >= member) {
            bail!(
                "ability artifact '{}' closure is not in unique canonical order",
                artifact.store_path
            );
        }
        previous_member = Some(member);

        validate_store_root(&member.store_path, "ability closure member store path")?;
        if !member_paths.insert(&member.store_path) {
            bail!(
                "ability artifact '{}' closure repeats store path '{}'",
                artifact.store_path,
                member.store_path
            );
        }
        member_hashes.insert(store_hash(&member.store_path)?);
        validate_sha256_identity("ability closure member NAR hash", &member.nar_hash)?;
        if member.nar_size == 0 {
            bail!(
                "ability closure member '{}' has zero NAR size",
                member.store_path
            );
        }

        if member.store_path == artifact.store_path {
            root_matches += 1;
            if member.nar_hash != artifact.nar_hash || member.nar_size != artifact.nar_size {
                bail!(
                    "ability artifact '{}' root closure identity does not match the artifact",
                    artifact.store_path
                );
            }
        }
    }
    for member in &artifact.closure {
        validate_sorted_store_hashes(&member.store_path, &member.references)?;
        for reference in &member.references {
            if !member_hashes.contains(reference.as_str()) {
                bail!(
                    "ability closure member '{}' references '{}' outside its signed closure",
                    member.store_path,
                    reference
                );
            }
        }
    }
    if root_matches != 1 {
        bail!(
            "ability artifact '{}' closure must contain its root exactly once",
            artifact.store_path
        );
    }

    Ok(())
}

fn validate_store_root(path: &str, label: &str) -> Result<()> {
    let (root, suffix) = crate::config_eval::stock::store_root_and_suffix(Path::new(path))
        .with_context(|| format!("validating {label}"))?;
    if !suffix.as_os_str().is_empty() || root.as_os_str() != std::ffi::OsStr::new(path) {
        bail!("{label} is not an exact Nix store root: {path}");
    }
    Ok(())
}

fn store_hash(path: &str) -> Result<&str> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("validated Nix store root has no UTF-8 object name")?;
    name.get(..32)
        .context("validated Nix store root has no 32-character hash")
}

fn validate_sha256_identity(label: &str, digest: &str) -> Result<Sha256Digest> {
    Sha256Digest::parse(digest)
        .with_context(|| format!("{label} is not a canonical SHA-256 identity"))
}

pub(crate) fn canonical_nar_hash(hash: &str) -> Result<String> {
    let hex = crate::verify::sha256_digest_hex(hash)
        .with_context(|| format!("normalizing ability NAR identity '{hash}'"))?;
    Ok(format!("sha256:{hex}"))
}

fn validate_sorted_store_hashes(owner: &str, references: &[String]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for reference in references {
        if reference.len() != 32
            || !reference
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        {
            bail!("ability companion '{owner}' has invalid reference '{reference}'");
        }
        if previous.is_some_and(|prior| prior >= reference.as_str()) {
            bail!("ability companion '{owner}' references are not sorted and unique");
        }
        previous = Some(reference);
    }
    Ok(())
}

pub(crate) fn collect_distinct_artifacts(
    package: &PackageDocument,
) -> Result<Vec<ArtifactReference>> {
    let mut by_content = BTreeMap::new();
    let mut insert = |artifact: &ArtifactReference| -> Result<()> {
        if let Some(existing) = by_content.insert(artifact.content, artifact.clone())
            && existing != *artifact
        {
            bail!(
                "ability package reuses content identity {} for different artifact references",
                artifact.content
            );
        }
        Ok(())
    };

    insert(&package.package.payload)?;
    insert(&package.package.source)?;
    for artifact in &package.artifacts {
        insert(artifact)?;
    }
    for artifact in package.module_entry_points.values() {
        insert(artifact)?;
    }
    for provider in &package.implementation.providers {
        insert(&provider.artifact)?;
    }
    for handler in package.implementation.handlers.values() {
        insert(&handler.artifact)?;
    }

    Ok(by_content.into_values().collect())
}

#[cfg(test)]
#[path = "ability_package/tests.rs"]
mod tests;
