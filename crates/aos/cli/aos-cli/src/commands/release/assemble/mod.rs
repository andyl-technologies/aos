//! Closed unsigned release-payload assembly.
//!
//! Assembly consumes only finalized, independently reviewable inputs. It
//! copies their exact bytes into a new payload, derives the artifact graph,
//! emits build-phase qualification evidence, and validates the resulting
//! unsigned manifest before making the output visible.

mod cache;
mod evidence;
mod images;
mod oci;
mod registry;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_nix::NixRunner;
use aos_release_format::artifact::{
    ArtifactKind, ArtifactRecord, ArtifactRelationship, BundlePath, Compression,
    ImageArtifactIdentity,
};
use aos_release_format::build::BuildReportV1;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::manifest::{
    FinalArtifactSet, ImageResult, PackageResult, ReleaseManifestV1,
};
use aos_release_format::plan::{PlatformCell, ReleasePlan};
use aos_release_format::platform::MatrixCell;
use aos_release_format::registry::{RegistryTier, registry_policy};
use aos_release_format::sbom::SpdxDocument;
use aos_release_format::signing::{SignerRole, TrustedEd25519Key};
use serde::{Deserialize, Serialize};

use crate::cli::ReleaseAssembleArgs;

use super::capture;

const ADVISORY_DISPOSITION_V1: &str = "aos.release.advisory-disposition/v1";
const LICENSE_INVENTORY_V1: &str = "aos.release.license-inventory/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryDispositionV1 {
    schema_version: String,
    plan_digest: Sha256Digest,
    sbom_digest: Sha256Digest,
    reviewed_at: String,
    authority_id: String,
    sources: Vec<AdvisorySource>,
    unresolved_advisories: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisorySource {
    name: String,
    snapshot: String,
}

#[derive(Serialize)]
struct LicenseInventoryV1<'a> {
    schema_version: &'static str,
    plan_digest: Sha256Digest,
    packages: Vec<LicenseInventoryEntry<'a>>,
}

#[derive(Serialize)]
struct LicenseInventoryEntry<'a> {
    artifact_id: &'a str,
    package: &'a str,
    version: &'a str,
    license_expression: &'a str,
    source_artifact_ids: Vec<&'a str>,
}

struct PayloadBuilder {
    root: PathBuf,
    artifacts: Vec<ArtifactRecord>,
}

impl PayloadBuilder {
    fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir(&root)
            .with_context(|| format!("creating release payload {}", root.display()))?;
        Ok(Self {
            root,
            artifacts: Vec::new(),
        })
    }

    fn copy(
        &mut self,
        source: &Path,
        id: String,
        kind: ArtifactKind,
        relative: String,
        attributes: ArtifactAttributes,
    ) -> Result<()> {
        let destination = self.root.join(&relative);
        let parent = destination
            .parent()
            .context("release artifact destination has no parent")?;
        fs::create_dir_all(parent)?;
        let captured = capture::copy_payload_file(source, &destination, &relative)?;
        if let Some(expected) = attributes.expected {
            if captured.size_bytes != expected.0 || captured.sha256 != expected.1 {
                bail!("release artifact {id} differs from its finalized identity");
            }
        }
        self.artifacts.push(ArtifactRecord {
            id,
            kind,
            platform: attributes.platform,
            system_variant: attributes.system_variant,
            image: attributes.image,
            path: captured.path,
            size_bytes: captured.size_bytes,
            sha256: captured.sha256,
            media_type: attributes.media_type,
            compression: attributes.compression,
            derivation: attributes.derivation,
            output: attributes.output,
            store_path: attributes.store_path,
            nar_hash: attributes.nar_hash,
            relationships: attributes.relationships,
        });
        Ok(())
    }

    fn write(
        &mut self,
        bytes: &[u8],
        id: String,
        kind: ArtifactKind,
        relative: String,
        media_type: &str,
    ) -> Result<()> {
        let source = self
            .root
            .join(format!(".generated-{}", self.artifacts.len()));
        write_new(&source, bytes)?;
        let result = self.copy(
            &source,
            id,
            kind,
            relative,
            ArtifactAttributes::exact(media_type, bytes)?,
        );
        fs::remove_file(&source)?;
        result
    }
}

struct ArtifactAttributes {
    platform: Option<aos_release_format::platform::Platform>,
    system_variant: Option<String>,
    image: Option<ImageArtifactIdentity>,
    media_type: String,
    compression: Compression,
    derivation: Option<String>,
    output: Option<String>,
    store_path: Option<String>,
    nar_hash: Option<Sha256Digest>,
    relationships: Vec<ArtifactRelationship>,
    expected: Option<(u64, Sha256Digest)>,
}

impl ArtifactAttributes {
    fn plain(media_type: &str) -> Self {
        Self {
            platform: None,
            system_variant: None,
            image: None,
            media_type: media_type.to_owned(),
            compression: Compression::None,
            derivation: None,
            output: None,
            store_path: None,
            nar_hash: None,
            relationships: Vec::new(),
            expected: None,
        }
    }

    fn exact(media_type: &str, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            expected: Some((u64::try_from(bytes.len())?, Sha256Digest::of_bytes(bytes))),
            ..Self::plain(media_type)
        })
    }
}

/// Requires the build report's repeat-build results to satisfy the registry.
///
/// Report validation already applies this policy; assembly restates it
/// because it is where the release first claims repeat-build evidence.
/// Production registries fail closed on any unreproduced output. Testing
/// registries accept outputs recorded as not reproduced.
fn require_repeat_build_policy(registry: &str, report: &BuildReportV1) -> Result<()> {
    let tier = registry_policy(registry)?.tier();
    report.require_reproducibility_policy(tier)
}

/// Assembles finalized package, registry, image, OCI, and evidence bytes.
pub(super) fn run(args: &ReleaseAssembleArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    if args.output.exists() {
        bail!(
            "release assembly output already exists: {}",
            args.output.display()
        );
    }
    let completed = require_utc(&args.completed_at, "assembly completion time")?;
    let plan_bytes = read_canonical(&args.plan, "release plan")?;
    let plan: ReleasePlan = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    let build_bytes = read_canonical(&args.build_report, "build report")?;
    let report: BuildReportV1 = canonical::from_slice(&build_bytes, "build report")?;
    report.validate(&plan, plan_digest)?;
    if require_utc(&report.completed_at, "build completion time")? > completed {
        bail!("assembly completed before its build report");
    }
    require_repeat_build_policy(&plan.registry, &report)?;

    let sbom_bytes = read_canonical(&args.sbom, "release SBOM")?;
    let sbom: SpdxDocument = canonical::from_slice(&sbom_bytes, "release SBOM")?;
    sbom.validate()?;
    if sbom != SpdxDocument::from_build(&report) {
        bail!("release SBOM differs from the validated build report");
    }

    let advisory_bytes = read_canonical(&args.advisory_disposition, "advisory disposition")?;
    let advisory: AdvisoryDispositionV1 =
        canonical::from_slice(&advisory_bytes, "advisory disposition")?;
    validate_advisory(
        &advisory,
        plan_digest,
        Sha256Digest::of_bytes(&sbom_bytes),
        completed,
        registry_policy(&plan.registry)?.tier(),
    )?;

    let authorization_bytes =
        capture::control_file(&args.contributor_authorization, "contributor authorization")?;
    if Sha256Digest::of_bytes(&authorization_bytes) != plan.source.contributor_authorization_digest
    {
        bail!("contributor authorization differs from the release plan");
    }

    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-assemble-")
        .tempdir_in(parent)?;
    let assembled = temporary.path().join("assembled");
    fs::create_dir(&assembled)?;
    let mut payload = PayloadBuilder::new(assembled.join("payload"))?;

    payload.copy(
        &args.build_report,
        "provenance/build-report".to_owned(),
        ArtifactKind::Provenance,
        "evidence/build-report.json".to_owned(),
        ArtifactAttributes::exact(
            "application/vnd.aos.release.build-report.v1+json",
            &build_bytes,
        )?,
    )?;
    payload.copy(
        &args.sbom,
        "sbom/release".to_owned(),
        ArtifactKind::Sbom,
        "evidence/sbom.spdx.json".to_owned(),
        ArtifactAttributes::exact("application/spdx+json", &sbom_bytes)?,
    )?;
    payload.copy(
        &args.contributor_authorization,
        "evidence/contributor-authorization".to_owned(),
        ArtifactKind::Evidence,
        "evidence/contributor-authorization.json".to_owned(),
        ArtifactAttributes::exact("application/json", &authorization_bytes)?,
    )?;
    payload.copy(
        &args.advisory_disposition,
        "evidence/advisory-disposition".to_owned(),
        ArtifactKind::Evidence,
        "evidence/advisory-disposition.json".to_owned(),
        ArtifactAttributes::exact(
            "application/vnd.aos.release.advisory-disposition.v1+json",
            &advisory_bytes,
        )?,
    )?;

    let cache_key = cache_key(&args.cache_key, &plan)?;
    let cache = cache::assemble(&args.cache, &report, &cache_key, &mut payload)?;
    let license_bytes = license_inventory(plan_digest, &report, &cache.source_ids)?;
    payload.write(
        &license_bytes,
        "license/release-inventory".to_owned(),
        ArtifactKind::License,
        "evidence/license-inventory.json".to_owned(),
        "application/vnd.aos.release.license-inventory.v1+json",
    )?;
    cache::attach_supply_chain_relationships(&mut payload.artifacts, &cache)?;

    registry::assemble(
        &args.registry,
        &args.registry_result,
        &plan,
        plan_digest,
        &mut payload,
    )?;
    images::assemble(&args.image_sets, &plan, nix, &mut payload)?;
    if let Some(container) = &args.container {
        oci::assemble(container, &args.registry, &plan, &mut payload)?;
    } else {
        oci::require_absent(&args.registry)?;
    }

    let packages = package_results(&plan);
    let images = image_results(&plan);
    let mut artifacts = vec![ArtifactRecord {
        id: "control/release-plan".to_owned(),
        kind: ArtifactKind::ReleasePlan,
        platform: None,
        system_variant: None,
        image: None,
        path: BundlePath::parse("release-plan.json")?,
        size_bytes: u64::try_from(plan_bytes.len())?,
        sha256: plan_digest,
        media_type: "application/json".to_owned(),
        compression: Compression::None,
        derivation: None,
        output: None,
        store_path: None,
        nar_hash: None,
        relationships: Vec::new(),
    }];
    artifacts.append(&mut payload.artifacts);
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));

    let mut manifest = ReleaseManifestV1 {
        schema_version: aos_release_format::RELEASE_MANIFEST_V1.to_owned(),
        release_id: plan.release_id.clone(),
        version: plan.version.clone(),
        release_class: plan.release_class,
        registry: plan.registry.clone(),
        plan_digest,
        source_commit: plan.source.commit.clone(),
        packages,
        images,
        artifacts,
        evidence: Vec::new(),
    };
    let evidence = evidence::build(
        &plan,
        &manifest,
        &report,
        &sbom_bytes,
        &advisory_bytes,
        advisory.unresolved_advisories.len(),
        &license_bytes,
        &authorization_bytes,
        &args.completed_at,
        &mut payload,
    )?;
    manifest.artifacts.append(&mut payload.artifacts);
    manifest
        .artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    manifest.evidence = evidence;
    manifest.validate(&plan)?;

    let manifest_bytes = canonical::to_vec(&manifest)?;
    write_new(
        &assembled.join("release-manifest-payload.json"),
        &manifest_bytes,
    )?;
    File::open(&payload.root)?.sync_all()?;
    File::open(&assembled)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &assembled,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.assembly-result/v1",
        "release_id": plan.release_id,
        "artifacts": manifest.artifacts.len(),
        "evidence": manifest.evidence.len(),
        "payload": args.output.join("payload"),
        "manifest_payload": args.output.join("release-manifest-payload.json"),
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Assembled {} exact artifacts at {}",
        manifest.artifacts.len(),
        args.output.display()
    ));
    Ok(())
}

fn package_results(plan: &ReleasePlan) -> Vec<PackageResult> {
    plan.packages
        .iter()
        .map(|package| PackageResult {
            name: package.name.clone(),
            platforms: package
                .platforms
                .iter()
                .map(|cell| PlatformCell {
                    platform: cell.platform,
                    decision: map_decision(&cell.decision),
                })
                .collect(),
        })
        .collect()
}

fn image_results(plan: &ReleasePlan) -> Vec<ImageResult> {
    plan.images
        .iter()
        .map(|image| ImageResult {
            system_variant: image.system_variant.clone(),
            platforms: image
                .platforms
                .iter()
                .map(|cell| PlatformCell {
                    platform: cell.platform,
                    decision: map_decision(&cell.decision),
                })
                .collect(),
        })
        .collect()
}

fn map_decision(
    decision: &MatrixCell<aos_release_format::plan::PlannedArtifactSet>,
) -> MatrixCell<FinalArtifactSet> {
    match decision {
        MatrixCell::Artifact { artifact } => MatrixCell::Artifact {
            artifact: FinalArtifactSet {
                artifact_ids: artifact
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.id.clone())
                    .collect(),
            },
        },
        MatrixCell::NotApplicable { rule, reason } => MatrixCell::NotApplicable {
            rule: rule.clone(),
            reason: reason.clone(),
        },
        MatrixCell::Blocked {
            required_work,
            failure_evidence,
        } => MatrixCell::Blocked {
            required_work: required_work.clone(),
            failure_evidence: failure_evidence.clone(),
        },
    }
}

fn license_inventory(
    plan_digest: Sha256Digest,
    report: &BuildReportV1,
    source_ids: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let packages = report
        .outputs
        .iter()
        .map(|output| {
            let source_artifact_ids = output
                .source_store_paths
                .iter()
                .map(|path| {
                    source_ids
                        .get(path)
                        .map(String::as_str)
                        .with_context(|| format!("missing source artifact for {path}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(LicenseInventoryEntry {
                artifact_id: &output.id,
                package: &output.package,
                version: &output.version,
                license_expression: &output.license_expression,
                source_artifact_ids,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    canonical::to_vec(&LicenseInventoryV1 {
        schema_version: LICENSE_INVENTORY_V1,
        plan_digest,
        packages,
    })
}

/// Validates the operator's advisory disposition against the exact inputs.
///
/// Every tier requires a disposition bound to this plan and SBOM that names
/// its advisory sources. Unresolved advisories block a production release;
/// the testing tier accepts them and the build-integrity evidence states how
/// many remain.
fn validate_advisory(
    advisory: &AdvisoryDispositionV1,
    plan_digest: Sha256Digest,
    sbom_digest: Sha256Digest,
    completed: std::time::SystemTime,
    tier: RegistryTier,
) -> Result<()> {
    aos_release_format::artifact::require_identifier(
        &advisory.authority_id,
        "advisory disposition authority",
    )?;
    if advisory.schema_version != ADVISORY_DISPOSITION_V1
        || advisory.plan_digest != plan_digest
        || advisory.sbom_digest != sbom_digest
        || advisory.sources.is_empty()
        || advisory
            .sources
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        || advisory.sources.iter().any(|source| {
            source.name.trim().is_empty()
                || source.snapshot.trim().is_empty()
                || source.name.chars().any(char::is_control)
                || source.snapshot.chars().any(char::is_control)
        })
    {
        bail!("advisory disposition is incomplete or bound to different inputs");
    }

    if advisory
        .unresolved_advisories
        .iter()
        .any(|entry| entry.trim().is_empty() || entry.chars().any(char::is_control))
    {
        bail!("advisory disposition lists a blank or malformed unresolved advisory");
    }
    if !advisory.unresolved_advisories.is_empty() && !tier.accepts_unresolved_advisories() {
        bail!(
            "advisory disposition leaves {} advisories unresolved, which the {tier} registry tier refuses",
            advisory.unresolved_advisories.len()
        );
    }
    if require_utc(&advisory.reviewed_at, "advisory review time")? > completed {
        bail!("advisory disposition was reviewed after assembly completion");
    }
    Ok(())
}

fn cache_key(specification: &str, plan: &ReleasePlan) -> Result<TrustedEd25519Key> {
    let (key_id, path) = super::finalize_cache::parse_key_spec(specification)?;
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::Cache)
        .context("release plan lacks cache signer policy")?;
    if requirement.threshold != 1 || requirement.key_ids.as_slice() != [key_id.as_str()] {
        bail!("cache key differs from the release plan's exact threshold-one signer policy");
    }
    super::finalize_cache::load_cache_public_key(&key_id, &path)
}

fn read_canonical(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_utc(value: &str, label: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("{label} must be an RFC 3339 UTC timestamp");
    }
    humantime::parse_rfc3339(value).with_context(|| format!("parsing {label}"))
}

#[cfg(test)]
mod tests {
    use aos_release_format::build::{BUILD_REPORT_V1, BuildOutputEvidence, ReproducibilityResult};
    use aos_release_format::platform::Platform;
    use aos_release_format::registry::{EXPERIMENTAL_REGISTRY, MAIN_REGISTRY};

    use super::*;

    fn report_with(reproducibility: ReproducibilityResult) -> BuildReportV1 {
        BuildReportV1 {
            schema_version: BUILD_REPORT_V1.to_owned(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            source_commit: "0".repeat(40),
            outputs: vec![BuildOutputEvidence {
                id: "package/example/x86_64-linux".to_owned(),
                package: "example".to_owned(),
                version: "1.0.0".to_owned(),
                license_expression: "Apache-2.0".to_owned(),
                source_store_paths: vec![],
                platform: Platform::X86_64Linux,
                derivation: "/nix/store/22222222222222222222222222222222-example.drv".to_owned(),
                output: "out".to_owned(),
                store_path: "/nix/store/11111111111111111111111111111111-example".to_owned(),
                nar_hash: format!("sha256:{}", "a".repeat(64)),
                nar_size: 1,
                closure_size: 1,
                references: vec![],
                reproducibility,
            }],
            sources: vec![],
            completed_at: "2026-10-04T00:00:00Z".to_owned(),
        }
    }

    fn disposition(unresolved: &[&str]) -> AdvisoryDispositionV1 {
        AdvisoryDispositionV1 {
            schema_version: ADVISORY_DISPOSITION_V1.to_owned(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            sbom_digest: Sha256Digest::of_bytes("sbom"),
            reviewed_at: "2026-10-04T00:00:00Z".to_owned(),
            authority_id: "release-security-review".to_owned(),
            sources: vec![AdvisorySource {
                name: "osv".to_owned(),
                snapshot: "sha256:0".to_owned(),
            }],
            unresolved_advisories: unresolved.iter().map(|entry| (*entry).to_owned()).collect(),
        }
    }

    fn check_disposition(advisory: &AdvisoryDispositionV1, tier: RegistryTier) -> Result<()> {
        let completed = require_utc("2026-10-05T00:00:00Z", "completion")?;
        validate_advisory(
            advisory,
            Sha256Digest::of_bytes("plan"),
            Sha256Digest::of_bytes("sbom"),
            completed,
            tier,
        )
    }

    #[test]
    fn resolved_dispositions_pass_on_every_tier() -> Result<()> {
        for tier in [RegistryTier::Testing, RegistryTier::Production] {
            check_disposition(&disposition(&[]), tier)?;
        }
        Ok(())
    }

    #[test]
    fn testing_tier_accepts_unresolved_advisories() -> Result<()> {
        let advisory = disposition(&["crates.io:example@1.0.0: GHSA-0000-0000-0000"]);

        check_disposition(&advisory, RegistryTier::Testing)
    }

    #[test]
    fn production_tier_refuses_unresolved_advisories() {
        let advisory = disposition(&["crates.io:example@1.0.0: GHSA-0000-0000-0000"]);

        let error = check_disposition(&advisory, RegistryTier::Production)
            .expect_err("production assembly must fail closed");
        assert!(error.to_string().contains("1 advisories unresolved"));
    }

    #[test]
    fn blank_unresolved_entries_are_malformed_on_every_tier() {
        for tier in [RegistryTier::Testing, RegistryTier::Production] {
            assert!(check_disposition(&disposition(&["  "]), tier).is_err());
        }
    }

    #[test]
    fn production_registry_rejects_not_reproduced_outputs() {
        let report = report_with(ReproducibilityResult::NotReproduced);

        let error = require_repeat_build_policy(MAIN_REGISTRY, &report)
            .expect_err("production assembly must fail closed");

        assert!(
            error
                .to_string()
                .contains("without a successful repeat build")
        );
    }

    #[test]
    fn testing_registries_accept_not_reproduced_outputs() -> Result<()> {
        let report = report_with(ReproducibilityResult::NotReproduced);

        require_repeat_build_policy(EXPERIMENTAL_REGISTRY, &report)?;
        require_repeat_build_policy("andyl/experimental-v2", &report)?;
        Ok(())
    }

    #[test]
    fn every_registry_accepts_reproduced_outputs() -> Result<()> {
        let report = report_with(ReproducibilityResult::Reproduced);

        require_repeat_build_policy(MAIN_REGISTRY, &report)?;
        require_repeat_build_policy(EXPERIMENTAL_REGISTRY, &report)?;
        Ok(())
    }

    #[test]
    fn unknown_registries_fail_closed() {
        let report = report_with(ReproducibilityResult::Reproduced);

        assert!(require_repeat_build_policy("example/unknown", &report).is_err());
    }
}
