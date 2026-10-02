//! Deterministic, test-only authorities and artifacts for the release fleet test.
//!
//! This binary is installed only in `pkgs.aos.testSupport`. It deliberately
//! uses fixed private keys and must never be used outside an isolated test.
//!
//! Subcommands:
//!
//! - `contract`: the qualification contract the fixture plans with, for the
//!   work directory of `aos maintain release new --request-only`;
//! - `prepare`: a finalized `aos-2026.9.0-rc.1` candidate bundle on
//!   `andyl/main` planned for `staging/candidate` and `production/candidate`
//!   on the fleet's two Hubs from the first-release request `new` derived, its
//!   qualification-snapshot predecessor, public keys, and a `finalized`
//!   journal. The fixture stands in for the Nix-evaluated `step plan` leaf,
//!   which needs an AOS source checkout the fleet does not carry;
//! - `bootstrap-intent`: a release-evidence-signed registry bootstrap intent
//!   for one environment of a prepared plan;
//! - `review`: an accepted release-evidence review of a qualification report;
//! - `fitness`: signed attestations for every fitness kind the production
//!   destination's profile demands, bound to the fleet's live identities;
//! - `sign-exchange-v1`: the qualification authority's signer exchange;
//! - `maintainer-upstream-proxy`: a TLS proxy for the maintainer update test;
//! - no subcommand: a native qualification executor reading one request on
//!   stdin.

mod artifact_consumption_fixture;
mod initrd_contract_fixture;
mod native_deployment_fixture;

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use aos_core::nar::cache::{
    NarCompression, NarInfoSigner, StaticNarInfoInput, nar_url, render_static_narinfo,
};
use aos_release::artifact::{
    ArtifactKind, ArtifactRecord, ArtifactRelation, ArtifactRelationship, BundlePath, Compression,
    ImageArtifactIdentity,
};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::{
    EvidenceRecord, GateResult, QUALIFICATION_EXECUTOR_RESPONSE, QualificationExecutorRequest,
    QualificationExecutorResponse,
};
use aos_release::fitness::{FITNESS_REPORT, FitnessReport, LiveBindings, signer_roster_digest};
use aos_release::inventory::PackageInventoryV1;
use aos_release::inventory::PackagePublicationMetadata;
use aos_release::manifest::{
    FinalArtifactSet, MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1, ManifestSignature,
    PackageResult, ReleaseManifestV1,
};
use aos_release::plan::{
    PackagePlan, PlannedArtifact, PlannedArtifactSet, PlannedSurface, PlatformCell, ReleaseClass,
    ReleasePlan, ReleasePlanRequest, RequestedDestination, RetentionPolicy, SourceIdentity,
    SurfaceKind, SurfaceRole, planned_destinations,
};
use aos_release::platform::{MatrixCell, Platform};
use aos_release::qualification::ChangeScope;
use aos_release::qualification_admission::{QUALIFICATION_REVIEW, QualificationReview};
use aos_release::qualification_evidence::CheckObservation;
use aos_release::receipt::{
    HubEnvironment, RECEIPT_SIGNATURE_DOMAIN, REGISTRY_BOOTSTRAP_INTENT, RegistryBootstrapIntent,
    SIGNED_RECEIPT, SignedReceiptEnvelope,
};
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignatureResponse, SignerRequirement, SignerRole,
    SigningContext, SigningOperation, SigningRequest,
};
use aos_release::state::{JournalEntry, ReleaseState};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::CertificateDer;

const RELEASE_SEED: [u8; 32] = [7; 32];
const QUALIFICATION_SEED: [u8; 32] = [8; 32];
const RELEASE_KEY_ID: &str = "release-evidence-v1";
const QUALIFICATION_KEY_ID: &str = "qualification-v1";
const PROVIDER_REVISION: &str = "fleet-provider-v1";
const QUALIFICATION_IDENTITY: &str = "fleet-qualification-authority";
const RELEASE_ID: &str = "aos-2026.9.0-rc.1";
const RELEASE_VERSION: &str = "2026.9.0-rc.1";
const STAGING_ORIGIN: &str = "https://aos.staging.andyl.org";
const STAGING_DEPLOYMENT: &str = "fleet-staging-v1";
const PRODUCTION_ORIGIN: &str = "https://aos.andyl.org";
const PRODUCTION_DEPLOYMENT: &str = "fleet-production-v1";
/// Channel of both planned destinations: a release candidate on `andyl/main`.
const CHANNEL: &str = "candidate";
/// Production destination whose `functional` profile demands fitness.
const PRODUCTION_DESTINATION: &str = "production/candidate";
/// Live identities the fleet test passes to `publish` and `channel advance`;
/// `fitness` binds its attestations to exactly these values.
const HUB_SCHEMA: &str = "2";
const TOOLING_LABEL: &str = "fleet-tooling-closure";
const ALERT_CONFIG_LABEL: &str = "fleet-alert-config";
const TIME: &str = "2026-09-03T12:00:00Z";
const SIGNER_REQUEST_DOMAIN: &[u8] = b"aos.release.signer-exchange/v1\0";
const SIGNER_RESPONSE_DOMAIN: &[u8] = b"aos.release.signer-exchange-response/v1\0";

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("contract") => write_contract(&arguments[1..]),
        Some("prepare") => prepare(&arguments[1..]),
        Some("adopt-native-fixture") => native_deployment_fixture::adopt(&arguments[1..]),
        Some("artifact-consumption-evidence") => {
            artifact_consumption_fixture::generate(&arguments[1..])
        }
        Some("initrd-contract") => initrd_contract_fixture::verify(&arguments[1..]),
        Some("image-assembly-contract") => {
            initrd_contract_fixture::verify_assembly(&arguments[1..])
        }
        Some("image-assembly-attachments") => {
            initrd_contract_fixture::verify_assembly_attachments(&arguments[1..])
        }
        Some("validate-package-inventory") => validate_package_inventory(&arguments[1..]),
        Some("bootstrap-intent") => bootstrap_intent(&arguments[1..]),
        Some("sign-exchange-v1") => signer_exchange(),
        Some("review") => review(&arguments[1..]),
        Some("fitness") => fitness(&arguments[1..]),
        Some("maintainer-upstream-proxy") => maintainer_upstream_proxy(&arguments[1..]).await,
        None => qualification_executor().await,
        Some(command) => bail!("unknown release fleet fixture command: {command}"),
    }
}

fn validate_package_inventory(arguments: &[String]) -> Result<()> {
    if arguments.len() < 2 {
        bail!("usage: aos-release-fleet-fixture validate-package-inventory INVENTORY PLATFORM...");
    }

    let path = Path::new(&arguments[0]);
    let bytes = fs::read(path)
        .with_context(|| format!("reading release package inventory {}", path.display()))?;
    let inventory: PackageInventoryV1 = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding release package inventory {}", path.display()))?;
    let platforms = arguments[1..]
        .iter()
        .map(|value| value.parse::<Platform>())
        .collect::<Result<Vec<_>>>()?;
    inventory.validate_for_platforms(&platforms)?;

    Ok(())
}

/// Writes the contract the fixture plans with, as `new` would export it.
fn write_contract(arguments: &[String]) -> Result<()> {
    if arguments.len() != 1 {
        bail!("usage: aos-release-fleet-fixture contract OUTPUT");
    }
    write_new(
        PathBuf::from(&arguments[0]),
        &canonical::to_vec(&fleet_contract()?)?,
    )
}

/// Returns the shared contract with the fleet package as its only catalog rule.
fn fleet_contract() -> Result<aos_release::qualification::QualificationContract> {
    let mut contract = qualification_fixture::contract()?;
    contract.package_rules = vec![aos_release::qualification::PackageRule {
        name: "fleet-package".into(),
        role: aos_release::qualification::PackageRole::GeneralCatalog,
        inherit_dependency_obligations: true,
        execution: None,
    }];
    Ok(contract)
}

/// Reads the first-release request `new` derived and checks it fits the fleet.
///
/// The fixture keeps the request's registry base, generation, surfaces,
/// destinations, and policy binding, and substitutes only what the
/// Nix-evaluated planner would add: the package matrix and source identity.
fn first_release_request(path: &Path) -> Result<ReleasePlanRequest> {
    let request: ReleasePlanRequest =
        canonical::from_slice(&fs::read(path)?, "first-release plan request")?;
    if !request.first_release {
        bail!("the fleet plans a registry's first release; the request is an ordinary one");
    }
    if request.registry != aos_release::registry::MAIN_REGISTRY
        || request.release_id != RELEASE_ID
        || request.version != RELEASE_VERSION
        || request.surfaces != fleet_surfaces()
    {
        bail!("the request does not describe the fleet's andyl/main candidate on its two Hubs");
    }
    if request.public_evidence_policy_digest != fleet_contract()?.digest()? {
        bail!("the request binds a different qualification contract than the fixture plans with");
    }
    let mut requested: Vec<String> = request
        .destinations
        .iter()
        .map(|destination| format!("{}/{}", destination.surface, destination.channel))
        .collect();
    requested.sort();
    if requested != ["production/candidate", "staging/candidate"] {
        bail!("the request plans {requested:?}, not the fleet's candidate destinations");
    }
    Ok(request)
}

fn prepare(arguments: &[String]) -> Result<()> {
    if arguments.len() != 9 {
        bail!(
            "usage: aos-release-fleet-fixture prepare BASE_SURFACE OUTPUT PREDECESSOR TRUST_DIR REQUEST X86_LINUX AARCH64_LINUX X86_DARWIN AARCH64_DARWIN"
        );
    }
    let base = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let predecessor = Path::new(&arguments[2]);
    let trust = Path::new(&arguments[3]);
    let request = first_release_request(Path::new(&arguments[4]))?;
    let base_commit = &request.registry_base_commit;
    if output.exists() || predecessor.exists() || trust.exists() {
        bail!("fixture outputs must not already exist");
    }

    copy_tree(base, output)?;
    fs::create_dir_all(trust)?;
    write_public_key(
        trust.join("release.pub"),
        &SigningKey::from_bytes(&RELEASE_SEED),
    )?;
    write_public_key(
        trust.join("qualification.pub"),
        &SigningKey::from_bytes(&QUALIFICATION_SEED),
    )?;

    let package_inputs = Platform::ALL
        .into_iter()
        .zip(arguments[5..].iter().map(PathBuf::from))
        .collect::<Vec<_>>();
    let package_cells = package_inputs
        .iter()
        .map(|(platform, _)| PlatformCell {
            platform: *platform,
            decision: MatrixCell::Artifact {
                artifact: PlannedArtifactSet {
                    artifacts: vec![PlannedArtifact {
                        id: package_id(*platform),
                        derivation: None,
                        output: None,
                        store_path: None,
                        source_store_paths: Vec::new(),
                    }],
                },
            },
        })
        .collect::<Vec<_>>();
    let mut plan = release_plan(&request, package_cells.clone())?;
    plan.validate()?;
    let mut plan_bytes = canonical::to_vec(&plan)?;
    write_new(output.join("release-plan.json"), &plan_bytes)?;

    let mut artifacts = Vec::new();
    inventory_tree(output, output, &mut artifacts)?;
    for (platform, source) in &package_inputs {
        let package_bytes = fs::read(source)
            .with_context(|| format!("reading mounted package NAR {}", source.display()))?;
        let relative = fixture_nar_url(*platform, &package_bytes)?;
        let destination = output.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        write_new(destination, &package_bytes)?;

        let narinfo_bytes = fixture_narinfo(*platform, &package_bytes)?.into_bytes();
        let narinfo_relative =
            format!("releases/candidate/{RELEASE_VERSION}/packages/{platform}.narinfo");
        write_new(output.join(&narinfo_relative), &narinfo_bytes)?;
        artifacts.push(record(
            narinfo_id(*platform),
            ArtifactKind::NarInfo,
            Some(*platform),
            &narinfo_relative,
            &narinfo_bytes,
        )?);

        let mut package = record(
            package_id(*platform),
            ArtifactKind::PackageNar,
            Some(*platform),
            &relative,
            &package_bytes,
        )?;
        package.relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::AuthenticatedBy,
            target: narinfo_id(*platform),
        });
        artifacts.push(package);
    }
    for platform in Platform::LINUX {
        let contract_id = format!("provenance/image/server/{platform}/provider-contract");
        let contract_path = format!("releases/candidate/{RELEASE_VERSION}/fixtures/{contract_id}");
        let contract_bytes =
            format!("synthetic image provider contract: {platform}\n").into_bytes();
        write_new(output.join(&contract_path), &contract_bytes)?;
        artifacts.push(record(
            contract_id.clone(),
            ArtifactKind::Provenance,
            Some(platform),
            &contract_path,
            &contract_bytes,
        )?);

        for (suffix, role, bytes) in [
            (
                "payload",
                "aos.test.image-artifact.payload/v1",
                format!("synthetic release protocol fixture: image/server/{platform}\n")
                    .into_bytes(),
            ),
            (
                "metadata",
                "aos.test.image-artifact.metadata/v1",
                canonical::canonical_json(&qualification_fixture::metadata()?)?,
            ),
        ] {
            let id = if suffix == "payload" {
                format!("image/server/{platform}")
            } else {
                format!("image/server/{platform}/{suffix}")
            };
            // Payload and metadata are siblings even though the payload's
            // logical artifact id names the image itself.
            let path = format!(
                "releases/candidate/{RELEASE_VERSION}/fixtures/image/server/{platform}/{suffix}"
            );
            write_new(output.join(&path), &bytes)?;
            let mut artifact = record(id, ArtifactKind::Image, Some(platform), &path, &bytes)?;
            artifact.system_variant = Some("server".into());
            artifact.image = Some(ImageArtifactIdentity {
                contract_schema: "aos.test.image-provider/v1".into(),
                contract_artifact: contract_id.clone(),
                role: role.into(),
            });
            artifact.relationships.push(ArtifactRelationship {
                relation: ArtifactRelation::Documents,
                target: contract_id.clone(),
            });
            artifacts.push(artifact);
        }

        let id = format!("oci/{platform}");
        let path = format!("releases/candidate/{RELEASE_VERSION}/fixtures/{id}");
        let bytes = format!("synthetic release protocol fixture: {id}\n").into_bytes();
        write_new(output.join(&path), &bytes)?;
        artifacts.push(record(
            id,
            ArtifactKind::OciManifest,
            Some(platform),
            &path,
            &bytes,
        )?);
    }
    let index_path = format!("releases/candidate/{RELEASE_VERSION}/fixtures/oci/index");
    let index_bytes = b"synthetic release protocol fixture: oci/index\n";
    write_new(output.join(&index_path), index_bytes)?;
    artifacts.push(record(
        "oci/index".into(),
        ArtifactKind::OciIndex,
        None,
        &index_path,
        index_bytes,
    )?);
    let gate_report = canonical::to_vec(&json!({
        "schema_version": "aos.release.fleet-gate-report/v1",
        "result": "passed"
    }))?;
    let gate_path = "releases/candidate/2026.9.0-rc.1/evidence/preflight.json";
    write_new(output.join(gate_path), &gate_report)?;
    let gate_record = record(
        "evidence/fleet-preflight".into(),
        ArtifactKind::Evidence,
        None,
        gate_path,
        &gate_report,
    )?;
    let gate_report_digest = gate_record.sha256;
    artifacts.push(gate_record);
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));

    let mut manifest = ReleaseManifestV1 {
        schema_version: aos_release::RELEASE_MANIFEST_V1.into(),
        release_id: RELEASE_ID.into(),
        version: RELEASE_VERSION.into(),
        release_class: ReleaseClass::Candidate,
        registry: aos_release::registry::MAIN_REGISTRY.into(),
        plan_digest: Sha256Digest::of_bytes(&plan_bytes),
        source_commit: base_commit.clone(),
        packages: vec![PackageResult {
            name: "fleet-package".into(),
            platforms: package_cells
                .into_iter()
                .map(|cell| PlatformCell {
                    platform: cell.platform,
                    decision: MatrixCell::Artifact {
                        artifact: FinalArtifactSet {
                            artifact_ids: vec![package_id(cell.platform)],
                        },
                    },
                })
                .collect(),
        }],
        images: vec![aos_release::manifest::ImageResult {
            system_variant: "server".into(),
            platforms: Platform::LINUX
                .into_iter()
                .map(|platform| PlatformCell {
                    platform,
                    decision: MatrixCell::Artifact {
                        artifact: FinalArtifactSet {
                            artifact_ids: vec![
                                format!("image/server/{platform}"),
                                format!("image/server/{platform}/metadata"),
                            ],
                        },
                    },
                })
                .collect(),
        }],
        artifacts,
        evidence: vec![EvidenceRecord {
            qualification: None,
            id: "fleet-preflight".into(),
            policy_id: "fleet-release-gate-v1".into(),
            policy_digest: digest("fleet-release-gate-policy"),
            platform: None,
            subjects: Platform::ALL.into_iter().map(package_id).collect(),
            result: GateResult::Passed,
            report_digest: gate_report_digest,
            authority_id: "fleet-preflight-authority".into(),
            nonce: Some("1".repeat(64)),
            started_at: TIME.into(),
            finished_at: TIME.into(),
        }],
    };
    let predecessor =
        prepare_predecessor(output, predecessor, &plan, &manifest, gate_report_digest)?;
    plan.qualification_predecessor = Some(predecessor);
    plan.validate()?;
    plan_bytes = canonical::to_vec(&plan)?;
    fs::write(output.join("release-plan.json"), &plan_bytes)?;
    bind_plan_artifact(&mut manifest, &plan_bytes)?;
    manifest.plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    manifest.evidence = build_evidence(&plan, &manifest, gate_report_digest)?;
    manifest.validate(&plan)?;
    let envelope = signed_manifest(&plan_bytes, manifest)?;
    let manifest_digest = envelope.payload_digest;
    write_new(
        output.join("release-manifest.json"),
        &canonical::to_vec(&envelope)?,
    )?;
    write_journal(
        trust.join("release-journal.jsonl"),
        Sha256Digest::of_bytes(&plan_bytes),
        manifest_digest,
    )?;
    Ok(())
}

/// Synthesizes passing build-phase observations for every planned destination.
fn build_evidence(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    gate_report_digest: Sha256Digest,
) -> Result<Vec<EvidenceRecord>> {
    // Whole seconds: coordinators admit observations against a
    // seconds-precision `now`, so a sub-second finish could read as future.
    let finished = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    aos_release::qualification_evidence::cases(
        plan,
        manifest,
        None,
        aos_release::qualification::QualificationPhase::Build,
    )?
    .iter()
    .map(|case| {
        fixture_evidence(
            case,
            gate_report_digest,
            "fleet-preflight-authority",
            None,
            &finished,
        )
    })
    .collect()
}

fn prepare_predecessor(
    source: &Path,
    output: &Path,
    release_plan: &ReleasePlan,
    release_manifest: &ReleaseManifestV1,
    gate_report_digest: Sha256Digest,
) -> Result<aos_release::qualification_evidence::QualificationPredecessor> {
    let mut plan = release_plan.clone();
    plan.qualification_predecessor = None;
    plan.release_id = format!(
        "{}{}",
        aos_release::plan::QUALIFICATION_SNAPSHOT_RELEASE_PREFIX,
        plan.version
    );
    plan.source.source_tag = format!(
        "{}{}",
        aos_release::plan::QUALIFICATION_SNAPSHOT_TAG_PREFIX,
        plan.version
    );
    // A qualification snapshot is never published, so it plans no destination.
    plan.destinations.clear();
    plan.profile_overrides.clear();
    plan.validate()?;
    let plan_bytes = canonical::to_vec(&plan)?;

    copy_tree(source, output)?;
    fs::write(output.join("release-plan.json"), &plan_bytes)?;

    let mut manifest = release_manifest.clone();
    manifest.release_id.clone_from(&plan.release_id);
    manifest.plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    bind_plan_artifact(&mut manifest, &plan_bytes)?;
    manifest.evidence = build_evidence(&plan, &manifest, gate_report_digest)?;
    manifest.validate(&plan)?;

    let envelope = signed_manifest(&plan_bytes, manifest)?;
    let manifest_digest = envelope.payload_digest;
    write_new(
        output.join("release-manifest.json"),
        &canonical::to_vec(&envelope)?,
    )?;
    Ok(
        aos_release::qualification_evidence::QualificationPredecessor {
            registry: plan.registry,
            release_id: plan.release_id,
            manifest_digest,
        },
    )
}

fn bind_plan_artifact(manifest: &mut ReleaseManifestV1, plan_bytes: &[u8]) -> Result<()> {
    let artifact = manifest
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.id == "control/release-plan")
        .context("release fixture lacks its plan artifact")?;
    artifact.size_bytes = u64::try_from(plan_bytes.len())?;
    artifact.sha256 = Sha256Digest::of_bytes(plan_bytes);
    Ok(())
}

fn signed_manifest(plan_bytes: &[u8], manifest: ReleaseManifestV1) -> Result<ManifestEnvelopeV1> {
    let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &manifest)?;
    let signing_key = SigningKey::from_bytes(&RELEASE_SEED);
    let request = signing_request(
        SignerRole::ReleaseEvidence,
        RELEASE_KEY_ID,
        "release-manifest",
        &manifest.registry,
        &manifest.release_id,
        Sha256Digest::of_bytes(plan_bytes),
        Some(manifest_digest),
        manifest_digest,
        SignatureAlgorithm::Ed25519,
    );
    let response = signature_response(&request, &signing_key, request.digest()?.as_bytes())?;
    Ok(ManifestEnvelopeV1 {
        schema_version: MANIFEST_ENVELOPE_V1.into(),
        payload: manifest,
        payload_digest: manifest_digest,
        signatures: vec![ManifestSignature { request, response }],
    })
}

/// Builds the candidate plan for both Hub surfaces and both candidate destinations.
///
/// Destinations are filled by [`planned_destinations`], the same derivation
/// `aos maintain release step plan` applies to a request, so their profiles, gates,
/// soak, and rings are exactly the contract's.
fn release_plan(
    request: &ReleasePlanRequest,
    platforms: Vec<PlatformCell<PlannedArtifactSet>>,
) -> Result<ReleasePlan> {
    let base_commit = request.registry_base_commit.as_str();
    // Two Hub surfaces need no surface-receipt signer; a planned channel
    // needs the channel signer.
    let roles = [
        SignerRole::Registry,
        SignerRole::Cache,
        SignerRole::Provenance,
        SignerRole::ReleaseEvidence,
        SignerRole::Qualification,
        SignerRole::TufRoot,
        SignerRole::TufTargets,
        SignerRole::TufCandidate,
        SignerRole::TufSnapshot,
        SignerRole::TufTimestamp,
        SignerRole::Channel,
    ];
    let contract = fleet_contract()?;

    let mut plan = ReleasePlan {
        schema_version: aos_release::RELEASE_PLAN.into(),
        public_evidence_policy_digest: contract.digest()?,
        qualification: contract,
        qualification_predecessor: Some(
            aos_release::qualification_evidence::QualificationPredecessor {
                registry: aos_release::registry::MAIN_REGISTRY.into(),
                release_id: "fleet-predecessor".into(),
                manifest_digest: digest("fleet-predecessor"),
            },
        ),
        release_id: RELEASE_ID.into(),
        version: RELEASE_VERSION.into(),
        release_class: ReleaseClass::Candidate,
        registry: aos_release::registry::MAIN_REGISTRY.into(),
        registry_base_commit: base_commit.into(),
        registry_base_generation: request.registry_base_generation,
        source: SourceIdentity {
            commit: base_commit.into(),
            tree_digest: digest("fleet-source-tree"),
            protected_branch: "master".into(),
            source_tag: "release/2026.9.0-rc.1".into(),
            contributor_authorization_digest: digest("fleet-contributor-authorization"),
        },
        packages: vec![PackagePlan {
            platform_versions: Default::default(),
            name: "fleet-package".into(),
            publication: Some(PackagePublicationMetadata {
                version: "1.0.0".into(),
                description: "Four-platform release fleet fixture".into(),
                homepage: None,
                license_expression: "Apache-2.0".into(),
                maintainers: vec!["AOS release fleet".into()],
            }),
            platforms,
        }],
        images: vec![aos_release::plan::ImagePlan {
            system_variant: "server".into(),
            platforms: Platform::LINUX
                .into_iter()
                .map(|platform| PlatformCell {
                    platform,
                    decision: MatrixCell::Artifact {
                        artifact: PlannedArtifactSet {
                            artifacts: [
                                format!("image/server/{platform}"),
                                format!("image/server/{platform}/metadata"),
                            ]
                            .into_iter()
                            .map(|id| PlannedArtifact {
                                id,
                                derivation: None,
                                output: None,
                                store_path: None,
                                source_store_paths: Vec::new(),
                            })
                            .collect(),
                        },
                    },
                })
                .collect(),
        }],
        signers: roles
            .into_iter()
            .map(|role| SignerRequirement {
                role,
                key_ids: vec![match role {
                    SignerRole::ReleaseEvidence => RELEASE_KEY_ID.into(),
                    SignerRole::Qualification => QUALIFICATION_KEY_ID.into(),
                    _ => format!("fleet-{role:?}").to_ascii_lowercase(),
                }],
                threshold: 1,
                provider_revision: PROVIDER_REVISION.into(),
            })
            .collect(),
        surfaces: fleet_surfaces(),
        destinations: Vec::new(),
        change_scope: None,
        profile_overrides: Vec::new(),
        retention: RetentionPolicy {
            policy_id: "fleet-retention-v1".into(),
            policy_digest: digest("fleet-retention-policy"),
            require_corresponding_source: true,
        },
        restricted_operator_policy_digest: digest("fleet-restricted-operator-policy"),
    };

    // The fleet has no predecessor manifest to compare, so every population
    // is affecting (the fail-closed scope).
    plan.change_scope = Some(ChangeScope::everything_planned(
        &plan,
        "fleet fixture: no predecessor manifest; every population is affecting",
    ));
    let requested =
        [SurfaceRole::Staging, SurfaceRole::Production].map(|surface| RequestedDestination {
            surface,
            channel: CHANNEL.into(),
            effective: None,
        });
    plan.destinations = planned_destinations(
        &plan.qualification,
        &plan.registry,
        &requested,
        plan.change_scope.as_ref(),
    )?;
    Ok(plan)
}

/// Returns the fleet's staging and production Hub surfaces.
fn fleet_surfaces() -> Vec<PlannedSurface> {
    [
        (SurfaceRole::Staging, STAGING_ORIGIN, STAGING_DEPLOYMENT),
        (
            SurfaceRole::Production,
            PRODUCTION_ORIGIN,
            PRODUCTION_DEPLOYMENT,
        ),
    ]
    .into_iter()
    .map(|(role, origin, identity)| PlannedSurface {
        role,
        kind: SurfaceKind::Hub,
        origin: origin.into(),
        readback_origin: None,
        identity: identity.into(),
    })
    .collect()
}

fn inventory_tree(
    root: &Path,
    directory: &Path,
    artifacts: &mut Vec<ArtifactRecord>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            inventory_tree(root, &path, artifacts)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "release-manifest.json" {
                continue;
            }
            let kind = if relative == "release-plan.json" {
                ArtifactKind::ReleasePlan
            } else {
                ArtifactKind::RegistryObject
            };
            let id = if kind == ArtifactKind::ReleasePlan {
                "control/release-plan".into()
            } else {
                format!("surface/{:04}", artifacts.len())
            };
            artifacts.push(record(id, kind, None, &relative, &fs::read(path)?)?);
        } else {
            bail!("release fixture surface contains a non-regular entry");
        }
    }
    Ok(())
}

fn record(
    id: String,
    kind: ArtifactKind,
    platform: Option<Platform>,
    path: &str,
    bytes: &[u8],
) -> Result<ArtifactRecord> {
    Ok(ArtifactRecord {
        id,
        kind,
        platform,
        system_variant: None,
        image: None,
        path: BundlePath::parse(path)?,
        size_bytes: u64::try_from(bytes.len())?,
        sha256: Sha256Digest::of_bytes(bytes),
        media_type: "application/octet-stream".into(),
        compression: Compression::None,
        derivation: None,
        output: None,
        store_path: None,
        nar_hash: None,
        relationships: Vec::new(),
    })
}

fn signing_request(
    role: SignerRole,
    key_id: &str,
    artifact_kind: &str,
    registry: &str,
    release_id: &str,
    plan_digest: Sha256Digest,
    manifest_digest: Option<Sha256Digest>,
    payload_digest: Sha256Digest,
    algorithm: SignatureAlgorithm,
) -> SigningRequest {
    SigningRequest {
        schema_version: SIGNING_REQUEST_DOMAIN.into(),
        request_id: format!("fleet/{artifact_kind}"),
        nonce: "2".repeat(64),
        registry: registry.into(),
        release_id: release_id.into(),
        plan_digest,
        manifest_digest,
        role,
        key_id: key_id.into(),
        provider_revision: PROVIDER_REVISION.into(),
        algorithm,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: artifact_kind.into(),
        },
        payload_digest,
        approval_policy_digest: digest("fleet-restricted-operator-policy"),
    }
}

fn signature_response(
    request: &SigningRequest,
    key: &SigningKey,
    signed_bytes: &[u8],
) -> Result<SignatureResponse> {
    Ok(SignatureResponse {
        schema_version: "aos.release.signature-response/v1".into(),
        request_digest: request.digest()?,
        role: request.role,
        key_id: request.key_id.clone(),
        provider_revision: request.provider_revision.clone(),
        algorithm: request.algorithm,
        provider_operation_id: format!("fleet-{}", request.request_id.replace('/', "-")),
        verification_identity: if request.role == SignerRole::Qualification {
            QUALIFICATION_IDENTITY.into()
        } else {
            "fleet-release-evidence-authority".into()
        },
        verification_material_digest: Sha256Digest::of_bytes(key.verifying_key().to_bytes()),
        output_digest: None,
        signature_base64: base64::engine::general_purpose::STANDARD
            .encode(key.sign(signed_bytes).to_bytes()),
    })
}

fn write_journal(path: PathBuf, plan: Sha256Digest, manifest: Sha256Digest) -> Result<()> {
    // Only the global build lifecycle is prepared; every destination entry is
    // appended by the `aos maintain release step` commands under test.
    let mut entries: Vec<JournalEntry> = Vec::new();
    for state in [
        ReleaseState::Planned,
        ReleaseState::Built,
        ReleaseState::Finalized,
    ] {
        let prior = entries.last();
        entries.push(JournalEntry {
            schema_version: aos_release::RELEASE_JOURNAL_ENTRY.into(),
            sequence: u64::try_from(entries.len() + 1)?,
            previous_entry_digest: prior.map(JournalEntry::digest).transpose()?,
            plan_digest: plan,
            manifest_digest: (state >= ReleaseState::Finalized).then_some(manifest),
            prior_state: prior.map(|entry| entry.new_state),
            new_state: state,
            destination: None,
            operation_ids: vec![format!("fleet-{state:?}").to_ascii_lowercase()],
            evidence: Vec::new(),
            recorded_at: TIME.into(),
        });
    }
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(canonical::to_vec(&entry)?);
        bytes.push(b'\n');
    }
    write_new(path, &bytes)
}

fn signer_exchange() -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut domain = vec![0; SIGNER_REQUEST_DOMAIN.len()];
    input.read_exact(&mut domain)?;
    if domain != SIGNER_REQUEST_DOMAIN {
        bail!("wrong signer request domain");
    }
    let request_bytes = read_frame(&mut input)?;
    let payload = read_frame(&mut input)?;
    let request: SigningRequest = canonical::from_slice(&request_bytes, "signing request")?;
    request.validate()?;
    request.verify_payload_bytes(&payload)?;
    let (key, signed_bytes) = match request.role {
        SignerRole::Qualification => {
            let signed_bytes = if request.algorithm == SignatureAlgorithm::Ed25519Payload {
                payload.clone()
            } else {
                request.digest()?.as_bytes().to_vec()
            };
            (SigningKey::from_bytes(&QUALIFICATION_SEED), signed_bytes)
        }
        _ => bail!("fleet signer refuses role {:?}", request.role),
    };
    let response = canonical::to_vec(&signature_response(&request, &key, &signed_bytes)?)?;
    let mut output = std::io::stdout().lock();
    output.write_all(SIGNER_RESPONSE_DOMAIN)?;
    write_frame(&mut output, &response)?;
    write_frame(&mut output, &[])?;
    output.flush()?;
    Ok(())
}

#[path = "../../../aos-release/src/test_support/qualification/mod.rs"]
mod qualification_fixture;

async fn qualification_executor() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: QualificationExecutorRequest =
        canonical::from_slice(input.as_bytes(), "qualification request")?;
    request.validate()?;
    let mut builder = reqwest::Client::builder();
    let bundle = fs::read("/etc/ssl/certs/ca-certificates.crt")?;
    for certificate in rustls_pemfile::certs(&mut BufReader::new(bundle.as_slice())) {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(&certificate?)?);
    }
    let client = builder.build()?;
    stream::iter(&request.objects)
        .map(|object| {
            let client = &client;
            async move {
                let bytes = client
                    .get(&object.url)
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?;
                if u64::try_from(bytes.len())? != object.size_bytes
                    || Sha256Digest::of_bytes(&bytes) != object.sha256
                {
                    bail!(
                        "public qualification object changed: {}",
                        object.artifact_id
                    );
                }
                Result::<()>::Ok(())
            }
        })
        .buffer_unordered(32)
        .try_collect::<Vec<_>>()
        .await?;
    let report = json!({
        "schema_version": "aos.release.fleet-executor-report/v1",
        "platform": request.platform,
        "objects_verified": request.objects.len()
    });
    let case = &request.qualification_case;
    // Whole seconds, as in `build_evidence`.
    let now = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    let response = QualificationExecutorResponse {
        schema_version: QUALIFICATION_EXECUTOR_RESPONSE.into(),
        request_digest: request.digest()?,
        evidence: fixture_evidence(
            case,
            Sha256Digest::of_bytes(canonical::canonical_json(&report)?),
            &format!("fleet-executor-{}", request.platform),
            Some(request.nonce.clone()),
            &now,
        )?,
        report,
    };
    std::io::stdout().write_all(&canonical::to_vec(&response)?)?;
    Ok(())
}

/// Generates synthetic observations only for the isolated publication protocol fixture.
fn fixture_evidence(
    case: &aos_release::qualification_evidence::QualificationCase,
    report_digest: Sha256Digest,
    authority: &str,
    nonce: Option<String>,
    finish: &str,
) -> Result<EvidenceRecord> {
    use aos_release::qualification_evidence::{CheckObservation, QualificationObservation};

    let seconds = if case.phase == aos_release::qualification::QualificationPhase::Complete {
        14 * 24 * 60 * 60
    } else {
        0
    };
    let finished = humantime::parse_rfc3339(finish)?;
    let environment = qualification_fixture::environment(case)?;
    let capabilities = qualification_fixture::capabilities(case)?;
    let environment_digest = environment
        .as_ref()
        .map(|environment| environment.digest())
        .transpose()?
        .unwrap_or(digest("synthetic-protocol-environment"));
    let checks = case
        .checks
        .iter()
        .map(|id| {
            (
                id.clone(),
                CheckObservation {
                    passed: true,
                    detail: "Synthetic protocol fixture; no OS qualification claim".into(),
                },
            )
        })
        .collect();
    let operations = if case.target.is_some() {
        qualification_fixture::measurements()
    } else {
        std::collections::BTreeMap::from([("synthetic-requests".into(), 1)])
    };
    Ok(EvidenceRecord {
        qualification: Some(QualificationObservation {
            environment,
            capabilities,
            assessment: qualification_fixture::assessment(case)?,
            native_adapter_matrix: None,
            case_digest: case.digest()?,
            executor_digest: digest("synthetic-protocol-executor"),
            environment_digest,
            checks,
            observed_seconds: seconds,
            operations,
            predecessor: case.predecessor.clone(),
        }),
        id: format!("qualification/{}", case.id),
        policy_id: case.requirement_id.clone(),
        policy_digest: case.policy_digest,
        platform: case.platform,
        subjects: case.subjects.clone(),
        result: GateResult::Passed,
        report_digest,
        authority_id: authority.into(),
        nonce,
        started_at: humantime::format_rfc3339_seconds(
            finished - std::time::Duration::from_secs(seconds),
        )
        .to_string(),
        finished_at: finish.into(),
    })
}

fn review(arguments: &[String]) -> Result<()> {
    if arguments.len() != 3 {
        bail!("usage: review PLAN REPORT OUTPUT");
    }
    let payload = QualificationReview {
        schema_version: QUALIFICATION_REVIEW.into(),
        plan_digest: Sha256Digest::of_bytes(fs::read(&arguments[0])?),
        report_digest: Sha256Digest::of_bytes(fs::read(&arguments[1])?),
        authority_id: RELEASE_KEY_ID.into(),
        accepted: true,
    };
    write_new(
        PathBuf::from(&arguments[2]),
        &release_evidence_envelope(&payload)?,
    )
}

/// Writes one signed attestation per fitness kind the production destination demands.
///
/// Each attestation is bound to the fleet's live identities: the production
/// Hub deployment, the plan's signer roster, and the fixed Hub schema,
/// tooling, and alert-configuration identities the fleet test passes to
/// `publish` and `channel advance`. It prints those three flag values as JSON.
fn fitness(arguments: &[String]) -> Result<()> {
    if arguments.len() != 2 {
        bail!("usage: fitness PLAN OUTPUT");
    }
    let plan: ReleasePlan = canonical::from_slice(&fs::read(&arguments[0])?, "release plan")?;
    let output = Path::new(&arguments[1]);
    if output.exists() {
        bail!("fitness output must not already exist");
    }

    let destination = plan.destination(PRODUCTION_DESTINATION)?;
    let surface = plan.surface(destination.surface)?;
    let live = fleet_live_bindings(&plan, surface)?;
    let performed_at = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
    let profile = plan.qualification.profile(&destination.profile)?;
    for name in profile.fitness.keys() {
        let kind = plan.qualification.fitness_kind(name)?;
        let report = FitnessReport {
            schema_version: FITNESS_REPORT.into(),
            performed_at: performed_at.clone(),
            checks: kind
                .checks
                .iter()
                .map(|check| {
                    (
                        check.clone(),
                        CheckObservation {
                            passed: true,
                            detail: "Synthetic fleet exercise; no environment fitness claim".into(),
                        },
                    )
                })
                .collect(),
            operator: "fleet-operator".into(),
        };
        let evidence_digest = Sha256Digest::of_bytes(canonical::to_vec(&report)?);
        let attestation = report.attest(kind, &live, evidence_digest, RELEASE_KEY_ID)?;
        write_new(
            output.join(name).join(format!("{performed_at}.json")),
            &release_evidence_envelope(&attestation)?,
        )?;
    }

    println!(
        "{}",
        json!({
            "hub_schema": HUB_SCHEMA,
            "tooling_digest": digest(TOOLING_LABEL).to_string(),
            "alert_config_digest": digest(ALERT_CONFIG_LABEL).to_string(),
        })
    );
    Ok(())
}

/// Returns the live identities `aos maintain release step` derives for a Hub surface
/// when given the fleet's fitness flags.
fn fleet_live_bindings(plan: &ReleasePlan, surface: &PlannedSurface) -> Result<LiveBindings> {
    Ok(LiveBindings {
        registry: plan.registry.clone(),
        surface: Some(surface.identity.clone()),
        surface_kind: Some(surface.kind),
        hub_schema: Some(HUB_SCHEMA.into()),
        signer_roster: Some(signer_roster_digest(plan)?),
        tooling: Some(digest(TOOLING_LABEL)),
        alert_config: Some(digest(ALERT_CONFIG_LABEL)),
    })
}

/// Signs the bootstrap intent for one environment of a prepared plan.
///
/// The fixture's plan requires one release-evidence signature, so a single
/// envelope satisfies the planned threshold.
fn bootstrap_intent(arguments: &[String]) -> Result<()> {
    if arguments.len() != 3 {
        bail!("usage: bootstrap-intent PLAN staging|production OUTPUT");
    }
    let plan_bytes = fs::read(&arguments[0])?;
    let plan: ReleasePlan = canonical::from_slice(&plan_bytes, "release plan")?;
    let (role, environment) = match arguments[1].as_str() {
        "staging" => (SurfaceRole::Staging, HubEnvironment::Staging),
        "production" => (SurfaceRole::Production, HubEnvironment::Production),
        other => bail!("unknown bootstrap environment {other}"),
    };
    let intent = RegistryBootstrapIntent {
        schema_version: REGISTRY_BOOTSTRAP_INTENT.into(),
        environment,
        deployment_id: plan.surface(role)?.identity.clone(),
        registry: plan.registry.clone(),
        base_commit: plan.registry_base_commit.clone(),
        plan_digest: Sha256Digest::of_bytes(&plan_bytes),
        authority_id: "fleet-release-evidence".into(),
        approved_at: TIME.into(),
    };
    intent.validate()?;
    write_new(
        PathBuf::from(&arguments[2]),
        &release_evidence_envelope(&intent)?,
    )
}

/// Signs a canonical payload with the fixed release-evidence key.
fn release_evidence_envelope(payload: &impl serde::Serialize) -> Result<Vec<u8>> {
    let signed = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, canonical::to_vec(payload)?);
    let signature = SigningKey::from_bytes(&RELEASE_SEED).sign(signed.as_bytes());
    canonical::to_vec(&SignedReceiptEnvelope {
        schema_version: SIGNED_RECEIPT.into(),
        key_id: RELEASE_KEY_ID.into(),
        payload: serde_json::to_value(payload)?,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })
}

async fn maintainer_upstream_proxy(arguments: &[String]) -> Result<()> {
    if arguments.len() != 4 {
        bail!("usage: maintainer-upstream-proxy LISTEN UPSTREAM CERTIFICATE PRIVATE_KEY");
    }
    let acceptor = tls_acceptor(&arguments[2], &arguments[3])?;
    let listener = TcpListener::bind(&arguments[0]).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let upstream = arguments[1].clone();
        tokio::spawn(async move {
            let result = async {
                let mut client = acceptor.accept(socket).await?;
                let request = read_http_head(&mut client).await?;
                if is_fixture_github_tags_request(&request) {
                    let body = br#"[{"name":"v1.1.0"},{"name":"v1.0.0"}]"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    client.write_all(response.as_bytes()).await?;
                    client.write_all(body).await?;
                    client.shutdown().await?;
                    return Result::<()>::Ok(());
                }
                if request_host(&request) == Some("api.github.com") {
                    client
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await?;
                    client.shutdown().await?;
                    return Ok(());
                }

                let mut server = TcpStream::connect(upstream).await?;
                server.write_all(&request).await?;
                tokio::io::copy_bidirectional(&mut client, &mut server).await?;
                Result::<()>::Ok(())
            }
            .await;
            if let Err(error) = result {
                eprintln!("maintainer upstream proxy connection failed: {error:#}");
            }
        });
    }
}

fn tls_acceptor(certificate: &str, private_key: &str) -> Result<TlsAcceptor> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| {
            anyhow::anyhow!("a process-wide Rustls crypto provider is already installed")
        })?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(certificate)?))
        .collect::<std::io::Result<Vec<CertificateDer<'static>>>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(private_key)?))?
        .context("TLS fixture private key is absent")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn read_http_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Vec<u8>> {
    const MAX_HEAD_BYTES: usize = 64 * 1024;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            bail!("TLS client closed before sending an HTTP header");
        }
        if request.len().saturating_add(count) > MAX_HEAD_BYTES {
            bail!("TLS fixture request header exceeds {MAX_HEAD_BYTES} bytes");
        }
        request.extend_from_slice(&buffer[..count]);
    }
    Ok(request)
}

fn is_fixture_github_tags_request(request: &[u8]) -> bool {
    let Some(line) = request.split(|byte| *byte == b'\n').next() else {
        return false;
    };
    matches!(
        request_host(request),
        Some("api.github.com" | "aos.andyl.org")
    ) && line.starts_with(b"GET /repos/andyl-technologies/maintain-fixture/tags?")
        && line.ends_with(b" HTTP/1.1\r")
}

fn request_host(request: &[u8]) -> Option<&str> {
    std::str::from_utf8(request)
        .ok()?
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(source_path, destination_path)?;
        } else {
            bail!("base surface contains a non-regular entry");
        }
    }
    Ok(())
}

fn package_id(platform: Platform) -> String {
    format!("package/fleet-package/{platform}")
}

fn narinfo_id(platform: Platform) -> String {
    format!("narinfo/fleet-package/{platform}")
}

fn fixture_narinfo(platform: Platform, nar_bytes: &[u8]) -> Result<String> {
    let digest = Sha256Digest::of_bytes(nar_bytes).to_string();
    let store_path = fixture_store_path(platform);
    let mut secret = [0_u8; 64];
    secret[..RELEASE_SEED.len()].copy_from_slice(&RELEASE_SEED);
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    let signer = NarInfoSigner::from_key_content(&format!("fleet-cache-v1:{encoded}"))?;

    render_static_narinfo(
        &StaticNarInfoInput {
            store_path: &store_path,
            nar_hash: &digest,
            nar_size: u64::try_from(nar_bytes.len())?,
            references: &[],
            deriver: None,
            signatures: &[],
            file_hash: &digest,
            file_size: u64::try_from(nar_bytes.len())?,
            compression: NarCompression::None,
        },
        "/nix/store",
        Some(&signer),
    )
}

fn fixture_nar_url(platform: Platform, nar_bytes: &[u8]) -> Result<String> {
    let digest = Sha256Digest::of_bytes(nar_bytes).to_string();
    nar_url(&fixture_store_path(platform), &digest, NarCompression::None)
}

fn fixture_store_path(platform: Platform) -> String {
    format!("/nix/store/00000000000000000000000000000000-release-fleet-{platform}")
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(value)
}

fn write_public_key(path: PathBuf, key: &SigningKey) -> Result<()> {
    write_new(
        path,
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
        )
        .as_bytes(),
    )
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut length = [0; 8];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u64::from_be_bytes(length))?;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer.write_all(&u64::try_from(bytes.len())?.to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_release::artifact::BundlePath;
    use aos_release::fitness::{FitnessAttestation, require_destination_fitness};
    use aos_release::qualification::QualificationPhase;
    use aos_release::signing::TrustedEd25519Key;
    use aos_release::state::parse_journal;
    use aos_release::verify::CapturedFile;

    use super::*;

    /// Prepared fixture outputs inside one temporary directory.
    struct Prepared {
        _temporary: tempfile::TempDir,
        output: PathBuf,
        predecessor: PathBuf,
        trust: PathBuf,
    }

    fn prepared() -> Result<Prepared> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().join("base");
        let output = temporary.path().join("surface");
        let predecessor = temporary.path().join("predecessor");
        let trust = temporary.path().join("trust");
        fs::create_dir_all(base.join("info"))?;
        let commit = "a".repeat(64);
        fs::write(base.join("HEAD"), b"ref: refs/heads/master\n")?;
        fs::write(
            base.join("info/refs"),
            format!("{commit}\trefs/heads/master\n"),
        )?;
        let request = temporary.path().join("plan-request.json");
        fs::write(
            &request,
            canonical::to_vec(&first_release_request_fixture(&commit)?)?,
        )?;
        let mut arguments = vec![
            base.display().to_string(),
            output.display().to_string(),
            predecessor.display().to_string(),
            trust.display().to_string(),
            request.display().to_string(),
        ];
        for platform in Platform::ALL {
            let path = temporary.path().join(format!("{platform}.nar"));
            fs::write(&path, format!("NAR fixture for {platform}"))?;
            arguments.push(path.display().to_string());
        }

        prepare(&arguments)?;
        Ok(Prepared {
            _temporary: temporary,
            output,
            predecessor,
            trust,
        })
    }

    /// Builds the first-release request `new --request-only` would derive for
    /// the fleet's candidate on its two Hubs.
    fn first_release_request_fixture(base_commit: &str) -> Result<ReleasePlanRequest> {
        Ok(ReleasePlanRequest {
            schema_version: aos_release::plan::PLAN_REQUEST.into(),
            qualification_predecessor: None,
            release_id: RELEASE_ID.into(),
            version: RELEASE_VERSION.into(),
            release_class: ReleaseClass::Candidate,
            registry: aos_release::registry::MAIN_REGISTRY.into(),
            registry_base_commit: base_commit.into(),
            registry_base_generation: 0,
            first_release: true,
            source: aos_release::plan::PlanningSource {
                protected_branch: "master".into(),
                source_tag: format!("release/{RELEASE_VERSION}"),
                contributor_authorization_digest: digest("fleet-contributor-authorization"),
            },
            images: Vec::new(),
            signers: Vec::new(),
            surfaces: fleet_surfaces(),
            destinations: [SurfaceRole::Staging, SurfaceRole::Production]
                .into_iter()
                .map(|surface| RequestedDestination {
                    surface,
                    channel: CHANNEL.into(),
                    effective: None,
                })
                .collect(),
            change_scope: None,
            profile_overrides: Vec::new(),
            retention: RetentionPolicy {
                policy_id: "fleet-retention-v1".into(),
                policy_digest: digest("fleet-retention-policy"),
                require_corresponding_source: true,
            },
            public_evidence_policy_digest: fleet_contract()?.digest()?,
            restricted_operator_policy_digest: digest("fleet-restricted-operator-policy"),
        })
    }

    fn prepared_plan(prepared: &Prepared) -> Result<(ReleasePlan, ReleaseManifestV1)> {
        let plan = canonical::from_slice(
            &fs::read(prepared.output.join("release-plan.json"))?,
            "fixture plan",
        )?;
        let envelope: ManifestEnvelopeV1 = canonical::from_slice(
            &fs::read(prepared.output.join("release-manifest.json"))?,
            "fixture manifest",
        )?;
        Ok((plan, envelope.payload))
    }

    #[test]
    fn maintainer_fixture_intercepts_only_the_exact_github_tags_route() {
        let request = b"GET /repos/andyl-technologies/maintain-fixture/tags?per_page=100&page=1 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        assert!(is_fixture_github_tags_request(request));
        assert!(!is_fixture_github_tags_request(
            b"GET /repos/other/project/tags?page=1 HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        ));
        assert!(is_fixture_github_tags_request(
            b"GET /repos/andyl-technologies/maintain-fixture/tags?page=1 HTTP/1.1\r\nHost: aos.andyl.org\r\n\r\n"
        ));
    }

    #[test]
    fn first_release_request_retains_native_policy_and_rejects_other_intent() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("request.json");
        let mut request = first_release_request_fixture(&"a".repeat(64))?;
        fs::write(&path, canonical::to_vec(&request)?)?;

        let retained = first_release_request(&path)?;
        assert_eq!(retained, request);
        assert!(fleet_contract()?.requirements.iter().any(|requirement| {
            requirement.native_operation_spec.is_some()
        }));

        request.public_evidence_policy_digest = digest("different-policy");
        fs::write(&path, canonical::to_vec(&request)?)?;
        assert!(first_release_request(&path).is_err());

        request.public_evidence_policy_digest = fleet_contract()?.digest()?;
        request.first_release = false;
        fs::write(&path, canonical::to_vec(&request)?)?;
        assert!(first_release_request(&path).is_err());
        Ok(())
    }

    #[test]
    fn prepared_four_platform_surface_verifies_offline() -> Result<()> {
        let prepared = prepared()?;
        let Prepared {
            output,
            predecessor,
            trust,
            ..
        } = &prepared;

        let plan = fs::read(output.join("release-plan.json"))?;
        let envelope = fs::read(output.join("release-manifest.json"))?;
        let files = captured_files(output, output)?;
        let key =
            TrustedEd25519Key::from_encoded(RELEASE_KEY_ID, &fs::read(trust.join("release.pub"))?)?;
        let summary = aos_release::verify::verify_release(&plan, &envelope, &files, &[key])?;
        assert_eq!(summary.release_id, RELEASE_ID);
        assert_eq!(summary.signatures_verified, 1);

        let predecessor_plan = fs::read(predecessor.join("release-plan.json"))?;
        let predecessor_envelope = fs::read(predecessor.join("release-manifest.json"))?;
        let predecessor_files = captured_files(predecessor, predecessor)?;
        let key =
            TrustedEd25519Key::from_encoded(RELEASE_KEY_ID, &fs::read(trust.join("release.pub"))?)?;
        let predecessor_summary = aos_release::verify::verify_release(
            &predecessor_plan,
            &predecessor_envelope,
            &predecessor_files,
            &[key],
        )?;
        assert!(
            predecessor_summary
                .release_id
                .starts_with("qualification-snapshot-")
        );

        let journal = parse_journal(&fs::read(trust.join("release-journal.jsonl"))?)?;
        assert_eq!(
            journal.last().map(|entry| entry.new_state),
            Some(ReleaseState::Finalized)
        );
        let plan: ReleasePlan = canonical::from_slice(&plan, "fixture plan")?;
        let summary = aos_release::verify::verify_journal_for_plan(&plan, &journal)?;
        assert!(summary.destinations.is_empty());
        summary.can_publish(&plan, "staging/candidate")?;
        assert!(summary.can_publish(&plan, PRODUCTION_DESTINATION).is_err());
        Ok(())
    }

    #[test]
    fn plan_names_both_candidate_destinations_on_two_hubs() -> Result<()> {
        let prepared = prepared()?;
        let (plan, _) = prepared_plan(&prepared)?;

        let destinations: Vec<(&str, &str)> = plan
            .destinations
            .iter()
            .map(|destination| (destination.name.as_str(), destination.profile.as_str()))
            .collect();
        assert_eq!(
            destinations,
            [
                ("staging/candidate", "build"),
                (PRODUCTION_DESTINATION, "functional")
            ]
        );

        // The functional profile rolls out in one ring and closes on its own.
        let production = plan.destination(PRODUCTION_DESTINATION)?;
        assert_eq!(production.ring_range(1)?, (0, 255));
        assert!(production.ring_range(2).is_err());
        assert_eq!(
            plan.surface(SurfaceRole::Production)?.identity,
            PRODUCTION_DEPLOYMENT
        );
        Ok(())
    }

    /// Pins the case populations the fleet test's report assertions rely on.
    #[test]
    fn production_candidate_phases_select_the_fleet_cases() -> Result<()> {
        let prepared = prepared()?;
        let (plan, manifest) = prepared_plan(&prepared)?;

        let cases = |phase| {
            aos_release::qualification_evidence::cases(
                &plan,
                &manifest,
                Some(PRODUCTION_DESTINATION),
                phase,
            )
        };
        let requirements = |cases: &[aos_release::qualification_evidence::QualificationCase]| {
            let mut ids: Vec<String> = cases
                .iter()
                .map(|case| case.requirement_id.clone())
                .collect();
            ids.sort();
            ids
        };

        // Staging retains five native obligations, delivery, four package
        // cells, and four Linux disk/container claims. The native matrix and
        // disk update claims bind the frozen predecessor bundle.
        let staging = cases(QualificationPhase::Staging)?;
        assert_eq!(staging.len(), 14);
        let native_requirements: Vec<_> = requirements(&staging)
            .into_iter()
            .filter(|id| id.starts_with("ability-"))
            .collect();
        assert_eq!(
            native_requirements,
            [
                "ability-crucible-baseline",
                "ability-native-activation",
                "ability-native-adapter-matrix",
                "ability-native-kubernetes",
                "ability-native-recovery",
            ]
        );
        assert_eq!(
            staging
                .iter()
                .filter(|case| case.requirement_id.starts_with("claim-"))
                .count(),
            4
        );
        assert_eq!(
            staging
                .iter()
                .filter(|case| case.predecessor.is_some())
                .count(),
            3
        );
        assert_eq!(
            staging
                .iter()
                .filter(|case| case.requirement_id == "package-function")
                .count(),
            4
        );

        // Rollout: one platform-independent health case, without a predecessor.
        let rollout = cases(QualificationPhase::Rollout)?;
        assert_eq!(requirements(&rollout), ["rollout-health"]);
        assert!(rollout.iter().all(|case| case.predecessor.is_none()));

        // Functional claims stop at A2: there is no complete phase.
        assert!(cases(QualificationPhase::Complete)?.is_empty());
        Ok(())
    }

    #[test]
    fn fitness_attestations_satisfy_the_production_destination() -> Result<()> {
        let prepared = prepared()?;
        let (plan, _) = prepared_plan(&prepared)?;
        let directory = prepared.trust.join("fitness");

        fitness(&[
            prepared
                .output
                .join("release-plan.json")
                .display()
                .to_string(),
            directory.display().to_string(),
        ])?;

        // Load the store the way `aos maintain release step publish` does.
        let key = TrustedEd25519Key::from_encoded(
            RELEASE_KEY_ID,
            &fs::read(prepared.trust.join("release.pub"))?,
        )?;
        let mut attestations = Vec::new();
        let mut kinds = Vec::new();
        for kind in fs::read_dir(&directory)? {
            let kind = kind?;
            kinds.push(kind.file_name().to_string_lossy().into_owned());
            for entry in fs::read_dir(kind.path())? {
                let bytes = fs::read(entry?.path())?;
                attestations.push(FitnessAttestation::verify_signed(
                    &bytes,
                    &plan,
                    std::slice::from_ref(&key),
                )?);
            }
        }
        kinds.sort();
        assert_eq!(
            kinds,
            [
                "alert-delivery",
                "authority-recovery",
                "hub-restore",
                "storage-restore"
            ]
        );

        // The live identities `fitness_gate` derives from the fleet's flags.
        let surface = plan.surface(SurfaceRole::Production)?;
        let live = LiveBindings {
            registry: plan.registry.clone(),
            surface: Some(surface.identity.clone()),
            surface_kind: Some(surface.kind),
            hub_schema: Some(HUB_SCHEMA.into()),
            signer_roster: Some(signer_roster_digest(&plan)?),
            tooling: Some(Sha256Digest::parse(&digest(TOOLING_LABEL).to_string())?),
            alert_config: Some(Sha256Digest::parse(
                &digest(ALERT_CONFIG_LABEL).to_string(),
            )?),
        };
        let now = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
        require_destination_fitness(&plan, PRODUCTION_DESTINATION, &attestations, &live, &now)?;
        require_destination_fitness(&plan, "staging/candidate", &[], &live, &now)?;

        let other_surface = LiveBindings {
            surface: Some(STAGING_DEPLOYMENT.into()),
            ..live
        };
        assert!(
            require_destination_fitness(
                &plan,
                PRODUCTION_DESTINATION,
                &attestations,
                &other_surface,
                &now
            )
            .is_err()
        );
        Ok(())
    }

    fn captured_files(root: &Path, directory: &Path) -> Result<Vec<CapturedFile>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                files.extend(captured_files(root, &path)?);
            } else if path.file_name().and_then(|name| name.to_str())
                != Some("release-manifest.json")
            {
                let bytes = fs::read(&path)?;
                files.push(CapturedFile {
                    path: BundlePath::parse(
                        path.strip_prefix(root)?
                            .to_string_lossy()
                            .replace('\\', "/"),
                    )?,
                    size_bytes: u64::try_from(bytes.len())?,
                    sha256: Sha256Digest::of_bytes(bytes),
                });
            }
        }
        Ok(files)
    }
}
