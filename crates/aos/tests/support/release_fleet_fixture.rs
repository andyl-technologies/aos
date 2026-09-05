//! Deterministic, test-only authorities and artifacts for the release fleet test.
//!
//! This binary is installed only in `pkgs.aos.testSupport`. It deliberately
//! uses fixed private keys and must never be used outside an isolated test.

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::{ArtifactKind, ArtifactRecord, BundlePath, Compression};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::{
    EvidenceRecord, GateRequirement, GateResult, QUALIFICATION_EXECUTOR_RESPONSE_V1,
    QualificationExecutorRequestV1, QualificationExecutorResponseV1,
};
use aos_release::inventory::PackagePublicationMetadata;
use aos_release::manifest::{
    FinalArtifactSet, MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1, ManifestSignature,
    PackageResult, ReleaseManifestV1,
};
use aos_release::plan::{
    ChannelIntent, PackagePlan, PlannedArtifact, PlannedArtifactSet, PlatformCell, ReleaseClass,
    ReleasePlanV1, RetentionPolicy, SourceIdentity,
};
use aos_release::platform::{MatrixCell, Platform};
use aos_release::receipt::{
    COMPLETION_RECEIPT_V1, CompletionReceiptV1, RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1,
    SignedReceiptEnvelopeV1,
};
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignatureResponseV1, SignerRequirement, SignerRole,
    SigningContext, SigningOperation, SigningRequestV1,
};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
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
const STAGING_DEPLOYMENT: &str = "fleet-staging-v1";
const PRODUCTION_DEPLOYMENT: &str = "fleet-production-v1";
const TIME: &str = "2026-09-03T12:00:00Z";
const SIGNER_REQUEST_DOMAIN: &[u8] = b"aos.release.signer-exchange/v1\0";
const SIGNER_RESPONSE_DOMAIN: &[u8] = b"aos.release.signer-exchange-response/v1\0";

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("prepare") => prepare(&arguments[1..]),
        Some("sign-exchange-v1") => signer_exchange(),
        Some("completion") => completion(&arguments[1..]),
        Some("review") => review(&arguments[1..]),
        Some("maintainer-upstream-proxy") => maintainer_upstream_proxy(&arguments[1..]).await,
        None => qualification_executor().await,
        Some(command) => bail!("unknown release fleet fixture command: {command}"),
    }
}

fn prepare(arguments: &[String]) -> Result<()> {
    if arguments.len() != 8 {
        bail!(
            "usage: aos-release-fleet-fixture prepare BASE_SURFACE OUTPUT TRUST_DIR BASE_COMMIT X86_LINUX AARCH64_LINUX X86_DARWIN AARCH64_DARWIN"
        );
    }
    let base = Path::new(&arguments[0]);
    let output = Path::new(&arguments[1]);
    let trust = Path::new(&arguments[2]);
    let base_commit = &arguments[3];
    if output.exists() || trust.exists() {
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
        .zip(arguments[4..].iter().map(PathBuf::from))
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
    let plan = release_plan(base_commit, package_cells.clone())?;
    plan.validate()?;
    let plan_bytes = canonical::to_vec(&plan)?;
    write_new(output.join("release-plan.json"), &plan_bytes)?;

    let mut artifacts = Vec::new();
    inventory_tree(output, output, &mut artifacts)?;
    for (platform, source) in &package_inputs {
        let relative = format!("releases/candidate/{RELEASE_VERSION}/packages/{platform}.nar");
        let destination = output.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, &destination)
            .with_context(|| format!("copying mounted package NAR {}", source.display()))?;
        artifacts.push(record(
            package_id(*platform),
            ArtifactKind::PackageNar,
            Some(*platform),
            &relative,
            &fs::read(&destination)?,
        )?);
    }
    for (id, kind, platform) in Platform::LINUX
        .into_iter()
        .flat_map(|platform| {
            [
                (
                    format!("image/server/{platform}"),
                    ArtifactKind::RawImage,
                    Some(platform),
                ),
                (
                    format!("oci/{platform}"),
                    ArtifactKind::OciManifest,
                    Some(platform),
                ),
            ]
        })
        .chain([(String::from("oci/index"), ArtifactKind::OciIndex, None)])
    {
        let path = format!("releases/candidate/{RELEASE_VERSION}/fixtures/{id}");
        let bytes = format!("synthetic release protocol fixture: {id}\n");
        write_new(output.join(&path), bytes.as_bytes())?;
        let mut artifact = record(id, kind, platform, &path, bytes.as_bytes())?;
        if kind == ArtifactKind::RawImage {
            artifact.system_variant = Some("server".into());
        }
        artifacts.push(artifact);
    }
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
                            artifact_ids: vec![format!("image/server/{platform}")],
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
    manifest.evidence = aos_release::qualification_evidence::cases(
        &plan,
        &manifest,
        aos_release::qualification::QualificationPhase::Build,
    )?
    .iter()
    .map(|case| {
        fixture_evidence(
            case,
            gate_report_digest,
            "fleet-preflight-authority",
            None,
            &humantime::format_rfc3339(std::time::SystemTime::now()).to_string(),
        )
    })
    .collect::<Result<Vec<_>>>()?;
    manifest.validate(&plan)?;
    let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &manifest)?;
    let signing_key = SigningKey::from_bytes(&RELEASE_SEED);
    let request = signing_request(
        SignerRole::ReleaseEvidence,
        RELEASE_KEY_ID,
        "release-manifest",
        Sha256Digest::of_bytes(&plan_bytes),
        Some(manifest_digest),
        manifest_digest,
        SignatureAlgorithm::Ed25519,
    );
    let response = signature_response(&request, &signing_key, request.digest()?.as_bytes())?;
    let envelope = ManifestEnvelopeV1 {
        schema_version: MANIFEST_ENVELOPE_V1.into(),
        payload: manifest,
        payload_digest: manifest_digest,
        signatures: vec![ManifestSignature { request, response }],
    };
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

fn release_plan(
    base_commit: &str,
    platforms: Vec<PlatformCell<PlannedArtifactSet>>,
) -> Result<ReleasePlanV1> {
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
    let mut plan = ReleasePlanV1 {
        schema_version: aos_release::RELEASE_PLAN_V1.into(),
        qualification: None,
        qualification_predecessor: None,
        release_id: RELEASE_ID.into(),
        version: RELEASE_VERSION.into(),
        release_class: ReleaseClass::Candidate,
        registry: aos_release::registry::MAIN_REGISTRY.into(),
        registry_base_commit: base_commit.into(),
        registry_base_generation: 1,
        source: SourceIdentity {
            commit: base_commit.into(),
            tree_digest: digest("fleet-source-tree"),
            protected_branch: "master".into(),
            source_tag: "release/2026.9.0-rc.1".into(),
            contributor_authorization_digest: digest("fleet-contributor-authorization"),
        },
        packages: vec![PackagePlan {
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
        images: Vec::new(),
        gates: vec![GateRequirement {
            policy_id: "fleet-release-gate-v1".into(),
            policy_digest: digest("fleet-release-gate-policy"),
            required_for_stable: true,
        }],
        staging_deployment_id: STAGING_DEPLOYMENT.into(),
        production_deployment_id: PRODUCTION_DEPLOYMENT.into(),
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
        intended_channels: vec![ChannelIntent {
            channel: "candidate".into(),
            first_partition: 0,
            last_partition: 255,
        }],
        retention: RetentionPolicy {
            policy_id: "fleet-retention-v1".into(),
            policy_digest: digest("fleet-retention-policy"),
            require_corresponding_source: true,
        },
        public_evidence_policy_digest: digest("fleet-public-evidence-policy"),
        restricted_operator_policy_digest: digest("fleet-restricted-operator-policy"),
    };
    let mut contract: aos_release::qualification::QualificationContractV1 = canonical::from_slice(
        include_bytes!("../../../aos-release/tests/fixtures/qualification-contract.json"),
        "fixture contract",
    )?;
    contract.package_rules = vec![aos_release::qualification::PackageRule {
        name: "fleet-package".into(),
        role: aos_release::qualification::PackageRole::GeneralCatalog,
        inherit_dependency_obligations: true,
    }];
    plan.schema_version = aos_release::RELEASE_PLAN_V2.into();
    plan.gates = contract.gates(plan.release_class)?;
    plan.public_evidence_policy_digest =
        Sha256Digest::of_canonical(aos_release::qualification::CONTRACT_V1, &contract)?;
    plan.qualification = Some(contract);
    plan.qualification_predecessor = Some(
        aos_release::qualification_evidence::QualificationPredecessor {
            registry: plan.registry.clone(),
            release_id: "fleet-predecessor".into(),
            manifest_digest: digest("fleet-predecessor"),
        },
    );
    plan.images = vec![aos_release::plan::ImagePlan {
        system_variant: "server".into(),
        platforms: Platform::LINUX
            .into_iter()
            .map(|platform| PlatformCell {
                platform,
                decision: MatrixCell::Artifact {
                    artifact: PlannedArtifactSet {
                        artifacts: vec![PlannedArtifact {
                            id: format!("image/server/{platform}"),

                            derivation: None,
                            output: None,
                            store_path: None,
                            source_store_paths: Vec::new(),
                        }],
                    },
                },
            })
            .collect(),
    }];
    Ok(plan)
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
    plan_digest: Sha256Digest,
    manifest_digest: Option<Sha256Digest>,
    payload_digest: Sha256Digest,
    algorithm: SignatureAlgorithm,
) -> SigningRequestV1 {
    SigningRequestV1 {
        schema_version: SIGNING_REQUEST_DOMAIN.into(),
        request_id: format!("fleet/{artifact_kind}"),
        nonce: "2".repeat(64),
        registry: aos_release::registry::MAIN_REGISTRY.into(),
        release_id: RELEASE_ID.into(),
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
    request: &SigningRequestV1,
    key: &SigningKey,
    signed_bytes: &[u8],
) -> Result<SignatureResponseV1> {
    Ok(SignatureResponseV1 {
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
    let mut entries: Vec<JournalEntryV1> = Vec::new();
    for state in [
        ReleaseState::Planned,
        ReleaseState::Built,
        ReleaseState::Finalized,
    ] {
        let prior = entries.last();
        entries.push(JournalEntryV1 {
            schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.into(),
            sequence: u64::try_from(entries.len() + 1)?,
            previous_entry_digest: prior
                .map(|entry| Sha256Digest::of_canonical("aos.release.journal-entry/v1", entry))
                .transpose()?,
            plan_digest: plan,
            manifest_digest: (state >= ReleaseState::Finalized).then_some(manifest),
            prior_state: prior.map(|entry| entry.new_state),
            new_state: state,
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
    let request: SigningRequestV1 = canonical::from_slice(&request_bytes, "signing request")?;
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

async fn qualification_executor() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: QualificationExecutorRequestV1 =
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
    let case = request
        .qualification_case
        .as_ref()
        .context("fleet executor requires v2 case")?;
    let now = humantime::format_rfc3339(std::time::SystemTime::now()).to_string();
    let response = QualificationExecutorResponseV1 {
        schema_version: QUALIFICATION_EXECUTOR_RESPONSE_V1.into(),
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
    Ok(EvidenceRecord {
        qualification: Some(QualificationObservation {
            case_digest: case.digest()?,
            executor_digest: digest("synthetic-protocol-executor"),
            environment_digest: digest("synthetic-protocol-environment"),
            checks: case
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
                .collect(),
            observed_seconds: seconds,
            operations: std::collections::BTreeMap::from([("synthetic-requests".into(), 1)]),
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
        started_at: humantime::format_rfc3339(finished - std::time::Duration::from_secs(seconds))
            .to_string(),
        finished_at: finish.into(),
    })
}

fn review(arguments: &[String]) -> Result<()> {
    if arguments.len() != 3 {
        bail!("usage: review PLAN REPORT OUTPUT");
    }
    let payload = aos_release::qualification_admission::QualificationReviewV1 {
        schema_version: "aos.release.qualification-review/v1".into(),
        plan_digest: Sha256Digest::of_bytes(fs::read(&arguments[0])?),
        report_digest: Sha256Digest::of_bytes(fs::read(&arguments[1])?),
        authority_id: RELEASE_KEY_ID.into(),
        accepted: true,
    };
    let digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, canonical::to_vec(&payload)?);
    let signature = SigningKey::from_bytes(&RELEASE_SEED).sign(digest.as_bytes());
    write_new(
        PathBuf::from(&arguments[2]),
        &canonical::to_vec(&SignedReceiptEnvelopeV1 {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: RELEASE_KEY_ID.into(),
            payload: serde_json::to_value(payload)?,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        })?,
    )
}

fn completion(arguments: &[String]) -> Result<()> {
    if arguments.len() != 6 {
        bail!("usage: completion PLAN MANIFEST PRODUCTION_RECEIPT CHANNEL_RECEIPT JOURNAL OUTPUT");
    }
    let plan_bytes = fs::read(&arguments[0])?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    let envelope: ManifestEnvelopeV1 =
        canonical::from_slice(&fs::read(&arguments[1])?, "release manifest")?;
    let production_digest = Sha256Digest::of_bytes(fs::read(&arguments[2])?);
    let channel_digest = Sha256Digest::of_bytes(fs::read(&arguments[3])?);
    let journal = parse_journal(&fs::read(&arguments[4])?)?;
    let prior = journal.last().context("rolling journal is empty")?;
    let receipt = CompletionReceiptV1 {
        schema_version: COMPLETION_RECEIPT_V1.into(),
        release_id: plan.release_id,
        plan_digest: Sha256Digest::of_bytes(plan_bytes),
        manifest_digest: envelope.payload_digest,
        production_receipt_digest: production_digest,
        channel_receipt_digests: vec![channel_digest],
        prior_journal_entry_digest: Sha256Digest::of_canonical(
            "aos.release.journal-entry/v1",
            prior,
        )?,
        retention_policy_id: plan.retention.policy_id,
        retention_policy_digest: plan.retention.policy_digest,
        corresponding_source_retained: true,
        operational_handoff_complete: true,
        authority_id: RELEASE_KEY_ID.into(),
        completed_at: TIME.into(),
    };
    receipt.validate()?;
    let payload = canonical::to_vec(&receipt)?;
    let key = SigningKey::from_bytes(&RELEASE_SEED);
    let signature_digest = Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, &payload);
    let signed = SignedReceiptEnvelopeV1 {
        schema_version: SIGNED_RECEIPT_V1.into(),
        key_id: RELEASE_KEY_ID.into(),
        payload: serde_json::to_value(receipt)?,
        signature_base64: base64::engine::general_purpose::STANDARD
            .encode(key.sign(signature_digest.as_bytes()).to_bytes()),
    };
    write_new(&arguments[5], &canonical::to_vec(&signed)?)
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
    use aos_release::signing::TrustedEd25519Key;
    use aos_release::verify::CapturedFile;

    use super::*;

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
    fn prepared_four_platform_surface_verifies_offline() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().join("base");
        let output = temporary.path().join("surface");
        let trust = temporary.path().join("trust");
        fs::create_dir_all(base.join("info"))?;
        let commit = "a".repeat(64);
        fs::write(base.join("HEAD"), b"ref: refs/heads/master\n")?;
        fs::write(
            base.join("info/refs"),
            format!("{commit}\trefs/heads/master\n"),
        )?;
        let mut arguments = vec![
            base.display().to_string(),
            output.display().to_string(),
            trust.display().to_string(),
            commit,
        ];
        for platform in Platform::ALL {
            let path = temporary.path().join(format!("{platform}.nar"));
            fs::write(&path, format!("NAR fixture for {platform}"))?;
            arguments.push(path.display().to_string());
        }

        prepare(&arguments)?;
        let plan = fs::read(output.join("release-plan.json"))?;
        let envelope = fs::read(output.join("release-manifest.json"))?;
        let files = captured_files(&output, &output)?;
        let key =
            TrustedEd25519Key::from_encoded(RELEASE_KEY_ID, &fs::read(trust.join("release.pub"))?)?;
        let summary = aos_release::verify::verify_release(&plan, &envelope, &files, &[key])?;
        assert_eq!(summary.release_id, RELEASE_ID);
        assert_eq!(summary.signatures_verified, 1);
        let journal = fs::read(trust.join("release-journal.jsonl"))?;
        assert_eq!(
            parse_journal(&journal)?.last().map(|entry| entry.new_state),
            Some(ReleaseState::Finalized)
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
