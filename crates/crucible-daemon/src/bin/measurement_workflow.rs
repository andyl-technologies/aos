//! Builds immutable compact inputs for the private resident throughput fixture.
//!
//! This is a build-time authoring tool. Its output describes the existing fixed
//! corpus and carries no runtime admission, process identity, or resource loan.
//! The used actor must authenticate the installed descriptor before importing
//! its compact inputs through the ordinary campaign service.

use std::error::Error;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crucible::{
    Configuration, Icount, NodeId, Plan, Properties, ReadyPoint, ScenarioDefForm, Seed,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::{
    CampaignHash, ConfigurationArtifact, ConfigurationId, ScenarioArtifact, ScenarioDefId,
};
use serde::{Deserialize, Serialize};

const WIDTHS: [usize; 3] = [1, 2, 4];
const TARGET_DIVISORS: [u64; 3] = [1, 2, 0];
const REPEATS: usize = 3;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    schema: &'static str,
    family: &'static str,
    native_count: usize,
    hot_fork: Option<()>,
    world_memory_mib: u64,
    execution_quanta: u64,
    service_profile: ServiceProfile,
    qemu: Artifact,
    plugin: Artifact,
    rows: Vec<Row>,
}

/// Required operator inputs, distinct from target-derived control floors.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServicePolicy {
    actor_main_stack_bytes: u64,
    sqlite_bootstrap_bytes: u64,
    sqlite_heap_bytes: u64,
    sqlite_connections: usize,
    registry: ResourceVector,
    registry_project_id: u32,
    catalog_project_id: u32,
    registry_maximum_inodes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedServicePolicy {
    #[serde(flatten)]
    authored: ServicePolicy,
    sqlite_bootstrap_proof: InstalledObject,
    campaign_policy: InstalledObject,
    campaign_policy_projection: InstalledObject,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CampaignPolicyProjection {
    schema: &'static str,
    original_toml_blake3: String,
    document: toml::Value,
}

#[derive(Serialize)]
struct InstalledObject {
    path: &'static str,
    blake3: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceVector {
    resident_peak_bytes: u64,
    backing_peak_bytes: u64,
    metadata_bytes: u64,
    staging_bytes: u64,
    paging_io_slots: u64,
    cpu_slots: u64,
    task_slots: u64,
    file_descriptors: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceProfile {
    operator: PublishedServicePolicy,
    catalog: ResourceVector,
    catalog_maximum_inodes: u64,
    native: ResourceVector,
    aggregate: Aggregate,
    preparation_seconds: u64,
    invocation_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Aggregate {
    native_slots: u64,
    cpu_slots: u64,
    resident_bytes: u64,
    backing_bytes: u64,
    metadata_bytes: u64,
    staging_bytes: u64,
    task_slots: u64,
    file_descriptors: u64,
    paging_io_slots: u64,
    dirty_units: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    path: PathBuf,
    bytes: u64,
    blake3: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Row {
    target_divisor: u64,
    repeat: usize,
    attempts: Vec<Attempt>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Attempt {
    seed: u64,
    campaign: String,
    scenario_file: String,
    schedule_file: String,
    scenario_id: ScenarioDefId,
    configuration_artifact_id: crucible_campaign::ConfigurationArtifactId,
    scenario_blake3: String,
    schedule_blake3: String,
}

fn main() {
    if let Err(error) = generate() {
        eprintln!("immutable measurement workflow: {error}");
        std::process::exit(1);
    }
}

fn generate() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = PathBuf::from(arguments.next().ok_or("missing output directory")?);
    let width = arguments
        .next()
        .and_then(|argument| {
            argument
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
        })
        .filter(|width| WIDTHS.contains(width))
        .ok_or("native width must be one, two, or four")?;
    let qemu = installed_artifact(PathBuf::from(arguments.next().ok_or("missing QEMU")?))?;
    let plugin = installed_artifact(PathBuf::from(arguments.next().ok_or("missing plugin")?))?;
    let policy_path = PathBuf::from(arguments.next().ok_or("missing authored service policy")?);
    let proof_path = PathBuf::from(arguments.next().ok_or("missing installed SQLite proof")?);
    let campaign_path = PathBuf::from(arguments.next().ok_or("missing authored campaign policy")?);
    let (service_profile, campaign_projection) =
        service_profile(policy_path, proof_path, campaign_path)?;
    if arguments.next().is_some() {
        return Err("unexpected authoring argument".into());
    }
    // Refuse overwrite so a partial builder result cannot silently replace a
    // previously authored compatibility basis.
    fs::create_dir(&output)?;
    let mut policy_file = File::options()
        .write(true)
        .create_new(true)
        .open(output.join("campaign-policy.json"))?;
    std::io::Write::write_all(&mut policy_file, &campaign_projection)?;
    let rows = generate_rows(&output, width)?;
    let descriptor = Descriptor {
        schema: "crucible.measurement-resident-workflow.v2",
        family: "residentThroughput",
        native_count: width,
        hot_fork: None,
        world_memory_mib: 512,
        execution_quanta: 32,
        service_profile,
        qemu,
        plugin,
        rows,
    };
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(output.join("workflow.json"))?;
    serde_json::to_writer(file, &descriptor)?;
    Ok(())
}

fn service_profile(
    path: PathBuf,
    proof_path: PathBuf,
    campaign_path: PathBuf,
) -> Result<(ServiceProfile, Vec<u8>), Box<dyn Error>> {
    // This parser runs in the immutable builder. It authors required ceilings;
    // the runtime must still prepay its actual controls and enforce the vector.
    let mut bytes = Vec::new();
    File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err("service policy exceeds its finite input extent".into());
    }
    let operator: ServicePolicy = serde_json::from_slice(&bytes)?;
    if !valid_main_stack(operator.actor_main_stack_bytes) {
        return Err(
            "main stack must be positive, page aligned and within the actor resident envelope"
                .into(),
        );
    }

    // Identities come from the supplied immutable bytes, never caller hashes.
    // This authoring validation does not qualify native bootstrap or issue credit.
    let proof = read_installed_input(&proof_path, 1 << 20)?;
    let target: serde_json::Value = serde_json::from_slice(&proof)?;
    if target.get("schema").and_then(serde_json::Value::as_str)
        != Some("crucible.sqlite-bootstrap-target.v1")
    {
        return Err("unsupported installed SQLite proof schema".into());
    }
    let campaign =
        read_installed_input(&campaign_path, crucible_daemon::MAX_CAMPAIGN_POLICY_BYTES)?;
    let campaign_projection = compile_campaign_policy(&campaign)?;
    let campaign_policy_projection = installed_object(
        "/etc/crucible/measurement-service-policy.json",
        &campaign_projection,
    );
    let sqlite_bootstrap_proof =
        installed_object("/etc/crucible/sqlite-bootstrap-target.json", &proof);
    let campaign_policy =
        installed_object("/etc/crucible/measurement-service-policy.toml", &campaign);
    let registry = &operator.registry;
    if operator.sqlite_bootstrap_bytes == 0
        || operator.sqlite_heap_bytes == 0
        || operator.sqlite_heap_bytes > i64::MAX as u64
        || operator.sqlite_connections == 0
        || !valid_project_ids(operator.registry_project_id, operator.catalog_project_id)
        || operator.registry_maximum_inodes == 0
        || operator.registry_maximum_inodes > 1 << 20
        || [
            registry.resident_peak_bytes,
            registry.backing_peak_bytes,
            registry.metadata_bytes,
            registry.staging_bytes,
            registry.paging_io_slots,
            registry.cpu_slots,
            registry.task_slots,
            registry.file_descriptors,
        ]
        .contains(&0)
        || registry.metadata_bytes > registry.resident_peak_bytes
        || registry.staging_bytes > registry.resident_peak_bytes
        || registry.resident_peak_bytes > 16 << 30
        || registry.backing_peak_bytes > (64 << 30) - (8 << 30)
        || registry.metadata_bytes > 8 << 30
        || registry.staging_bytes > 1 << 30
        || registry.paging_io_slots > 16
        || registry.cpu_slots > 10
        || registry.task_slots > 4096
        || registry.file_descriptors > 65_536
    {
        return Err("invalid authored registry or SQLite service partition".into());
    }

    // These vectors are the immutable throughput corpus declarations. They
    // preserve metadata and staging as subsets of full resident capacity.
    let profile = ServiceProfile {
        operator: PublishedServicePolicy {
            authored: operator,
            sqlite_bootstrap_proof,
            campaign_policy,
            campaign_policy_projection,
        },
        catalog: ResourceVector {
            resident_peak_bytes: 512 << 20,
            backing_peak_bytes: 8 << 30,
            metadata_bytes: 256 << 20,
            staging_bytes: 32 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        },
        catalog_maximum_inodes: 1_048_576,
        native: ResourceVector {
            resident_peak_bytes: 1536 << 20,
            backing_peak_bytes: 4 << 30,
            metadata_bytes: 512 << 20,
            staging_bytes: 32 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 69,
            file_descriptors: 1056,
        },
        aggregate: Aggregate {
            native_slots: 4,
            cpu_slots: 10,
            resident_bytes: 16 << 30,
            backing_bytes: 64 << 30,
            metadata_bytes: 8 << 30,
            staging_bytes: 1 << 30,
            task_slots: 4096,
            file_descriptors: 65_536,
            paging_io_slots: 16,
            dirty_units: 150_000,
        },
        preparation_seconds: 3600,
        invocation_seconds: 3900,
    };
    Ok((profile, campaign_projection))
}

fn compile_campaign_policy(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Parse with the ordinary strict policy codec before projecting the exact
    // document. Only immutable build-time authoring pays this TOML parse.
    crucible_daemon::UnixPeerCampaignPolicy::from_toml_bytes(bytes)?;
    let document = toml::from_str(std::str::from_utf8(bytes)?)?;
    let projection = CampaignPolicyProjection {
        schema: "crucible.measurement-campaign-policy.v1",
        original_toml_blake3: blake3::hash(bytes).to_hex().to_string(),
        document,
    };
    Ok(serde_json::to_vec(&projection)?)
}

// Separate quota roots must never alias the same filesystem project account.
fn valid_project_ids(registry: u32, catalog: u32) -> bool {
    registry != 0
        && catalog != 0
        && registry != catalog
        && registry <= i32::MAX as u32
        && catalog <= i32::MAX as u32
}

fn valid_main_stack(bytes: u64) -> bool {
    bytes != 0 && bytes.is_multiple_of(4096) && bytes <= 16 << 30
}

fn read_installed_input(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if !path.is_absolute() || !path.starts_with("/nix/store") {
        return Err("authoring input is not an immutable installed store locator".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("installed authoring input exceeds its finite extent".into());
    }
    Ok(bytes)
}

fn installed_object(path: &'static str, bytes: &[u8]) -> InstalledObject {
    InstalledObject {
        path,
        blake3: blake3::hash(bytes).to_hex().to_string(),
    }
}

fn installed_artifact(path: PathBuf) -> Result<Artifact, Box<dyn Error>> {
    if !path.starts_with("/nix/store") || !path.is_absolute() {
        return Err("artifact is not an installed immutable store locator".into());
    }
    let mut file = File::open(&path)?;
    let mut hasher = blake3::Hasher::new();
    let bytes = std::io::copy(&mut file, &mut hasher)?;
    if bytes == 0 {
        return Err("empty installed artifact".into());
    }
    Ok(Artifact {
        path,
        bytes,
        blake3: hasher.finalize().to_hex().to_string(),
    })
}

fn generate_rows(output: &Path, width: usize) -> Result<Vec<Row>, Box<dyn Error>> {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: "memory".into(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let preceding = WIDTHS
        .iter()
        .take_while(|candidate| **candidate != width)
        .sum::<usize>();
    let mut rows = Vec::new();
    for (target, divisor) in TARGET_DIVISORS.into_iter().enumerate() {
        for repeat in 0..REPEATS {
            let mut attempts = Vec::new();
            for worker in 0..width {
                let index = target * REPEATS * WIDTHS.iter().sum::<usize>()
                    + preceding * REPEATS
                    + repeat * width
                    + worker;
                let seed = 1000 + u64::try_from(index)?;
                let scenario = ScenarioDefForm::from_components(
                    &world,
                    &Plan::empty(),
                    &Properties::empty(),
                    Seed::from_u64(seed),
                )?;
                let configuration = Configuration::genesis(scenario.scenario_def());
                let scenario_bytes = scenario.to_compact_binary();
                let schedule_bytes = configuration.schedule.to_compact_binary();
                let scenario_id =
                    ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
                let scenario_artifact = ScenarioArtifact::new(
                    scenario_id,
                    crucible_daemon::CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5,
                    scenario_bytes.clone(),
                )?;
                let configuration_artifact = ConfigurationArtifact::new(
                    scenario_id,
                    scenario_artifact.id()?,
                    ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes)),
                    crucible_daemon::CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V4,
                    schedule_bytes.clone(),
                )?;
                let scenario_file = format!("scenario-{seed}.bin");
                let schedule_file = format!("schedule-{seed}.bin");
                fs::write(output.join(&scenario_file), &scenario_bytes)?;
                fs::write(output.join(&schedule_file), &schedule_bytes)?;
                attempts.push(Attempt {
                    seed,
                    campaign: format!("throughput-{seed}"),
                    scenario_file,
                    schedule_file,
                    scenario_id,
                    configuration_artifact_id: configuration_artifact.id()?,
                    scenario_blake3: blake3::hash(&scenario_bytes).to_hex().to_string(),
                    schedule_blake3: blake3::hash(&schedule_bytes).to_hex().to_string(),
                });
            }
            rows.push(Row {
                target_divisor: divisor,
                repeat,
                attempts,
            });
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_stack_requires_explicit_page_aligned_authored_extent() {
        assert!(!valid_main_stack(0));
        assert!(!valid_main_stack(4095));
        assert!(valid_main_stack(4096));
        assert!(valid_main_stack(16 << 30));
        assert!(!valid_main_stack((16 << 30) + 4096));
    }

    #[test]
    fn catalog_and_registry_require_distinct_authored_project_ids() {
        assert!(!valid_project_ids(0, 1));
        assert!(!valid_project_ids(1, 0));
        assert!(!valid_project_ids(1, 1));
        assert!(valid_project_ids(1, 2));
        assert!(!valid_project_ids(u32::MAX, 2));

        let incomplete = serde_json::json!({
            "actorMainStackBytes": 4096,
            "sqliteBootstrapBytes": 4096,
            "sqliteHeapBytes": 4096,
            "sqliteConnections": 1,
            "registry": {
                "residentPeakBytes": 1, "backingPeakBytes": 1,
                "metadataBytes": 1, "stagingBytes": 1,
                "pagingIoSlots": 1, "cpuSlots": 1,
                "taskSlots": 1, "fileDescriptors": 1
            },
            "registryProjectId": 1,
            "registryMaximumInodes": 1
        });
        assert!(serde_json::from_value::<ServicePolicy>(incomplete).is_err());
    }

    #[test]
    fn installed_identity_uses_exact_input_bytes() {
        let first = installed_object("/etc/crucible/sqlite-bootstrap-target.json", b"first");
        let second = installed_object("/etc/crucible/sqlite-bootstrap-target.json", b"second");
        assert_ne!(first.blake3, second.blake3);
        assert_eq!(first.blake3, blake3::hash(b"first").to_hex().as_str());
    }

    #[test]
    fn campaign_projection_validates_policy_and_retains_exact_toml_identity() {
        let bytes = br#"schema = "crucible.campaign-local-policy"
version = 1
bindings = []
grants = []
"#;
        let encoded = compile_campaign_policy(bytes).expect("explicit deny-all component policy");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("projection JSON");
        assert_eq!(value["schema"], "crucible.measurement-campaign-policy.v1");
        assert_eq!(
            value["originalTomlBlake3"],
            blake3::hash(bytes).to_hex().as_str()
        );
        assert_eq!(
            value["document"]["schema"],
            "crucible.campaign-local-policy"
        );
        assert_eq!(value["document"]["bindings"], serde_json::json!([]));
        assert!(compile_campaign_policy(b"schema = 'foreign'\nversion = 1").is_err());
    }

    #[test]
    fn authoring_input_refuses_mutable_non_store_locator() {
        assert!(read_installed_input(Path::new("/tmp/foreign-policy"), 1024).is_err());
    }
}
