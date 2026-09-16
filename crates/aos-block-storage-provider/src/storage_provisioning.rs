//! `systemd-repart` backed one-time storage provisioning.
//!
//! The provider renders the same checked provisioning plan used by image
//! metadata, preflights every target, and records completion by relabeling the
//! GPT marker created in the root-disk transaction. A pending marker always
//! stops automatic replay.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_provider_protocol::ResourceContext;
use aos_storage_provisioning::{
    PartitionSpec, ProvisioningPlan, StoragePlan, assign_missing_partition_uuids,
    normalize_marker_uuid, validate_provisioning_plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::engine::{Backend, BackendObservation, ability_value};
use crate::process::{Executable, ExecutableReference};

const CONTEXT_SCHEMA: &str = "aos.storage.provisioning-context/v1";
const SCRATCH_ROOT: &str = "/run/aos/storage-provisioning";
const REPART_DIR: &str = "repart.d";
const REPART_TARGETS_FILE: &str = "repart-targets";
const STORAGE_PLAN_FILE: &str = "provisioning-plan.json";
const PENDING_LABEL: &str = "aos-provisioning-pending-v1";
const OPERATOR_LABEL: &str = "aos-provenance-operator-v1";
const FALLBACK_LABEL: &str = "aos-provenance-fallback-v1";
const SENTINEL_TYPE_GUID: &str = "163bea60-58c7-46e7-b69a-6846a5a688af";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    request: ProvisioningRequest,
    plan: DesiredPlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningRequest {
    name: String,
    enabled: bool,
    root_device: String,
    measured_boot: bool,
    policy: ProvisioningPolicy,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningPolicy {
    initialize: String,
    committed_divergence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DesiredPlan {
    schema: String,
    source: Source,
    marker_uuid: String,
    measured_boot: bool,
    partitions: BTreeMap<String, DesiredPartition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Source {
    Operator,
    Fallback,
}

impl Source {
    const fn label(self) -> &'static str {
        match self {
            Self::Operator => OPERATOR_LABEL,
            Self::Fallback => FALLBACK_LABEL,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DesiredPartition {
    target: PartitionTarget,
    label: String,
    partition_type: String,
    size_min: String,
    #[serde(default)]
    size_max: Option<String>,
    weight: i64,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    grow: bool,
    grow_fs: bool,
    priority: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PartitionTarget {
    RootDisk,
    Device { path: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    #[serde(rename = "schema")]
    _schema: String,
    systemd_repart: ExecutableReference,
    blkid: ExecutableReference,
    lsblk: ExecutableReference,
    sfdisk: ExecutableReference,
    udevadm: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    systemd_repart: Executable,
    blkid: Executable,
    lsblk: Executable,
    sfdisk: Executable,
    udevadm: Executable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiskState {
    Absent,
    Completed(Source),
    Drifted(Source),
    Pending,
    Unknown,
}

/// Implements one-time provisioning through exact systemd and util-linux tools.
pub struct StorageProvisioningBackend;

impl Backend for StorageProvisioningBackend {
    fn action_method(&self) -> &'static str {
        "commit"
    }

    fn path_output(&self) -> &'static str {
        "committed-source"
    }

    fn invocation_desired(
        &self,
        admitted: &AbilityValue,
        inputs: &AbilityValue,
    ) -> Result<AbilityValue> {
        let desired: Desired = decode(inputs)?;
        let request: ProvisioningRequest = decode(admitted)?;
        ensure!(
            desired.request == request,
            "runtime request differs from the admitted provisioning intent"
        );
        validate_desired(&desired)?;
        ability_value(serde_json::to_value(desired)?)
    }

    fn admit_context(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        _resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        validate_request(&decode(desired)?)?;
        let realization: Realization = decode(realization)?;
        ability_value(serde_json::to_value(Context {
            schema: CONTEXT_SCHEMA.into(),
            systemd_repart: realization.systemd_repart.resolve()?,
            blkid: realization.blkid.resolve()?,
            lsblk: realization.lsblk.resolve()?,
            sfdisk: realization.sfdisk.resolve()?,
            udevadm: realization.udevadm.resolve()?,
        })?)
    }

    fn observe_admission(
        &self,
        observation_schema: &str,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        _context: &AbilityValue,
    ) -> Result<BackendObservation> {
        let request: ProvisioningRequest = decode(desired)?;
        Ok(BackendObservation {
            evidence: observation(observation_schema, &request, None, "absent")?,
            ready: false,
            released: false,
            path: None,
            unknown: false,
        })
    }

    fn observe(
        &self,
        observation_schema: &str,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        _revision: RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation> {
        let desired_value: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_context(&context)?;
        let state = inspect_state(&desired_value, &context, target)?;
        let (state_name, committed_source, ready, unknown) = match state {
            DiskState::Absent => ("absent", None, false, false),
            DiskState::Completed(source) => ("completed", Some(source), true, false),
            DiskState::Drifted(source) => ("drifted", Some(source), false, false),
            DiskState::Pending => ("pending", None, false, true),
            DiskState::Unknown => ("unknown", None, false, true),
        };
        let evidence = observation(
            observation_schema,
            &desired_value.request,
            committed_source,
            state_name,
        )?;
        Ok(BackendObservation {
            evidence,
            ready,
            released: false,
            path: ready.then(|| desired_value.plan.source.name().to_string()),
            unknown,
        })
    }

    fn apply(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        _revision: RevisionId,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()> {
        let desired: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_desired(&desired)?;
        validate_context(&context)?;
        ensure!(
            desired.request.enabled,
            "disabled provisioning request cannot commit"
        );

        match inspect_state(&desired, &context, target)? {
            DiskState::Completed(source) if source == desired.plan.source => return Ok(()),
            DiskState::Absent => {}
            DiskState::Pending => bail!("pending provisioning marker requires explicit recovery"),
            DiskState::Completed(_) | DiskState::Drifted(_) => {
                bail!("committed storage layout is immutable; factory reset is required")
            }
            DiskState::Unknown => bail!("storage provisioning state is indeterminate"),
        }

        let deadline = operation_deadline(remaining_millis)?;
        let rendered = render(&desired, target)?;
        let root_disk = root_disk(&context.lsblk, &desired.request.root_device)?;
        let targets = rendered_targets(&rendered, &root_disk)?;

        for target in &targets {
            run_repart(&context, target, true, false, remaining(deadline)?)?;
        }
        for target in &targets {
            if let Err(apply_error) =
                run_repart(&context, target, false, false, remaining(deadline)?)
            {
                let verified = run_repart(&context, target, true, true, remaining(deadline)?)
                    .and_then(|value| all_unchanged(&value));
                ensure!(
                    matches!(verified, Ok(true)),
                    "systemd-repart failed and the resulting layout is incomplete: {apply_error:#}"
                );
            }
        }

        let _ = settle(&context.udevadm, remaining(deadline)?);
        let pending = wait_for_label(PENDING_LABEL, deadline)?;
        let partition_number = partition_number(&pending)?;
        run_success(
            &context.sfdisk,
            &[
                "--part-label",
                &root_disk,
                &partition_number,
                desired.plan.source.label(),
            ],
            remaining(deadline)?,
            "relabeling provisioning marker",
        )?;
        let _ = settle(&context.udevadm, remaining(deadline)?);
        wait_for_label(desired.plan.source.label(), deadline)?;

        ensure!(
            matches!(inspect_state(&desired, &context, target)?, DiskState::Completed(source) if source == desired.plan.source),
            "committed provisioning layout did not verify"
        );
        Ok(())
    }

    fn release(
        &self,
        _desired: &AbilityValue,
        _realization: &AbilityValue,
        _target: &ResourceReference,
        _context: &AbilityValue,
        _remaining_millis: u64,
    ) -> Result<()> {
        bail!("persistent provisioning transactions do not support release")
    }
}

fn inspect_state(
    desired: &Desired,
    context: &Context,
    target: &ResourceReference,
) -> Result<DiskState> {
    if label_path(PENDING_LABEL).exists() {
        return Ok(DiskState::Pending);
    }
    let operator = label_path(OPERATOR_LABEL).exists();
    let fallback = label_path(FALLBACK_LABEL).exists();
    let source = match (operator, fallback) {
        (false, false) => return Ok(DiskState::Absent),
        (true, false) => Source::Operator,
        (false, true) => Source::Fallback,
        (true, true) => return Ok(DiskState::Unknown),
    };
    let marker = fs::canonicalize(label_path(source.label()))
        .context("resolving committed provisioning marker")?;
    let marker_uuid = inspect_value(&context.lsblk, &["-ndo", "PARTUUID", "--"], &marker)?;
    if source != desired.plan.source || marker_uuid.to_ascii_lowercase() != desired.plan.marker_uuid
    {
        return Ok(DiskState::Drifted(source));
    }

    let rendered = render(desired, target)?;
    let root_disk = root_disk(&context.lsblk, &desired.request.root_device)?;
    let targets = rendered_targets(&rendered, &root_disk)?;
    for target in &targets {
        match run_repart(context, target, true, true, 15_000) {
            Ok(value) if all_unchanged(&value)? => {}
            Ok(_) => return Ok(DiskState::Drifted(source)),
            Err(_) => return Ok(DiskState::Unknown),
        }
    }
    Ok(DiskState::Completed(source))
}

struct RenderedPlan {
    directory: PathBuf,
}

struct RenderedTarget {
    device: String,
    definitions: String,
}

fn render(desired: &Desired, target: &ResourceReference) -> Result<RenderedPlan> {
    validate_repart_plan(&desired.plan)?;
    let mut plan = shared_plan(&desired.plan);
    let digest = aos_contract::Sha256Digest::of_canonical(
        "aos.storage.provisioning-scratch/v1",
        &target.resource,
    )?;
    let directory = Path::new(SCRATCH_ROOT).join(digest.hex());
    fs::create_dir_all(&directory).with_context(|| format!("creating {}", directory.display()))?;
    render_provisioning_plan(
        &directory,
        &mut plan,
        desired.plan.measured_boot,
        desired.plan.source.label(),
        &desired.plan.marker_uuid,
    )?;
    Ok(RenderedPlan { directory })
}

/// Renders one validated plan into private transient systemd-repart inputs.
fn render_provisioning_plan(
    scratch_dir: &Path,
    plan: &mut ProvisioningPlan,
    measured_boot: bool,
    marker_label: &str,
    marker_uuid: &str,
) -> Result<Vec<PathBuf>> {
    validate_provisioning_plan(plan, measured_boot)?;
    ensure!(
        matches!(
            marker_label,
            PENDING_LABEL | OPERATOR_LABEL | FALLBACK_LABEL
        ),
        "unsupported provisioning marker label '{marker_label}'"
    );
    let marker_uuid = normalize_marker_uuid(marker_uuid)?;
    assign_missing_partition_uuids(plan, &marker_uuid);
    fs::write(
        scratch_dir.join(STORAGE_PLAN_FILE),
        serde_json::to_vec_pretty(plan).context("serializing provisioning plan")?,
    )
    .context("writing provisioning-plan.json")?;

    let root = scratch_dir.join(REPART_DIR);
    if root.exists() {
        fs::remove_dir_all(&root).with_context(|| format!("clearing {}", root.display()))?;
    }
    fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;

    let mut groups: BTreeMap<&str, Vec<(&str, &PartitionSpec)>> = BTreeMap::new();
    for (name, partition) in &plan.storage.partitions {
        groups
            .entry(partition.device.as_deref().unwrap_or("root"))
            .or_default()
            .push((name, partition));
    }

    let mut targets = String::new();
    let mut written = Vec::new();
    let mut groups: Vec<_> = groups.into_iter().collect();
    // Commit the pending root-disk marker before another device can change.
    // A crash is then distinguishable from a never-started first boot.
    groups.sort_by_key(|(device, _)| (*device != "root", *device));
    for (index, (device, mut partitions)) in groups.into_iter().enumerate() {
        partitions.sort_by_key(|(name, partition)| (partition.grow, partition.priority, *name));
        let directory_name = format!("{index:04}");
        let directory = root.join(&directory_name);
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating {}", directory.display()))?;
        targets.push_str(device);
        targets.push('\t');
        targets.push_str(&directory_name);
        targets.push('\n');

        for (position, (name, partition)) in partitions.into_iter().enumerate() {
            let path = directory.join(format!("{:04}-{name}.conf", position + 10));
            fs::write(&path, render_partition(partition, measured_boot))
                .with_context(|| format!("writing {}", path.display()))?;
            written.push(path);
        }
        if device == "root" {
            let marker = directory.join("0000-aos-provisioning-marker.conf");
            fs::write(
                &marker,
                format!(
                    "[Partition]\nType={SENTINEL_TYPE_GUID}\nLabel={marker_label}\nUUID={marker_uuid}\nSizeMinBytes=1M\nSizeMaxBytes=1M\nPriority=1000000\n"
                ),
            )
            .with_context(|| format!("writing {}", marker.display()))?;
            written.push(marker);
        }
    }
    fs::write(scratch_dir.join(REPART_TARGETS_FILE), targets)
        .context("writing repart target index")?;
    Ok(written)
}

fn render_partition(partition: &PartitionSpec, measured_boot: bool) -> String {
    let mut result = format!(
        "[Partition]\nType={}\nLabel={}\nSizeMinBytes={}\nWeight={}\nGrowFileSystem={}\n",
        partition.partition_type,
        partition.label,
        partition.size_min,
        partition.weight,
        if partition.grow_fs { "yes" } else { "no" },
    );
    if let Some(maximum) = partition.size_max.as_deref() {
        result.push_str(&format!("SizeMaxBytes={maximum}\n"));
    } else if !partition.grow {
        result.push_str(&format!("SizeMaxBytes={}\n", partition.size_min));
    }
    let format = if partition.label == "var" && !measured_boot && partition.format.is_none() {
        Some("ext4")
    } else {
        partition.format.as_deref()
    };
    if let Some(format) = format {
        result.push_str(&format!("Format={format}\n"));
    }
    if let Some(uuid) = partition.uuid.as_deref() {
        result.push_str(&format!("UUID={uuid}\n"));
    }
    result
}

fn shared_plan(plan: &DesiredPlan) -> ProvisioningPlan {
    let partitions = plan
        .partitions
        .iter()
        .map(|(name, partition)| {
            let device = match &partition.target {
                PartitionTarget::RootDisk => None,
                PartitionTarget::Device { path } => Some(path.clone()),
            };
            (
                name.clone(),
                PartitionSpec {
                    device,
                    label: partition.label.clone(),
                    partition_type: partition.partition_type.clone(),
                    size_min: partition.size_min.clone(),
                    size_max: partition.size_max.clone(),
                    weight: partition.weight,
                    format: partition.format.clone(),
                    uuid: partition.uuid.clone(),
                    grow: partition.grow,
                    grow_fs: partition.grow_fs,
                    priority: partition.priority,
                },
            )
        })
        .collect();
    ProvisioningPlan {
        schema: "aos.provisioning-plan/v1".into(),
        storage: StoragePlan { partitions },
    }
}

fn rendered_targets(rendered: &RenderedPlan, root_disk: &str) -> Result<Vec<RenderedTarget>> {
    let index = fs::read_to_string(rendered.directory.join(REPART_TARGETS_FILE))
        .context("reading rendered target index")?;
    let mut targets = Vec::new();
    for line in index.lines() {
        let (device, directory) = line
            .split_once('\t')
            .context("rendered target index is malformed")?;
        let device = if device == "root" { root_disk } else { device };
        validate_device_path(device)?;
        targets.push(RenderedTarget {
            device: device.into(),
            definitions: rendered
                .directory
                .join(REPART_DIR)
                .join(directory)
                .to_string_lossy()
                .into_owned(),
        });
    }
    ensure!(!targets.is_empty(), "rendered target index is empty");
    Ok(targets)
}

fn run_repart(
    context: &Context,
    target: &RenderedTarget,
    dry_run: bool,
    json_output: bool,
    remaining_millis: u64,
) -> Result<Value> {
    let seed = inspect_value(
        &context.blkid,
        &["-p", "-s", "PTUUID", "-o", "value", "--"],
        Path::new(&target.device),
    )?;
    normalize_marker_uuid(&seed).context("validating GPT repart seed")?;
    let dry_run = if dry_run {
        "--dry-run=yes"
    } else {
        "--dry-run=no"
    };
    let definitions = format!("--definitions={}", target.definitions);
    let seed = format!("--seed={seed}");
    let mut arguments = vec![
        definitions.as_str(),
        dry_run,
        "--empty=allow",
        seed.as_str(),
    ];
    if json_output {
        arguments.push("--json=short");
    }
    arguments.push("--");
    arguments.push(&target.device);
    let output = context.systemd_repart.run(&arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "systemd-repart failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if json_output {
        serde_json::from_slice(&output.stdout).context("decoding systemd-repart observation")
    } else {
        Ok(Value::Null)
    }
}

fn all_unchanged(value: &Value) -> Result<bool> {
    let rows = value
        .as_array()
        .context("systemd-repart JSON result is not an array")?;
    Ok(rows.iter().all(|row| {
        row.as_object()
            .and_then(|row| row.get("activity"))
            .and_then(Value::as_str)
            == Some("unchanged")
    }))
}

fn root_disk(lsblk: &Executable, root_device: &str) -> Result<String> {
    validate_device_path(root_device)?;
    let canonical = fs::canonicalize(root_device).context("resolving root storage device")?;
    let parent = inspect_value(lsblk, &["-ndo", "PKNAME", "--"], &canonical)?;
    ensure!(
        !parent.contains('/'),
        "lsblk returned an invalid parent device"
    );
    let disk = format!("/dev/{parent}");
    validate_device_path(&disk)?;
    Ok(disk)
}

fn inspect_value(executable: &Executable, prefix: &[&str], path: &Path) -> Result<String> {
    let path = path.to_string_lossy();
    let mut arguments = prefix.to_vec();
    arguments.push(&path);
    let output = executable.run(&arguments, 5_000)?;
    ensure!(
        output.status.success(),
        "storage inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = String::from_utf8(output.stdout)
        .context("decoding storage inspection output")?
        .trim()
        .to_string();
    ensure!(!value.is_empty(), "storage inspection returned no value");
    Ok(value)
}

fn settle(udevadm: &Executable, remaining_millis: u64) -> Result<()> {
    let seconds = (remaining_millis / 1_000).clamp(1, 10).to_string();
    let timeout = format!("--timeout={seconds}");
    run_success(
        udevadm,
        &["settle", &timeout],
        remaining_millis,
        "settling device events",
    )
}

fn wait_for_label(label: &str, deadline: Instant) -> Result<PathBuf> {
    let path = label_path(label);
    loop {
        if path.exists() {
            return fs::canonicalize(&path)
                .with_context(|| format!("resolving provisioning label {label}"));
        }
        ensure!(
            monotonic_now() < deadline,
            "provisioning marker did not materialize"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn partition_number(device: &Path) -> Result<String> {
    let name = device
        .file_name()
        .context("pending marker has no device name")?;
    let value = fs::read_to_string(Path::new("/sys/class/block").join(name).join("partition"))
        .context("reading pending marker partition number")?;
    let value = value.trim();
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "pending marker has an invalid partition number"
    );
    Ok(value.into())
}

fn validate_desired(desired: &Desired) -> Result<()> {
    validate_request(&desired.request)?;
    ensure!(
        desired.request.measured_boot == desired.plan.measured_boot,
        "provisioning plan measured-boot policy differs from the admitted request"
    );
    ensure!(
        desired.plan.schema == "aos.storage.provisioning-plan/v1",
        "unsupported storage-provisioning plan schema"
    );
    normalize_marker_uuid(&desired.plan.marker_uuid)?;
    validate_repart_plan(&desired.plan)?;
    validate_provisioning_plan(&shared_plan(&desired.plan), desired.plan.measured_boot)
}

fn validate_repart_plan(plan: &DesiredPlan) -> Result<()> {
    for (name, partition) in &plan.partitions {
        ensure!(
            !matches!(
                partition.label.as_str(),
                "root-a"
                    | "root-b"
                    | "root-a-hash"
                    | "root-b-hash"
                    | "esp"
                    | "ESP"
                    | PENDING_LABEL
                    | OPERATOR_LABEL
                    | FALLBACK_LABEL
            ),
            "partition label '{}' is reserved or protected",
            partition.label
        );
        if let PartitionTarget::Device { path } = &partition.target {
            let device_name = path.strip_prefix("/dev/disk/by-id/").unwrap_or_default();
            ensure!(
                !device_name.is_empty() && !device_name.contains('/'),
                "partition '{name}' device must use one /dev/disk/by-id identity"
            );
        }

        validate_repart_partition_type(&partition.partition_type)?;
        ensure!(
            matches!(
                partition.format.as_deref(),
                None | Some("ext4" | "vfat" | "swap")
            ),
            "partition '{name}' uses a format unsupported by systemd-repart"
        );
        ensure!(
            (partition.partition_type == "swap") == (partition.format.as_deref() == Some("swap")),
            "partition '{name}' must use type = \"swap\" exactly when format = \"swap\""
        );
    }
    Ok(())
}

fn validate_repart_partition_type(value: &str) -> Result<()> {
    if matches!(value, "linux-generic" | "swap") {
        return Ok(());
    }

    let lower = value.to_ascii_lowercase();
    ensure!(
        lower != SENTINEL_TYPE_GUID
            && !matches!(
                lower.as_str(),
                "root"
                    | "root-a"
                    | "root-b"
                    | "root-verity"
                    | "root-verity-sig"
                    | "var"
                    | "esp"
                    | "xbootldr"
                    | "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
                    | "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
                    | "b921b045-1df0-41c3-af44-4c6f280d3fae"
                    | "44479540-f297-41b2-9af7-d131d5f0458a"
                    | "72ec70a6-cf74-40e6-bd49-4bda08e8f224"
                    | "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"
                    | "df3300ce-d69f-4c92-978c-9bfb0f38d820"
                    | "d13c5d3b-b5d1-422a-b29f-9454fdc89d76"
                    | "b6ed5582-440b-4209-b8da-5ff7c419ea3d"
                    | "41092b05-9fc8-4523-994f-2def0408b176"
            ),
        "partition type '{value}' is reserved or protected"
    );
    normalize_marker_uuid(value).context("raw partition type GUID")?;
    Ok(())
}

fn validate_request(request: &ProvisioningRequest) -> Result<()> {
    ensure!(
        !request.name.is_empty() && request.name.len() <= 128,
        "storage-provisioning request name is invalid"
    );
    validate_device_path(&request.root_device)?;
    ensure!(
        request.policy.initialize == "if-unprovisioned"
            && request.policy.committed_divergence == "require-factory-reset",
        "unsupported storage-provisioning policy"
    );
    Ok(())
}

fn observation(
    observation_schema: &str,
    request: &ProvisioningRequest,
    committed_source: Option<Source>,
    state: &str,
) -> Result<AbilityValue> {
    ability_value(json!({
        "schema": observation_schema,
        "expected": request,
        "committed_source": committed_source.map(Source::name),
        "state": state,
    }))
}

fn validate_context(context: &Context) -> Result<()> {
    ensure!(
        context.schema == CONTEXT_SCHEMA,
        "unsupported storage-provisioning context"
    );
    Ok(())
}

fn validate_device_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(path.is_absolute(), "storage device path is not absolute");
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "storage device path is not normalized"
    );
    Ok(())
}

fn label_path(label: &str) -> PathBuf {
    Path::new("/dev/disk/by-partlabel").join(label)
}

fn run_success(
    executable: &Executable,
    arguments: &[&str],
    remaining_millis: u64,
    operation: &str,
) -> Result<()> {
    let output = executable.run(arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn operation_deadline(remaining_millis: u64) -> Result<Instant> {
    ensure!(
        remaining_millis > 0,
        "storage-provisioning deadline expired"
    );
    monotonic_now()
        .checked_add(Duration::from_millis(remaining_millis))
        .context("storage-provisioning deadline overflow")
}

fn remaining(deadline: Instant) -> Result<u64> {
    let duration = deadline
        .checked_duration_since(monotonic_now())
        .context("storage-provisioning deadline expired")?;
    u64::try_from(duration.as_millis().max(1)).context("storage-provisioning deadline overflow")
}

// The monotonic clock only enforces the runtime-supplied operation budget. It
// does not affect desired state, revisions, observations, or emitted evidence.
#[allow(clippy::disallowed_methods)]
fn monotonic_now() -> Instant {
    Instant::now()
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding storage provisioning value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> Desired {
        Desired {
            request: ProvisioningRequest {
                name: "first-boot".into(),
                enabled: true,
                root_device: "/dev/disk/by-partlabel/root-a".into(),
                measured_boot: false,
                policy: ProvisioningPolicy {
                    initialize: "if-unprovisioned".into(),
                    committed_divergence: "require-factory-reset".into(),
                },
                prerequisites: Vec::new(),
            },
            plan: DesiredPlan {
                schema: "aos.storage.provisioning-plan/v1".into(),
                source: Source::Operator,
                marker_uuid: "01234567-89ab-cdef-8123-456789abcdef".into(),
                measured_boot: false,
                partitions: BTreeMap::from([(
                    "var".into(),
                    DesiredPartition {
                        target: PartitionTarget::RootDisk,
                        label: "var".into(),
                        partition_type: "linux-generic".into(),
                        size_min: "1G".into(),
                        size_max: None,
                        weight: 1,
                        format: None,
                        uuid: None,
                        grow: true,
                        grow_fs: true,
                        priority: 1,
                    },
                )]),
            },
        }
    }

    #[test]
    fn converts_the_wire_plan_into_the_single_shared_renderer_model() {
        let desired = desired();
        validate_desired(&desired).expect("valid desired provisioning request");

        let plan = shared_plan(&desired.plan);
        assert_eq!(plan.storage.partitions["var"].device, None);
        assert_eq!(plan.storage.partitions["var"].label, "var");
    }

    #[test]
    fn runtime_plan_must_bind_the_exact_admitted_request() {
        let backend = StorageProvisioningBackend;
        let desired = desired();
        let admitted = ability_value(serde_json::to_value(&desired.request).expect("request JSON"))
            .expect("request value");
        let inputs = ability_value(serde_json::to_value(&desired).expect("input JSON"))
            .expect("input value");

        assert_eq!(
            backend
                .invocation_desired(&admitted, &inputs)
                .expect("bound runtime plan"),
            inputs
        );

        let mut different = desired;
        different.request.name = "another-transaction".into();
        let different = ability_value(serde_json::to_value(different).expect("different JSON"))
            .expect("different value");
        assert!(backend.invocation_desired(&admitted, &different).is_err());
    }

    #[test]
    fn rejects_unstable_explicit_device_paths() {
        let mut desired = desired();
        desired.plan.partitions.get_mut("var").expect("var").target = PartitionTarget::Device {
            path: "/dev/sda".into(),
        };

        let error = validate_desired(&desired).expect_err("unstable device must fail");
        assert!(error.to_string().contains("/dev/disk/by-id"));
    }

    #[test]
    fn rejects_repart_specific_types_and_formats() {
        let mut protected_type = desired();
        protected_type
            .plan
            .partitions
            .get_mut("var")
            .expect("var")
            .partition_type = "root-a".into();
        let error = validate_desired(&protected_type).expect_err("protected type must fail");
        assert!(error.to_string().contains("reserved or protected"));

        let mut unsupported_format = desired();
        unsupported_format
            .plan
            .partitions
            .get_mut("var")
            .expect("var")
            .format = Some("xfs".into());
        let error =
            validate_desired(&unsupported_format).expect_err("unsupported format must fail");
        assert!(error.to_string().contains("unsupported by systemd-repart"));
    }

    #[test]
    fn all_unchanged_requires_every_result_row() {
        assert!(all_unchanged(&json!([{"activity": "unchanged"}])).expect("valid result"));
        assert!(
            !all_unchanged(&json!([
                {"activity": "unchanged"},
                {"activity": "create"}
            ]))
            .expect("valid result")
        );
    }
}
