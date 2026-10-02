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
use aos_ability_runtime::activation::{Action, Invocation};
use aos_storage_provisioning::{
    ArraySpec, PartitionSpec, ProvisioningPlan, StoragePlan, assign_missing_partition_uuids,
    normalize_marker_uuid, validate_provisioning_plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::native_state;
use crate::process::run_native;

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
    prerequisites: Vec<String>,
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
    #[serde(default)]
    arrays: BTreeMap<String, ArraySpec>,
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
    encryption: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    systemd_repart: PathBuf,
    blkid: PathBuf,
    lsblk: PathBuf,
    sfdisk: PathBuf,
    udevadm: PathBuf,
    mdadm: PathBuf,
    mkfs_ext4: PathBuf,
    mkfs_xfs: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DiskState {
    Absent,
    Completed(Source),
    Drifted(Source),
    Pending,
    Unknown(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    request: ProvisioningRequest,
    plan: DesiredPlan,
    tools: Context,
}

/// Executes the native one-time provisioning transaction.
///
/// # Errors
/// Returns an error for invalid plans, pending or conflicting durable markers,
/// unsupported teardown, or failed exact native block-device operations.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported provisioning action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "action differs from native invocation"
    );
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    let desired = Desired {
        request: input.request,
        plan: input.plan,
    };
    validate_desired(&desired)?;
    let _lock = native_state::Lock::acquire(Path::new(SCRATCH_ROOT))?;
    ensure!(
        action != "remove" && invocation.action != Action::Remove,
        "persistent provisioning transactions do not support removal; factory reset is required"
    );
    if action == "observe" {
        let status = match inspect_state(&desired, &input.tools, &invocation.id)? {
            DiskState::Completed(source) if source == desired.plan.source => "current",
            DiskState::Absent => "retry-safe",
            DiskState::Completed(_)
            | DiskState::Drifted(_)
            | DiskState::Pending
            | DiskState::Unknown(_) => "indeterminate",
        };
        let result = if status == "current" {
            json!({"status":status,"outputs":outputs(&desired, &invocation.id)})
        } else {
            json!({"status":status})
        };
        return Ok(serde_json::to_vec(&result)?);
    }
    ensure!(
        desired.request.enabled,
        "disabled provisioning request cannot commit"
    );
    converge(
        &desired,
        &input.tools,
        &invocation.id,
        invocation.effect.timeout_ms,
    )?;
    Ok(serde_json::to_vec(&outputs(&desired, &invocation.id))?)
}

fn outputs(desired: &Desired, id: &str) -> Value {
    json!({"source":desired.plan.source.name(),"marker_uuid":desired.plan.marker_uuid,"resource":id})
}

fn converge(
    desired: &Desired,
    context: &Context,
    target: &str,
    remaining_millis: u64,
) -> Result<()> {
    match inspect_state(desired, context, target)? {
        DiskState::Completed(source) if source == desired.plan.source => return Ok(()),
        DiskState::Absent => {}
        DiskState::Pending => bail!("pending provisioning marker requires explicit recovery"),
        DiskState::Completed(_) | DiskState::Drifted(_) => {
            bail!("committed storage layout is immutable; factory reset is required")
        }
        DiskState::Unknown(reason) => {
            bail!("storage provisioning state is indeterminate: {reason}")
        }
    }

    let deadline = operation_deadline(remaining_millis)?;
    let rendered = render(desired, target)?;
    let root_disk = root_disk(&context.lsblk, &desired.request.root_device)?;
    let targets = rendered_targets(&rendered, &root_disk)?;

    for target in &targets {
        run_repart(context, target, true, false, remaining(deadline)?)?;
    }
    for target in &targets {
        if let Err(apply_error) = run_repart(context, target, false, false, remaining(deadline)?) {
            let verified = run_repart(context, target, true, true, remaining(deadline)?)
                .and_then(|value| all_unchanged(&value));
            ensure!(
                matches!(verified, Ok(true)),
                "systemd-repart failed and the resulting layout is incomplete: {apply_error:#}"
            );
        }
    }

    let _ = settle(&context.udevadm, remaining(deadline)?);
    prepare_topology(desired, context, deadline)?;
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
        matches!(inspect_state(desired, context, target)?, DiskState::Completed(source) if source == desired.plan.source),
        "committed provisioning layout did not verify"
    );
    Ok(())
}

/// Creates the upper storage layers before publishing the durable GPT marker.
/// A failure leaves the pending marker intact; replay requires explicit recovery.
fn prepare_topology(desired: &Desired, context: &Context, deadline: Instant) -> Result<()> {
    use aos_storage_provisioning::topology::{
        Encryption, VolumeSource, render_topology, resolve_topology,
    };

    let topology = resolve_topology(&shared_plan(&desired.plan), desired.plan.measured_boot)?;
    let stash = Path::new("/run/aos-metadata");
    fs::create_dir_all(stash)?;
    render_topology(stash, &topology)?;
    for array in &topology.arrays {
        let device = format!("/dev/md/{}", array.name);
        ensure!(
            !Path::new(&device).exists(),
            "refusing to adopt an ambient MD array {}",
            array.name
        );
        for member in &array.members {
            wait_for_path(Path::new(member), deadline)?;
            let signature = run_native(
                &context.blkid,
                &["-p", "-s", "TYPE", "-o", "value", member],
                remaining(deadline)?,
            )?;
            ensure!(
                signature.status.success() || signature.status.code() == Some(2),
                "failed to inspect MD member {member}"
            );
            ensure!(
                signature.stdout.iter().all(u8::is_ascii_whitespace),
                "MD member {member} already carries a storage signature"
            );
        }
        let count = array.members.len().to_string();
        let mut arguments = vec![
            "--create",
            device.as_str(),
            "--run",
            "--metadata=1.2",
            "--homehost=aos",
            "--name",
            array.name.as_str(),
            "--level",
            array.level.as_str(),
            "--raid-devices",
            count.as_str(),
        ];
        arguments.extend(array.members.iter().map(String::as_str));
        run_success(
            &context.mdadm,
            &arguments,
            remaining(deadline)?,
            "creating declared MD array",
        )?;
        settle(&context.udevadm, remaining(deadline)?)?;
        wait_for_path(Path::new(&device), deadline)?;
    }
    for volume in &topology.volumes {
        if volume.source != VolumeSource::Array || volume.encryption != Encryption::None {
            continue;
        }
        let Some(filesystem) = volume.filesystem.as_deref() else {
            continue;
        };
        let formatter = match filesystem {
            "ext4" => &context.mkfs_ext4,
            "xfs" => &context.mkfs_xfs,
            _ => bail!("unsupported array filesystem {filesystem}"),
        };
        run_success(
            formatter,
            &["-q", "-L", &volume.label, &volume.device],
            remaining(deadline)?,
            "formatting declared MD volume",
        )?;
    }
    settle(&context.udevadm, remaining(deadline)?)?;
    Ok(())
}

fn wait_for_path(path: &Path, deadline: Instant) -> Result<()> {
    while !path.exists() {
        let _ = remaining(deadline)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn inspect_state(desired: &Desired, context: &Context, target: &str) -> Result<DiskState> {
    if label_path(PENDING_LABEL).exists() {
        return Ok(DiskState::Pending);
    }
    let operator = label_path(OPERATOR_LABEL).exists();
    let fallback = label_path(FALLBACK_LABEL).exists();
    let source = match (operator, fallback) {
        (false, false) => return Ok(DiskState::Absent),
        (true, false) => Source::Operator,
        (false, true) => Source::Fallback,
        (true, true) => {
            return Ok(DiskState::Unknown(
                "both operator and fallback provisioning markers exist".into(),
            ));
        }
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
            Err(error) => {
                return Ok(DiskState::Unknown(format!(
                    "inspecting committed layout on {}: {error:#}",
                    target.device
                )));
            }
        }
    }
    match topology_matches(desired, context) {
        Ok(true) => Ok(DiskState::Completed(source)),
        Ok(false) => Ok(DiskState::Drifted(source)),
        Err(error) => Ok(DiskState::Unknown(format!(
            "inspecting committed storage topology: {error:#}"
        ))),
    }
}

/// Checks stored member superblocks without requiring arrays to be assembled.
/// Missing members remain compatible with the degraded-boot assembly policy.
fn topology_matches(desired: &Desired, context: &Context) -> Result<bool> {
    let topology = aos_storage_provisioning::topology::resolve_topology(
        &shared_plan(&desired.plan),
        desired.plan.measured_boot,
    )?;
    for array in &topology.arrays {
        let mut uuid = None;
        for member in &array.members {
            if !Path::new(member).exists() {
                continue;
            }
            let output = run_native(&context.mdadm, &["--examine", "--export", member], 15_000)?;
            if !output.status.success() {
                return Ok(false);
            }
            let values = std::str::from_utf8(&output.stdout)?
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect::<BTreeMap<_, _>>();
            let count = array.members.len().to_string();
            let name = format!("aos:{}", array.name);
            if values.get("MD_LEVEL") != Some(&array.level.as_str())
                || values.get("MD_DEVICES") != Some(&count.as_str())
                || !matches!(values.get("MD_NAME"), Some(value) if *value == name || *value == array.name)
            {
                return Ok(false);
            }
            let found = values
                .get("MD_UUID")
                .context("MD member lacks array identity")?
                .to_string();
            if uuid.as_ref().is_some_and(|previous| previous != &found) {
                return Ok(false);
            }
            uuid = Some(found);
        }
        if uuid.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

struct RenderedPlan {
    directory: PathBuf,
}

struct RenderedTarget {
    device: String,
    definitions: String,
}

fn render(desired: &Desired, target: &str) -> Result<RenderedPlan> {
    validate_repart_plan(&desired.plan)?;
    let mut plan = shared_plan(&desired.plan);
    let digest =
        aos_contract::Sha256Digest::of_canonical("aos.storage.provisioning-scratch/v1", &target)?;
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
    let topology = aos_storage_provisioning::topology::resolve_topology(plan, measured_boot)?;
    aos_storage_provisioning::topology::render_topology(scratch_dir, &topology)?;
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
            let format = if topology.members.contains(name) {
                None
            } else if let Some(volume) = topology.volumes.iter().find(|volume| {
                volume.name == name
                    && volume.source == aos_storage_provisioning::topology::VolumeSource::Partition
            }) {
                if volume.encryption == aos_storage_provisioning::topology::Encryption::None {
                    volume.filesystem.as_deref()
                } else {
                    None
                }
            } else {
                partition.format.as_deref()
            };
            fs::write(&path, render_partition(partition, format))
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

fn render_partition(partition: &PartitionSpec, format: Option<&str>) -> String {
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
                    encryption: partition.encryption.clone(),
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
        storage: StoragePlan {
            partitions,
            arrays: plan.arrays.clone(),
        },
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
    let output = run_native(&context.systemd_repart, &arguments, remaining_millis)?;
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

fn root_disk(lsblk: &Path, root_device: &str) -> Result<String> {
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

fn inspect_value(executable: &Path, prefix: &[&str], path: &Path) -> Result<String> {
    let path = path.to_string_lossy();
    let mut arguments = prefix.to_vec();
    arguments.push(&path);
    let output = run_native(executable, &arguments, 5_000)?;
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

fn settle(udevadm: &Path, remaining_millis: u64) -> Result<()> {
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
                None | Some("ext4" | "xfs" | "vfat" | "swap")
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
    if matches!(value, "linux-generic" | "linux-raid" | "swap") {
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
    executable: &Path,
    arguments: &[&str],
    remaining_millis: u64,
    operation: &str,
) -> Result<()> {
    let output = run_native(executable, arguments, remaining_millis)?;
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
                arrays: BTreeMap::new(),
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
                        encryption: None,
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
    fn md_members_remain_raw_and_array_topology_is_rendered_before_commit() {
        let mut desired = desired();
        let mut mirror = desired.plan.partitions["var"].clone();
        mirror.label = "var-mirror".into();
        mirror.partition_type = "linux-raid".into();
        mirror.grow = false;
        desired
            .plan
            .partitions
            .get_mut("var")
            .unwrap()
            .partition_type = "linux-raid".into();
        desired.plan.partitions.insert("var-mirror".into(), mirror);
        desired.plan.arrays.insert(
            "var".into(),
            ArraySpec {
                level: "raid1".into(),
                members: vec!["var".into(), "var-mirror".into()],
                format: Some("ext4".into()),
                encryption: None,
            },
        );
        validate_desired(&desired).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut plan = shared_plan(&desired.plan);
        let paths = render_provisioning_plan(
            directory.path(),
            &mut plan,
            false,
            PENDING_LABEL,
            &desired.plan.marker_uuid,
        )
        .unwrap();

        for path in paths
            .iter()
            .filter(|path| path.file_name().unwrap().to_string_lossy().contains("var"))
        {
            let definition = fs::read_to_string(path).unwrap();
            assert!(definition.contains("Type=linux-raid"));
            assert!(!definition.contains("Format="));
        }
        let arrays = fs::read_to_string(directory.path().join("storage-arrays")).unwrap();
        assert!(arrays.contains(
            "var\traid1\t2\t/dev/disk/by-partlabel/var,/dev/disk/by-partlabel/var-mirror"
        ));
        let volumes = fs::read_to_string(directory.path().join("storage-volumes")).unwrap();
        assert!(volumes.contains("var\tarray\t/dev/md/var\tvar\tnone\text4"));
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
    fn runtime_plan_must_match_request_measured_boot_policy() {
        let mut desired = desired();
        validate_desired(&desired).unwrap();

        desired.request.measured_boot = !desired.plan.measured_boot;
        assert!(validate_desired(&desired).is_err());
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
            .format = Some("btrfs".into());
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
