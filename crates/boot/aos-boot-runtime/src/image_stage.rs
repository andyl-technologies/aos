//! Stages authenticated systemd images into the opposite immutable root slot.
//!
//! The source disk and every published artifact must match signed delivery
//! metadata. Storage is read-back verified before durable profile publication;
//! staging never exposes a discoverable normal boot entry or selects a boot.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use aos_boot_identity::{BootSlot, NormalBootIdentity, parse_normal, pe::read_uki_text};
use aos_release_format::artifact::BundlePath;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::boot_storage::with_writable_boot;
use crate::image_profile::{BOOT_ROOT, IMAGE_PROFILE, candidate_path, private_directory};
use crate::recovery::{RecoveryEvidence, validate_uki_identity};
use aos_nix::executable::validate_store_executable;

#[path = "image_stage/copy_up.rs"]
mod copy_up;

#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum StageAction {
    Preflight,
    Stage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    action: StageAction,
    generation: u32,
    source: PathBuf,
    metadata: PathBuf,
    artifacts: PathBuf,
    delivery: Value,
    candidate: Value,
    running: Value,
    retained_generations: Vec<Value>,
    retained_store_roots: Vec<String>,
    initrd_state_directory: PathBuf,
    initrd_storage_root: PathBuf,
    retained_initrd_store_roots: Vec<String>,
}

struct Tools {
    mount: PathBuf,
    umount: PathBuf,
    blkid: PathBuf,
    veritysetup: PathBuf,
    nix_store: PathBuf,
}

struct PreparedRecovery {
    evidence: RecoveryEvidence,
    uki: PathBuf,
    entry: PathBuf,
}

/// Executes physical staging with exact tool paths supplied by the retained wrapper.
///
/// # Errors
/// Returns an error for invalid input, active-slot or retained-slot conflicts,
/// unsafe device topology, hash or boot identity drift, write/read-back failure,
/// or failure to durably publish authenticated profile payloads.
pub(crate) fn run_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 10,
        "image stage requires five exact retained tools"
    );
    let names = [
        "--mount",
        "--umount",
        "--blkid",
        "--veritysetup",
        "--nix-store",
    ];
    let mut paths = Vec::new();
    for (index, name) in names.into_iter().enumerate() {
        ensure!(
            arguments[index * 2] == name,
            "noncanonical image stage tool arguments"
        );
        let path = PathBuf::from(&arguments[index * 2 + 1]);
        validate_store_executable(&path, name)?;
        paths.push(path);
    }
    let tools = Tools {
        mount: paths[0].clone(),
        umount: paths[1].clone(),
        blkid: paths[2].clone(),
        veritysetup: paths[3].clone(),
        nix_store: paths[4].clone(),
    };
    let mut bytes = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "staging request exceeds its boundary"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    let receipt = stage(&request, &tools)?;
    io::stdout().write_all(&serde_json::to_vec(&receipt)?)?;
    Ok(())
}

fn stage(request: &Request, tools: &Tools) -> Result<Value> {
    ensure!(
        request.schema == "aos.image-candidate-stage" && request.generation > 0,
        "invalid stage identity"
    );
    ensure!(
        integer(&request.candidate, "number")? == u64::from(request.generation),
        "candidate generation differs from staging intent"
    );
    let index: Value = serde_json::from_slice(&read_bounded(
        Path::new("/var/lib/profiles/image/state.json"),
        1024 * 1024,
    )?)?;
    ensure!(
        index.get("generations") == Some(&Value::Array(request.retained_generations.clone()))
            && integer(&index, "running")? == integer(&request.running, "number")?
            && index.get("pending").is_none_or(Value::is_null)
            && index.get("active_rollout").is_none_or(Value::is_null),
        "physical staging request differs from current retained image authority"
    );
    ensure!(
        request
            .retained_generations
            .iter()
            .any(|image| image == &request.running),
        "physical staging running identity is absent from the retained index"
    );
    let active = parse_normal(&fs::read_to_string("/proc/cmdline")?)?;
    let target = match active.slot {
        BootSlot::A => "b",
        BootSlot::B => "a",
    };
    let candidate_version = string(&request.candidate, "version")?;
    ensure!(
        candidate_version == string(&request.delivery, "release")?,
        "candidate version differs from signed delivery"
    );
    ensure!(
        string(&request.candidate, "state_version")? == string(&request.running, "state_version")?,
        "candidate state format differs from running image"
    );
    let retirement_required = slot_occupied(&request.retained_generations, target)?;
    if request.action == StageAction::Stage {
        ensure!(
            !retirement_required,
            "inactive slot remains referenced by a retained image; retire it before staging"
        );
    }
    let document = request
        .delivery
        .pointer("/artifact_contract/document")
        .context("delivery has no authenticated metadata document")?;
    verify_path(
        &request.metadata,
        integer(document, "byte_size")?,
        string(document, "sha256")?,
    )?;
    ensure!(
        request.artifacts
            == Path::new(string(
                request
                    .delivery
                    .pointer("/artifact_contract/artifacts")
                    .context("delivery has no artifact set")?,
                "store_path"
            )?),
        "staging artifact set differs from signed delivery"
    );
    let metadata: Value = serde_json::from_slice(&read_bounded(&request.metadata, 1024 * 1024)?)?;
    ensure!(
        matches!(
            string(&metadata, "schema_version")?,
            "aos.image.metadata/v1" | "aos.image.metadata/v2"
        ),
        "unknown finalized image metadata"
    );
    ensure!(
        string(&metadata, "version")? == candidate_version,
        "finalized version differs from candidate"
    );
    let root = metadata
        .get("root")
        .context("metadata has no root identity")?;
    let disk = metadata
        .get("disk")
        .context("metadata has no disk identity")?;
    let logical = disk
        .get("logical")
        .context("metadata has no logical disk")?;
    ensure!(
        digest_hex(string(logical, "sha256")?)?
            == digest_hex(string(&request.delivery, "logical_disk_sha256")?)?,
        "logical disk identity differs from signed delivery"
    );
    verify_path(
        &request.source,
        integer(&request.delivery, "byte_size")?,
        string(&request.delivery, "sha256")?,
    )?;

    let scratch = tempfile::Builder::new()
        .prefix("aos-image-stage-")
        .tempdir_in("/var/tmp")?;
    let raw_path = scratch.path().join("source.raw");
    let mut raw = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&raw_path)?;
    let input = File::open(&request.source)?;
    let mut decoder = zstd::stream::read::Decoder::new(input)?;
    let limit = integer(logical, "size_bytes")?;
    let written = io::copy(
        &mut decoder
            .by_ref()
            .take(limit.checked_add(1).context("logical size overflow")?),
        &mut raw,
    )?;
    ensure!(written == limit, "raw delivery expands to another length");
    raw.sync_all()?;
    verify_path(&raw_path, limit, string(logical, "sha256")?)?;
    let layout = disk
        .get("layout")
        .context("metadata has no partition geometry")?;
    // Finalized logical disks use the assembly's 512-byte GPT geometry.
    let root_offset = integer(layout, "root_a_start")?
        .checked_mul(512)
        .context("root offset overflow")?;
    let hash_offset = integer(layout, "root_a_hash_start")?
        .checked_mul(512)
        .context("verity offset overflow")?;
    let root_size = integer(root, "filesystem_size_bytes")?;
    let hash_size = integer(root, "verity_size_bytes")?;
    let root_path = scratch.path().join("root.img");
    let hash_path = scratch.path().join("root.verity");
    extract_range(
        &raw_path,
        &root_path,
        root_offset,
        root_size,
        integer(layout, "root_sectors")?,
    )?;
    extract_range(
        &raw_path,
        &hash_path,
        hash_offset,
        hash_size,
        integer(layout, "hash_sectors")?,
    )?;
    verify_path(&root_path, root_size, string(root, "filesystem_sha256")?)?;
    verify_path(&hash_path, hash_size, string(root, "verity_sha256")?)?;
    successful(
        Command::new(&tools.veritysetup)
            .arg("verify")
            .arg(&root_path)
            .arg(&hash_path)
            .arg(string(root, "root_hash")?),
    )?;

    let artifacts = if request.artifacts.join("artifacts").is_dir() {
        request.artifacts.join("artifacts")
    } else {
        request.artifacts.clone()
    };
    let efi = metadata
        .get("efi")
        .context("metadata has no EFI identity")?;
    let normal = efi
        .get(format!("normal_{target}"))
        .context("metadata has no target UKI")?;
    let recovery = prepare_recovery(
        efi,
        &artifacts,
        target,
        candidate_version,
        request.generation,
    )?;
    let fact = normal
        .get("artifact")
        .context("target UKI has no artifact identity")?;
    let uki_path = artifact_path(&artifacts, fact)?;
    verify_path(
        &uki_path,
        integer(fact, "size_bytes")?,
        string(fact, "sha256")?,
    )?;
    let identity = read_candidate_boot_identity(&uki_path)?;
    ensure!(
        identity.slot != active.slot && identity.root_hash == string(root, "root_hash")?,
        "target UKI does not bind the opposite slot and authenticated root"
    );
    let measurement = artifact_path(
        &artifacts,
        normal
            .get("measurement")
            .context("target UKI lacks measurement evidence")?,
    )?;
    let signature = artifact_path(
        &artifacts,
        normal
            .get("measurement_signature")
            .context("target UKI lacks measurement signature")?,
    )?;
    for (path, key) in [
        (&measurement, "measurement"),
        (&signature, "measurement_signature"),
    ] {
        let value = normal
            .get(key)
            .context("target UKI lacks measurement evidence")?;
        verify_path(
            path,
            integer(value, "size_bytes")?,
            string(value, "sha256")?,
        )?;
    }

    let devices = discover_devices(&tools.blkid)?;
    let destination = &devices[&format!("root-{target}")];
    let hash_destination = &devices[&format!("root-{target}-hash")];
    check_device_unused(destination)?;
    check_device_unused(hash_destination)?;
    validate_block_capacity(destination, root_size)?;
    validate_block_capacity(hash_destination, hash_size)?;
    validate_esp_mount(&devices["ESP"])?;
    validate_candidate_root(&root_path, request, tools, scratch.path())?;
    if request.action == StageAction::Preflight {
        return Ok(json!({
            "schema":"aos.image-candidate-stage-preflight",
            "generation":request.generation,
            "retirement_required":retirement_required,
        }));
    }
    let running_top = Path::new(string(&request.running, "toplevel")?);
    ensure!(
        fs::read_link("/run/current-system")? == running_top,
        "staging running image differs from the immutable boot identity"
    );
    // The fixed-point image build wires the same immutable initrd into its
    // toplevel and UKI. Read that retained source, independent of EFI names
    // consumed by boot counting or optional bootstrap measurement fields.
    let running_initrd = fs::canonicalize(running_top.join("initrd"))?;
    aos_release_format::artifact::require_store_path(
        running_initrd
            .to_str()
            .context("running initrd is not UTF-8")?,
        false,
    )?;
    let running_inventory =
        crate::initrd_archive::registered_initrd_roots(&running_initrd.join("initrd.img"))?;
    let candidate_inventory = crate::initrd_archive::registered_roots(&uki_path)?;
    let journal = crate::initrd_store::writable_journal(
        &request.initrd_state_directory,
        &request.initrd_storage_root,
        Path::new(BOOT_ROOT),
    )?;
    // Boot commit restores the ESP read-only. Publish the capsule through its
    // checked /boot view without changing the sealed journal mount's access.
    with_writable_boot(&tools.mount, || {
        crate::initrd_store::preserve(
            &tools.nix_store,
            &journal,
            &request.retained_initrd_store_roots,
            &running_inventory,
            &candidate_inventory,
        )
        .context("publishing retained initrd store capsule")
    })?;
    copy_up::persist(&tools.nix_store, request)?;
    write_block(
        &root_path,
        destination,
        root_size,
        string(root, "filesystem_sha256")?,
    )?;
    write_block(
        &hash_path,
        hash_destination,
        hash_size,
        string(root, "verity_sha256")?,
    )?;
    successful(
        Command::new(&tools.veritysetup)
            .arg("verify")
            .arg(destination)
            .arg(hash_destination)
            .arg(string(root, "root_hash")?),
    )?;
    let source = candidate_path(request.generation)?;
    publish_candidate(
        Path::new(IMAGE_PROFILE),
        request.generation,
        &uki_path,
        &measurement,
        &signature,
        recovery.as_ref(),
    )?;
    let mut receipt = json!({
        "schema":"aos.image-candidate-staged", "generation":request.generation,
        "toplevel":string(&request.candidate, "toplevel")?,
        "boot_artifact_contract":string(&request.candidate, "boot_artifact_contract")?,
        "boot_provider_state":{
            "schema":"aos.systemd.boot-generation-state/v1",
            "evidence":{
                "installed-entry":format!("EFI/Linux/candidate-gen{}+3.efi", request.generation),
                "uki-source-path":source,
                "uki-sha256":string(fact,"sha256")?, "uki-byte-size":integer(fact,"size_bytes")?,
                "slot":target.to_ascii_uppercase()
            }
        }
    });
    if let Some(recovery) = recovery {
        receipt["boot_provider_state"]["evidence"]["recovery"] =
            serde_json::to_value(recovery.evidence)?;
    }
    Ok(receipt)
}

fn prepare_recovery(
    efi: &Value,
    artifacts: &Path,
    target: &str,
    release: &str,
    generation: u32,
) -> Result<Option<PreparedRecovery>> {
    let copy_a = efi.get("recovery_a").filter(|value| !value.is_null());
    let copy_b = efi.get("recovery_b").filter(|value| !value.is_null());
    ensure!(
        copy_a.is_some() == copy_b.is_some(),
        "candidate metadata has an incomplete recovery pair"
    );
    let Some(fact) = (match target {
        "a" => copy_a,
        "b" => copy_b,
        _ => anyhow::bail!("recovery target has an invalid slot"),
    }) else {
        return Ok(None);
    };
    ensure!(
        copy_a.is_some_and(Value::is_object) && copy_b.is_some_and(Value::is_object),
        "candidate recovery facts are not artifact objects"
    );

    let uki = artifact_path(artifacts, fact)?;
    let byte_size = integer(fact, "size_bytes")?;
    ensure!(
        byte_size > 0 && byte_size <= 512 * 1024 * 1024,
        "candidate recovery UKI exceeds its byte bound"
    );
    let sha256 = string(fact, "sha256")?;
    verify_path(&uki, byte_size, sha256)?;
    let copy = target.to_ascii_uppercase();
    let recovery_abi = validate_uki_identity(&uki, &copy, release)?;
    let evidence = RecoveryEvidence {
        copy: copy.clone(),
        uki_path: format!("EFI/AOS/recovery-{target}.efi"),
        entry_path: format!("loader/entries/recovery-{target}.conf"),
        source_path: format!("candidates/{generation}/recovery-{target}.efi"),
        sha256: digest_hex(sha256)?.to_string(),
        byte_size,
        release: release.to_string(),
        recovery_abi,
    };
    evidence.validate_identity(&copy)?;

    let entry = artifact_path(
        artifacts,
        &json!({"path":format!("recovery-{target}.conf")}),
    )?;
    ensure!(
        read_bounded(&entry, 4096)? == evidence.entry_bytes()?,
        "candidate recovery loader entry differs from its authenticated identity"
    );
    Ok(Some(PreparedRecovery {
        evidence,
        uki,
        entry,
    }))
}

fn slot_occupied(generations: &[Value], target: &str) -> Result<bool> {
    let mut occupied = false;
    for generation in generations {
        if generation
            .pointer("/boot_provider_state/evidence/retired")
            .and_then(Value::as_bool)
            == Some(true)
        {
            continue;
        }
        let slot = generation
            .pointer("/boot_provider_state/evidence/slot")
            .and_then(Value::as_str)
            .context("retained image lacks a physical slot identity")?;
        ensure!(
            matches!(slot, "A" | "B" | "a" | "b"),
            "retained image has an unknown physical slot"
        );
        occupied |= slot.eq_ignore_ascii_case(target);
    }
    Ok(occupied)
}

fn validate_candidate_root(
    root: &Path,
    request: &Request,
    tools: &Tools,
    scratch: &Path,
) -> Result<()> {
    let mounted = scratch.join("root");
    fs::create_dir(&mounted)?;
    successful(
        Command::new(&tools.mount)
            .args(["-t", "erofs", "-o", "loop,ro,nodev,nosuid,noexec"])
            .arg(root)
            .arg(&mounted),
    )?;
    let validation = validate_candidate_metadata(&mounted, &request.candidate);
    let unmount = successful(Command::new(&tools.umount).arg(&mounted));
    validation?;
    unmount
}

fn validate_candidate_metadata(mounted: &Path, candidate: &Value) -> Result<()> {
    let toplevel_value = string(candidate, "toplevel")?;
    let toplevel = Path::new(toplevel_value);
    ensure!(
        copy_up::store_root(toplevel_value)? == toplevel,
        "candidate toplevel is not an exact store root"
    );
    ensure!(
        fs::read_link(mounted.join("usr/lib/aos/toplevel"))
            .context("reading candidate root toplevel link")?
            == toplevel,
        "candidate root embeds another toplevel"
    );

    // /nix is an empty overlay mountpoint in the unbooted image. Inspect its
    // immutable lower directly instead of resolving paths through the host.
    let metadata = mounted
        .join("usr/lib/aos")
        .join(toplevel.strip_prefix("/")?)
        .join("meta");
    for (file, field) in [
        ("package-name", "package_name"),
        ("version", "version"),
        ("state-version", "state_version"),
        ("native-executor-ref", "native_executor_ref"),
        ("boot-artifact-contract", "boot_artifact_contract"),
        ("evaluation-descriptor", "evaluation_descriptor"),
    ] {
        let path = metadata.join(file);
        let bytes = read_bounded(&path, 64 * 1024)
            .with_context(|| format!("reading candidate root metadata {}", path.display()))?;
        ensure!(
            std::str::from_utf8(&bytes)?.trim() == string(candidate, field)?,
            "candidate root metadata differs at {file}"
        );
    }

    let library_path = metadata.join("module-library.json");
    let library: Value =
        serde_json::from_slice(&read_bounded(&library_path, 64 * 1024).with_context(|| {
            format!("reading candidate root metadata {}", library_path.display())
        })?)?;
    ensure!(
        candidate.get("module_library") == Some(&library),
        "candidate root module library differs"
    );
    Ok(())
}

fn discover_devices(blkid: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut devices = BTreeMap::new();
    let mut parent = None;
    for label in [
        "ESP",
        "root-a",
        "root-a-hash",
        "root-b",
        "root-b-hash",
        "var",
    ] {
        let output = Command::new(blkid)
            .args(["-c", "/dev/null", "-o", "device", "-t"])
            .arg(format!("PARTLABEL={label}"))
            .output()?;
        ensure!(
            output.status.success(),
            "cannot discover installed partition {label}"
        );
        let text = std::str::from_utf8(&output.stdout)?;
        let matches = text
            .lines()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "installed partition {label} is missing or ambiguous"
        );
        let path = fs::canonicalize(matches[0])?;
        ensure!(
            path.starts_with("/dev") && fs::metadata(&path)?.file_type().is_block_device(),
            "installed partition is not a device"
        );
        let sys = fs::canonicalize(
            Path::new("/sys/class/block").join(path.file_name().context("block node has no name")?),
        )?;
        ensure!(
            sys.join("partition").is_file(),
            "installed node is not a partition"
        );
        let disk = sys
            .parent()
            .context("partition has no parent")?
            .to_path_buf();
        ensure!(
            fs::read_to_string(disk.join("removable"))?.trim() == "0",
            "installed disk is removable"
        );
        if let Some(expected) = &parent {
            ensure!(
                expected == &disk,
                "installed partitions belong to different disks"
            );
        } else {
            parent = Some(disk);
        }
        devices.insert(label.into(), path);
    }
    Ok(devices)
}

fn check_device_unused(device: &Path) -> Result<()> {
    let name = device.file_name().context("block node has no name")?;
    ensure!(
        fs::read_dir(Path::new("/sys/class/block").join(name).join("holders"))?
            .next()
            .is_none(),
        "inactive partition has an active device-mapper holder"
    );
    let device_id = fs::read_to_string(Path::new("/sys/class/block").join(name).join("dev"))?;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        ensure!(
            line.split_ascii_whitespace().nth(2) != Some(device_id.trim()),
            "inactive partition is mounted"
        );
    }
    Ok(())
}

fn validate_esp_mount(esp: &Path) -> Result<()> {
    let name = esp.file_name().context("ESP node has no name")?;
    let id = fs::read_to_string(Path::new("/sys/class/block").join(name).join("dev"))?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let matches = mounts
        .lines()
        .filter(|line| line.split_ascii_whitespace().nth(4) == Some("/boot"))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0].split_ascii_whitespace().nth(2) == Some(id.trim())
            && matches[0].contains(" - vfat "),
        "boot mount is not the authenticated ESP"
    );
    Ok(())
}

fn extract_range(
    source: &Path,
    destination: &Path,
    offset: u64,
    size: u64,
    sectors: u64,
) -> Result<()> {
    ensure!(
        size > 0
            && size
                <= sectors
                    .checked_mul(512)
                    .context("partition size overflow")?,
        "component exceeds partition extent"
    );
    let mut input = File::open(source)?;
    ensure!(
        offset
            .checked_add(size)
            .is_some_and(|end| end <= input.metadata().map(|m| m.len()).unwrap_or(0)),
        "component is outside logical disk"
    );
    input.seek(SeekFrom::Start(offset))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    ensure!(
        io::copy(&mut input.take(size), &mut output)? == size,
        "short component extraction"
    );
    output.sync_all()?;
    Ok(())
}

fn validate_block_capacity(destination: &Path, size: u64) -> Result<()> {
    let mut device = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(destination)?;
    ensure!(
        device.metadata()?.file_type().is_block_device(),
        "destination is not a block device"
    );
    ensure!(
        device.seek(SeekFrom::End(0))? >= size,
        "destination partition is smaller than candidate"
    );
    Ok(())
}

fn write_block(source: &Path, destination: &Path, size: u64, digest: &str) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(destination)?;
    ensure!(
        output.metadata()?.file_type().is_block_device(),
        "destination is not a block device"
    );
    // A regular seek on the already opened device obtains its usable extent.
    ensure!(
        output.seek(SeekFrom::End(0))? >= size,
        "destination partition is smaller than candidate"
    );
    output.seek(SeekFrom::Start(0))?;
    ensure!(
        io::copy(&mut File::open(source)?.take(size), &mut output)? == size,
        "short inactive slot write"
    );
    output.sync_all()?;
    let input = File::open(destination)?;
    ensure!(
        digest_reader(&mut input.take(size))? == digest_hex(digest)?,
        "inactive slot read-back differs"
    );
    Ok(())
}

fn publish_candidate(
    profile: &Path,
    generation: u32,
    uki: &Path,
    measurement: &Path,
    signature: &Path,
    recovery: Option<&PreparedRecovery>,
) -> Result<()> {
    candidate_path(generation)?;
    let candidates = private_directory(profile, "candidates")?;
    let destination = private_directory(&candidates, &generation.to_string())?;
    let mut sources = vec![
        (uki, "candidate.efi".to_string()),
        (measurement, "candidate.efi.measurement".to_string()),
        (signature, "candidate.efi.measurement.sig".to_string()),
    ];
    if let Some(recovery) = recovery {
        let copy = recovery.evidence.copy.to_ascii_lowercase();
        sources.push((&recovery.uki, format!("recovery-{copy}.efi")));
        sources.push((&recovery.entry, format!("recovery-{copy}.conf")));
    }
    for (source, name) in sources {
        let temp = destination.join(format!(".{name}.tmp"));
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&temp)?;
        io::copy(&mut File::open(source)?, &mut output)?;
        output.sync_all()?;
        ensure!(
            digest_reader(&mut File::open(&temp)?)? == digest_reader(&mut File::open(source)?)?,
            "hidden boot artifact read-back differs"
        );
        fs::rename(temp, destination.join(name))?;
    }
    File::open(&destination)?.sync_all()?;
    File::open(
        destination
            .parent()
            .context("candidate directory has no parent")?,
    )?
    .sync_all()?;
    Ok(())
}

/// Resolves a canonical component beneath the authenticated immutable artifact tree.
fn artifact_path(root: &Path, fact: &Value) -> Result<PathBuf> {
    let relative = BundlePath::parse(string(fact, "path")?)?;
    let mut path = root.to_path_buf();
    ensure!(
        fs::symlink_metadata(&path)?.is_dir(),
        "artifact root is not a real directory"
    );
    let components = relative.as_str().split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "artifact path traverses a symlink"
        );
        if index + 1 == components.len() {
            ensure!(
                metadata.is_file(),
                "artifact component is not a regular file"
            );
        } else {
            ensure!(metadata.is_dir(), "artifact path parent is not a directory");
        }
    }
    Ok(path)
}

fn read_candidate_boot_identity(path: &Path) -> Result<NormalBootIdentity> {
    // Preflight and staging share this artifact. Reading its identity must not
    // rewrite the PE image or discard its signature, as objcopy can do.
    let cmdline = read_uki_text(path, "cmdline")
        .with_context(|| format!("reading candidate UKI identity from {}", path.display()))?;
    Ok(parse_normal(&cmdline)?)
}

fn verify_path(path: &Path, size: u64, digest: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "staged artifact is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() == size,
        "staged artifact length differs: {}: expected {size} bytes, found {}",
        path.display(),
        metadata.len()
    );
    ensure!(
        digest_reader(&mut file)? == digest_hex(digest)?,
        "staged artifact digest differs: {}",
        path.display()
    );
    Ok(())
}

fn digest_hex(value: &str) -> Result<&str> {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "artifact SHA-256 identity is malformed"
    );
    Ok(hex)
}

fn digest_reader(reader: &mut impl Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let size = reader.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        digest.update(&bytes[..size]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn read_bounded(path: &Path, size: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "metadata is not a regular file");
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(size + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= size, "metadata exceeds its boundary");
    Ok(bytes)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}
fn integer(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing integer {key}"))
}
fn successful(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "selected staging tool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_candidate_identity_reads_preserve_the_complete_pe_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("candidate.efi");
        let root_hash = "0123456789abcdef".repeat(4);
        let cmdline = format!(
            "root=/dev/mapper/root ro systemd.verity=yes \
             systemd.verity_root_data=/dev/disk/by-partlabel/root-b \
             systemd.verity_root_hash=/dev/disk/by-partlabel/root-b-hash \
             roothash={root_hash} rd.luks=0"
        );

        // Preserve the PE optional header, padding and opaque certificate tail,
        // not just the section bytes needed to parse the boot identity.
        let mut original = vec![0_u8; 1024];
        original[..2].copy_from_slice(b"MZ");
        original[60..64].copy_from_slice(&128_u32.to_le_bytes());
        original[128..132].copy_from_slice(b"PE\0\0");
        original[132..134].copy_from_slice(&0x8664_u16.to_le_bytes());
        original[134..136].copy_from_slice(&1_u16.to_le_bytes());
        original[148..150].copy_from_slice(&240_u16.to_le_bytes());
        original[152..154].copy_from_slice(&0x20b_u16.to_le_bytes());
        original[260..264].copy_from_slice(&16_u32.to_le_bytes());
        original[296..300].copy_from_slice(&1024_u32.to_le_bytes());
        original[300..304].copy_from_slice(&4104_u32.to_le_bytes());
        original[392..400].copy_from_slice(b".cmdline");
        original[400..404].copy_from_slice(&(cmdline.len() as u32 + 1).to_le_bytes());
        original[408..412].copy_from_slice(&512_u32.to_le_bytes());
        original[412..416].copy_from_slice(&512_u32.to_le_bytes());
        original[512..512 + cmdline.len()].copy_from_slice(cmdline.as_bytes());
        original.extend_from_slice(&4104_u32.to_le_bytes());
        original.extend_from_slice(&0x0200_u16.to_le_bytes());
        original.extend_from_slice(&2_u16.to_le_bytes());
        original.extend((0..4096).map(|index| (index % 251) as u8));
        fs::write(&path, &original).unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&original)));

        // Preflight and stage both inspect the same authenticated artifact.
        for _ in 0..2 {
            verify_path(&path, original.len() as u64, &digest).unwrap();
            let identity = read_candidate_boot_identity(&path).unwrap();
            assert_eq!(identity.slot, BootSlot::B);
            assert_eq!(identity.root_hash, root_hash);
            verify_path(&path, original.len() as u64, &digest).unwrap();
            assert_eq!(fs::read(&path).unwrap(), original);
        }

        // The provider still rejects a syntactically valid PE with a bad
        // native boot identity; shared reader tests cover PE/text bounds.
        original[512] = b'X';
        fs::write(&path, &original).unwrap();
        assert!(read_candidate_boot_identity(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn candidate_metadata_uses_the_immutable_store_before_overlay_mounting() {
        let image = tempfile::tempdir().unwrap();
        let toplevel = "/nix/store/00000000000000000000000000000000-aos-system-toplevel";
        let candidate = json!({
            "toplevel": toplevel,
            "package_name": "aos",
            "version": "2.0.0",
            "state_version": "1",
            "native_executor_ref": "/nix/store/00000000000000000000000000000000-runtime",
            "boot_artifact_contract": "/nix/store/00000000000000000000000000000000-boot",
            "evaluation_descriptor": "/nix/store/00000000000000000000000000000000-descriptor",
            "module_library": {"store_path": "/nix/store/00000000000000000000000000000000-modules"}
        });
        let metadata = image
            .path()
            .join("usr/lib/aos")
            .join(toplevel.trim_start_matches('/'))
            .join("meta");
        fs::create_dir_all(&metadata).unwrap();
        fs::create_dir(image.path().join("nix")).unwrap();
        std::os::unix::fs::symlink(toplevel, image.path().join("usr/lib/aos/toplevel")).unwrap();

        let fields = [
            ("package-name", "package_name"),
            ("version", "version"),
            ("state-version", "state_version"),
            ("native-executor-ref", "native_executor_ref"),
            ("boot-artifact-contract", "boot_artifact_contract"),
            ("evaluation-descriptor", "evaluation_descriptor"),
        ];
        for (file, field) in fields {
            fs::write(
                metadata.join(file),
                format!("{}\n", candidate[field].as_str().unwrap()),
            )
            .unwrap();
        }
        fs::write(
            metadata.join("module-library.json"),
            serde_json::to_vec(&candidate["module_library"]).unwrap(),
        )
        .unwrap();

        assert!(!image.path().join("nix/store").exists());
        validate_candidate_metadata(image.path(), &candidate).unwrap();

        // A mounted runtime view must not substitute for the candidate's lower.
        let runtime_metadata = image
            .path()
            .join(toplevel.trim_start_matches('/'))
            .join("meta");
        fs::create_dir_all(&runtime_metadata).unwrap();
        fs::write(runtime_metadata.join("version"), "another-image\n").unwrap();
        validate_candidate_metadata(image.path(), &candidate).unwrap();

        for (_, field) in fields {
            let mut changed = candidate.clone();
            changed[field] = json!("another-image");
            let error = validate_candidate_metadata(image.path(), &changed).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("candidate root metadata differs")
            );
        }
        let mut changed = candidate.clone();
        changed["module_library"] = json!({"store_path": "another-library"});
        assert!(validate_candidate_metadata(image.path(), &changed).is_err());

        fs::remove_file(metadata.join("version")).unwrap();
        let error = validate_candidate_metadata(image.path(), &candidate).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reading candidate root metadata")
        );
    }

    #[test]
    fn canonical_artifact_paths_select_exact_payloads_and_reject_escapes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("efi")).unwrap();
        let expected = temp.path().join("efi/uki-b.efi");
        fs::write(&expected, b"signed target slot UKI").unwrap();

        assert_eq!(
            artifact_path(temp.path(), &json!({"path":"efi/uki-b.efi"})).unwrap(),
            expected
        );
        for path in [
            "../outside",
            "/outside",
            "efi//uki-b.efi",
            "efi/./uki-b.efi",
            "efi/../uki-b.efi",
        ] {
            assert!(artifact_path(temp.path(), &json!({"path":path})).is_err());
        }
        assert!(artifact_path(temp.path(), &json!({})).is_err());

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("uki.efi"), b"foreign payload").unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("alias")).unwrap();
        assert!(artifact_path(temp.path(), &json!({"path":"alias/uki.efi"})).is_err());
        std::os::unix::fs::symlink(&expected, temp.path().join("alias.efi")).unwrap();
        assert!(artifact_path(temp.path(), &json!({"path":"alias.efi"})).is_err());
    }

    #[test]
    fn staging_rejects_retained_slot_before_writing() {
        let retained = [json!({"boot_provider_state":{"evidence":{"slot":"B"}}})];
        assert!(slot_occupied(&retained, "b").unwrap());
        assert!(!slot_occupied(&retained, "a").unwrap());
        assert!(slot_occupied(&[json!({})], "b").is_err());
        let retired = [json!({"boot_provider_state":{"evidence":{"slot":"B","retired":true}}})];
        assert!(!slot_occupied(&retired, "b").unwrap());
    }

    #[test]
    fn third_stage_requires_explicit_retirement_of_the_original_slot() {
        let mut generations =
            vec![json!({"number":1,"boot_provider_state":{"evidence":{"slot":"A"}}})];
        assert!(!slot_occupied(&generations, "b").unwrap());
        generations.push(json!({"number":2,"boot_provider_state":{"evidence":{"slot":"B"}}}));
        assert!(slot_occupied(&generations, "a").unwrap());
        generations[0]["boot_provider_state"]["evidence"]["retired"] = json!(true);
        assert!(!slot_occupied(&generations, "a").unwrap());
        generations.push(json!({"number":3,"boot_provider_state":{"evidence":{"slot":"A"}}}));
        assert!(slot_occupied(&generations, "b").unwrap());
    }

    #[test]
    fn authenticated_component_bounds_and_digest_are_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("raw");
        fs::write(&input, b"abcdefghijkl").unwrap();
        let output = temp.path().join("component");
        extract_range(&input, &output, 3, 4, 1).unwrap();
        verify_path(&output, 4, &hex::encode(Sha256::digest(b"defg"))).unwrap();
        verify_path(
            &output,
            4,
            &format!("sha256:{}", hex::encode(Sha256::digest(b"defg"))),
        )
        .unwrap();
        let error = verify_path(&output, 3, &hex::encode(Sha256::digest(b"defg")))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&output.display().to_string()));
        assert!(error.contains("expected 3 bytes"));
        assert!(error.contains("found 4"));
        assert!(extract_range(&input, &temp.path().join("outside"), 11, 4, 1).is_err());
        assert!(extract_range(&input, &temp.path().join("oversize"), 0, 4, 0).is_err());
    }

    #[test]
    fn publication_retains_private_sources_outside_the_esp() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("uki");
        fs::write(&source, b"pinned artifact").unwrap();
        let profile = temp.path().join("profile");
        fs::create_dir(&profile).unwrap();
        publish_candidate(&profile, 2, &source, &source, &source, None).unwrap();
        let hidden = profile.join(candidate_path(2).unwrap());
        assert_eq!(fs::read(&hidden).unwrap(), b"pinned artifact");
        assert!(!temp.path().join("EFI/Linux").exists());
    }

    #[test]
    fn recovery_pair_is_optional_but_cannot_be_partial() {
        let temp = tempfile::tempdir().unwrap();
        let empty = json!({});
        assert!(
            prepare_recovery(&empty, temp.path(), "b", "1.0.0", 2)
                .unwrap()
                .is_none()
        );

        for partial in [json!({"recovery_a":{}}), json!({"recovery_b":{}})] {
            let error = prepare_recovery(&partial, temp.path(), "b", "1.0.0", 2)
                .err()
                .unwrap();
            assert!(error.to_string().contains("incomplete recovery pair"));
        }
    }

    #[test]
    fn interrupted_private_recovery_pair_replays_without_esp_publication() {
        let temp = tempfile::tempdir().unwrap();
        let normal = temp.path().join("normal");
        let recovery_uki = temp.path().join("recovery-source");
        let recovery_entry = temp.path().join("recovery-entry");
        fs::write(&normal, b"signed normal").unwrap();
        fs::write(&recovery_uki, b"signed recovery").unwrap();
        let evidence = RecoveryEvidence {
            copy: "B".to_string(),
            uki_path: "EFI/AOS/recovery-b.efi".to_string(),
            entry_path: "loader/entries/recovery-b.conf".to_string(),
            source_path: "candidates/2/recovery-b.efi".to_string(),
            sha256: hex::encode(Sha256::digest(b"signed recovery")),
            byte_size: 15,
            release: "1.0.0".to_string(),
            recovery_abi: 1,
        };
        let entry_bytes = evidence.entry_bytes().unwrap();
        fs::write(&recovery_entry, &entry_bytes).unwrap();
        let recovery = PreparedRecovery {
            evidence,
            uki: recovery_uki,
            entry: recovery_entry,
        };
        let candidates = private_directory(temp.path(), "candidates").unwrap();
        let generation = private_directory(&candidates, "2").unwrap();
        fs::write(generation.join(".recovery-b.efi.tmp"), b"partial").unwrap();
        fs::write(generation.join(".recovery-b.conf.tmp"), b"partial entry").unwrap();

        for _ in 0..2 {
            publish_candidate(temp.path(), 2, &normal, &normal, &normal, Some(&recovery)).unwrap();
        }

        assert_eq!(
            fs::read(generation.join("recovery-b.efi")).unwrap(),
            b"signed recovery"
        );
        assert_eq!(
            fs::read(generation.join("recovery-b.conf")).unwrap(),
            entry_bytes
        );
        assert_eq!(
            fs::read(generation.join("candidate.efi")).unwrap(),
            b"signed normal"
        );
        assert!(!generation.join(".recovery-b.efi.tmp").exists());
        assert!(!generation.join(".recovery-b.conf.tmp").exists());
        assert!(!temp.path().join("EFI").exists());
    }

    #[test]
    fn interrupted_profile_publication_replays_identical_signed_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("uki");
        fs::write(&source, b"signed candidate").unwrap();
        let candidates = private_directory(temp.path(), "candidates").unwrap();
        let generation = private_directory(&candidates, "2").unwrap();
        fs::write(generation.join(".candidate.efi.tmp"), b"partial").unwrap();

        publish_candidate(temp.path(), 2, &source, &source, &source, None).unwrap();
        publish_candidate(temp.path(), 2, &source, &source, &source, None).unwrap();

        for name in [
            "candidate.efi",
            "candidate.efi.measurement",
            "candidate.efi.measurement.sig",
        ] {
            assert_eq!(
                fs::read(generation.join(name)).unwrap(),
                b"signed candidate"
            );
        }
        assert!(!generation.join(".candidate.efi.tmp").exists());
        assert!(!temp.path().join("EFI").exists());
    }
}
