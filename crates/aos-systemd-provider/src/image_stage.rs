//! Stages authenticated systemd images into the opposite immutable root slot.
//!
//! The source disk and every published artifact must match signed delivery
//! metadata. Storage is read-back verified before hidden ESP publication;
//! staging never exposes a discoverable normal boot entry or selects a boot.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use aos_boot_identity::{BootSlot, parse_normal};
use aos_release::artifact::BundlePath;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::executable::validate_store_executable;

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
}

struct Tools {
    mount: PathBuf,
    umount: PathBuf,
    blkid: PathBuf,
    objcopy: PathBuf,
    veritysetup: PathBuf,
}

/// Executes physical staging with exact tool paths supplied by the retained wrapper.
///
/// # Errors
/// Returns an error for invalid input, active-slot or retained-slot conflicts,
/// unsafe device topology, hash or boot identity drift, write/read-back failure,
/// or failure to restore the ESP's read-only posture.
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
        "--objcopy",
        "--veritysetup",
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
        objcopy: paths[3].clone(),
        veritysetup: paths[4].clone(),
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
    let fact = normal
        .get("artifact")
        .context("target UKI has no artifact identity")?;
    let uki_path = artifact_path(&artifacts, fact)?;
    verify_path(
        &uki_path,
        integer(fact, "size_bytes")?,
        string(fact, "sha256")?,
    )?;
    let cmdline = scratch.path().join("uki.cmdline");
    successful(
        Command::new(&tools.objcopy)
            .arg("--dump-section")
            .arg(format!(".cmdline={}", cmdline.display()))
            .arg(&uki_path),
    )?;
    let identity = parse_normal(
        std::str::from_utf8(&read_bounded(&cmdline, 64 * 1024)?)?.trim_end_matches('\0'),
    )?;
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
    validate_esp_mount(&devices["ESP"])?;
    successful(Command::new(&tools.mount).args(["-o", "remount,rw", "/boot"]))?;
    let hidden = format!("EFI/.aos-candidates/{}", request.generation);
    let publication = publish_hidden(
        &Path::new("/boot").join(&hidden),
        &uki_path,
        &measurement,
        &signature,
    );
    let readonly = successful(Command::new(&tools.mount).args(["-o", "remount,ro", "/boot"]));
    publication?;
    readonly?;
    Ok(json!({
        "schema":"aos.image-candidate-staged", "generation":request.generation,
        "toplevel":string(&request.candidate, "toplevel")?,
        "boot_artifact_contract":string(&request.candidate, "boot_artifact_contract")?,
        "boot_provider_state":{
            "schema":"aos.systemd.boot-generation-state/v1",
            "evidence":{
                "installed-entry":format!("EFI/Linux/candidate-gen{}+3.efi", request.generation),
                "uki-source-path":format!("{hidden}/candidate.efi"),
                "uki-sha256":string(fact,"sha256")?, "uki-byte-size":integer(fact,"size_bytes")?,
                "slot":target.to_ascii_uppercase()
            }
        }
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
    let validation = (|| {
        let toplevel = Path::new(string(&request.candidate, "toplevel")?);
        ensure!(
            fs::read_link(mounted.join("usr/lib/aos/toplevel"))? == toplevel,
            "candidate root embeds another toplevel"
        );
        let metadata = mounted.join(toplevel.strip_prefix("/")?).join("meta");
        for (file, field) in [
            ("package-name", "package_name"),
            ("version", "version"),
            ("state-version", "state_version"),
            ("native-executor-ref", "native_executor_ref"),
            ("boot-artifact-contract", "boot_artifact_contract"),
            ("evaluation-descriptor", "evaluation_descriptor"),
        ] {
            let bytes = read_bounded(&metadata.join(file), 64 * 1024)?;
            ensure!(
                std::str::from_utf8(&bytes)?.trim() == string(&request.candidate, field)?,
                "candidate root metadata differs at {file}"
            );
        }
        let library: Value = serde_json::from_slice(&read_bounded(
            &metadata.join("module-library.json"),
            64 * 1024,
        )?)?;
        ensure!(
            request.candidate.get("module_library") == Some(&library),
            "candidate root module library differs"
        );
        Ok(())
    })();
    let unmount = successful(Command::new(&tools.umount).arg(&mounted));
    validation?;
    unmount
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

fn publish_hidden(
    destination: &Path,
    uki: &Path,
    measurement: &Path,
    signature: &Path,
) -> Result<()> {
    fs::create_dir_all(destination)?;
    for (source, name) in [
        (uki, "candidate.efi"),
        (measurement, "candidate.efi.measurement"),
        (signature, "candidate.efi.measurement.sig"),
    ] {
        let temp = destination.join(format!(".{name}.tmp"));
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
    File::open(destination)?.sync_all()?;
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

fn verify_path(path: &Path, size: u64, digest: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() == size,
        "staged artifact length differs"
    );
    ensure!(
        digest_reader(&mut file)? == digest_hex(digest)?,
        "staged artifact digest differs"
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
        assert!(verify_path(&output, 3, &hex::encode(Sha256::digest(b"defg"))).is_err());
        assert!(extract_range(&input, &temp.path().join("outside"), 11, 4, 1).is_err());
        assert!(extract_range(&input, &temp.path().join("oversize"), 0, 4, 0).is_err());
    }

    #[test]
    fn publication_keeps_normal_entries_hidden() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("uki");
        fs::write(&source, b"pinned artifact").unwrap();
        let hidden = temp.path().join("EFI/.aos-candidates/2");
        publish_hidden(&hidden, &source, &source, &source).unwrap();
        assert_eq!(
            fs::read(hidden.join("candidate.efi")).unwrap(),
            b"pinned artifact"
        );
        assert!(!temp.path().join("EFI/Linux").exists());
    }
}
