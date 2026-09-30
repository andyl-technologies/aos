//! Provider-owned import of signed measurements for installed boot artifacts.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const BOOT_ROOT: &str = "/boot";
const IMAGE_STATE: &str = "/var/lib/profiles/image/state.json";
const BOOT_STORAGE_METADATA: &str = "/run/current-system/meta/boot-storage.json";
const MOUNTINFO: &str = "/proc/self/mountinfo";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootStorageMetadata {
    esp_devices: Vec<PathBuf>,
}

struct UkiMeasurement {
    uki_sha256: String,
    expected_pcr11: String,
}

/// Returns authenticated measurements of the physically selected running image.
///
/// # Errors
/// Returns an error for an unretained verifier/key, malformed signed metadata,
/// an ambiguous UKI, mismatched UKI bytes, or invalid signed root measurements.
pub(crate) fn run(arguments: &[String]) -> Result<()> {
    let [
        openssl_flag,
        openssl,
        objcopy_flag,
        objcopy,
        key_flag,
        public_key,
    ] = arguments
    else {
        bail!(
            "usage: aos-systemd-image-evidence --openssl PATH --objcopy PATH --pcr-public-key PATH"
        );
    };
    ensure!(
        openssl_flag == "--openssl"
            && objcopy_flag == "--objcopy"
            && key_flag == "--pcr-public-key",
        "image verifier arguments are not canonical"
    );
    for path in [openssl, objcopy, public_key] {
        let path = Path::new(path);
        ensure!(
            path.is_absolute()
                && path.starts_with("/nix/store")
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                && fs::canonicalize(path)? == path
                && fs::symlink_metadata(path)?.is_file(),
            "image verifier inputs must be canonical immutable files"
        );
    }
    let evidence = verified_evidence(
        Path::new(public_key),
        Path::new(openssl),
        Path::new(objcopy),
    )?;
    std::io::stdout().write_all(&serde_json::to_vec(&evidence)?)?;
    Ok(())
}

fn verified_evidence(public_key: &Path, openssl: &Path, objcopy: &Path) -> Result<Value> {
    validate_boot_mount()?;
    let images: Value =
        serde_json::from_slice(&read_bounded(Path::new(IMAGE_STATE), 1024 * 1024)?)?;
    let running_number = images
        .get("running")
        .and_then(Value::as_u64)
        .context("image state has no running generation number")?;
    let generations = images
        .get("generations")
        .and_then(Value::as_array)
        .context("image state has no generation list")?;
    let matching = generations
        .iter()
        .filter(|generation| {
            generation.get("number").and_then(Value::as_u64) == Some(running_number)
        })
        .collect::<Vec<_>>();
    let [running] = matching.as_slice() else {
        bail!("running image is absent or ambiguous");
    };
    let toplevel = running
        .get("toplevel")
        .and_then(Value::as_str)
        .context("running image omits immutable toplevel")?;
    ensure!(
        fs::read_link("/run/current-system")? == Path::new(toplevel),
        "running image differs from verified immutable boot identity"
    );
    let boot_contract = running
        .get("boot_artifact_contract")
        .and_then(Value::as_str)
        .context("running image omits boot contract")?;
    let provider = running
        .get("boot_provider_state")
        .and_then(|state| state.get("evidence"))
        .context("running image omits backend evidence")?;
    let recorded = safe_source_path(
        provider
            .get("uki-source-path")
            .and_then(Value::as_str)
            .context("running image has no authenticated UKI source path")?,
    )?;
    let recorded_uki = Path::new(BOOT_ROOT).join(&recorded);
    let installed = safe_uki_path(
        provider
            .get("installed-entry")
            .and_then(Value::as_str)
            .context("running image has no installed entry")?,
    )?;
    let live_uki = resolve_unique_live_uki(Path::new(BOOT_ROOT), &installed)?;
    let measurement = PathBuf::from(format!("{}.measurement", recorded_uki.display()));
    let signature = PathBuf::from(format!("{}.sig", measurement.display()));
    read_bounded(&signature, 16 * 1024)?;
    let measurement_bytes = read_bounded(&measurement, 4096)?;
    // Verify the exact buffered document that is parsed below. Re-reading the
    // writable ESP path after verification would introduce a substitution race.
    let mut verifier = Command::new(openssl)
        .env_clear()
        .args(["dgst", "-sha256", "-verify"])
        .arg(public_key)
        .arg("-signature")
        .arg(&signature)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    verifier
        .stdin
        .take()
        .context("signature verifier input is absent")?
        .write_all(&measurement_bytes)?;
    ensure!(
        verifier.wait()?.success(),
        "signed boot measurement verification failed"
    );
    let parsed = parse_measurement(std::str::from_utf8(&measurement_bytes)?)?;
    // Capture the UKI once before checking its signature-bound digest and
    // parsing sections. The ESP can be writable during image maintenance.
    fs::create_dir_all("/run/aos")?;
    let stage = tempfile::Builder::new()
        .prefix("image-evidence-")
        .tempdir_in("/run/aos")?;
    let captured = stage.path().join("uki.efi");
    let source = rustix::fs::open(
        &live_uki,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let source = fs::File::from(source);
    ensure!(
        source.metadata()?.is_file() && source.metadata()?.len() <= 512 * 1024 * 1024,
        "signed UKI is not a bounded regular file"
    );
    let mut captured_file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&captured)?;
    let copied = std::io::copy(&mut source.take(512 * 1024 * 1024 + 1), &mut captured_file)?;
    ensure!(
        copied <= 512 * 1024 * 1024,
        "signed UKI grew beyond its bound"
    );
    captured_file.sync_all()?;
    ensure!(
        sha256_file(&captured)? == parsed.uki_sha256,
        "signed measurement belongs to a different boot artifact"
    );

    let cmdline_path = stage.path().join("cmdline");
    let status = Command::new(objcopy)
        .env_clear()
        .args(["-O", "binary", "--only-section=.cmdline"])
        .arg(&captured)
        .arg(&cmdline_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    ensure!(
        status.success(),
        "extracting signed UKI command line failed"
    );
    let cmdline = read_bounded(&cmdline_path, 64 * 1024)?;
    let cmdline = std::str::from_utf8(&cmdline)?.trim_end_matches('\0');
    ensure!(
        !cmdline.contains('\0'),
        "signed UKI command line contains an embedded NUL"
    );
    let root_hash = unique_parameter(cmdline, "roothash")?;
    if let Some(root_hash) = &root_hash {
        ensure!(
            is_lower_hex_digest(root_hash),
            "signed root hash is not canonical SHA-256"
        );
    }
    let root_uuid = unique_parameter(cmdline, "aos.verity-uuid")?;
    if let Some(uuid) = &root_uuid {
        ensure!(
            uuid.len() == 36
                && uuid.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "signed verity UUID is not canonical"
        );
    }
    Ok(
        serde_json::json!({"toplevel":toplevel,"boot_artifact_contract":boot_contract,
        "expected_pcr11":parsed.expected_pcr11,"root_verity_roothash":root_hash,
        "root_verity_uuid":root_uuid}),
    )
}

fn unique_parameter(cmdline: &str, name: &str) -> Result<Option<String>> {
    let prefix = format!("{name}=");
    let matches = cmdline
        .split_ascii_whitespace()
        .filter_map(|word| word.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [value] if !value.is_empty() => Ok(Some((*value).into())),
        _ => bail!("signed UKI command line has ambiguous or empty {name}"),
    }
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "boot evidence is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "boot evidence grew beyond its bound"
    );
    Ok(bytes)
}

fn validate_boot_mount() -> Result<()> {
    let metadata: BootStorageMetadata = serde_json::from_slice(&fs::read(BOOT_STORAGE_METADATA)?)?;
    ensure!(
        !metadata.esp_devices.is_empty(),
        "boot storage metadata has no ESP devices"
    );
    let mountinfo = fs::read_to_string(MOUNTINFO)?;
    let matches = mountinfo
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let separator = fields.iter().position(|field| *field == "-")?;
            (fields.get(4) == Some(&BOOT_ROOT)).then(|| {
                (
                    fields.get(separator + 2).copied().unwrap_or_default(),
                    fields.get(5).copied().unwrap_or_default(),
                )
            })
        })
        .collect::<Vec<_>>();
    let [(source, options)] = matches.as_slice() else {
        bail!("boot storage mount is absent or ambiguous");
    };
    ensure!(
        options
            .split(',')
            .any(|option| option == "ro" || option == "rw"),
        "boot storage mount has no access mode"
    );
    let source = Path::new(source);
    ensure!(
        metadata
            .esp_devices
            .iter()
            .any(|device| same_device(device, source)),
        "boot storage mount source is outside the selected ESP set"
    );
    Ok(())
}

fn same_device(expected: &Path, actual: &Path) -> bool {
    expected == actual
        || expected
            .canonicalize()
            .ok()
            .zip(actual.canonicalize().ok())
            .is_some_and(|(expected, actual)| expected == actual)
}

fn safe_uki_path(recorded: &str) -> Result<PathBuf> {
    let path = Path::new(recorded);
    let components = path.components().collect::<Vec<_>>();
    let [
        Component::Normal(efi),
        Component::Normal(linux),
        Component::Normal(file),
    ] = components.as_slice()
    else {
        bail!("unsafe recorded boot artifact path {recorded:?}");
    };
    ensure!(
        *efi == "EFI" && *linux == "Linux",
        "boot artifact is outside EFI/Linux"
    );
    ensure!(
        file.to_str()
            .is_some_and(|name| name.len() > 4 && name.ends_with(".efi")),
        "invalid boot artifact filename"
    );
    Ok(path.to_path_buf())
}

fn safe_source_path(value: &str) -> Result<PathBuf> {
    if let Ok(path) = safe_uki_path(value) {
        return Ok(path);
    }
    let parts = value.split('/').collect::<Vec<_>>();
    ensure!(
        parts.len() == 4
            && parts[0] == "EFI"
            && parts[1] == ".aos-candidates"
            && parts[3] == "candidate.efi",
        "invalid staged UKI source"
    );
    let generation: u32 = parts[2].parse()?;
    ensure!(
        generation > 0 && generation.to_string() == parts[2],
        "invalid staged generation"
    );
    Ok(PathBuf::from(value))
}

fn resolve_unique_live_uki(boot_root: &Path, recorded: &Path) -> Result<PathBuf> {
    let exact = boot_root.join(recorded);
    if exact.is_file() {
        return Ok(exact);
    }
    let filename = recorded
        .file_name()
        .and_then(|name| name.to_str())
        .context("recorded boot artifact has no UTF-8 filename")?;
    let stable = stable_entry(filename)?;
    let stem = stable
        .strip_suffix(".efi")
        .context("stable boot entry has no suffix")?;
    let directory = boot_root.join("EFI/Linux");
    let mut matching = fs::read_dir(&directory)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name == stable || (name.starts_with(&format!("{stem}+")) && name.ends_with(".efi"))
            })
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "live boot artifact is missing or ambiguous"
    );
    Ok(matching.remove(0))
}

fn stable_entry(entry: &str) -> Result<String> {
    let stem = entry
        .strip_suffix(".efi")
        .context("boot entry has no .efi suffix")?;
    let stable = match stem.rsplit_once('+') {
        Some((base, tries))
            if !base.is_empty()
                && !tries.is_empty()
                && tries.split('-').count() <= 2
                && tries.split('-').all(|part| {
                    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                }) =>
        {
            base
        }
        Some(_) => bail!("boot entry has an invalid terminal boot count"),
        None => stem,
    };
    Ok(format!("{stable}.efi"))
}

fn parse_measurement(document: &str) -> Result<UkiMeasurement> {
    let lines = document.lines().collect::<Vec<_>>();
    let [schema, uki, expected] = lines.as_slice() else {
        bail!("measurement metadata must contain exactly three lines");
    };
    ensure!(
        *schema == "aos.uki-measurement/v1",
        "unsupported measurement schema"
    );
    let uki_sha256 = uki
        .strip_prefix("uki_sha256=")
        .context("measurement metadata has no boot artifact digest")?;
    let expected_pcr11 = expected
        .strip_prefix("expected_pcr11=sha256:")
        .context("measurement metadata has no PCR 11 digest")?;
    ensure!(
        is_lower_hex_digest(uki_sha256),
        "boot artifact digest is not canonical SHA-256"
    );
    ensure!(
        is_lower_hex_digest(expected_pcr11),
        "PCR 11 digest is not canonical SHA-256"
    );
    Ok(UkiMeasurement {
        uki_sha256: uki_sha256.to_string(),
        expected_pcr11: format!("sha256:{expected_pcr11}"),
    })
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_metadata_is_strict_and_canonical() {
        let parsed = parse_measurement(&format!(
            "aos.uki-measurement/v1\nuki_sha256={}\nexpected_pcr11=sha256:{}\n",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .unwrap();
        assert_eq!(parsed.uki_sha256, "a".repeat(64));
        assert_eq!(parsed.expected_pcr11, format!("sha256:{}", "b".repeat(64)));
        assert!(parse_measurement("aos.uki-measurement/v1\nuki_sha256=AA\n").is_err());
    }
}
