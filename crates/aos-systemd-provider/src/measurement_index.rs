//! Provider-owned import of signed measurements for installed boot artifacts.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
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

/// Imports the signed PCR 11 expectation for the running seed image.
///
/// # Errors
///
/// Returns an error when the selected ESP, running image state, boot artifact,
/// signed measurement, or public key cannot be authenticated exactly.
pub(crate) fn run(arguments: &[String]) -> Result<()> {
    let [flag, public_key] = arguments else {
        bail!("usage: aos-systemd-image-measurement-index --pcr-public-key PATH");
    };
    ensure!(
        flag == "--pcr-public-key",
        "unknown measurement-index argument"
    );
    let public_key = PathBuf::from(public_key);
    ensure!(
        public_key.is_absolute(),
        "PCR public key path must be absolute"
    );

    import_measurement(&public_key)
}

fn import_measurement(public_key: &Path) -> Result<()> {
    validate_boot_mount()?;

    let state_path = Path::new(IMAGE_STATE);
    let mut images: Value = serde_json::from_slice(
        &fs::read(state_path).with_context(|| format!("reading {}", state_path.display()))?,
    )
    .context("decoding image generation state")?;
    let running_number = images
        .get("running")
        .and_then(Value::as_u64)
        .context("image state has no running generation number")?;
    let generations = images
        .get_mut("generations")
        .and_then(Value::as_array_mut)
        .context("image state has no generation list")?;
    let mut matching = generations.iter_mut().filter(|generation| {
        generation.get("number").and_then(Value::as_u64) == Some(running_number)
    });
    let running = matching
        .next()
        .context("running image generation is absent")?;
    ensure!(
        matching.next().is_none(),
        "running image generation is ambiguous"
    );
    let registry = running
        .get("registry")
        .and_then(Value::as_str)
        .context("running image has no registry")?;
    if registry != "seed" {
        ensure!(
            running
                .get("expected_pcr11")
                .and_then(Value::as_str)
                .is_some_and(|digest| !digest.is_empty()),
            "registry image has no authenticated PCR 11 expectation"
        );
        return Ok(());
    }

    let recorded = safe_uki_path(
        running
            .get("uki_path")
            .and_then(Value::as_str)
            .context("running image has no boot artifact path")?,
    )?;
    let recorded_uki = Path::new(BOOT_ROOT).join(&recorded);
    let live_uki = resolve_unique_live_uki(Path::new(BOOT_ROOT), &recorded)?;
    let measurement = PathBuf::from(format!("{}.measurement", recorded_uki.display()));
    let signature = PathBuf::from(format!("{}.sig", measurement.display()));
    for required in [
        live_uki.as_path(),
        measurement.as_path(),
        signature.as_path(),
        public_key,
    ] {
        ensure!(
            required.is_file(),
            "required file is missing: {}",
            required.display()
        );
    }

    run_command(
        Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(public_key)
            .arg("-signature")
            .arg(&signature)
            .arg(&measurement),
        "verifying signed boot measurement metadata",
    )?;
    let parsed = parse_measurement(&fs::read_to_string(&measurement)?)?;
    ensure!(
        sha256_file(&live_uki)? == parsed.uki_sha256,
        "measurement metadata belongs to a different boot artifact"
    );

    if let Some(recorded) = running.get("expected_pcr11").and_then(Value::as_str) {
        ensure!(
            recorded == parsed.expected_pcr11,
            "catalog and signed boot artifact PCR 11 disagree"
        );
        return Ok(());
    }
    running["expected_pcr11"] = Value::String(parsed.expected_pcr11);
    write_atomic(state_path, &serde_json::to_vec_pretty(&images)?)
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
            if !base.is_empty() && tries.bytes().all(|byte| byte.is_ascii_digit()) =>
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

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("image state path has no parent")?;
    let temporary = parent.join(".measurement-index-state.tmp");
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(&temporary)?,
        Ok(_) => bail!("measurement index temporary path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn run_command(command: &mut Command, action: &str) -> Result<()> {
    let status = command.status().with_context(|| action.to_string())?;
    ensure!(status.success(), "{action} failed with {status}");
    Ok(())
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
