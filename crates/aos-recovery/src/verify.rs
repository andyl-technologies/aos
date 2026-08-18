//! Verifies immutable normal slots without mounting their filesystems.
//!
//! Authority is the db-signed manifest embedded in the recovery initrd plus
//! the db signature covering each normal UKI. The verifier uses only fixed
//! executable paths, fixed device paths selected by [`BootSlot`], and UKI
//! filenames discovered beneath the read-only ESP. A successful result is a
//! capability retained by the calling recovery session.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aos_boot_identity::{BootSlot, parse_normal};

use crate::device::discover_host_layout;

const DB_CERT: &str = "/etc/aos/trust/db.crt";
const MANIFEST: &str = "/lib/aos/recovery/slot-manifest.json";
const MANIFEST_SIGNATURE: &str = "/lib/aos/recovery/slot-manifest.json.sig";
const WORK_DIR: &str = "/run/aos-recovery";
const ESP_MOUNT: &str = "/run/aos-recovery/esp";
const SUPPORTED_RECOVERY_ABI: &str = "1";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_NORMAL_UKIS: usize = 64;
const MAX_UKI_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TEXT_SECTION_BYTES: u64 = 64 * 1024;

const MANIFEST_FILTER: &str = r#"
  def exact_keys($keys): (keys | sort) == ($keys | sort);
  def digest: type == "string" and test("^[0-9a-f]{64}$");
  if (. | exact_keys(["schema", "release", "recoveryAbi", "slots"]))
     and .schema == "aos.recovery-slot-manifest/v1"
     and (.release | type == "string" and test("^[A-Za-z0-9._+-]+$") and length <= 128)
     and .recoveryAbi == 1
     and (.slots | exact_keys(["A", "B"]))
     and all(.slots[];
       exact_keys(["rootData", "rootHashDevice", "rootHash", "ukiSha256"])
       and (.rootHash | digest)
       and (.ukiSha256 | digest))
     and .slots.A.rootData == "/dev/disk/by-partlabel/root-a"
     and .slots.A.rootHashDevice == "/dev/disk/by-partlabel/root-a-hash"
     and .slots.B.rootData == "/dev/disk/by-partlabel/root-b"
     and .slots.B.rootHashDevice == "/dev/disk/by-partlabel/root-b-hash"
  then [.release, (.recoveryAbi | tostring), .slots[$slot].rootData,
        .slots[$slot].rootHashDevice, .slots[$slot].rootHash,
        .slots[$slot].ukiSha256] | @tsv
  else error("invalid recovery slot manifest")
  end
"#;

/// Reports a precise failed boundary in offline slot verification.
#[derive(Debug)]
pub enum VerificationError {
    /// A required fixed-path file or directory operation failed.
    Io(io::Error),
    /// A fixed helper failed or returned malformed output.
    Helper(String),
    /// The db-authenticated manifest failed strict schema validation.
    Manifest(String),
    /// No unique normal UKI matched the authenticated slot digest.
    UkiMatch { count: usize },
    /// The matched normal UKI failed db signature validation.
    UkiSignature,
    /// The signed UKI carried a malformed or mismatched release identity.
    ReleaseIdentity(String),
    /// The signed UKI command line failed normal identity validation.
    BootIdentity(String),
    /// The signed UKI selected a different immutable slot.
    SlotMismatch,
    /// The signed UKI root hash disagreed with authenticated metadata.
    RootHashMismatch,
    /// The root and hash partitions failed full dm-verity verification.
    Verity,
    /// A one-shot boot was requested without same-session verification.
    NotVerified(BootSlot),
    /// An invariant internal to the recovery process was violated.
    Internal(String),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O failure: {error}"),
            Self::Helper(reason) => write!(formatter, "recovery helper failed: {reason}"),
            Self::Manifest(reason) => write!(formatter, "slot manifest rejected: {reason}"),
            Self::UkiMatch { count } => {
                write!(
                    formatter,
                    "expected one authenticated normal UKI, found {count}"
                )
            }
            Self::UkiSignature => formatter.write_str("normal UKI db signature rejected"),
            Self::ReleaseIdentity(reason) => {
                write!(formatter, "signed release identity rejected: {reason}")
            }
            Self::BootIdentity(reason) => {
                write!(formatter, "normal boot identity rejected: {reason}")
            }
            Self::SlotMismatch => formatter.write_str("normal UKI selects the opposite slot"),
            Self::RootHashMismatch => {
                formatter.write_str("normal UKI root hash disagrees with authenticated metadata")
            }
            Self::Verity => formatter.write_str("dm-verity verification failed"),
            Self::NotVerified(slot) => {
                write!(formatter, "slot {slot:?} is not verified in this session")
            }
            Self::Internal(reason) => {
                write!(formatter, "internal recovery invariant failed: {reason}")
            }
        }
    }
}

impl Error for VerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for VerificationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Captures the exact boot entry authorized by successful slot verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSlot {
    /// Immutable slot proven by the normal UKI and dm-verity tree.
    pub slot: BootSlot,
    /// Type-2 entry filename to pass to `bootctl set-oneshot`.
    pub entry_id: String,
    /// Signed release identity carried by the verified UKI.
    pub release: String,
    /// Whether the entry filename currently carries an sd-boot tries suffix.
    pub counted: bool,
}

impl VerifiedSlot {
    /// Sets this exact verified entry for one boot and reboots.
    ///
    /// EFI variables are normally mounted read-only. This method temporarily
    /// remounts only efivarfs read-write, writes `LoaderEntryOneShot`, syncs,
    /// restores the read-only mount, and reboots. It never edits image state or
    /// a normal entry filename.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] if an EFI remount, one-shot selection,
    /// synchronization, read-only restoration, or reboot request fails.
    pub fn boot_once(&self) -> Result<(), VerificationError> {
        let current = verify_slot(self.slot)?;
        if current != *self {
            return Err(VerificationError::Internal(
                "slot identity changed after same-session verification".into(),
            ));
        }
        run_success(
            "/bin/mount",
            [
                "-o",
                "remount,rw,nosuid,nodev,noexec",
                "/sys/firmware/efi/efivars",
            ],
        )?;

        let selection = run_success(
            "/bin/bootctl",
            [
                "--esp-path",
                ESP_MOUNT,
                "set-oneshot",
                self.entry_id.as_str(),
            ],
        );
        let sync = run_success("/bin/sync", std::iter::empty::<&str>());
        let restore = run_success(
            "/bin/mount",
            [
                "-o",
                "remount,ro,nosuid,nodev,noexec",
                "/sys/firmware/efi/efivars",
            ],
        );

        restore?;
        selection?;
        sync?;
        run_success("/bin/systemctl", ["reboot"])
    }
}

#[derive(Debug)]
struct ManifestSlot {
    release: String,
    root_hash: String,
    uki_sha256: String,
}

/// Verifies one immutable slot without mounting its root filesystem.
///
/// # Errors
///
/// Returns [`VerificationError`] for any signature, schema, identity, slot,
/// digest, or dm-verity failure. No failure is downgraded to a bootable result.
pub fn verify_slot(slot: BootSlot) -> Result<VerifiedSlot, VerificationError> {
    prepare_runtime()?;
    let layout =
        discover_host_layout().map_err(|error| VerificationError::Helper(error.to_string()))?;
    verify_manifest_signature()?;
    let manifest = read_manifest_slot(slot)?;
    mount_esp_read_only(&layout.esp)?;

    let candidates = matching_ukis(&manifest.uki_sha256)?;
    if candidates.len() != 1 {
        return Err(VerificationError::UkiMatch {
            count: candidates.len(),
        });
    }
    let uki = candidates
        .first()
        .ok_or_else(|| VerificationError::Internal("unique UKI disappeared".into()))?;

    if !run_output("/bin/sbverify", ["--cert", DB_CERT], Some(uki))?
        .status
        .success()
    {
        return Err(VerificationError::UkiSignature);
    }

    let cmdline = extract_text_section(uki, ".cmdline", "normal.cmdline")?;
    let identity = parse_normal(&cmdline)
        .map_err(|error| VerificationError::BootIdentity(error.to_string()))?;
    if identity.slot != slot {
        return Err(VerificationError::SlotMismatch);
    }
    if identity.root_hash != manifest.root_hash {
        return Err(VerificationError::RootHashMismatch);
    }

    let os_release = extract_text_section(uki, ".osrel", "normal.osrel")?;
    let release = release_version(&os_release)?;
    if release != manifest.release {
        return Err(VerificationError::ReleaseIdentity(format!(
            "UKI release `{release}` does not match manifest `{}`",
            manifest.release
        )));
    }

    let (root_data, root_hash_device) = match slot {
        BootSlot::A => (&layout.root_a, &layout.root_a_hash),
        BootSlot::B => (&layout.root_b, &layout.root_b_hash),
    };
    let root_data = root_data
        .to_str()
        .ok_or_else(|| VerificationError::Helper("root device is not UTF-8".into()))?;
    let root_hash_device = root_hash_device
        .to_str()
        .ok_or_else(|| VerificationError::Helper("hash device is not UTF-8".into()))?;
    if !run_success(
        "/bin/veritysetup",
        [
            "verify",
            root_data,
            root_hash_device,
            manifest.root_hash.as_str(),
        ],
    )
    .is_ok()
    {
        return Err(VerificationError::Verity);
    }

    let entry_id = uki
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| VerificationError::Internal("verified UKI filename is not UTF-8".into()))?
        .to_owned();
    Ok(VerifiedSlot {
        slot,
        counted: entry_id.contains('+'),
        entry_id,
        release,
    })
}

fn prepare_runtime() -> Result<(), VerificationError> {
    bounded_file(MANIFEST, MAX_MANIFEST_BYTES)?;
    bounded_file(MANIFEST_SIGNATURE, MAX_SIGNATURE_BYTES)?;
    bounded_file(DB_CERT, MAX_MANIFEST_BYTES)?;
    fs::create_dir_all(WORK_DIR)?;
    fs::create_dir_all(ESP_MOUNT)?;
    Ok(())
}

fn verify_manifest_signature() -> Result<(), VerificationError> {
    let public_key = format!("{WORK_DIR}/db-public.pem");
    let output = Command::new("/bin/openssl")
        .args(["x509", "-pubkey", "-noout", "-in", DB_CERT])
        .output()?;
    if !output.status.success() {
        return Err(VerificationError::Manifest(stderr_reason(&output)));
    }
    fs::write(&public_key, output.stdout)?;

    let output = Command::new("/bin/openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            &public_key,
            "-signature",
            MANIFEST_SIGNATURE,
            MANIFEST,
        ])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(VerificationError::Manifest(stderr_reason(&output)))
    }
}

fn read_manifest_slot(slot: BootSlot) -> Result<ManifestSlot, VerificationError> {
    let slot_name = match slot {
        BootSlot::A => "A",
        BootSlot::B => "B",
    };
    let output = Command::new("/bin/jq")
        .args(["-er", "--arg", "slot", slot_name, MANIFEST_FILTER, MANIFEST])
        .output()?;
    if !output.status.success() {
        return Err(VerificationError::Manifest(stderr_reason(&output)));
    }
    let line = String::from_utf8(output.stdout)
        .map_err(|error| VerificationError::Manifest(error.to_string()))?;
    let fields: Vec<&str> = line.trim_end().split('\t').collect();
    if fields.len() != 6 || fields[1] != SUPPORTED_RECOVERY_ABI {
        return Err(VerificationError::Manifest(
            "strict projection returned malformed fields".into(),
        ));
    }
    Ok(ManifestSlot {
        release: fields[0].to_owned(),
        root_hash: fields[4].to_owned(),
        uki_sha256: fields[5].to_owned(),
    })
}

fn mount_esp_read_only(device: &Path) -> Result<(), VerificationError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.get(4) != Some(&ESP_MOUNT) {
            continue;
        }
        let read_only = fields
            .get(5)
            .is_some_and(|options| options.split(',').any(|option| option == "ro"));
        let separator = fields.iter().position(|field| *field == "-");
        let vfat = separator
            .and_then(|index| fields.get(index + 1))
            .is_some_and(|filesystem| *filesystem == "vfat");
        let source_matches = separator
            .and_then(|index| fields.get(index + 2))
            .and_then(|source| fs::canonicalize(source).ok())
            .zip(fs::canonicalize(device).ok())
            .is_some_and(|(source, expected)| source == expected);
        return if read_only && vfat && source_matches {
            Ok(())
        } else {
            Err(VerificationError::Helper(
                "ESP mount exists without the required read-only vfat posture".into(),
            ))
        };
    }

    let output = Command::new("/bin/mount")
        .args(["-t", "vfat", "-o", "ro,nodev,nosuid,noexec"])
        .arg(device)
        .arg(ESP_MOUNT)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(VerificationError::Helper(stderr_reason(&output)))
    }
}

fn matching_ukis(expected_sha256: &str) -> Result<Vec<PathBuf>, VerificationError> {
    let directory = Path::new(ESP_MOUNT).join("EFI/Linux");
    let canonical_directory = fs::canonicalize(&directory)?;
    let mut matches = Vec::new();
    let mut inspected = 0_usize;

    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("efi") {
            continue;
        }
        inspected += 1;
        if inspected > MAX_NORMAL_UKIS {
            return Err(VerificationError::Helper(format!(
                "ESP contains more than {MAX_NORMAL_UKIS} normal UKIs"
            )));
        }
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&canonical_directory) {
            return Err(VerificationError::Helper(
                "normal UKI escaped the fixed ESP directory".into(),
            ));
        }
        bounded_file(&canonical, MAX_UKI_BYTES)?;
        if sha256(&canonical)? == expected_sha256 {
            matches.push(canonical);
        }
    }
    Ok(matches)
}

fn sha256(path: &Path) -> Result<String, VerificationError> {
    let output = Command::new("/bin/openssl")
        .args(["dgst", "-sha256", "-r"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(VerificationError::Helper(stderr_reason(&output)));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| VerificationError::Helper(error.to_string()))?;
    let digest = text.split_ascii_whitespace().next().unwrap_or_default();
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(digest.to_ascii_lowercase())
    } else {
        Err(VerificationError::Helper(
            "openssl returned a malformed SHA-256 digest".into(),
        ))
    }
}

fn extract_text_section(
    uki: &Path,
    section: &str,
    output_name: &str,
) -> Result<String, VerificationError> {
    let output_path = Path::new(WORK_DIR).join(output_name);
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }
    let output = Command::new("/bin/objcopy")
        .args(["-O", "binary", "--only-section", section])
        .arg(uki)
        .arg(&output_path)
        .output()?;
    if !output.status.success() {
        return Err(VerificationError::Helper(stderr_reason(&output)));
    }
    bounded_file(&output_path, MAX_TEXT_SECTION_BYTES)?;
    let mut bytes = fs::read(output_path)?;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.contains(&0) {
        return Err(VerificationError::Helper(format!(
            "UKI section {section} contains an interior NUL"
        )));
    }
    String::from_utf8(bytes).map_err(|error| VerificationError::Helper(error.to_string()))
}

fn bounded_file(path: impl AsRef<Path>, maximum: u64) -> Result<(), VerificationError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(VerificationError::Helper(format!(
            "{} is not a regular file within the {}-byte limit",
            path.display(),
            maximum
        )));
    }
    Ok(())
}

fn release_version(os_release: &str) -> Result<String, VerificationError> {
    let mut version = None;
    for line in os_release.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "VERSION" {
            continue;
        }
        if version.is_some() {
            return Err(VerificationError::ReleaseIdentity(
                "duplicate VERSION field".into(),
            ));
        }
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'));
        let value = value.ok_or_else(|| {
            VerificationError::ReleaseIdentity("VERSION is not canonically quoted".into())
        })?;
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        {
            return Err(VerificationError::ReleaseIdentity(
                "VERSION contains unsupported bytes".into(),
            ));
        }
        version = Some(value.to_owned());
    }
    version.ok_or_else(|| VerificationError::ReleaseIdentity("VERSION is missing".into()))
}

fn run_success<I, S>(program: &str, args: I) -> Result<(), VerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(VerificationError::Helper(format!(
            "{program}: {}",
            stderr_reason(&output)
        )))
    }
}

fn run_output<I, S>(
    program: &str,
    args: I,
    final_path: Option<&Path>,
) -> Result<Output, VerificationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(args);
    if let Some(path) = final_path {
        command.arg(path);
    }
    command.output().map_err(VerificationError::Io)
}

fn stderr_reason(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    }
}

#[cfg(test)]
mod tests {
    use super::release_version;

    #[test]
    fn accepts_one_canonical_signed_release_version() {
        let version = release_version("NAME=\"AOS\"\nVERSION=\"2026.08\"\n");
        assert!(matches!(version.as_deref(), Ok("2026.08")));
    }

    #[test]
    fn rejects_missing_duplicate_or_unquoted_release_versions() {
        assert!(release_version("NAME=\"AOS\"\n").is_err());
        assert!(release_version("VERSION=2026.08\n").is_err());
        assert!(release_version("VERSION=\"a\"\nVERSION=\"b\"\n").is_err());
    }
}
