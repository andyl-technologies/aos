//! Verifies and restores authenticated system-image bundles from removable media.
//!
//! Transport, component names, destinations, and publication order are fixed.
//! The removable filesystem is mounted read-only, every component is verified
//! before authorization, and only the slot opposite the running recovery copy
//! can be replaced.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aos_boot_identity::{BootSlot, parse_normal, parse_recovery};

use crate::device::{HostLayout, discover_host_layout, discover_recovery_media};
use crate::maintenance::RestoreAuthorization;
use crate::status::RecoveryCopy;
use crate::trust;

const MEDIA_MOUNT: &str = "/run/aos-recovery/media";
const BUNDLE_DIR: &str = "/run/aos-recovery/media/aos/recovery";
const MANIFEST: &str = "/run/aos-recovery/media/aos/recovery/recovery-bundle.json";
const SIGNATURE: &str = "/run/aos-recovery/media/aos/recovery/recovery-bundle.json.sig";
const ESP_MOUNT: &str = "/run/aos-recovery/esp";
const WORK_DIR: &str = "/run/aos-recovery";
const MAX_COMPONENTS: usize = 10;

const MANIFEST_FILTER: &str = r#"
  def exact_keys($keys): (keys | sort) == ($keys | sort);
  def digest: type == "string" and test("^[0-9a-f]{64}$");
  def positive_integer: type == "number" and floor == . and . > 0;
  def expected: {
    "root-image": "root.img", "root-verity": "root.verity",
    "root-hash": "root.roothash", "normal-uki-a": "uki-a.efi",
    "normal-uki-b": "uki-b.efi", "recovery-uki-a": "recovery-a.efi",
    "recovery-uki-b": "recovery-b.efi", "recovery-entry-a": "recovery-a.conf",
    "recovery-entry-b": "recovery-b.conf", "image-metadata": "image-info.json"
  };
  if (. | exact_keys(["schema", "release", "architecture", "platform",
                       "module_abi", "recovery_abi", "components"]))
     and .schema == "aos.recovery-bundle/v1"
     and (.release | type == "string" and test("^[A-Za-z0-9._+-]+$") and length <= 128)
     and (.architecture | type == "string" and test("^[A-Za-z0-9_-]+$") and length <= 64)
     and (.platform | type == "string" and test("^[A-Za-z0-9._-]+$") and length <= 128)
     and (.module_abi | positive_integer) and (.recovery_abi | positive_integer)
     and (.components | type == "array" and length == 10)
     and ([.components[].id] | unique | length) == 10
     and all(.components[];
       exact_keys(["id", "path", "byte_size", "sha256"])
       and (expected[.id] // "") == .path
       and (.byte_size | positive_integer)
       and (.sha256 | digest))
     and ([.components[].id] | sort) == (expected | keys | sort)
  then ([.release, .architecture, .platform, (.module_abi | tostring),
         (.recovery_abi | tostring)] | @tsv),
       (.components[] | [.id, .path, (.byte_size | tostring), .sha256] | @tsv)
  else error("invalid recovery bundle manifest")
  end
"#;

/// Reports a failed authentication, validation, or fixed-destination write.
#[derive(Debug)]
pub enum RestoreError {
    /// A fixed-path filesystem operation failed.
    Io(io::Error),
    /// A fixed helper rejected its input or failed.
    Helper(String),
    /// The signed bundle manifest or directory layout was malformed.
    Manifest(String),
    /// A component differed in type, size, or digest.
    Component(String),
    /// The target ESP or block device did not have the required posture.
    Destination(String),
}

impl fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "restore I/O failure: {error}"),
            Self::Helper(reason) => write!(formatter, "restore helper failed: {reason}"),
            Self::Manifest(reason) => write!(formatter, "bundle manifest rejected: {reason}"),
            Self::Component(reason) => write!(formatter, "bundle component rejected: {reason}"),
            Self::Destination(reason) => {
                write!(formatter, "restore destination rejected: {reason}")
            }
        }
    }
}

impl Error for RestoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RestoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug)]
struct Component {
    path: PathBuf,
    byte_size: u64,
    sha256: String,
}

/// Retains a fully authenticated, read-only bundle until operator authorization.
#[derive(Debug)]
pub struct VerifiedBundle {
    /// Slot that this bundle is permitted to replace.
    pub target: BootSlot,
    /// Signed release identity displayed before destructive confirmation.
    pub release: String,
    components: BTreeMap<String, Component>,
    host: HostLayout,
}

impl VerifiedBundle {
    /// Writes and read-back-verifies the inactive slot and publishes its boot artifacts.
    ///
    /// The opaque authorization is consumed. Recovery and loader-entry bytes
    /// are published before the new normal counted UKI becomes discoverable.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError`] on any target validation, write, sync,
    /// read-back, or ESP read-only restoration failure.
    pub fn restore(self, _authorization: RestoreAuthorization) -> Result<(), RestoreError> {
        mount_esp_read_only(&self.host.esp)?;
        remount_esp(true)?;
        let disarm = disarm_slot_ukis(self.target);
        let restore_after_disarm = remount_esp(false);
        disarm?;
        restore_after_disarm?;

        let (root, hash) = match self.target {
            BootSlot::A => (&self.host.root_a, &self.host.root_a_hash),
            BootSlot::B => (&self.host.root_b, &self.host.root_b_hash),
        };
        write_slot_storage(&self, root, hash)?;

        remount_esp(true)?;
        let publication =
            publish_boot_artifacts(&self).and_then(|()| cleanup_disabled_slot_ukis(self.target));
        let restore = remount_esp(false);
        match (publication, restore) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(restore_error)) => Err(RestoreError::Destination(format!(
                "{error}; ESP also failed to return read-only: {restore_error}"
            ))),
        }
    }

    fn component(&self, id: &str) -> Result<&Component, RestoreError> {
        self.components
            .get(id)
            .ok_or_else(|| RestoreError::Manifest(format!("component {id} disappeared")))
    }
}

/// Mounts and authenticates the fixed offline bundle for the opposite slot.
///
/// # Errors
///
/// Returns [`RestoreError`] unless the removable filesystem, db signature,
/// strict manifest, exact directory members, and every component verify.
pub fn verify_offline_bundle(copy: RecoveryCopy) -> Result<VerifiedBundle, RestoreError> {
    let host =
        discover_host_layout().map_err(|error| RestoreError::Destination(error.to_string()))?;
    let media = discover_recovery_media(&host)
        .map_err(|error| RestoreError::Destination(error.to_string()))?;
    fs::create_dir_all(MEDIA_MOUNT)?;
    mount_media_read_only(&media)?;
    verify_manifest_signature()?;
    let (release, components) = parse_manifest()?;
    verify_exact_directory(&components)?;
    for (id, component) in &components {
        verify_component(id, component)?;
    }
    let root_hash = canonical_bundle_root_hash(&components)?;
    for (id, component) in &components {
        if matches!(
            id.as_str(),
            "normal-uki-a" | "normal-uki-b" | "recovery-uki-a" | "recovery-uki-b"
        ) {
            verify_bundle_uki_identity(id, component, &release, &root_hash)?;
        }
    }
    verify_bundle_verity(&components, &root_hash)?;
    verify_recovery_entries(&components, &release)?;
    Ok(VerifiedBundle {
        target: match copy {
            RecoveryCopy::A => BootSlot::B,
            RecoveryCopy::B => BootSlot::A,
        },
        release,
        components,
        host,
    })
}

fn mount_media_read_only(device: &Path) -> Result<(), RestoreError> {
    if mount_is_read_only_filesystem(MEDIA_MOUNT, device, "ext4")? {
        return Ok(());
    }
    let output = Command::new("/bin/mount")
        .args(["-t", "ext4", "-o", "ro,nodev,nosuid,noexec"])
        .arg(device)
        .arg(MEDIA_MOUNT)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RestoreError::Helper(stderr_reason(&output)))
    }
}

fn verify_manifest_signature() -> Result<(), RestoreError> {
    bounded_regular(Path::new(MANIFEST), 256 * 1024)?;
    bounded_regular(Path::new(SIGNATURE), 16 * 1024)?;
    trust::verify_detached_signature(Path::new(MANIFEST), Path::new(SIGNATURE))
        .map_err(RestoreError::Manifest)
}

fn parse_manifest() -> Result<(String, BTreeMap<String, Component>), RestoreError> {
    let output = Command::new("/bin/jq")
        .args(["-er", MANIFEST_FILTER, MANIFEST])
        .output()?;
    if !output.status.success() {
        return Err(RestoreError::Manifest(stderr_reason(&output)));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| RestoreError::Manifest(error.to_string()))?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| RestoreError::Manifest("manifest projection is empty".into()))?;
    let header = header.split('\t').collect::<Vec<_>>();
    if header.len() != 5 {
        return Err(RestoreError::Manifest(
            "manifest identity projection is malformed".into(),
        ));
    }
    let os_release = fs::read_to_string("/etc/os-release")?;
    let platform = unique_os_release(&os_release, "AOS_PLATFORM")?;
    let module_abi = unique_os_release(&os_release, "AOS_MODULE_ABI")?;
    let recovery_abi = unique_os_release(&os_release, "AOS_RECOVERY_ABI")?;
    if header[1] != std::env::consts::ARCH
        || header[2] != platform
        || header[3] != module_abi
        || header[4] != recovery_abi
    {
        return Err(RestoreError::Manifest(
            "bundle architecture, platform, module ABI, or recovery ABI is incompatible".into(),
        ));
    }
    let release = header[0].to_string();
    let mut components = BTreeMap::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(RestoreError::Manifest(
                "component projection is malformed".into(),
            ));
        }
        let size = fields[2]
            .parse::<u64>()
            .map_err(|error| RestoreError::Manifest(error.to_string()))?;
        let path = Path::new(BUNDLE_DIR).join(fields[1]);
        components.insert(
            fields[0].to_string(),
            Component {
                path,
                byte_size: size,
                sha256: fields[3].to_string(),
            },
        );
    }
    if components.len() != MAX_COMPONENTS {
        return Err(RestoreError::Manifest(
            "manifest component count changed after projection".into(),
        ));
    }
    Ok((release, components))
}

fn unique_os_release<'a>(os_release: &'a str, key: &str) -> Result<&'a str, RestoreError> {
    let values = os_release
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter_map(|(found, value)| (found == key).then_some(value.trim_matches('"')))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        _ => Err(RestoreError::Manifest(format!(
            "recovery os-release has no unique {key}"
        ))),
    }
}

fn verify_exact_directory(components: &BTreeMap<String, Component>) -> Result<(), RestoreError> {
    let mut expected = components
        .values()
        .filter_map(|component| component.path.file_name().map(OsStr::to_owned))
        .collect::<BTreeSet<_>>();
    expected.insert(OsStr::new("recovery-bundle.json").to_owned());
    expected.insert(OsStr::new("recovery-bundle.json.sig").to_owned());
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(BUNDLE_DIR)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(RestoreError::Manifest(
                "bundle contains a symlink, directory, or special node".into(),
            ));
        }
        actual.insert(entry.file_name());
    }
    if actual != expected {
        return Err(RestoreError::Manifest(
            "bundle has missing or trailing unaccounted files".into(),
        ));
    }
    Ok(())
}

fn verify_component(id: &str, component: &Component) -> Result<(), RestoreError> {
    let maximum = match id {
        "root-image" | "root-verity" => 64 * 1024 * 1024 * 1024_u64,
        "normal-uki-a" | "normal-uki-b" | "recovery-uki-a" | "recovery-uki-b" => 512 * 1024 * 1024,
        "image-metadata" => 1024 * 1024,
        "root-hash" | "recovery-entry-a" | "recovery-entry-b" => 4096,
        _ => return Err(RestoreError::Manifest(format!("unknown component {id}"))),
    };
    if component.byte_size > maximum {
        return Err(RestoreError::Component(format!(
            "{id} exceeds its {maximum}-byte bound"
        )));
    }
    bounded_regular(&component.path, maximum)?;
    if fs::metadata(&component.path)?.len() != component.byte_size {
        return Err(RestoreError::Component(format!("{id} size mismatch")));
    }
    if sha256(&component.path)? != component.sha256 {
        return Err(RestoreError::Component(format!("{id} digest mismatch")));
    }
    Ok(())
}

fn canonical_bundle_root_hash(
    components: &BTreeMap<String, Component>,
) -> Result<String, RestoreError> {
    let component = components
        .get("root-hash")
        .ok_or_else(|| RestoreError::Manifest("bundle has no root-hash component".into()))?;
    let text = fs::read_to_string(&component.path)?;
    let root_hash = text.trim();
    if root_hash.len() != 64
        || !root_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RestoreError::Component(
            "root-hash is not canonical lowercase SHA-256".into(),
        ));
    }
    Ok(root_hash.to_string())
}

fn verify_bundle_uki_identity(
    id: &str,
    component: &Component,
    release: &str,
    root_hash: &str,
) -> Result<(), RestoreError> {
    if trust::verify_uki(&component.path).is_err() {
        return Err(RestoreError::Component(format!(
            "{id} is not authorized by Secure Boot db"
        )));
    }

    let cmdline = extract_uki_section(&component.path, ".cmdline", id)?;
    match id {
        "normal-uki-a" | "normal-uki-b" => {
            let identity = parse_normal(&cmdline)
                .map_err(|error| RestoreError::Component(format!("{id}: {error}")))?;
            let expected = if id.ends_with("-a") {
                BootSlot::A
            } else {
                BootSlot::B
            };
            if identity.slot != expected {
                return Err(RestoreError::Component(format!(
                    "{id} signed command line selects the wrong slot"
                )));
            }
            if identity.root_hash != root_hash {
                return Err(RestoreError::Component(format!(
                    "{id} signed root hash disagrees with root.roothash"
                )));
            }
            let os_release = extract_uki_section(&component.path, ".osrel", id)?;
            if unique_os_release(&os_release, "VERSION_ID")? != release {
                return Err(RestoreError::Component(format!(
                    "{id} signed release disagrees with the bundle"
                )));
            }
        }
        "recovery-uki-a" | "recovery-uki-b" => {
            parse_recovery(&cmdline)
                .map_err(|error| RestoreError::Component(format!("{id}: {error}")))?;
            let os_release = extract_uki_section(&component.path, ".osrel", id)?;
            let expected_copy = if id.ends_with("-a") { "A" } else { "B" };
            if unique_os_release(&os_release, "VERSION_ID")? != release
                || unique_os_release(&os_release, "AOS_RECOVERY_COPY")? != expected_copy
                || unique_os_release(&os_release, "AOS_RECOVERY_ABI")? != "1"
            {
                return Err(RestoreError::Component(format!(
                    "{id} signed release, copy, or ABI disagrees with the bundle"
                )));
            }
        }
        _ => {
            return Err(RestoreError::Component(format!(
                "unexpected UKI component {id}"
            )));
        }
    }
    Ok(())
}

fn verify_bundle_verity(
    components: &BTreeMap<String, Component>,
    root_hash: &str,
) -> Result<(), RestoreError> {
    let root = components
        .get("root-image")
        .ok_or_else(|| RestoreError::Manifest("bundle has no root-image component".into()))?;
    let hash = components
        .get("root-verity")
        .ok_or_else(|| RestoreError::Manifest("bundle has no root-verity component".into()))?;
    let output = Command::new("/bin/veritysetup")
        .arg("verify")
        .arg(&root.path)
        .arg(&hash.path)
        .arg(root_hash)
        .output()?;
    if !output.status.success() {
        return Err(RestoreError::Component(format!(
            "root image and verity tree are incoherent: {}",
            stderr_reason(&output)
        )));
    }
    Ok(())
}

fn verify_recovery_entries(
    components: &BTreeMap<String, Component>,
    release: &str,
) -> Result<(), RestoreError> {
    for (suffix, copy) in [("a", "A"), ("b", "B")] {
        let component = components
            .get(&format!("recovery-entry-{suffix}"))
            .ok_or_else(|| {
                RestoreError::Manifest(format!("bundle has no recovery-entry-{suffix} component"))
            })?;
        let expected =
            format!("title AOS Recovery {copy} ({release})\nefi /EFI/AOS/recovery-{suffix}.efi\n");
        if fs::read(&component.path)? != expected.as_bytes() {
            return Err(RestoreError::Component(format!(
                "recovery-entry-{suffix} is not canonical for the bundle"
            )));
        }
    }
    Ok(())
}

fn extract_uki_section(uki: &Path, section: &str, id: &str) -> Result<String, RestoreError> {
    let destination =
        Path::new(WORK_DIR).join(format!("bundle-{}-{}", id, section.trim_start_matches('.')));
    let output = Command::new("/bin/objcopy")
        .args(["-O", "binary"])
        .arg(format!("--only-section={section}"))
        .arg(uki)
        .arg(&destination)
        .output()?;
    if !output.status.success() {
        return Err(RestoreError::Component(format!(
            "cannot inspect {section} in {id}"
        )));
    }
    let mut bytes = fs::read(destination)?;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(RestoreError::Component(format!(
            "{id} has no {section} section"
        )));
    }
    String::from_utf8(bytes).map_err(|error| RestoreError::Component(error.to_string()))
}

fn write_block_component(component: &Component, destination: &Path) -> Result<(), RestoreError> {
    let resolved = fs::canonicalize(destination)?;
    if !resolved.starts_with("/dev") {
        return Err(RestoreError::Destination(format!(
            "{} resolves outside /dev",
            destination.display()
        )));
    }
    let mut output = OpenOptions::new().write(true).open(destination)?;
    if !output.metadata()?.file_type().is_block_device() {
        return Err(RestoreError::Destination(format!(
            "{} is not a block device",
            destination.display()
        )));
    }
    let mut input = File::open(&component.path)?;
    let copied = io::copy(&mut input, &mut output)?;
    if copied != component.byte_size {
        return Err(RestoreError::Destination("short block write".into()));
    }
    output.sync_all()?;
    if sha256_prefix(destination, component.byte_size)? != component.sha256 {
        return Err(RestoreError::Destination(
            "block-device read-back digest mismatch".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageBoundary {
    RootWritten,
    VerityWritten,
}

fn write_slot_storage(
    bundle: &VerifiedBundle,
    root: &Path,
    hash: &Path,
) -> Result<(), RestoreError> {
    write_slot_storage_with(
        &bundle.components,
        root,
        hash,
        write_block_component,
        |_| Ok(()),
    )
}

fn write_slot_storage_with<F, C>(
    components: &BTreeMap<String, Component>,
    root: &Path,
    hash: &Path,
    mut writer: F,
    mut checkpoint: C,
) -> Result<(), RestoreError>
where
    F: FnMut(&Component, &Path) -> Result<(), RestoreError>,
    C: FnMut(StorageBoundary) -> Result<(), RestoreError>,
{
    let root_component = components
        .get("root-image")
        .ok_or_else(|| RestoreError::Manifest("component root-image disappeared".into()))?;
    let verity_component = components
        .get("root-verity")
        .ok_or_else(|| RestoreError::Manifest("component root-verity disappeared".into()))?;
    writer(root_component, root)?;
    checkpoint(StorageBoundary::RootWritten)?;
    writer(verity_component, hash)?;
    checkpoint(StorageBoundary::VerityWritten)
}

fn publish_boot_artifacts(bundle: &VerifiedBundle) -> Result<(), RestoreError> {
    publish_boot_artifacts_with(
        bundle.target,
        &bundle.release,
        &bundle.components,
        Path::new(ESP_MOUNT),
        verify_installed,
        |_| Ok(()),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationBoundary {
    Staged,
    RecoveryPublished,
    EntryPublished,
    NormalPublished,
}

fn publish_boot_artifacts_with<F, V>(
    target: BootSlot,
    release: &str,
    components: &BTreeMap<String, Component>,
    esp_root: &Path,
    mut verify: V,
    mut checkpoint: F,
) -> Result<(), RestoreError>
where
    F: FnMut(PublicationBoundary) -> Result<(), RestoreError>,
    V: FnMut(&Component, &Path) -> Result<(), RestoreError>,
{
    let suffix = slot_suffix(target);
    let staging = esp_root.join("EFI/.aos-staging");
    fs::create_dir_all(&staging)?;
    let component = |id: &str| {
        components
            .get(id)
            .ok_or_else(|| RestoreError::Manifest(format!("component {id} disappeared")))
    };
    let recovery = component(&format!("recovery-uki-{suffix}"))?;
    let recovery_entry = component(&format!("recovery-entry-{suffix}"))?;
    let normal = component(&format!("normal-uki-{suffix}"))?;

    let recovery_temp = staging.join(format!("restore-recovery-{suffix}.efi"));
    let entry_temp = staging.join(format!("restore-recovery-{suffix}.conf"));
    let normal_temp = staging.join(format!("restore-normal-{suffix}.efi"));
    copy_regular(recovery, &recovery_temp)?;
    copy_regular(recovery_entry, &entry_temp)?;
    copy_regular(normal, &normal_temp)?;
    verify(recovery, &recovery_temp)?;
    verify(recovery_entry, &entry_temp)?;
    verify(normal, &normal_temp)?;
    sync_path(&staging)?;
    checkpoint(PublicationBoundary::Staged)?;

    let recovery_destination = esp_root
        .join("EFI/AOS")
        .join(format!("recovery-{suffix}.efi"));
    let entry_destination = esp_root
        .join("loader/entries")
        .join(format!("recovery-{suffix}.conf"));
    fs::create_dir_all(
        recovery_destination.parent().ok_or_else(|| {
            RestoreError::Destination("recovery destination has no parent".into())
        })?,
    )?;
    fs::create_dir_all(entry_destination.parent().ok_or_else(|| {
        RestoreError::Destination("loader entry destination has no parent".into())
    })?)?;
    fs::rename(&recovery_temp, &recovery_destination)?;
    let recovery_parent = recovery_destination
        .parent()
        .ok_or_else(|| RestoreError::Destination("recovery destination has no parent".into()))?;
    sync_path(recovery_parent)?;
    verify(recovery, &recovery_destination)?;
    checkpoint(PublicationBoundary::RecoveryPublished)?;
    fs::rename(&entry_temp, &entry_destination)?;
    let entry_parent = entry_destination.parent().ok_or_else(|| {
        RestoreError::Destination("loader entry destination has no parent".into())
    })?;
    sync_path(entry_parent)?;
    verify(recovery_entry, &entry_destination)?;
    checkpoint(PublicationBoundary::EntryPublished)?;

    let normal_name = format!("aos-restored-{release}-slot-{suffix}+3.efi");
    let normal_destination = esp_root.join("EFI/Linux").join(normal_name);
    fs::create_dir_all(normal_destination.parent().ok_or_else(|| {
        RestoreError::Destination("normal UKI destination has no parent".into())
    })?)?;
    fs::rename(&normal_temp, &normal_destination)?;
    let normal_parent = normal_destination
        .parent()
        .ok_or_else(|| RestoreError::Destination("normal UKI destination has no parent".into()))?;
    sync_path(normal_parent)?;
    verify(normal, &normal_destination)?;
    checkpoint(PublicationBoundary::NormalPublished)?;
    sync_path(esp_root)
}

fn disarm_slot_ukis(slot: BootSlot) -> Result<(), RestoreError> {
    disarm_slot_ukis_with(slot, Path::new(ESP_MOUNT), classify_installed_uki)
}

fn disarm_slot_ukis_with<F>(
    slot: BootSlot,
    esp_root: &Path,
    mut classify: F,
) -> Result<(), RestoreError>
where
    F: FnMut(&Path, usize) -> Result<BootSlot, RestoreError>,
{
    let linux = esp_root.join("EFI/Linux");
    let staging = esp_root.join("EFI/.aos-staging");
    fs::create_dir_all(&staging)?;
    let disabled_prefix = format!("disabled-restore-{}-", slot_suffix(slot));
    let mut disabled_count = 0_usize;
    for entry in fs::read_dir(&staging)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(&disabled_prefix)
        {
            continue;
        }
        disabled_count += 1;
        if disabled_count > 64 || !entry.file_type()?.is_file() {
            return Err(RestoreError::Destination(
                "inactive-slot recovery staging is ambiguous".into(),
            ));
        }
    }
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&linux)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(OsStr::to_str) != Some("efi")
        {
            continue;
        }
        candidates.push(entry.path());
        if candidates.len() > 64 {
            return Err(RestoreError::Destination(
                "ESP contains more than 64 normal UKIs".into(),
            ));
        }
    }
    for (index, candidate) in candidates.into_iter().enumerate() {
        if classify(&candidate, index)? == slot {
            let name = candidate
                .file_name()
                .ok_or_else(|| RestoreError::Destination("normal UKI has no filename".into()))?;
            fs::rename(
                &candidate,
                staging.join(format!("{disabled_prefix}{}", name.to_string_lossy())),
            )?;
        }
    }
    sync_path(&linux)?;
    sync_path(&staging)
}

fn classify_installed_uki(candidate: &Path, index: usize) -> Result<BootSlot, RestoreError> {
    if trust::verify_uki(candidate).is_err() {
        return Err(RestoreError::Destination(format!(
            "installed normal UKI {} is not authorized by Secure Boot db",
            candidate.display()
        )));
    }
    let section = Path::new(WORK_DIR).join(format!("restore-cmdline-{index}"));
    let output = Command::new("/bin/objcopy")
        .args(["-O", "binary", "--only-section=.cmdline"])
        .arg(candidate)
        .arg(&section)
        .output()?;
    if !output.status.success() {
        return Err(RestoreError::Destination(format!(
            "cannot classify normal UKI {}",
            candidate.display()
        )));
    }
    let mut bytes = fs::read(&section)?;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let cmdline =
        String::from_utf8(bytes).map_err(|error| RestoreError::Destination(error.to_string()))?;
    parse_normal(&cmdline)
        .map(|identity| identity.slot)
        .map_err(|error| RestoreError::Destination(error.to_string()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupBoundary {
    Removed(usize),
}

fn cleanup_disabled_slot_ukis(slot: BootSlot) -> Result<(), RestoreError> {
    cleanup_disabled_slot_ukis_with(slot, Path::new(ESP_MOUNT), |_| Ok(()))
}

fn cleanup_disabled_slot_ukis_with<F>(
    slot: BootSlot,
    esp_root: &Path,
    mut checkpoint: F,
) -> Result<(), RestoreError>
where
    F: FnMut(CleanupBoundary) -> Result<(), RestoreError>,
{
    let staging = esp_root.join("EFI/.aos-staging");
    let disabled_prefix = format!("disabled-restore-{}-", slot_suffix(slot));
    let mut removed = 0_usize;
    for entry in fs::read_dir(&staging)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(&disabled_prefix)
        {
            continue;
        }
        removed += 1;
        if removed > 128 || !entry.file_type()?.is_file() {
            return Err(RestoreError::Destination(
                "inactive-slot recovery cleanup is ambiguous".into(),
            ));
        }
        fs::remove_file(entry.path())?;
        checkpoint(CleanupBoundary::Removed(removed))?;
    }
    sync_path(&staging)
}

fn mount_esp_read_only(device: &Path) -> Result<(), RestoreError> {
    fs::create_dir_all(ESP_MOUNT)?;
    if mount_is_read_only_filesystem(ESP_MOUNT, device, "vfat")? {
        return Ok(());
    }
    let output = Command::new("/bin/mount")
        .args(["-t", "vfat", "-o", "ro,nodev,nosuid,noexec"])
        .arg(device)
        .arg(ESP_MOUNT)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RestoreError::Helper(stderr_reason(&output)))
    }
}

fn remount_esp(writable: bool) -> Result<(), RestoreError> {
    let mode = if writable { "rw" } else { "ro" };
    run_success(
        "/bin/mount",
        [
            "-o",
            &format!("remount,{mode},nodev,nosuid,noexec"),
            ESP_MOUNT,
        ],
    )
}

fn mount_is_read_only_filesystem(
    mount: &str,
    expected_device: &Path,
    expected_filesystem: &str,
) -> Result<bool, RestoreError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.get(4) != Some(&mount) {
            continue;
        }
        let read_only = fields
            .get(5)
            .is_some_and(|options| options.split(',').any(|option| option == "ro"));
        let separator = fields.iter().position(|field| *field == "-");
        let filesystem_matches = separator
            .and_then(|index| fields.get(index + 1))
            .is_some_and(|filesystem| *filesystem == expected_filesystem);
        let source = separator.and_then(|index| fields.get(index + 2));
        let source_matches = source
            .and_then(|source| fs::canonicalize(source).ok())
            .zip(fs::canonicalize(expected_device).ok())
            .is_some_and(|(source, expected)| source == expected);
        if !read_only || !filesystem_matches || !source_matches {
            return Err(RestoreError::Destination(format!(
                "{mount} is not the expected read-only {expected_filesystem} device"
            )));
        }
        return Ok(true);
    }
    Ok(false)
}

fn copy_regular(component: &Component, destination: &Path) -> Result<(), RestoreError> {
    let mut input = File::open(&component.path)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(destination)?;
    let copied = io::copy(&mut input, &mut output)?;
    if copied != component.byte_size {
        return Err(RestoreError::Destination("short ESP write".into()));
    }
    output.sync_all()?;
    Ok(())
}

fn verify_installed(component: &Component, destination: &Path) -> Result<(), RestoreError> {
    if fs::metadata(destination)?.len() != component.byte_size
        || sha256(destination)? != component.sha256
    {
        return Err(RestoreError::Destination(
            "ESP artifact failed read-back verification".into(),
        ));
    }
    Ok(())
}

fn bounded_regular(path: &Path, maximum: u64) -> Result<(), RestoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(RestoreError::Component(format!(
            "{} is not a regular file within its bound",
            path.display()
        )));
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, RestoreError> {
    let output = Command::new("/bin/openssl")
        .args(["dgst", "-sha256", "-r"])
        .arg(path)
        .output()?;
    parse_digest(&output)
}

fn sha256_prefix(path: &Path, length: u64) -> Result<String, RestoreError> {
    let mut input = File::open(path)?.take(length);
    let mut child = Command::new("/bin/openssl")
        .args(["dgst", "-sha256", "-r"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| RestoreError::Helper("openssl stdin was not created".into()))?;
    let copied = io::copy(&mut input, &mut stdin)?;
    drop(stdin);
    if copied != length {
        return Err(RestoreError::Destination("short block read-back".into()));
    }
    parse_digest(&child.wait_with_output()?)
}

fn parse_digest(output: &std::process::Output) -> Result<String, RestoreError> {
    if !output.status.success() {
        return Err(RestoreError::Helper(stderr_reason(output)));
    }
    let text = String::from_utf8(output.stdout.clone())
        .map_err(|error| RestoreError::Helper(error.to_string()))?;
    let digest = text.split_ascii_whitespace().next().unwrap_or_default();
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(digest.to_string())
    } else {
        Err(RestoreError::Helper(
            "openssl returned a malformed SHA-256 digest".into(),
        ))
    }
}

fn sync_path(path: &Path) -> Result<(), RestoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn run_success<I, S>(program: &str, args: I) -> Result<(), RestoreError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RestoreError::Helper(stderr_reason(&output)))
    }
}

fn slot_suffix(slot: BootSlot) -> &'static str {
    match slot {
        BootSlot::A => "a",
        BootSlot::B => "b",
    }
}

fn stderr_reason(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use aos_boot_identity::BootSlot;

    use super::{
        CleanupBoundary, Component, PublicationBoundary, RestoreError, StorageBoundary,
        cleanup_disabled_slot_ukis_with, disarm_slot_ukis_with, publish_boot_artifacts_with,
        slot_suffix, write_slot_storage_with,
    };

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aos-recovery-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn component(root: &Path, id: &str, bytes: &[u8]) -> Component {
        let path = root.join(id);
        fs::write(&path, bytes).unwrap();
        Component {
            path,
            byte_size: bytes.len() as u64,
            sha256: test_digest(bytes),
        }
    }

    fn test_digest(bytes: &[u8]) -> String {
        format!("{bytes:02x?}")
    }

    fn verify_test_artifact(component: &Component, destination: &Path) -> Result<(), RestoreError> {
        let bytes = fs::read(destination)?;
        if bytes.len() as u64 != component.byte_size || test_digest(&bytes) != component.sha256 {
            return Err(RestoreError::Destination(
                "test artifact failed read-back verification".into(),
            ));
        }
        Ok(())
    }

    #[test]
    fn recovery_esp_transaction_replays_every_cut_in_both_directions() {
        let boundaries = [
            PublicationBoundary::Staged,
            PublicationBoundary::RecoveryPublished,
            PublicationBoundary::EntryPublished,
            PublicationBoundary::NormalPublished,
        ];
        for slot in [BootSlot::A, BootSlot::B] {
            for boundary in boundaries {
                let root = temporary_root(&format!("{:?}-{boundary:?}", slot));
                let source = root.join("source");
                let esp = root.join("esp");
                fs::create_dir_all(&source).unwrap();
                fs::create_dir_all(esp.join("EFI/Linux")).unwrap();
                fs::create_dir_all(esp.join("EFI/AOS")).unwrap();
                let suffix = slot_suffix(slot);
                let opposite = match slot {
                    BootSlot::A => BootSlot::B,
                    BootSlot::B => BootSlot::A,
                };
                let opposite_suffix = slot_suffix(opposite);
                let old_target = esp.join(format!("EFI/Linux/old-target-{suffix}.efi"));
                let old_opposite =
                    esp.join(format!("EFI/Linux/old-opposite-{opposite_suffix}.efi"));
                let opposite_recovery = esp.join(format!("EFI/AOS/recovery-{opposite_suffix}.efi"));
                fs::write(&old_target, b"old target normal").unwrap();
                fs::write(&old_opposite, b"old opposite normal").unwrap();
                fs::write(&opposite_recovery, b"opposite recovery").unwrap();
                let mut components = BTreeMap::new();
                components.insert(
                    format!("recovery-uki-{suffix}"),
                    component(&source, "recovery.efi", b"recovery bytes"),
                );
                components.insert(
                    format!("recovery-entry-{suffix}"),
                    component(&source, "recovery.conf", b"entry bytes"),
                );
                components.insert(
                    format!("normal-uki-{suffix}"),
                    component(&source, "normal.efi", b"normal bytes"),
                );

                disarm_slot_ukis_with(slot, &esp, |candidate, _| {
                    if candidate.file_name() == old_target.file_name() {
                        Ok(slot)
                    } else {
                        Ok(opposite)
                    }
                })
                .unwrap();
                assert!(!old_target.exists());
                assert_eq!(fs::read(&old_opposite).unwrap(), b"old opposite normal");

                let interrupted = publish_boot_artifacts_with(
                    slot,
                    "test-release",
                    &components,
                    &esp,
                    verify_test_artifact,
                    |found| {
                        if found == boundary {
                            Err(RestoreError::Destination("injected cut".into()))
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(interrupted.is_err());
                publish_boot_artifacts_with(
                    slot,
                    "test-release",
                    &components,
                    &esp,
                    verify_test_artifact,
                    |_| Ok(()),
                )
                .unwrap();

                let cleanup_cut = cleanup_disabled_slot_ukis_with(slot, &esp, |found| {
                    if found == CleanupBoundary::Removed(1) {
                        Err(RestoreError::Destination("injected cleanup cut".into()))
                    } else {
                        Ok(())
                    }
                });
                assert!(cleanup_cut.is_err());
                cleanup_disabled_slot_ukis_with(slot, &esp, |_| Ok(())).unwrap();

                assert_eq!(
                    fs::read(esp.join(format!("EFI/AOS/recovery-{suffix}.efi"))).unwrap(),
                    b"recovery bytes"
                );
                assert_eq!(
                    fs::read(esp.join(format!("loader/entries/recovery-{suffix}.conf"))).unwrap(),
                    b"entry bytes"
                );
                assert_eq!(
                    fs::read(esp.join(format!(
                        "EFI/Linux/aos-restored-test-release-slot-{suffix}+3.efi"
                    )))
                    .unwrap(),
                    b"normal bytes"
                );
                assert!(
                    fs::read_dir(esp.join("EFI/.aos-staging"))
                        .unwrap()
                        .next()
                        .is_none()
                );
                assert_eq!(fs::read(&old_opposite).unwrap(), b"old opposite normal");
                assert_eq!(fs::read(&opposite_recovery).unwrap(), b"opposite recovery");
                fs::remove_dir_all(&root).unwrap();
            }
        }
    }

    #[test]
    fn recovery_storage_transaction_replays_every_cut_in_both_directions() {
        for slot in [BootSlot::A, BootSlot::B] {
            for boundary in [StorageBoundary::RootWritten, StorageBoundary::VerityWritten] {
                let root = temporary_root(&format!("storage-{:?}-{boundary:?}", slot));
                let source = root.join("source");
                fs::create_dir_all(&source).unwrap();
                let root_destination = root.join("target-root");
                let hash_destination = root.join("target-hash");
                let opposite_root = root.join("opposite-root");
                fs::write(&root_destination, b"old root").unwrap();
                fs::write(&hash_destination, b"old hash").unwrap();
                fs::write(&opposite_root, b"opposite root").unwrap();
                let mut components = BTreeMap::new();
                components.insert(
                    "root-image".into(),
                    component(&source, "root.img", b"new root bytes"),
                );
                components.insert(
                    "root-verity".into(),
                    component(&source, "root.verity", b"new hash bytes"),
                );
                let writer = |component: &Component, destination: &Path| {
                    fs::copy(&component.path, destination)?;
                    verify_test_artifact(component, destination)
                };

                let interrupted = write_slot_storage_with(
                    &components,
                    &root_destination,
                    &hash_destination,
                    writer,
                    |found| {
                        if found == boundary {
                            Err(RestoreError::Destination("injected storage cut".into()))
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(interrupted.is_err());
                write_slot_storage_with(
                    &components,
                    &root_destination,
                    &hash_destination,
                    writer,
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(fs::read(&root_destination).unwrap(), b"new root bytes");
                assert_eq!(fs::read(&hash_destination).unwrap(), b"new hash bytes");
                assert_eq!(fs::read(&opposite_root).unwrap(), b"opposite root");
                fs::remove_dir_all(&root).unwrap();
            }
        }
    }

    #[test]
    fn changed_media_is_rejected_before_esp_publication() {
        let root = temporary_root("changed-media");
        let source = root.join("source");
        let esp = root.join("esp");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&esp).unwrap();
        let mut components = BTreeMap::new();
        components.insert(
            "recovery-uki-a".into(),
            component(&source, "recovery.efi", b"authenticated recovery"),
        );
        components.insert(
            "recovery-entry-a".into(),
            component(&source, "recovery.conf", b"authenticated entry"),
        );
        components.insert(
            "normal-uki-a".into(),
            component(&source, "normal.efi", b"authenticated normal"),
        );
        let recovery_source = components.get("recovery-uki-a").unwrap().path.clone();
        fs::write(recovery_source, b"changed after authorization").unwrap();

        let result = publish_boot_artifacts_with(
            BootSlot::A,
            "test-release",
            &components,
            &esp,
            verify_test_artifact,
            |_| Ok(()),
        );
        assert!(result.is_err());
        assert!(!esp.join("EFI/AOS/recovery-a.efi").exists());
        assert!(!esp.join("loader/entries/recovery-a.conf").exists());
        assert!(
            !esp.join("EFI/Linux/aos-restored-test-release-slot-a+3.efi")
                .exists()
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
