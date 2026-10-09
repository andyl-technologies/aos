//! Shared canonical metadata for final image bytes.
//!
//! Coordinator metadata includes its required assembly commitments. The
//! self-contained producer records only observed filesystem, disk and EFI facts;
//! unavailable verity or measurement facts are omitted, never synthesized.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;
use serde::{Deserialize, Serialize};

use crate::disk::FinalDiskLayoutV1;
use crate::input::digest_regular_file;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) capabilities: Option<aos_release::qualification::capabilities::ImageCapabilities>,
    pub(crate) schema_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) assembly_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) release_id: Option<&'a str>,
    pub(crate) version: &'a str,
    pub(crate) platform: Platform,
    pub(crate) system_variant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sbat_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secure_boot_certificate_sha256: Option<Sha256Digest>,
    pub(crate) root: RootMetadata,
    pub(crate) efi: EfiMetadata,
    pub(crate) disk: DiskMetadata<'a>,
    pub(crate) formats: Vec<ArtifactFact>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootMetadata {
    pub(crate) filesystem_sha256: Sha256Digest,
    pub(crate) filesystem_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verity_sha256: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verity_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EfiMetadata {
    pub(crate) normal_a: UkiMetadata,
    pub(crate) normal_b: UkiMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_a: Option<ArtifactFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_b: Option<ArtifactFact>,
    pub(crate) bootloader: ArtifactFact,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UkiMetadata {
    pub(crate) artifact: ArtifactFact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expected_ready_pcr11: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) measurement: Option<ArtifactFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) measurement_signature: Option<ArtifactFact>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiskMetadata<'a> {
    pub(crate) logical: ArtifactFact,
    pub(crate) disk_guid: &'a str,
    pub(crate) fat_volume_id: &'a str,
    pub(crate) layout: &'a FinalDiskLayoutV1,
    pub(crate) inactive_slot_state: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactFact {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: Sha256Digest,
}

pub(crate) fn uki_metadata(
    id: &str,
    uki: &Path,
    expected_ready_pcr11: Sha256Digest,
    measurement: &Path,
    signature: &Path,
) -> Result<UkiMetadata> {
    Ok(UkiMetadata {
        artifact: artifact_fact(id, &format!("{id}.efi"), uki)?,
        expected_ready_pcr11: Some(expected_ready_pcr11),
        measurement: Some(artifact_fact(
            &format!("{id}-measurement"),
            &format!("{id}.efi.measurement"),
            measurement,
        )?),
        measurement_signature: Some(artifact_fact(
            &format!("{id}-measurement-signature"),
            &format!("{id}.efi.measurement.sig"),
            signature,
        )?),
    })
}

pub(crate) fn artifact_fact(id: &str, relative: &str, path: &Path) -> Result<ArtifactFact> {
    BundlePath::parse(relative)?;
    let (size_bytes, sha256) = digest_regular_file(path)?;
    Ok(ArtifactFact {
        id: id.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        sha256,
    })
}

/// Final normal UKI and its optional signed measurement sidecars.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EfiSource {
    /// Identifies the finalized PE bytes.
    pub artifact: PathBuf,
    /// Identifies the prediction bound to those exact PE bytes.
    pub measurement: Option<PathBuf>,
    /// Identifies the signature over that prediction.
    pub measurement_signature: Option<PathBuf>,
}

/// Supplies observed, final self-contained image artifacts to the serializer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfContainedInput {
    /// Names the actual image release.
    pub version: String,
    /// Names the system policy variant.
    pub system_variant: String,
    /// Identifies the image's target platform.
    pub platform: Platform,
    /// Identifies the exact filesystem bytes before partition padding.
    pub root_filesystem: PathBuf,
    /// Identifies the actual verity hash tree, when enabled.
    pub verity_tree: Option<PathBuf>,
    /// Identifies the actual root-hash text, when verity is enabled.
    pub root_hash: Option<PathBuf>,
    /// Supplies the slot-A normal UKI.
    pub normal_a: EfiSource,
    /// Supplies the slot-B normal UKI.
    pub normal_b: EfiSource,
    /// Identifies the slot-A recovery UKI, when enabled.
    pub recovery_a: Option<PathBuf>,
    /// Identifies the slot-B recovery UKI, when enabled.
    pub recovery_b: Option<PathBuf>,
    /// Identifies the finalized firmware boot manager.
    pub bootloader: PathBuf,
    /// Identifies the actual uncompressed GPT disk.
    pub logical_disk: PathBuf,
    /// Identifies the bounded `sfdisk --json` observation of that disk.
    pub partition_table: PathBuf,
    /// Records the observed FAT volume identifier.
    pub fat_volume_id: String,
    /// Identifies the exact downloadable compressed bytes.
    pub raw_format: PathBuf,
    /// Names those bytes in the public artifact set.
    pub raw_filename: String,
    /// Identifies the public Secure Boot certificate, when signing is enabled.
    pub secure_boot_certificate: Option<PathBuf>,
}

/// Serializes canonical metadata from actual self-contained image bytes.
///
/// The producer verifies its signatures before calling this function. This
/// serializer checks regular file identities, actual GPT geometry and partition
/// content, and measurement bindings. It does not grant runtime admission.
///
/// # Errors
/// Returns an error for unsafe files, malformed observed geometry, mismatched
/// partition content, incomplete verity or measurement inputs, malformed PCR
/// predictions, changed UKI bytes, or failed canonical serialization.
pub fn self_contained(input: &SelfContainedInput) -> Result<Vec<u8>> {
    ensure!(
        !input.version.is_empty() && !input.system_variant.is_empty(),
        "image identity is empty"
    );
    let logical = artifact_fact("logical-disk", "image.logical.raw", &input.logical_disk)?;
    let table: ObservedTable =
        serde_json::from_slice(&read_regular(&input.partition_table, 1024 * 1024)?)?;
    let (layout, disk_guid) = table.layout(logical.size_bytes)?;
    verify_zero_partition(
        &input.logical_disk,
        layout.root_b_start,
        layout.root_sectors,
    )?;
    if layout.hash_sectors != 0 {
        verify_zero_partition(
            &input.logical_disk,
            layout.root_b_hash_start,
            layout.hash_sectors,
        )?;
    }
    let (filesystem_size_bytes, filesystem_sha256) = digest_regular_file(&input.root_filesystem)?;
    verify_partition(
        &input.logical_disk,
        layout.root_a_start,
        layout.root_sectors,
        filesystem_size_bytes,
        filesystem_sha256,
    )?;
    let (verity_sha256, verity_size_bytes, root_hash) = match (&input.verity_tree, &input.root_hash)
    {
        (Some(tree), Some(hash)) => {
            let (size, digest) = digest_regular_file(tree)?;
            verify_partition(
                &input.logical_disk,
                layout.root_a_hash_start,
                layout.hash_sectors,
                size,
                digest,
            )?;
            let bytes = read_regular(hash, 256)?;
            let value = std::str::from_utf8(&bytes)?.trim();
            Sha256Digest::parse(&format!("sha256:{value}"))?;
            (Some(digest), Some(size), Some(value.to_owned()))
        }
        (None, None) => {
            ensure!(
                layout.hash_sectors == 0,
                "unrecorded verity partitions exist"
            );
            (None, None, None)
        }
        _ => anyhow::bail!("verity tree and root hash must be supplied together"),
    };
    ensure!(
        input.recovery_a.is_some() == input.recovery_b.is_some(),
        "recovery requires both slot artifacts"
    );
    let recovery = |id, name, path: &Option<PathBuf>| {
        path.as_deref()
            .map(|path| artifact_fact(id, name, path))
            .transpose()
    };
    let metadata = ImageMetadata {
        schema_version: "aos.image.metadata/v1",
        capabilities: None,
        assembly_digest: None,
        release_id: None,
        version: &input.version,
        platform: input.platform,
        system_variant: &input.system_variant,
        sbat_generation: None,
        secure_boot_certificate_sha256: input
            .secure_boot_certificate
            .as_deref()
            .map(digest_regular_file)
            .transpose()?
            .map(|(_, digest)| digest),
        root: RootMetadata {
            filesystem_size_bytes,
            filesystem_sha256,
            verity_size_bytes,
            verity_sha256,
            root_hash,
        },
        efi: EfiMetadata {
            normal_a: self_contained_uki("uki-a", &input.normal_a)?,
            normal_b: self_contained_uki("uki-b", &input.normal_b)?,
            recovery_a: recovery("recovery-uki-a", "recovery-a.efi", &input.recovery_a)?,
            recovery_b: recovery("recovery-uki-b", "recovery-b.efi", &input.recovery_b)?,
            bootloader: artifact_fact("bootloader", "systemd-boot.efi", &input.bootloader)?,
        },
        disk: DiskMetadata {
            logical,
            layout: &layout,
            disk_guid: &disk_guid,
            fat_volume_id: &input.fat_volume_id,
            inactive_slot_state: "zero-filled",
        },
        formats: vec![artifact_fact(
            "raw",
            &input.raw_filename,
            &input.raw_format,
        )?],
    };
    canonical::to_vec(&metadata)
}

fn self_contained_uki(id: &str, source: &EfiSource) -> Result<UkiMetadata> {
    match (&source.measurement, &source.measurement_signature) {
        (Some(measurement), Some(signature)) => {
            let (_, digest) = digest_regular_file(&source.artifact)?;
            let bytes = read_regular(measurement, 4096)?;
            let lines = std::str::from_utf8(&bytes)?.lines().collect::<Vec<_>>();
            ensure!(
                lines.len() == 3 && lines[0] == "aos.uki-measurement/v1",
                "malformed UKI measurement"
            );
            let recorded = lines[1]
                .strip_prefix("uki_sha256=")
                .context("measurement lacks its UKI binding")?;
            ensure!(
                Sha256Digest::parse(&format!("sha256:{recorded}"))? == digest,
                "measurement binds another UKI"
            );
            let prediction = lines[2]
                .strip_prefix("expected_pcr11=")
                .context("measurement lacks its ready PCR")?;
            let metadata = uki_metadata(
                id,
                &source.artifact,
                Sha256Digest::parse(prediction)?,
                measurement,
                signature,
            )?;
            Ok(metadata)
        }
        (None, None) => Ok(UkiMetadata {
            artifact: artifact_fact(id, &format!("{id}.efi"), &source.artifact)?,
            expected_ready_pcr11: None,
            measurement: None,
            measurement_signature: None,
        }),
        _ => anyhow::bail!("measurement and signature must be supplied together"),
    }
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "metadata input is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "metadata input changed during reading"
    );
    Ok(bytes)
}

fn verify_partition(
    disk: &Path,
    start: u64,
    sectors: u64,
    size: u64,
    expected: Sha256Digest,
) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _};

    let capacity = sectors
        .checked_mul(512)
        .context("partition size overflow")?;
    ensure!(
        size > 0 && size <= capacity,
        "artifact exceeds its observed partition"
    );
    let mut disk = fs::File::open(disk)?;
    disk.seek(std::io::SeekFrom::Start(
        start
            .checked_mul(512)
            .context("partition offset overflow")?,
    ))?;
    let mut remaining = size;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let count = disk.read(&mut buffer[..remaining.min(64 * 1024) as usize])?;
        ensure!(count != 0, "partition artifact is truncated");
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    ensure!(
        Sha256Digest::from_bytes(digest.finalize().into()) == expected,
        "partition content differs from artifact bytes"
    );
    Ok(())
}

fn verify_zero_partition(disk: &Path, start: u64, sectors: u64) -> Result<()> {
    use std::io::{Read as _, Seek as _};

    let mut disk = fs::File::open(disk)?;
    disk.seek(std::io::SeekFrom::Start(
        start
            .checked_mul(512)
            .context("inactive partition offset overflow")?,
    ))?;
    let mut remaining = sectors
        .checked_mul(512)
        .context("inactive partition size overflow")?;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let count = disk.read(&mut buffer[..remaining.min(64 * 1024) as usize])?;
        ensure!(
            count != 0 && buffer[..count].iter().all(|byte| *byte == 0),
            "inactive partition is not zero-filled"
        );
        remaining -= count as u64;
    }
    Ok(())
}

#[derive(Deserialize)]
struct ObservedTable {
    partitiontable: ObservedPartitions,
}
#[derive(Deserialize)]
struct ObservedPartitions {
    label: String,
    id: String,
    unit: String,
    sectorsize: u64,
    partitions: Vec<ObservedPartition>,
}
#[derive(Deserialize)]
struct ObservedPartition {
    name: String,
    start: u64,
    size: u64,
}

impl ObservedTable {
    fn layout(self, bytes: u64) -> Result<(FinalDiskLayoutV1, String)> {
        let table = self.partitiontable;
        ensure!(
            table.label == "gpt"
                && table.unit == "sectors"
                && table.sectorsize == 512
                && bytes % 512 == 0,
            "image requires observed 512-byte GPT geometry"
        );
        let mut ordered = table.partitions.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|partition| partition.start);
        ensure!(
            ordered.windows(2).all(|pair| pair[0]
                .start
                .checked_add(pair[0].size)
                .is_some_and(|end| end <= pair[1].start)),
            "observed GPT partitions overlap"
        );
        let partition = |name| {
            let matches = table
                .partitions
                .iter()
                .filter(|partition| partition.name == name)
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "missing or duplicate GPT partition {name}"
            );
            let partition = matches[0];
            ensure!(
                partition.size > 0
                    && partition
                        .start
                        .checked_add(partition.size)
                        .is_some_and(|end| end <= bytes / 512),
                "GPT partition escapes disk"
            );
            Ok(partition)
        };
        let esp = partition("ESP")?;
        let root_a = partition("root-a")?;
        let root_b = partition("root-b")?;
        ensure!(
            root_a.size == root_b.size,
            "root slots have different capacities"
        );
        let hashes = table
            .partitions
            .iter()
            .any(|partition| partition.name == "root-a-hash" || partition.name == "root-b-hash");
        let (root_a_hash_start, hash_sectors, root_b_hash_start) = if hashes {
            let a = partition("root-a-hash")?;
            let b = partition("root-b-hash")?;
            ensure!(a.size == b.size, "verity slots have different capacities");
            (a.start, a.size, b.start)
        } else {
            (0, 0, 0)
        };
        let layout = FinalDiskLayoutV1 {
            disk_sectors: bytes / 512,
            esp_start: esp.start,
            esp_sectors: esp.size,
            root_a_start: root_a.start,
            root_sectors: root_a.size,
            root_a_hash_start,
            hash_sectors,
            root_b_start: root_b.start,
            root_b_hash_start,
        };
        Ok((layout, table.id))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use super::*;

    fn fixture_input(directory: &Path) -> SelfContainedInput {
        let root = directory.join("root.img");
        fs::write(&root, b"actual filesystem bytes").unwrap();
        let efi = directory.join("efi-file");
        fs::write(&efi, b"regular EFI artifact protocol fixture").unwrap();
        let raw = directory.join("image.raw");
        let mut disk = fs::File::create(&raw).unwrap();
        disk.set_len(32 * 512).unwrap();
        disk.seek(std::io::SeekFrom::Start(4 * 512)).unwrap();
        disk.write_all(&fs::read(&root).unwrap()).unwrap();
        let table = directory.join("partition-table.json");
        fs::write(&table, serde_json::to_vec(&serde_json::json!({
            "partitiontable": {"label":"gpt","id":"observed-test-guid","unit":"sectors","sectorsize":512,
                "partitions":[{"name":"ESP","start":1,"size":2},
                    {"name":"root-a","start":4,"size":2},
                    {"name":"root-b","start":8,"size":2}]}
        })).unwrap()).unwrap();
        let compressed = directory.join("raw.zst");
        fs::write(&compressed, b"download encoding protocol fixture").unwrap();
        let slot = || EfiSource {
            artifact: efi.clone(),
            measurement: None,
            measurement_signature: None,
        };
        SelfContainedInput {
            version: "1".into(),
            system_variant: "test".into(),
            platform: Platform::X86_64Linux,
            root_filesystem: root,
            verity_tree: None,
            root_hash: None,
            normal_a: slot(),
            normal_b: slot(),
            recovery_a: None,
            recovery_b: None,
            bootloader: efi,
            logical_disk: raw,
            partition_table: table,
            fat_volume_id: "observed-test-fat".into(),
            raw_format: compressed,
            raw_filename: "disk.zst".into(),
            secure_boot_certificate: None,
        }
    }

    #[test]
    fn canonical_metadata_records_actual_file_bytes_without_invented_commitments() {
        let directory = tempfile::tempdir().unwrap();
        let input = fixture_input(directory.path());

        let bytes = self_contained(&input).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(value["schema_version"], "aos.image.metadata/v1");
        assert_eq!(
            value["root"]["filesystem_size_bytes"],
            fs::metadata(&input.root_filesystem).unwrap().len()
        );
        assert_eq!(
            value["root"]["filesystem_sha256"],
            serde_json::to_value(digest_regular_file(&input.root_filesystem).unwrap().1).unwrap()
        );
        assert_eq!(value["efi"]["normal_b"]["artifact"]["path"], "uki-b.efi");
        assert_eq!(value["disk"]["layout"]["root_a_start"], 4);
        assert!(value.get("schemaVersion").is_none());
        assert!(value.get("assembly_digest").is_none());
        assert!(value.get("capabilities").is_none());
        assert!(
            value["efi"]["normal_a"]
                .get("expected_ready_pcr11")
                .is_none()
        );
        assert!(value["root"].get("verity_sha256").is_none());
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(directory.path().to_str().unwrap())
        );
        assert_eq!(canonical::to_vec(&value).unwrap(), bytes);
    }

    #[test]
    fn metadata_rejects_changed_partition_bytes_and_nonempty_inactive_slot() {
        let directory = tempfile::tempdir().unwrap();
        let input = fixture_input(directory.path());
        fs::write(&input.root_filesystem, b"replacement filesystem").unwrap();
        assert!(self_contained(&input).is_err());

        let input = fixture_input(directory.path());
        let mut disk = fs::OpenOptions::new()
            .write(true)
            .open(&input.logical_disk)
            .unwrap();
        disk.seek(std::io::SeekFrom::Start(8 * 512)).unwrap();
        disk.write_all(b"unexpected inactive bytes").unwrap();
        assert!(self_contained(&input).is_err());
    }

    #[test]
    fn measurement_must_bind_exact_uki_and_requires_both_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let mut input = fixture_input(directory.path());
        let measurement = directory.path().join("uki.measurement");
        let signature = directory.path().join("uki.measurement.sig");
        fs::write(&signature, b"signature protocol fixture").unwrap();
        fs::write(
            &measurement,
            format!(
                "aos.uki-measurement/v1\nuki_sha256={}\nexpected_pcr11=sha256:{}\n",
                "a".repeat(64),
                "b".repeat(64)
            ),
        )
        .unwrap();
        input.normal_a.measurement = Some(measurement.clone());
        input.normal_a.measurement_signature = Some(signature);
        assert!(self_contained(&input).is_err());

        let actual = digest_regular_file(&input.normal_a.artifact).unwrap().1;
        fs::write(
            &measurement,
            format!(
                "aos.uki-measurement/v1\nuki_sha256={}\nexpected_pcr11=sha256:{}\n",
                actual.hex(),
                "b".repeat(64)
            ),
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&self_contained(&input).unwrap()).unwrap();
        assert_eq!(
            value["efi"]["normal_a"]["expected_ready_pcr11"],
            format!("sha256:{}", "b".repeat(64))
        );
        input.normal_a.measurement_signature = None;
        assert!(self_contained(&input).is_err());
    }
}
