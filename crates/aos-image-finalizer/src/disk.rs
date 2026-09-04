//! Canonical GPT disk and deterministic EFI System Partition construction.

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::assembly::UnsignedImageAssemblyV1;
use crate::filesystem::normalize_tree_times;
use crate::finalize::PreparedFilesystemsV1;
use crate::tools::PinnedTool;
use crate::uki::SignedEfiArtifactsV1;

const FAT_EPOCH_SECONDS: i64 = 315_532_800;
const MAX_SFDISK_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Exact finalized disk geometry, expressed in logical sectors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FinalDiskLayoutV1 {
    /// Total logical sectors including GPT headroom.
    pub disk_sectors: u64,
    /// ESP start.
    pub esp_start: u64,
    /// ESP length.
    pub esp_sectors: u64,
    /// Slot-A root start.
    pub root_a_start: u64,
    /// Slot-A/root-slot length.
    pub root_sectors: u64,
    /// Slot-A verity start.
    pub root_a_hash_start: u64,
    /// Verity-slot length.
    pub hash_sectors: u64,
    /// Slot-B root start.
    pub root_b_start: u64,
    /// Slot-B verity start.
    pub root_b_hash_start: u64,
}

/// Canonical logical disk plus its independently checked geometry.
#[derive(Debug)]
pub struct LogicalDiskV1 {
    /// Exact uncompressed GPT disk bytes.
    pub path: PathBuf,
    /// Verified partition geometry.
    pub layout: FinalDiskLayoutV1,
    /// Exact deterministic FAT32 ESP bytes used in the disk.
    pub esp: PathBuf,
}

#[derive(Deserialize)]
struct SfdiskDocument {
    partitiontable: SfdiskTable,
}

#[derive(Deserialize)]
struct SfdiskTable {
    label: String,
    id: String,
    unit: String,
    partitions: Vec<SfdiskPartition>,
}

#[derive(Deserialize)]
struct SfdiskPartition {
    start: u64,
    size: u64,
    #[serde(rename = "type")]
    type_guid: String,
    uuid: String,
    name: String,
}

/// Builds the canonical ESP and sparse logical A/B GPT disk.
///
/// Slot A is populated as the initial known-good system. Slot B remains all
/// zeroes until the first transactional update, matching runtime staging
/// semantics; both normal/recovery UKIs remain separately publishable.
///
/// # Errors
///
/// Returns an error for geometry overflow, content exceeding a partition,
/// unsafe existing output, FAT/GPT tool failure, or independently observed
/// GPT identity that differs from the captured recipe.
pub async fn build_logical_disk(
    assembly: &UnsignedImageAssemblyV1,
    prepared: &PreparedFilesystemsV1,
    efi: &SignedEfiArtifactsV1,
    work: &Path,
    mkfs_vfat: &PinnedTool,
    mcopy: &PinnedTool,
    sfdisk: &PinnedTool,
) -> Result<LogicalDiskV1> {
    let output = work.join("disk-output");
    let esp_tree = work.join("esp-tree");
    fs::create_dir(&output)?;
    fs::create_dir(&esp_tree)?;
    populate_esp_tree(assembly, efi, &esp_tree)?;
    normalize_tree_times(&esp_tree, FAT_EPOCH_SECONDS)?;

    let layout = FinalDiskLayoutV1::derive(assembly)?;
    let esp = output.join("esp.fat");
    let esp_bytes = sectors_to_bytes(layout.esp_sectors, assembly.layout.sector_size)?;
    let esp_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&esp)?;
    esp_file.set_len(esp_bytes)?;
    esp_file.sync_all()?;
    let _ = mkfs_vfat
        .run(
            [
                "-F",
                "32",
                "-n",
                "ESP",
                "-i",
                &assembly.layout.fat_volume_id,
                "--invariant",
                path_text(&esp)?,
            ],
            MAX_SFDISK_OUTPUT_BYTES,
        )
        .await?;
    let _ = mcopy
        .run(
            [
                "-m",
                "-s",
                "-i",
                path_text(&esp)?,
                path_text(&esp_tree.join("EFI"))?,
                "::",
            ],
            MAX_SFDISK_OUTPUT_BYTES,
        )
        .await?;
    let _ = mcopy
        .run(
            [
                "-m",
                "-s",
                "-i",
                path_text(&esp)?,
                path_text(&esp_tree.join("loader"))?,
                "::",
            ],
            MAX_SFDISK_OUTPUT_BYTES,
        )
        .await?;
    require_exact_size(&esp, esp_bytes, "ESP")?;

    let disk = output.join("image.logical.raw");
    let disk_bytes = sectors_to_bytes(layout.disk_sectors, assembly.layout.sector_size)?;
    let mut disk_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&disk)?;
    disk_file.set_len(disk_bytes)?;
    disk_file.sync_all()?;
    let table = output.join("partition-table.sfdisk");
    write_partition_table(&table, assembly, &layout)?;
    let _ = sfdisk
        .run_with_input(
            ["--no-reread", "--no-tell-kernel", path_text(&disk)?],
            &table,
            MAX_SFDISK_OUTPUT_BYTES,
        )
        .await?;

    write_partition(&mut disk_file, &esp, layout.esp_start, layout.esp_sectors)?;
    write_partition(
        &mut disk_file,
        &prepared.root_filesystem,
        layout.root_a_start,
        layout.root_sectors,
    )?;
    write_partition(
        &mut disk_file,
        &prepared.verity.hash_tree,
        layout.root_a_hash_start,
        layout.hash_sectors,
    )?;
    disk_file.sync_all()?;
    verify_zero_partition(&mut disk_file, layout.root_b_start, layout.root_sectors)?;
    verify_zero_partition(
        &mut disk_file,
        layout.root_b_hash_start,
        layout.hash_sectors,
    )?;
    verify_partition_table(sfdisk, &disk, assembly, &layout).await?;
    require_exact_size(&disk, disk_bytes, "logical disk")?;
    Ok(LogicalDiskV1 {
        path: disk,
        layout,
        esp,
    })
}

impl FinalDiskLayoutV1 {
    /// Derives checked, aligned geometry from the captured layout contract.
    ///
    /// # Errors
    ///
    /// Returns an error for arithmetic overflow or non-MiB sector geometry.
    pub fn derive(assembly: &UnsignedImageAssemblyV1) -> Result<Self> {
        let sectors_per_mib = (1024_u64 * 1024)
            .checked_div(assembly.layout.sector_size)
            .context("sector size cannot represent a MiB")?;
        if sectors_per_mib == 0 || sectors_per_mib * assembly.layout.sector_size != 1024 * 1024 {
            bail!("sector size does not divide one MiB");
        }
        let esp_sectors = assembly
            .layout
            .esp_size_mib
            .checked_mul(sectors_per_mib)
            .context("ESP sector count overflow")?;
        let root_sectors = assembly
            .layout
            .root_partition_mib
            .checked_mul(sectors_per_mib)
            .context("root sector count overflow")?;
        let hash_sectors = assembly
            .layout
            .verity_partition_mib
            .checked_mul(sectors_per_mib)
            .context("verity sector count overflow")?;
        let root_a_start = align(
            assembly
                .layout
                .esp_start_sector
                .checked_add(esp_sectors)
                .context("root-A start overflow")?,
            assembly.layout.alignment_sectors,
        )?;
        let root_a_hash_start = align(
            root_a_start
                .checked_add(root_sectors)
                .context("root-A hash start overflow")?,
            assembly.layout.alignment_sectors,
        )?;
        let root_b_start = align(
            root_a_hash_start
                .checked_add(hash_sectors)
                .context("root-B start overflow")?,
            assembly.layout.alignment_sectors,
        )?;
        let root_b_hash_start = align(
            root_b_start
                .checked_add(root_sectors)
                .context("root-B hash start overflow")?,
            assembly.layout.alignment_sectors,
        )?;
        let disk_sectors = root_b_hash_start
            .checked_add(hash_sectors)
            .and_then(|value| value.checked_add(assembly.layout.alignment_sectors))
            .context("disk sector count overflow")?;
        Ok(Self {
            disk_sectors,
            esp_start: assembly.layout.esp_start_sector,
            esp_sectors,
            root_a_start,
            root_sectors,
            root_a_hash_start,
            hash_sectors,
            root_b_start,
            root_b_hash_start,
        })
    }
}

fn populate_esp_tree(
    assembly: &UnsignedImageAssemblyV1,
    efi: &SignedEfiArtifactsV1,
    root: &Path,
) -> Result<()> {
    for directory in [
        root.join("EFI/BOOT"),
        root.join("EFI/systemd"),
        root.join("EFI/Linux"),
        root.join("EFI/AOS"),
        root.join("loader/entries"),
    ] {
        fs::create_dir_all(directory)?;
    }
    copy_new(
        &efi.bootloader,
        &root
            .join("EFI/BOOT")
            .join(&assembly.layout.efi_filenames.fallback),
    )?;
    copy_new(
        &efi.bootloader,
        &root
            .join("EFI/systemd")
            .join(&assembly.layout.efi_filenames.systemd_boot),
    )?;
    let normal = root
        .join("EFI/Linux")
        .join(&assembly.layout.efi_filenames.normal_uki);
    copy_new(&efi.uki_a, &normal)?;
    copy_new(
        &efi.measurement_a.measurement,
        &normal.with_extension("efi.measurement"),
    )?;
    copy_new(
        &efi.measurement_a.signature,
        &normal.with_extension("efi.measurement.sig"),
    )?;
    copy_new(&efi.recovery_uki_a, &root.join("EFI/AOS/recovery-a.efi"))?;
    copy_new(&efi.recovery_uki_b, &root.join("EFI/AOS/recovery-b.efi"))?;
    write_new(
        &root.join("loader/loader.conf"),
        b"default aos-*.efi\ntimeout 3\nconsole-mode max\neditor no\n",
    )?;
    write_new(
        &root.join("loader/entries/recovery-a.conf"),
        format!(
            "title AOS Recovery A ({})\nefi /EFI/AOS/recovery-a.efi\n",
            assembly.version
        )
        .as_bytes(),
    )?;
    write_new(
        &root.join("loader/entries/recovery-b.conf"),
        format!(
            "title AOS Recovery B ({})\nefi /EFI/AOS/recovery-b.efi\n",
            assembly.version
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn write_partition_table(
    path: &Path,
    assembly: &UnsignedImageAssemblyV1,
    layout: &FinalDiskLayoutV1,
) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    writeln!(file, "label: gpt")?;
    writeln!(file, "label-id: {}", assembly.layout.disk_guid)?;
    for (start, size, type_guid, uuid, name) in expected_partitions(assembly, layout) {
        writeln!(
            file,
            "start={start}, size={size}, type={type_guid}, uuid={uuid}, name=\"{name}\""
        )?;
    }
    file.sync_all()?;
    Ok(())
}

fn expected_partitions<'a>(
    assembly: &'a UnsignedImageAssemblyV1,
    layout: &FinalDiskLayoutV1,
) -> [(u64, u64, &'a str, &'a str, &'static str); 5] {
    [
        (
            layout.esp_start,
            layout.esp_sectors,
            &assembly.layout.partition_type_guids.esp,
            &assembly.layout.partition_guids.esp,
            "ESP",
        ),
        (
            layout.root_a_start,
            layout.root_sectors,
            &assembly.layout.partition_type_guids.root,
            &assembly.layout.partition_guids.root_a,
            "root-a",
        ),
        (
            layout.root_a_hash_start,
            layout.hash_sectors,
            &assembly.layout.partition_type_guids.verity,
            &assembly.layout.partition_guids.root_a_hash,
            "root-a-hash",
        ),
        (
            layout.root_b_start,
            layout.root_sectors,
            &assembly.layout.partition_type_guids.root,
            &assembly.layout.partition_guids.root_b,
            "root-b",
        ),
        (
            layout.root_b_hash_start,
            layout.hash_sectors,
            &assembly.layout.partition_type_guids.verity,
            &assembly.layout.partition_guids.root_b_hash,
            "root-b-hash",
        ),
    ]
}

async fn verify_partition_table(
    sfdisk: &PinnedTool,
    disk: &Path,
    assembly: &UnsignedImageAssemblyV1,
    layout: &FinalDiskLayoutV1,
) -> Result<()> {
    let output = sfdisk
        .run(["--json", path_text(disk)?], MAX_SFDISK_OUTPUT_BYTES)
        .await?;
    let document: SfdiskDocument =
        serde_json::from_slice(&output.stdout).context("parsing sfdisk JSON")?;
    let table = document.partitiontable;
    if table.label != "gpt"
        || table.unit != "sectors"
        || !table.id.eq_ignore_ascii_case(&assembly.layout.disk_guid)
    {
        bail!("observed GPT header differs from the captured disk identity");
    }
    let expected = expected_partitions(assembly, layout);
    if table.partitions.len() != expected.len() {
        bail!("observed GPT has the wrong partition count");
    }
    for (actual, (start, size, type_guid, uuid, name)) in table.partitions.iter().zip(expected) {
        if actual.start != start
            || actual.size != size
            || !actual.type_guid.eq_ignore_ascii_case(type_guid)
            || !actual.uuid.eq_ignore_ascii_case(uuid)
            || actual.name != name
        {
            bail!("observed GPT partition differs from the captured layout");
        }
    }
    Ok(())
}

fn write_partition(
    disk: &mut fs::File,
    source: &Path,
    start_sector: u64,
    partition_sectors: u64,
) -> Result<()> {
    let offset = sectors_to_bytes(start_sector, 512)?;
    let capacity = sectors_to_bytes(partition_sectors, 512)?;
    let mut source = fs::File::open(source)?;
    let size = source.metadata()?.len();
    if size == 0 || size > capacity {
        bail!("partition payload is empty or exceeds its fixed capacity");
    }
    disk.seek(SeekFrom::Start(offset))?;
    let copied = std::io::copy(&mut source, disk)?;
    if copied != size {
        bail!("partition payload copy was incomplete");
    }
    Ok(())
}

fn verify_zero_partition(
    disk: &mut fs::File,
    start_sector: u64,
    partition_sectors: u64,
) -> Result<()> {
    disk.seek(SeekFrom::Start(sectors_to_bytes(start_sector, 512)?))?;
    let mut remaining = sectors_to_bytes(partition_sectors, 512)?;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
        disk.read_exact(&mut buffer[..wanted])?;
        if buffer[..wanted].iter().any(|byte| *byte != 0) {
            bail!("inactive partition is not zero-filled");
        }
        remaining -= u64::try_from(wanted)?;
    }
    Ok(())
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 {
        bail!("disk alignment cannot be zero");
    }
    let rounded = value
        .checked_add(alignment - 1)
        .context("disk alignment overflow")?;
    Ok(rounded / alignment * alignment)
}

fn sectors_to_bytes(sectors: u64, sector_size: u64) -> Result<u64> {
    sectors
        .checked_mul(sector_size)
        .context("disk byte offset overflow")
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let mut input = fs::File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_exact_size(path: &Path, expected: u64, label: &str) -> Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() != expected {
        bail!("{label} does not have its exact declared size");
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("disk finalizer path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_is_checked() {
        assert_eq!(align(2048, 2048).ok(), Some(2048));
        assert_eq!(align(2049, 2048).ok(), Some(4096));
        assert!(align(u64::MAX, 2048).is_err());
    }
}
