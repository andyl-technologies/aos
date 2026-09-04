//! Canonical downloadable disk encodings and exact round-trip verification.

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;

use crate::input::digest_regular_file;
use crate::tools::PinnedTool;

const MAX_QEMU_OUTPUT_BYTES: u64 = 1024 * 1024;
const VHD_FOOTER_BYTES: u64 = 512;

/// Download encodings proven to reconstruct one exact logical disk.
#[derive(Debug)]
pub struct DiskFormatsV1 {
    /// Zstandard-compressed raw disk.
    pub raw_zstd: PathBuf,
    /// Canonical QCOW2 encoding.
    pub qcow2: PathBuf,
    /// Canonical stream-optimized VMDK encoding.
    pub vmdk: PathBuf,
    /// Canonical dynamic VHD encoding.
    pub vhd: PathBuf,
    /// Exact logical-disk identity reconstructed by every format.
    pub logical_disk_sha256: Sha256Digest,
}

/// Converts a logical disk and round-trips every downloadable format.
///
/// # Errors
///
/// Returns an error when conversion/checking fails, an encoding exceeds the
/// download budget, a format contains an unrecognized nondeterministic field,
/// or any reconstruction differs in length or SHA-256 from `logical_disk`.
pub async fn build_disk_formats(
    logical_disk: &Path,
    output_directory: &Path,
    scratch: &Path,
    download_budget_bytes: u64,
    zstd: &PinnedTool,
    qemu_img: &PinnedTool,
) -> Result<DiskFormatsV1> {
    fs::create_dir(output_directory)?;
    fs::create_dir(scratch)?;
    let (logical_size, logical_digest) = digest_regular_file(logical_disk)?;

    let raw_zstd = output_directory.join("aos.raw.zst");
    let _ = zstd
        .run_to_new_file(
            [
                "--ultra",
                "-22",
                "--long=27",
                "-T1",
                "--no-progress",
                "-q",
                "-c",
                "--",
                path_text(logical_disk)?,
            ],
            None,
            &raw_zstd,
            download_budget_bytes,
        )
        .await?;
    verify_zstd_round_trip(&raw_zstd, logical_size, logical_digest, scratch, zstd).await?;

    let qcow2 = output_directory.join("aos.qcow2");
    convert(
        qemu_img,
        logical_disk,
        "qcow2",
        Some("compat=1.1,cluster_size=65536,lazy_refcounts=off"),
        &qcow2,
    )
    .await?;
    require_bounded(&qcow2, download_budget_bytes)?;
    verify_qemu_round_trip(
        &qcow2,
        "qcow2",
        logical_disk,
        logical_size,
        logical_digest,
        scratch,
        qemu_img,
    )
    .await?;

    let vmdk = output_directory.join("aos.vmdk");
    convert(
        qemu_img,
        logical_disk,
        "vmdk",
        Some("subformat=streamOptimized,compat6=on"),
        &vmdk,
    )
    .await?;
    normalize_vmdk_cid(&vmdk, logical_digest)?;
    require_bounded(&vmdk, download_budget_bytes)?;
    verify_qemu_round_trip(
        &vmdk,
        "vmdk",
        logical_disk,
        logical_size,
        logical_digest,
        scratch,
        qemu_img,
    )
    .await?;

    let vhd = output_directory.join("aos.vhd");
    convert(
        qemu_img,
        logical_disk,
        "vpc",
        Some("subformat=dynamic,force_size=on"),
        &vhd,
    )
    .await?;
    normalize_vhd_footers(&vhd, logical_digest)?;
    require_bounded(&vhd, download_budget_bytes)?;
    verify_qemu_round_trip(
        &vhd,
        "vpc",
        logical_disk,
        logical_size,
        logical_digest,
        scratch,
        qemu_img,
    )
    .await?;

    Ok(DiskFormatsV1 {
        raw_zstd,
        qcow2,
        vmdk,
        vhd,
        logical_disk_sha256: logical_digest,
    })
}

async fn convert(
    qemu_img: &PinnedTool,
    source: &Path,
    format: &str,
    options: Option<&str>,
    output: &Path,
) -> Result<()> {
    if output.symlink_metadata().is_ok() {
        bail!("disk encoding output already exists");
    }
    let mut command = vec![
        OsString::from("convert"),
        OsString::from("-f"),
        OsString::from("raw"),
        OsString::from("-O"),
        OsString::from(format),
    ];
    if let Some(options) = options {
        command.push(OsString::from("-o"));
        command.push(OsString::from(options));
    }
    command.push(source.as_os_str().to_owned());
    command.push(output.as_os_str().to_owned());
    let _ = qemu_img.run(command, MAX_QEMU_OUTPUT_BYTES).await?;
    Ok(())
}

async fn verify_zstd_round_trip(
    encoded: &Path,
    expected_size: u64,
    expected_digest: Sha256Digest,
    scratch: &Path,
    zstd: &PinnedTool,
) -> Result<()> {
    let reconstructed = scratch.join("raw-reconstructed.img");
    let _ = zstd
        .run_to_new_file(
            ["-d", "-q", "-c", "--", path_text(encoded)?],
            None,
            &reconstructed,
            expected_size,
        )
        .await?;
    require_reconstruction(&reconstructed, expected_size, expected_digest)
}

#[allow(clippy::too_many_arguments)]
async fn verify_qemu_round_trip(
    encoded: &Path,
    format: &str,
    logical_disk: &Path,
    expected_size: u64,
    expected_digest: Sha256Digest,
    scratch: &Path,
    qemu_img: &PinnedTool,
) -> Result<()> {
    if format == "qcow2" {
        let _ = qemu_img
            .run(
                ["check", "-f", format, path_text(encoded)?],
                MAX_QEMU_OUTPUT_BYTES,
            )
            .await?;
    }
    let _ = qemu_img
        .run(
            [
                "compare",
                "-f",
                "raw",
                "-F",
                format,
                path_text(logical_disk)?,
                path_text(encoded)?,
            ],
            MAX_QEMU_OUTPUT_BYTES,
        )
        .await?;
    let reconstructed = scratch.join(format!("{format}-reconstructed.img"));
    let _ = qemu_img
        .run(
            [
                "convert",
                "-f",
                format,
                "-O",
                "raw",
                path_text(encoded)?,
                path_text(&reconstructed)?,
            ],
            MAX_QEMU_OUTPUT_BYTES,
        )
        .await?;
    require_reconstruction(&reconstructed, expected_size, expected_digest)
}

fn normalize_vmdk_cid(path: &Path, logical_digest: Sha256Digest) -> Result<()> {
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let maximum = file.metadata()?.len().min(1024 * 1024);
    let mut prefix = vec![0_u8; usize::try_from(maximum)?];
    file.read_exact(&mut prefix)?;
    let marker = b"CID=";
    let positions = prefix
        .windows(marker.len())
        .enumerate()
        .filter(|(_, window)| *window == marker)
        .map(|(offset, _)| offset)
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        bail!("stream-optimized VMDK lacks one unambiguous CID field");
    }
    let value_start = positions[0] + marker.len();
    let value_end = value_start
        .checked_add(8)
        .context("VMDK CID offset overflow")?;
    if value_end > prefix.len()
        || !prefix[value_start..value_end]
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        bail!("stream-optimized VMDK has a malformed CID field");
    }
    prefix[value_start..value_end].copy_from_slice(&logical_digest.hex().as_bytes()[..8]);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&prefix)?;
    file.sync_all()?;
    Ok(())
}

fn normalize_vhd_footers(path: &Path, logical_digest: Sha256Digest) -> Result<()> {
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let length = file.metadata()?.len();
    if length < VHD_FOOTER_BYTES * 2 {
        bail!("dynamic VHD is shorter than its redundant footers");
    }
    for offset in [0, length - VHD_FOOTER_BYTES] {
        file.seek(SeekFrom::Start(offset))?;
        let mut footer = [0_u8; 512];
        file.read_exact(&mut footer)?;
        if &footer[..8] != b"conectix" {
            bail!("dynamic VHD lacks its canonical footer cookie");
        }
        footer[24..28].fill(0);
        footer[68..84].copy_from_slice(&logical_digest.as_bytes()[..16]);
        footer[84] = 0;
        footer[74] = (footer[74] & 0x0f) | 0x40;
        footer[76] = (footer[76] & 0x3f) | 0x80;
        footer[64..68].fill(0);
        let checksum = !footer
            .iter()
            .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        footer[64..68].copy_from_slice(&checksum.to_be_bytes());
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&footer)?;
    }
    file.sync_all()?;
    Ok(())
}

fn require_reconstruction(
    path: &Path,
    expected_size: u64,
    expected_digest: Sha256Digest,
) -> Result<()> {
    let (size, digest) = digest_regular_file(path)?;
    if size != expected_size || digest != expected_digest {
        bail!("disk encoding does not reconstruct the canonical logical disk");
    }
    Ok(())
}

fn require_bounded(path: &Path, maximum: u64) -> Result<u64> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("disk encoding is empty, special, or exceeds its download budget");
    }
    Ok(metadata.len())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("disk encoding path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_redundant_vhd_footer_identity() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("disk.vhd");
        let mut footer = [0_u8; 512];
        footer[..8].copy_from_slice(b"conectix");
        let mut bytes = footer.to_vec();
        bytes.extend_from_slice(&footer);
        fs::write(&path, bytes)?;
        normalize_vhd_footers(&path, Sha256Digest::of_bytes("disk"))?;
        let normalized = fs::read(path)?;
        assert_eq!(&normalized[..512], &normalized[512..]);
        assert_ne!(&normalized[64..80], &[0_u8; 16]);
        Ok(())
    }
}
