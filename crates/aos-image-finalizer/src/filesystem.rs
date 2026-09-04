//! Deterministic reconstruction of module-bearing filesystems.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};

use crate::assembly::ImageLayoutV1;
use crate::input::VerifiedTool;
use crate::tools::PinnedTool;

const MAX_TOOL_STDOUT_BYTES: u64 = 1024 * 1024;
const INITRD_EXPANSION_FACTOR: u64 = 32;

/// Extracts one EROFS image into a newly created tree.
///
/// # Errors
///
/// Returns an error when the destination exists, extraction fails, or the
/// pinned checker does not create the requested directory.
pub async fn extract_erofs(
    fsck_erofs: &PinnedTool,
    image: &Path,
    destination: &Path,
) -> Result<()> {
    if destination.symlink_metadata().is_ok() {
        bail!("EROFS extraction destination already exists");
    }
    let extract = format!("--extract={}", path_text(destination)?);
    let _ = fsck_erofs
        .run(
            [
                extract.as_str(),
                "--xattrs",
                "--preserve",
                path_text(image)?,
            ],
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    if !destination.is_dir() {
        bail!("EROFS checker did not create its extraction directory");
    }
    Ok(())
}

/// Rebuilds a normalized EROFS tree according to the captured recipe.
///
/// # Errors
///
/// Returns an error when normalization, image construction, structural
/// verification, or the byte budget fails.
pub async fn rebuild_erofs(
    mkfs_erofs: &PinnedTool,
    fsck_erofs: &PinnedTool,
    tree: &Path,
    output: &Path,
    layout: &ImageLayoutV1,
    maximum_bytes: u64,
) -> Result<()> {
    normalize_tree_times(tree, 1)?;
    if output.symlink_metadata().is_ok() {
        bail!("rebuilt EROFS output already exists");
    }
    let compression = format!("zstd,level={}", layout.erofs_compression_level);
    let output_text = path_text(output)?;
    let _ = mkfs_erofs
        .run(
            [
                "--all-root",
                "-T0",
                "-U",
                &layout.root_filesystem_uuid,
                "--workers=1",
                "-z",
                &compression,
                "-C262144",
                "-Eztailpacking",
                "-L",
                &layout.root_filesystem_label,
                output_text,
                path_text(tree)?,
            ],
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    require_bounded_file(output, maximum_bytes, "rebuilt EROFS")?;
    let _ = fsck_erofs.run([output_text], MAX_TOOL_STDOUT_BYTES).await?;
    Ok(())
}

/// Extracts one zstd-compressed `newc` initrd into a newly created tree.
///
/// # Errors
///
/// Returns an error when decompression exceeds its expansion bound, the
/// destination exists, or the pinned cpio implementation rejects the archive.
pub async fn extract_initrd(
    zstd: &PinnedTool,
    cpio_specification: &VerifiedTool,
    image: &Path,
    destination: &Path,
    compressed_budget_bytes: u64,
    scratch: &Path,
) -> Result<()> {
    fs::create_dir(scratch)
        .with_context(|| format!("creating initrd scratch {}", scratch.display()))?;
    let maximum_archive_bytes = compressed_budget_bytes
        .checked_mul(INITRD_EXPANSION_FACTOR)
        .context("initrd expansion budget overflow")?;
    let archive = scratch.join("initrd-uncompressed.cpio");
    let _ = zstd
        .run_to_new_file(
            ["-d", "-q", "-c", "--", path_text(image)?],
            None,
            &archive,
            maximum_archive_bytes,
        )
        .await?;
    fs::create_dir(destination)
        .with_context(|| format!("creating initrd tree {}", destination.display()))?;
    let cpio = PinnedTool::from_verified(
        cpio_specification.clone(),
        destination.to_path_buf(),
        std::time::Duration::from_secs(15 * 60),
    )?;
    let _ = cpio
        .run_with_input(
            ["--quiet", "-idmu", "--no-absolute-filenames"],
            &archive,
            MAX_TOOL_STDOUT_BYTES,
        )
        .await?;
    fs::remove_file(archive)?;
    Ok(())
}

/// Rebuilds one deterministic zstd-compressed `newc` initrd.
///
/// # Errors
///
/// Returns an error when tree traversal finds an unsupported name, cpio or
/// zstd fails, or the finalized initrd exceeds its budget.
pub async fn rebuild_initrd(
    cpio_specification: &VerifiedTool,
    zstd: &PinnedTool,
    tree: &Path,
    output: &Path,
    maximum_bytes: u64,
    scratch: &Path,
) -> Result<()> {
    normalize_tree_times(tree, 1)?;
    let list = scratch.join("initrd-file-list");
    write_sorted_file_list(tree, &list)?;
    let archive = scratch.join("initrd-rebuilt.cpio");
    let maximum_archive_bytes = maximum_bytes
        .checked_mul(INITRD_EXPANSION_FACTOR)
        .context("initrd expansion budget overflow")?;
    let cpio = PinnedTool::from_verified(
        cpio_specification.clone(),
        tree.to_path_buf(),
        std::time::Duration::from_secs(15 * 60),
    )?;
    let _ = cpio
        .run_to_new_file(
            [
                "--quiet",
                "-o",
                "-H",
                "newc",
                "-R",
                "+0:+0",
                "--reproducible",
                "--null",
            ],
            Some(&list),
            &archive,
            maximum_archive_bytes,
        )
        .await?;
    let _ = zstd
        .run_to_new_file(
            ["-19", "-T1", "-q", "-c", "--", path_text(&archive)?],
            None,
            output,
            maximum_bytes,
        )
        .await?;
    fs::remove_file(list)?;
    fs::remove_file(archive)?;
    Ok(())
}

/// Lists regular `.ko` files below a reconstructed tree without following
/// symbolic links.
///
/// # Errors
///
/// Returns an error when traversal fails or encounters a special file.
pub fn kernel_modules(tree: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    collect_entries(tree, Path::new(""), &mut entries)?;
    let mut modules = entries
        .into_iter()
        .filter(|relative| relative.extension() == Some(OsStr::new("ko")))
        .map(|relative| tree.join(relative))
        .collect::<Vec<_>>();
    modules.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    Ok(modules)
}

fn write_sorted_file_list(root: &Path, output: &Path) -> Result<()> {
    let mut entries = vec![PathBuf::from(".")];
    collect_entries(root, Path::new(""), &mut entries)?;
    entries.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    for path in entries {
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            bail!("filesystem tree contains a NUL pathname");
        }
        file.write_all(bytes)?;
        file.write_all(&[0])?;
    }
    file.sync_all()?;
    Ok(())
}

fn collect_entries(root: &Path, relative: &Path, entries: &mut Vec<PathBuf>) -> Result<()> {
    let directory = root.join(relative);
    let mut children = fs::read_dir(&directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<OsString>>>()?;
    children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in children {
        if name.as_bytes().contains(&0) || name == OsStr::new(".") || name == OsStr::new("..") {
            bail!("filesystem tree contains an unsafe pathname component");
        }
        let child = relative.join(name);
        let metadata = fs::symlink_metadata(root.join(&child))?;
        let kind = metadata.file_type();
        if !(kind.is_dir() || kind.is_file() || kind.is_symlink()) {
            bail!("filesystem tree contains a special file");
        }
        entries.push(child.clone());
        if kind.is_dir() {
            collect_entries(root, &child, entries)?;
        }
    }
    Ok(())
}

/// Sets every entry timestamp without following symbolic links.
///
/// # Errors
///
/// Returns an error when tree traversal or a no-follow timestamp update fails.
pub fn normalize_tree_times(root: &Path, epoch_seconds: i64) -> Result<()> {
    let mut entries = vec![PathBuf::new()];
    collect_entries(root, Path::new(""), &mut entries)?;
    let epoch = Timespec {
        tv_sec: epoch_seconds,
        tv_nsec: 0,
    };
    let timestamps = Timestamps {
        last_access: epoch,
        last_modification: epoch,
    };
    for relative in entries.into_iter().rev() {
        utimensat(
            CWD,
            root.join(relative),
            &timestamps,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }
    Ok(())
}

fn require_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<u64> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("{label} is empty, special, or exceeds its byte budget");
    }
    Ok(metadata.len())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("finalizer path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_walk_is_sorted_and_does_not_follow_links() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        fs::create_dir_all(temporary.path().join("lib/modules"))?;
        fs::write(temporary.path().join("lib/modules/z.ko"), b"z")?;
        fs::write(temporary.path().join("lib/modules/a.ko"), b"a")?;
        std::os::unix::fs::symlink("/outside.ko", temporary.path().join("lib/modules/link"))?;
        let modules = kernel_modules(temporary.path())?;
        assert!(modules[0].ends_with("a.ko"));
        assert!(modules[1].ends_with("z.ko"));
        assert_eq!(modules.len(), 2);
        Ok(())
    }

    #[test]
    fn normalized_list_is_nul_terminated_and_sorted() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        fs::create_dir(temporary.path().join("b"))?;
        fs::write(temporary.path().join("a"), b"a")?;
        let list = temporary.path().join("list");
        write_sorted_file_list(temporary.path(), &list)?;
        assert_eq!(fs::read(list)?, b".\0a\0b\0");
        Ok(())
    }
}
