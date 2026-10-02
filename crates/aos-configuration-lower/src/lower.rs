//! Publishes deterministic native lower images and verifies retained receipts.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::model::{Input, Lower};

/// Supplies immutable source-built tools used by lower assembly and inspection.
pub struct Tools {
    /// Names the AOS EROFS image writer.
    pub mkfs: PathBuf,
    /// Names the AOS EROFS checker.
    pub fsck: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    effect: String,
    revision: String,
    lower: Lower,
    input: Input,
}

/// Builds or reuses the exact native configuration image for one effect revision.
///
/// # Errors
/// Returns an error for invalid inputs, unsafe paths, inconsistent retained
/// state, file rendering failures, EROFS tool failures, or durability failures.
pub fn prepare(input: &Input, effect: &str, revision: &str, tools: &Tools) -> Result<Lower> {
    input.validate()?;
    validate_tool(&tools.mkfs)?;
    validate_tool(&tools.fsck)?;
    let input_sha256 = digest(&serde_json::to_value(input)?)?;
    let key = Sha256Digest::of_canonical(
        "aos.configuration-lower-key/v1",
        &(effect, revision, &input_sha256),
    )?
    .to_string();
    let directory = Path::new(&input.retained_root).join(key.trim_start_matches("sha256:"));
    if directory.exists() {
        let lower = read_receipt(&directory, effect)?.lower;
        ensure!(
            lower.input_sha256 == input_sha256,
            "lower input checksum differs"
        );
        validate(&lower, effect, tools)?;
        return Ok(lower);
    }
    fs::create_dir_all(&input.retained_root)?;
    let metadata = fs::symlink_metadata(&input.retained_root)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::getuid().as_raw(),
        "lower repository is not owned by the handler"
    );
    fs::set_permissions(&input.retained_root, fs::Permissions::from_mode(0o700))?;

    let stage = directory.with_extension(format!("stage-{}", std::process::id()));
    if stage.exists() {
        let metadata = fs::symlink_metadata(&stage)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "lower staging path was substituted"
        );
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let tree = stage.join("etc-tree");
    fs::create_dir(&tree)?;
    let result = (|| {
        crate::render::render(input, &tree)?;
        normalize_tree_directory_modes(&tree)?;
        sync_tree(&tree)?;
        let image = stage.join("etc.erofs");
        let status = Command::new(&tools.mkfs)
            .env_clear()
            .args([
                "--all-root",
                "-T0",
                "-U",
                "44128103-9422-4cf5-97c5-3e29752228bc",
                "-L",
                "aos-config",
            ])
            .arg(&image)
            .arg(&tree)
            .stdout(diagnostic_stdout()?)
            .status()?;
        ensure!(status.success(), "AOS mkfs.erofs failed: {status}");
        sync_file(&image)?;
        run_fsck(&tools.fsck, &image)?;
        let lower = Lower {
            directory: directory
                .to_str()
                .context("lower directory is not UTF-8")?
                .into(),
            image: directory
                .join("etc.erofs")
                .to_str()
                .context("lower image is not UTF-8")?
                .into(),
            receipt_effect: effect.into(),
            input_sha256,
            image_sha256: sha256_file(&image)?,
            tree_sha256: hash_tree(&tree)?,
        };
        let receipt = Receipt {
            schema: "aos.configuration-lower.receipt".into(),
            effect: effect.into(),
            revision: revision.into(),
            lower: lower.clone(),
            input: input.clone(),
        };
        write_durable(&stage.join("receipt.json"), &serde_json::to_vec(&receipt)?)?;
        sync_directory(&stage)?;
        fs::rename(&stage, &directory)?;
        sync_directory(Path::new(&input.retained_root))?;
        Ok(lower)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

/// Preserves retired managed paths when constructing the next generation.
///
/// Previous checked results bind the receipt carrying the earlier path set.
/// Whiteouts survive later updates until that path is explicitly authored again.
///
/// # Errors
/// Returns an error when the previous lower or its retained receipt is invalid.
pub fn inherit_removals(input: &mut Input, previous: &Lower, tools: &Tools) -> Result<()> {
    validate(previous, &previous.receipt_effect, tools)?;
    let receipt = read_receipt(Path::new(&previous.directory), &previous.receipt_effect)?;
    let mut removed = input
        .removed_paths
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    removed.extend(receipt.input.removed_paths.iter().cloned());
    let desired = input.desired_paths()?;
    removed.extend(
        receipt
            .input
            .desired_paths()?
            .into_iter()
            .filter(|path| !desired.contains(path)),
    );
    removed.retain(|path| !desired.contains(path));
    input.removed_paths = removed.into_iter().collect();
    input.validate()
}

/// Lists paths owned or retired by a checked immutable lower.
///
/// # Errors
/// Returns an error for mismatched retained input or receipt evidence.
pub fn managed_paths(lower: &Lower) -> Result<Vec<String>> {
    let receipt = read_receipt(Path::new(&lower.directory), &lower.receipt_effect)?;
    ensure!(
        receipt.lower == *lower,
        "managed path receipt differs from checked lower"
    );
    Ok(receipt
        .input
        .desired_paths()?
        .into_iter()
        .chain(receipt.input.removed_paths)
        .collect())
}

/// Observes an existing exact lower without performing any construction.
///
/// # Errors
/// Returns an error for invalid desired inputs or inconsistent retained evidence.
pub fn observe(
    input: &Input,
    effect: &str,
    revision: &str,
    tools: &Tools,
) -> Result<Option<Lower>> {
    input.validate()?;
    let input_sha256 = digest(&serde_json::to_value(input)?)?;
    let key = Sha256Digest::of_canonical(
        "aos.configuration-lower-key/v1",
        &(effect, revision, &input_sha256),
    )?
    .to_string();
    let directory = Path::new(&input.retained_root).join(key.trim_start_matches("sha256:"));
    if !directory.exists() {
        return Ok(None);
    }
    let lower = read_receipt(&directory, effect)?.lower;
    ensure!(
        lower.input_sha256 == input_sha256,
        "retained lower input checksum differs"
    );
    validate(&lower, effect, tools)?;
    Ok(Some(lower))
}

/// Verifies a retained lower against its checked result and native effect identity.
///
/// # Errors
/// Returns an error for substituted paths, a mismatched receipt, checksum drift,
/// unsupported tree entries, or failure of the immutable AOS EROFS checker.
pub fn validate(lower: &Lower, effect: &str, tools: &Tools) -> Result<()> {
    validate_beneath(lower, effect, tools, Path::new("/"))
}

/// Checks a canonical lower result from another immutable root view.
///
/// # Errors
/// Returns an error for receipt, path, checksum, or EROFS inconsistencies.
pub fn validate_beneath(lower: &Lower, effect: &str, tools: &Tools, root: &Path) -> Result<()> {
    validate_tool(&tools.fsck)?;
    let directory = Path::new(&lower.directory);
    ensure!(
        directory.is_absolute() && directory.join("etc.erofs") == Path::new(&lower.image),
        "lower image is outside its retained directory"
    );
    let directory = root.join(
        directory
            .strip_prefix("/")
            .context("lower directory is not absolute")?,
    );
    let receipt = read_receipt(&directory, effect)?;
    ensure!(
        receipt.lower == *lower,
        "retained lower receipt differs from checked native result"
    );
    let tree = directory.join("etc-tree");
    ensure!(
        hash_tree(&tree)? == lower.tree_sha256,
        "retained lower tree checksum differs"
    );
    let image = root.join(
        Path::new(&lower.image)
            .strip_prefix("/")
            .context("lower image is not absolute")?,
    );
    ensure!(
        fs::symlink_metadata(&image)?.is_file(),
        "retained lower image is not a regular file"
    );
    ensure!(
        sha256_file(&image)? == lower.image_sha256,
        "retained lower image checksum differs"
    );
    run_fsck(&tools.fsck, &image)
}

fn read_receipt(directory: &Path, effect: &str) -> Result<Receipt> {
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "retained lower directory is not real"
    );
    let path = directory.join("receipt.json");
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1024 * 1024,
        "lower receipt is not a bounded regular file"
    );
    let receipt: Receipt = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        digest(&serde_json::to_value(&receipt.input)?)? == receipt.lower.input_sha256,
        "receipt input checksum differs"
    );
    ensure!(
        receipt.schema == "aos.configuration-lower.receipt" && receipt.effect == effect,
        "lower receipt belongs to another effect"
    );
    Ok(receipt)
}

fn run_fsck(program: &Path, image: &Path) -> Result<()> {
    let status = Command::new(program)
        .env_clear()
        .arg(image)
        .stdout(diagnostic_stdout()?)
        .status()?;
    ensure!(status.success(), "AOS fsck.erofs rejected lower: {status}");
    Ok(())
}

// A native handler's stdout contains exactly one JSON response. Tool progress
// belongs on stderr even when upstream writes it to its ordinary stdout.
fn diagnostic_stdout() -> Result<Stdio> {
    Ok(Stdio::from(rustix::io::dup(std::io::stderr())?))
}

fn validate_tool(path: &Path) -> Result<()> {
    let text = path.to_str().context("tool path is not UTF-8")?;
    ensure!(
        text.starts_with("/nix/store/")
            && text
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | "..")),
        "configuration tool is outside immutable store"
    );
    Ok(())
}

fn digest(value: &serde_json::Value) -> Result<String> {
    Ok(Sha256Digest::of_bytes(aos_contract::canonical::canonical_json(value)?).to_string())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_tree(root: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspecting configuration tree {}", root.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("configuration lower tree is not a real directory");
    }
    let mut records = Vec::new();
    collect_tree_records(root, root, &mut records)?;
    digest(&serde_json::Value::Array(records))
}

fn collect_tree_records(
    root: &Path,
    directory: &Path,
    records: &mut Vec<serde_json::Value>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)
        .with_context(|| format!("reading configuration tree {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .context("configuration tree entry escaped its root")?;
        let relative = String::from_utf8(relative.as_os_str().as_bytes().to_vec())
            .context("configuration tree contains a non-UTF-8 path")?;
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting configuration tree entry {relative:?}"))?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path)
                .with_context(|| format!("reading configuration symlink {relative:?}"))?;
            let target = String::from_utf8(target.as_os_str().as_bytes().to_vec())
                .context("configuration tree contains a non-UTF-8 symlink target")?;
            records.push(serde_json::json!([relative, "symlink", target]));
        } else if metadata.is_dir() {
            records.push(serde_json::json!([
                relative,
                "directory",
                format!("{mode:04o}")
            ]));
            collect_tree_records(root, &path, records)?;
        } else if metadata.is_file() {
            records.push(serde_json::json!([
                relative,
                "file",
                format!("{mode:04o}"),
                sha256_file(&path)?
            ]));
        } else if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
            records.push(serde_json::json!([relative, "whiteout"]));
        } else {
            bail!("configuration tree contains unsupported entry {relative:?}");
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        let directory = directories[cursor].clone();
        cursor += 1;
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("reading {} for durable sync", directory.display()))?
        {
            let path = entry?.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path);
            } else if metadata.is_file() {
                sync_file(&path)?;
            }
        }
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

fn normalize_tree_directory_modes(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("configuration lower tree is not a real directory");
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(root, permissions)?;
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            normalize_tree_directory_modes(&path)?;
        }
    }
    Ok(())
}

fn sync_file(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}
