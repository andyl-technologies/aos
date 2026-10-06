//! Preserves admitted store closures physically before replacing an image lower.
//!
//! GC roots retain logical store identities, but cannot retain bytes supplied by
//! an immutable image that is about to be replaced. Copies are published only
//! after their NAR identity and durable contents match the selected store.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use super::{Request, string};

const CLOSURE_BYTES: u64 = 32 * 1024 * 1024;

pub(super) fn persist(nix_store: &Path, request: &Request) -> Result<()> {
    let mut roots = BTreeSet::new();
    for root in &request.retained_store_roots {
        ensure!(
            store_root(root)? == Path::new(root),
            "retained input is not an exact store root"
        );
        roots.insert(PathBuf::from(root));
    }
    for image in [&request.running, &request.candidate] {
        for field in [
            "native_executor_ref",
            "toplevel",
            "boot_artifact_contract",
            "evaluation_descriptor",
        ] {
            roots.insert(store_root(string(image, field)?)?);
        }
        roots.insert(store_root(string(&image["module_library"], "store_path")?)?);
    }

    let closure = closure_paths(&mut Command::new(nix_store), &roots)?;
    let upper = Path::new("/var/lib/nix-overlay/upper/store");
    fs::create_dir_all(upper)?;
    ensure!(
        fs::canonicalize(upper)? == upper,
        "physical store upper traverses an alias"
    );
    for path in closure {
        copy_verified(nix_store, &path, upper)
            .with_context(|| format!("preserving admitted store artifact {}", path.display()))?;
    }
    Ok(())
}

pub(super) fn store_root(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "store path is not normalized"
    );
    let relative = value
        .strip_prefix("/nix/store/")
        .context("input is outside the selected store")?;
    ensure!(
        relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "store path spelling is not canonical"
    );
    let name = relative.split('/').next().context("store root is absent")?;
    let (hash, label) = name.split_once('-').context("store root lacks its hash")?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
            && !label.is_empty(),
        "store root identity is malformed"
    );
    ensure!(
        path.to_string_lossy() == value && !value.ends_with('/'),
        "store path spelling is not canonical"
    );
    Ok(Path::new("/nix/store").join(name))
}

fn closure_paths(command: &mut Command, roots: &BTreeSet<PathBuf>) -> Result<BTreeSet<PathBuf>> {
    let mut child = command
        .args(["--query", "--requisites"])
        .args(roots)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("closure query has no stdout")?
        .take(CLOSURE_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > CLOSURE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        anyhow::bail!("store closure exceeds its bounded inventory");
    }
    ensure!(
        child.wait()?.success(),
        "selected store closure query failed"
    );
    let mut paths = BTreeSet::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let root = store_root(line)?;
        ensure!(
            root == Path::new(line),
            "closure query returned a store member instead of a root"
        );
        paths.insert(root);
    }
    ensure!(
        roots.is_subset(&paths),
        "closure query omitted an admitted root"
    );
    Ok(paths)
}

fn nar_identity(nix_store: &Path, path: &Path) -> Result<(u64, [u8; 32])> {
    let mut child = Command::new(nix_store)
        .arg("--dump")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut input = child.stdout.take().context("NAR dump has no stdout")?;
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let read = (|| -> Result<()> {
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .context("NAR size overflow")?;
            hash.update(&buffer[..count]);
        }
        Ok(())
    })();
    if let Err(error) = read {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    ensure!(child.wait()?.success(), "selected store NAR dump failed");
    Ok((size, hash.finalize().into()))
}

fn copy_verified(nix_store: &Path, source: &Path, upper: &Path) -> Result<()> {
    let destination = upper.join(source.file_name().context("artifact has no basename")?);
    let expected = nar_identity(nix_store, source).context("reading source NAR")?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            ensure!(
                nar_identity(nix_store, &destination)? == expected,
                "existing physical store artifact conflicts with admitted NAR"
            );
            verify_modes(source, &destination)?;
            sync_tree(&destination)?;
            File::open(upper)?.sync_all()?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let staging = tempfile::Builder::new()
        .prefix(".aos-image-copy-up-")
        .tempdir_in(upper)?;
    let staging = Staging(staging.keep());
    let temporary = &staging.0;
    if fs::symlink_metadata(source)?.is_dir() {
        copy_directory(source, temporary)?;
    } else {
        fs::remove_dir(temporary)?;
        copy_tree(source, temporary).context("copying physical artifact tree")?;
    }
    ensure!(
        nar_identity(nix_store, temporary)? == expected,
        "physical copy differs from admitted NAR"
    );
    verify_modes(source, temporary)?;
    sync_tree(temporary).context("syncing physical artifact tree")?;
    // Never replace an independently created physical store object.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        temporary,
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("publishing physical artifact without replacement")?;
    File::open(upper)?.sync_all()?;
    Ok(())
}

// NAR identity preserves file type and executable status, but not all Unix
// permission bits. A writable physical copy must not stand in for readonly input.
fn verify_modes(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata = fs::symlink_metadata(source)?;
    let destination_metadata = fs::symlink_metadata(destination)?;
    ensure!(
        source_metadata.file_type() == destination_metadata.file_type(),
        "physical store member type differs at {}",
        destination.display()
    );
    if source_metadata.file_type().is_symlink() {
        return Ok(());
    }
    ensure!(
        source_metadata.permissions().mode() & 0o7777
            == destination_metadata.permissions().mode() & 0o7777,
        "physical store member permissions differ at {}",
        destination.display()
    );
    if source_metadata.is_dir() {
        for child in fs::read_dir(source)? {
            let child = child?;
            verify_modes(&child.path(), &destination.join(child.file_name()))?;
        }
    }
    Ok(())
}

// The staged object is a direct sibling of the destination: moving a readonly
// directory between parents otherwise requires changing its mode to update '..'.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0).is_ok_and(|metadata| metadata.is_dir()) {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            let _ = fs::remove_file(&self.0);
        }
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        symlink(fs::read_link(source)?, destination)?;
    } else if metadata.is_dir() {
        fs::create_dir(destination)?;
        copy_directory(source, destination)?;
    } else if metadata.is_file() {
        let mut output = File::create_new(destination)?;
        std::io::copy(&mut File::open(source)?, &mut output)?;
        output.flush()?;
        fs::set_permissions(destination, metadata.permissions())?;
    } else {
        anyhow::bail!("immutable artifact contains an unsupported file type");
    }
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    let mut children = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        copy_tree(&child.path(), &destination.join(child.file_name()))?;
    }
    fs::set_permissions(destination, fs::symlink_metadata(source)?.permissions())?;
    Ok(())
}

fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for child in fs::read_dir(path)? {
            sync_tree(&child?.path())?;
        }
        File::open(path)?.sync_all()?;
    } else if metadata.is_file() {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn nix_store() -> PathBuf {
        let path = std::env::var_os("AOS_NIX_STORE")
            .map(PathBuf::from)
            .expect("tests require the source-built AOS_NIX_STORE");
        crate::executable::validate_store_executable(&path, "test nix-store").unwrap();
        path
    }

    #[test]
    fn actual_closure_copy_survives_source_disappearance_and_is_idempotent() {
        let nix = nix_store();
        let temporary = tempfile::tempdir().unwrap();
        let source_store = temporary.path().join("source");
        let source = temporary.path().join("payload");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("executor"), b"retained native executor\n").unwrap();
        fs::set_permissions(source.join("executor"), fs::Permissions::from_mode(0o555)).unwrap();
        symlink("executor", source.join("alias")).unwrap();
        let uri = format!("local?root={}", source_store.display());
        let added = Command::new(&nix)
            .args(["--store", &uri, "--add"])
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            added.status.success(),
            "{}",
            String::from_utf8_lossy(&added.stderr)
        );
        let logical = PathBuf::from(String::from_utf8(added.stdout).unwrap().trim());
        let roots = BTreeSet::from([logical.clone()]);
        let closure = closure_paths(Command::new(&nix).args(["--store", &uri]), &roots).unwrap();
        assert_eq!(closure, roots);
        let physical = source_store.join(logical.strip_prefix("/").unwrap());
        let upper = temporary.path().join("upper");
        fs::create_dir(&upper).unwrap();
        copy_verified(&nix, &physical, &upper).unwrap();
        let copied = upper.join(logical.file_name().unwrap());
        let before = nar_identity(&nix, &copied).unwrap();
        copy_verified(&nix, &physical, &upper).unwrap();
        assert_eq!(nar_identity(&nix, &copied).unwrap(), before);
        // Removing the whole supplying image/store must not remove its copy.
        fs::set_permissions(&physical, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&source_store).unwrap();
        assert_eq!(
            fs::read(copied.join("executor")).unwrap(),
            b"retained native executor\n"
        );
        assert_eq!(
            fs::metadata(copied.join("executor"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            fs::read_link(copied.join("alias")).unwrap(),
            Path::new("executor")
        );
        assert_eq!(nar_identity(&nix, &copied).unwrap(), before);
    }

    #[test]
    fn conflicting_upper_content_mode_and_alias_are_never_repaired() {
        let nix = nix_store();
        for variant in ["content", "mode", "alias"] {
            let temporary = tempfile::tempdir().unwrap();
            let source = temporary.path().join("artifact");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("program"), b"selected bytes").unwrap();
            fs::set_permissions(source.join("program"), fs::Permissions::from_mode(0o555)).unwrap();
            symlink("program", source.join("alias")).unwrap();
            let upper = temporary.path().join("upper");
            fs::create_dir(&upper).unwrap();
            copy_verified(&nix, &source, &upper).unwrap();
            let copied = upper.join("artifact");
            match variant {
                "content" => {
                    fs::set_permissions(copied.join("program"), fs::Permissions::from_mode(0o755))
                        .unwrap();
                    fs::write(copied.join("program"), b"foreign bytes").unwrap();
                }
                "mode" => {
                    fs::set_permissions(copied.join("program"), fs::Permissions::from_mode(0o444))
                        .unwrap()
                }
                _ => {
                    fs::remove_file(copied.join("alias")).unwrap();
                    symlink("foreign", copied.join("alias")).unwrap();
                }
            }
            let conflicting = nar_identity(&nix, &copied).unwrap();
            assert!(copy_verified(&nix, &source, &upper).is_err());
            assert_eq!(nar_identity(&nix, &copied).unwrap(), conflicting);
        }
    }

    #[test]
    fn nar_equal_writable_permission_drift_is_refused_without_repair() {
        let nix = nix_store();
        for (source_mode, destination_mode, directory) in [
            (0o444, 0o644, false),
            (0o555, 0o755, false),
            (0o555, 0o755, true),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let source = temporary.path().join("artifact");
            if directory {
                fs::create_dir(&source).unwrap();
                fs::write(source.join("data"), b"retained bytes").unwrap();
            } else {
                fs::write(&source, b"retained bytes").unwrap();
            }
            fs::set_permissions(&source, fs::Permissions::from_mode(source_mode)).unwrap();
            let upper = temporary.path().join("upper");
            fs::create_dir(&upper).unwrap();
            copy_verified(&nix, &source, &upper).unwrap();
            let copied = upper.join("artifact");
            fs::set_permissions(&copied, fs::Permissions::from_mode(destination_mode)).unwrap();

            let identity = nar_identity(&nix, &source).unwrap();
            assert_eq!(nar_identity(&nix, &copied).unwrap(), identity);
            let error = copy_verified(&nix, &source, &upper).unwrap_err();
            assert!(
                error.to_string().contains("permissions differ"),
                "{error:#}"
            );
            assert_eq!(nar_identity(&nix, &copied).unwrap(), identity);
            assert_eq!(
                fs::symlink_metadata(&copied).unwrap().permissions().mode() & 0o7777,
                destination_mode
            );
            if directory {
                fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    #[test]
    fn actual_reference_closure_and_symlink_root_survive_source_disappearance() {
        let nix = nix_store();
        let instantiate = nix.parent().unwrap().join("nix-instantiate");
        crate::executable::validate_store_executable(&instantiate, "test Nix evaluator").unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let source_store = temporary.path().join("source");
        let uri = format!("local?root={}", source_store.display());
        let evaluated = Command::new(instantiate)
            .args(["--store", &uri, "--eval", "--read-write-mode", "--json", "--expr"])
            .arg("let child = builtins.toFile \"copy-up-child\" \"retained child bytes\"; in builtins.toFile \"copy-up-parent\" (\"retained reference \" + child)")
            .output().unwrap();
        assert!(
            evaluated.status.success(),
            "{}",
            String::from_utf8_lossy(&evaluated.stderr)
        );
        let parent: String = serde_json::from_slice(&evaluated.stdout).unwrap();
        let roots = BTreeSet::from([PathBuf::from(&parent)]);
        let closure = closure_paths(Command::new(&nix).args(["--store", &uri]), &roots).unwrap();
        assert_eq!(closure.len(), 2);
        let upper = temporary.path().join("upper");
        fs::create_dir(&upper).unwrap();
        let mut identities = Vec::new();
        for path in &closure {
            let physical = source_store.join(path.strip_prefix("/").unwrap());
            copy_verified(&nix, &physical, &upper).unwrap();
            identities.push((
                upper.join(path.file_name().unwrap()),
                nar_identity(&nix, &physical).unwrap(),
            ));
        }
        let alias = temporary.path().join("root-alias");
        symlink("unavailable-target", &alias).unwrap();
        copy_verified(&nix, &alias, &upper).unwrap();
        fs::remove_file(&alias).unwrap();
        fs::remove_dir_all(&source_store).unwrap();
        for (path, identity) in identities {
            assert_eq!(nar_identity(&nix, &path).unwrap(), identity);
        }
        assert_eq!(
            fs::read_link(upper.join("root-alias")).unwrap(),
            Path::new("unavailable-target")
        );
        assert!(
            fs::read_to_string(upper.join(Path::new(&parent).file_name().unwrap()))
                .unwrap()
                .contains("/nix/store/")
        );
    }

    #[test]
    fn root_inventory_rejects_unconfined_or_noncanonical_paths() {
        for value in [
            "/tmp/artifact",
            "/nix/store/bad-name",
            "/nix/store/00000000000000000000000000000000-name/../other",
            "/nix/store/00000000000000000000000000000000-name//member",
            "/nix/store/00000000000000000000000000000000-name/",
        ] {
            assert!(store_root(value).is_err(), "{value}");
        }
    }
}
