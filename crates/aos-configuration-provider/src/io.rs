//! Publishes synchronized files and shares the service ownership lock.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, ensure};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use sha2::{Digest as _, Sha256};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn digest(contents: &[u8]) -> String {
    format!("{:x}", Sha256::digest(contents))
}

pub(crate) fn absolute(value: &str) -> Result<&Path> {
    ensure!(
        value.starts_with('/')
            && !value.contains('\0')
            && !value.split('/').any(|part| part == ".."),
        "expected a normalized absolute path"
    );
    Ok(Path::new(value))
}

pub(crate) fn normalize(value: &str) -> Result<String> {
    Ok(absolute(value)?
        .components()
        .collect::<std::path::PathBuf>()
        .to_str()
        .context("configuration path is not UTF-8")?
        .into())
}

pub(crate) fn owned_path(value: &str) -> Result<&Path> {
    let path = absolute(value)?;
    ensure!(
        !path.starts_with("/nix/store"),
        "native mutation cannot modify immutable store artifacts"
    );
    Ok(path)
}

pub(crate) fn mode(value: &str) -> Result<u32> {
    ensure!(
        (3..=4).contains(&value.len()) && value.bytes().all(|byte| (b'0'..=b'7').contains(&byte)),
        "invalid octal mode"
    );
    Ok(u32::from_str_radix(value, 8)?)
}

pub(crate) fn regular(path: &Path) -> Result<Option<File>> {
    let descriptor = match openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("opening owned resource without following links"),
    };
    let file = File::from(descriptor);
    ensure!(
        file.metadata()?.is_file(),
        "owned resource is not a regular file"
    );
    Ok(Some(file))
}

pub(crate) fn read_digest(path: &Path) -> Result<Option<String>> {
    let Some(mut file) = regular(path)? else {
        return Ok(None);
    };
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Some(format!("{:x}", hash.finalize())))
}

pub(crate) fn synchronize_parent(path: &Path) -> Result<()> {
    File::open(path.parent().context("resource has no parent")?)?.sync_all()?;
    Ok(())
}

pub(crate) fn unlink(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => synchronize_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn write(path: &Path, contents: &[u8], permissions: u32) -> Result<()> {
    let parent = path.parent().context("resource has no parent")?;
    fs::create_dir_all(parent)?;
    let (temporary, mut file) = temporary(parent)?;
    let result = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(permissions))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        synchronize_parent(path)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn temporary(parent: &Path) -> Result<(std::path::PathBuf, File)> {
    // A crash may leave an earlier temporary behind; only newly created files
    // are eligible for publication or cleanup, including after PID reuse.
    for _ in 0..1024 {
        let path = parent.join(format!(
            ".aos-native-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating configuration temporary"),
        }
    }
    anyhow::bail!("configuration temporary names exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stale_temporaries_are_preserved_while_publication_recovers() {
        let root = TempDir::new().unwrap();
        let sequence = SEQUENCE.load(Ordering::Relaxed);
        let stale = (sequence..sequence + 64)
            .map(|sequence| {
                root.path()
                    .join(format!(".aos-native-{}-{sequence}", std::process::id()))
            })
            .collect::<Vec<_>>();
        for path in &stale {
            fs::write(path, "prior interrupted write").unwrap();
        }

        let destination = root.path().join("configuration");
        write(&destination, b"desired", 0o600).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"desired");
        for path in &stale {
            assert_eq!(fs::read_to_string(path).unwrap(), "prior interrupted write");
        }
    }
}

pub(crate) fn lock(directory: &Path) -> Result<File> {
    if let Some(parent) = directory.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(directory.is_dir(), "configuration state is not a directory");
        }
        Err(error) => return Err(error).context("creating configuration state directory"),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join(".lock"))?;
    flock(&file, FlockOperation::LockExclusive)?;
    Ok(file)
}
