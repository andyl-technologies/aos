//! Held directory custody and create-only private observation files.

use std::{
    fs::File,
    io::Write,
    os::fd::OwnedFd,
    path::{Component, Path},
};

use anyhow::{ensure, Result};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) struct Journal {
    directory: OwnedFd,
}

impl Journal {
    pub fn create(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output name missing"))?;
        ensure!(
            path.components().all(|part| matches!(
                part,
                Component::RootDir | Component::CurDir | Component::Normal(_)
            )),
            "output traversal differs"
        );
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let mut directory = rustix::fs::openat(
            rustix::fs::CWD,
            if parent.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            flags,
            Mode::empty(),
        )?;
        inspect(&directory, false)?;
        for component in parent.components() {
            if let Component::Normal(part) = component {
                directory = rustix::fs::openat(&directory, part, flags, Mode::empty())?;
                inspect(&directory, false)?;
            }
        }
        inspect(&directory, true)?;
        rustix::fs::mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
        let child = rustix::fs::openat(&directory, name, flags, Mode::empty())?;
        inspect(&child, true)?;
        rustix::fs::fsync(&directory)?;
        Ok(Self { directory: child })
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<serde_json::Value> {
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "journal filename differs"
        );
        let fd = rustix::fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::fsync(&self.directory)?;
        Ok(
            serde_json::json!({"file":name,"sha256":digest(bytes),"byteSize":bytes.len().to_string()}),
        )
    }
}

fn inspect(fd: &OwnedFd, final_parent: bool) -> Result<()> {
    let value = rustix::fs::fstat(fd)?;
    let owner = rustix::process::geteuid().as_raw();
    let mode = u32::from(value.st_mode);
    ensure!(
        if final_parent {
            value.st_uid == owner && mode & 0o077 == 0
        } else {
            (value.st_uid == 0 || value.st_uid == owner)
                && (mode & 0o022 == 0 || value.st_uid == 0 && mode & 0o1000 != 0)
        },
        "journal directory custody differs"
    );
    Ok(())
}
