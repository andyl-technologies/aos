//! Descriptor-relative private staging and no-replace archive publication.
//!
//! Only the three fixed archive names are admitted. Staging cleanup never
//! recursively follows a path or removes a successfully published directory.
//! Directory durability can remain unknown after a successful rename.
//!
//! ```text
//! capture-directory/       (0700)
//!   archive.json           (0600, signed framing_only root)
//!   metadata.aosh          (0600, encrypted database records)
//!   private.aosh           (0600, encrypted exact originals)
//! ```

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Result};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

pub(super) const FILES: [&str; 3] = ["archive.json", "metadata.aosh", "private.aosh"];

pub(super) struct Directory {
    pub fd: OwnedFd,
}

fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn inspect_directory(fd: &OwnedFd, private: bool) -> Result<()> {
    let stat = fs::fstat(fd)?;
    let mode = stat.st_mode as u32;
    let root_sticky = stat.st_uid == 0 && mode & 0o1000 != 0;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && trusted_owner(stat.st_uid)
            && (mode & 0o022 == 0 || (!private && root_sticky))
            && (!private || mode & 0o077 == 0),
        "snapshot directory custody is invalid"
    );
    Ok(())
}

impl Directory {
    pub fn open(path: &Path, private: bool) -> Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = fs::openat(
            fs::CWD,
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            flags,
            Mode::empty(),
        )?;
        inspect_directory(&fd, false)?;
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    fd = fs::openat(&fd, name, flags, Mode::empty())?;
                    inspect_directory(&fd, false)?;
                }
                Component::RootDir | Component::CurDir => {}
                _ => anyhow::bail!("snapshot directory path is invalid"),
            }
        }
        inspect_directory(&fd, private)?;
        Ok(Self { fd })
    }

    pub fn file(&self, name: &str) -> Result<File> {
        ensure!(FILES.contains(&name), "snapshot filename is invalid");
        let fd = fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        inspect_file(&fd, true)?;
        Ok(File::from(fd))
    }

    pub fn exact_entries(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        let entries = fs::Dir::read_from(&self.fd)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            ensure!(
                FILES.iter().any(|expected| name == expected.as_bytes())
                    && seen.insert(name.to_vec()),
                "snapshot directory entries differ"
            );
        }
        ensure!(
            seen.len() == FILES.len(),
            "snapshot directory is incomplete"
        );
        Ok(())
    }
}

fn inspect_file(fd: &impl std::os::fd::AsFd, private: bool) -> Result<()> {
    let stat = fs::fstat(fd)?;
    let forbidden_permissions = if private { 0o077 } else { 0o022 };
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && trusted_owner(stat.st_uid)
            && stat.st_nlink == 1
            && (stat.st_mode as u32 & forbidden_permissions) == 0,
        "snapshot regular file custody is invalid"
    );
    Ok(())
}

fn parent_and_name(path: &Path) -> Result<(Directory, OsString)> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("snapshot path has no filename"))?;
    ensure!(name != "." && name != "..", "snapshot filename is invalid");
    Ok((Directory::open(parent, false)?, name.to_owned()))
}

/// Path admission protects against other-user substitution, not same-owner ABA.
/// SQLx still opens a filename, preserving normal WAL snapshot semantics.
pub(super) struct SourceAdmission {
    pub path: PathBuf,
    parent: Directory,
    parent_path: PathBuf,
    name: OsString,
    retained: OwnedFd,
}

impl SourceAdmission {
    pub fn open(path: &Path) -> Result<Self> {
        // SQLx enables SQLite URI parsing. An anchored absolute literal path
        // cannot be interpreted as a caller-supplied `file:` URI instead.
        let working_directory = std::env::current_dir()?;
        Self::open_with_working_directory(path, &working_directory)
    }

    pub(super) fn open_with_working_directory(
        path: &Path,
        working_directory: &Path,
    ) -> Result<Self> {
        ensure!(
            working_directory.is_absolute(),
            "snapshot working directory is invalid"
        );
        // Relative inputs use the same trusted CWD boundary as archive and
        // credential custody. SQLx still receives an absolute literal filename.
        // An explicitly supplied different working directory keeps its full
        // absolute ancestor checks.
        let custody_path = if path.is_relative() && working_directory == std::env::current_dir()? {
            path.to_owned()
        } else if path.is_relative() {
            working_directory.join(path)
        } else {
            path.to_owned()
        };
        let joined = if path.is_absolute() {
            path.to_owned()
        } else {
            working_directory.join(path)
        };
        let mut absolute = PathBuf::new();
        for component in joined.components() {
            match component {
                Component::RootDir | Component::Normal(_) => absolute.push(component.as_os_str()),
                Component::CurDir => {}
                _ => anyhow::bail!("snapshot source path is invalid"),
            }
        }
        let path = absolute.as_path();
        let parent_path = custody_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = Directory::open(parent_path, true)?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("snapshot source has no filename"))?
            .to_owned();
        ensure!(
            name != "." && name != "..",
            "snapshot source filename is invalid"
        );
        let retained = fs::openat(
            &parent.fd,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        inspect_file(&retained, false)?;
        Ok(Self {
            path: path.to_owned(),
            parent,
            parent_path: parent_path.to_owned(),
            name,
            retained,
        })
    }

    pub fn check_identity(&self) -> Result<()> {
        let current_parent = Directory::open(&self.parent_path, true)?;
        let original_parent = fs::fstat(&self.parent.fd)?;
        let named_parent = fs::fstat(&current_parent.fd)?;
        ensure!(
            original_parent.st_dev == named_parent.st_dev
                && original_parent.st_ino == named_parent.st_ino,
            "snapshot source parent identity changed"
        );
        let before = fs::fstat(&self.retained)?;
        let now = fs::statat(&self.parent.fd, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        let absolute = fs::statat(fs::CWD, &self.path, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            before.st_dev == absolute.st_dev && before.st_ino == absolute.st_ino,
            "snapshot absolute source identity changed"
        );
        ensure!(
            before.st_dev == now.st_dev
                && before.st_ino == now.st_ino
                && FileType::from_raw_mode(now.st_mode) == FileType::RegularFile
                && now.st_nlink == 1
                && trusted_owner(now.st_uid)
                && now.st_mode as u32 & 0o022 == 0,
            "snapshot source identity changed"
        );
        Ok(())
    }
}

pub(super) struct Stage {
    parent: Directory,
    directory: Directory,
    temporary_name: OsString,
    final_name: OsString,
    published: bool,
}

pub(super) enum PublishError {
    BeforeRename,
    DurabilityUnconfirmed,
}

impl Stage {
    pub fn create(destination: &Path) -> Result<Self> {
        let (parent, final_name) = parent_and_name(destination)?;
        match fs::statat(&parent.fd, &final_name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => anyhow::bail!("snapshot destination already exists or is unavailable"),
        }
        let temporary_name: OsString =
            format!(".aos-snapshot-{}", uuid::Uuid::new_v4().simple()).into();
        fs::mkdirat(&parent.fd, &temporary_name, Mode::RWXU)?;
        let opened = fs::openat(
            &parent.fd,
            &temporary_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let fd = match opened {
            Ok(fd) => fd,
            Err(error) => {
                let _ = fs::unlinkat(&parent.fd, &temporary_name, AtFlags::REMOVEDIR);
                return Err(error.into());
            }
        };
        let directory = Directory { fd };
        let stage = Self {
            parent,
            directory,
            temporary_name,
            final_name,
            published: false,
        };
        fs::fchmod(&stage.directory.fd, Mode::RWXU)?;
        inspect_directory(&stage.directory.fd, true)?;
        Ok(stage)
    }

    pub fn create_file(&self, name: &str) -> Result<File> {
        ensure!(FILES.contains(&name), "snapshot filename is invalid");
        let fd = fs::openat(
            &self.directory.fd,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)?;
        inspect_file(&fd, true)?;
        Ok(File::from(fd))
    }

    pub fn write_root(&self, root: &[u8]) -> Result<()> {
        ensure!(root.len() <= 64 * 1024, "snapshot root exceeds limits");
        let mut file = self.create_file("archive.json")?;
        file.write_all(root)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    fn check_named_identity(&self) -> Result<()> {
        let own = fs::fstat(&self.directory.fd)?;
        let named = fs::statat(
            &self.parent.fd,
            &self.temporary_name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            own.st_dev == named.st_dev
                && own.st_ino == named.st_ino
                && FileType::from_raw_mode(named.st_mode) == FileType::Directory,
            "snapshot staging identity changed"
        );
        inspect_directory(&self.directory.fd, true)?;
        Ok(())
    }

    pub fn publish(&mut self) -> std::result::Result<(), PublishError> {
        self.publish_with_sync(|fd| fs::fsync(fd))
    }

    // Kept private so tests can exercise both sides of the publication boundary.
    // Retained-fd checks detect replacement, but cannot make pathname rename
    // atomic with these checks against malicious same-owner ABA substitution.
    pub(super) fn publish_with_sync(
        &mut self,
        mut sync: impl FnMut(&OwnedFd) -> rustix::io::Result<()>,
    ) -> std::result::Result<(), PublishError> {
        self.check_named_identity()
            .map_err(|_| PublishError::BeforeRename)?;
        sync(&self.directory.fd).map_err(|_| PublishError::BeforeRename)?;
        self.check_named_identity()
            .map_err(|_| PublishError::BeforeRename)?;
        fs::renameat_with(
            &self.parent.fd,
            &self.temporary_name,
            &self.parent.fd,
            &self.final_name,
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| PublishError::BeforeRename)?;
        self.published = true;
        sync(&self.parent.fd).map_err(|_| PublishError::DurabilityUnconfirmed)?;
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Only known entries beneath the retained private staging inode are
        // removed. A changed parent name never selects a different directory.
        for name in FILES {
            let _ = fs::unlinkat(&self.directory.fd, name, AtFlags::empty());
        }
        let own = fs::fstat(&self.directory.fd);
        let named = fs::statat(
            &self.parent.fd,
            &self.temporary_name,
            AtFlags::SYMLINK_NOFOLLOW,
        );
        if let (Ok(own), Ok(named)) = (own, named) {
            if own.st_dev == named.st_dev && own.st_ino == named.st_ino {
                let _ = fs::unlinkat(&self.parent.fd, &self.temporary_name, AtFlags::REMOVEDIR);
            }
        }
    }
}

pub(super) fn root(directory: &Directory) -> Result<Vec<u8>> {
    directory.exact_entries()?;
    let file = directory.file("archive.json")?;
    let metadata = file.metadata()?;
    ensure!(metadata.len() <= 64 * 1024, "snapshot root exceeds limits");
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "snapshot root exceeds limits");
    Ok(bytes)
}
