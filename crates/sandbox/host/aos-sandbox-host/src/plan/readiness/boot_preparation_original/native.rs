//! Retains the fixed BootPreparation file and directory read prefixes.
//!
//! These owners reuse the shared exact positioned reader and its held/named
//! after engine. They supply no Source, file permission, floor or completion.

use std::error::Error;
use std::fs::Metadata;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::protected_file::{FixedProtectedReadClosedV3, FixedProtectedReadOriginalV3};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, statat, open};

use super::{BootPreparationClosedV1, BootPreparationPolicyErrorV1};

#[derive(Clone, Copy)]
enum FileFirst {
    Native,
    Policy,
}

pub(super) struct BootFileOriginalV1 {
    original: FixedProtectedReadOriginalV3,
    path: PathBuf,
    path_allocation: Option<Result<(), std::collections::TryReserveError>>,
    capture: Option<Result<(), FixedProtectedReadClosedV3>>,
    policy: Option<Result<usize, BootPreparationPolicyErrorV1>>,
    read: Option<Result<(), FixedProtectedReadClosedV3>>,
    post: Option<Result<(), FixedProtectedReadClosedV3>>,
    entered: bool,
    first: Option<FileFirst>,
}

impl BootFileOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            original: FixedProtectedReadOriginalV3::new(),
            path: PathBuf::new(),
            path_allocation: None,
            capture: None,
            policy: None,
            read: None,
            post: None,
            entered: false,
            first: None,
        }
    }

    pub(super) fn observe_once_v1(
        &mut self,
        path: &Path,
        maximum: usize,
        private: bool,
    ) -> Result<(), BootPreparationClosedV1> {
        if self.entered {
            return Err(BootPreparationClosedV1);
        }
        self.entered = true;
        self.path_allocation = Some(self.path.try_reserve_exact(path.as_os_str().len()));
        if !matches!(self.path_allocation, Some(Ok(()))) {
            return Err(BootPreparationClosedV1);
        }
        self.path.push(path);
        self.capture = Some(self.original.capture_once_v3(path));
        if matches!(self.capture, Some(Err(_))) {
            self.first.get_or_insert(FileFirst::Native);
        }
        if matches!(self.capture, Some(Ok(()))) {
            self.policy = Some(require_metadata(
                self.original.metadata_v3(),
                maximum,
                private,
            ));
            if matches!(self.policy, Some(Err(_))) {
                self.first.get_or_insert(FileFirst::Policy);
            }
            if let Some(Ok(bytes)) = self.policy.as_ref() {
                self.read = Some(self.original.read_exact_bytes_and_eof_once_v3(*bytes));
                if matches!(self.read, Some(Err(_))) {
                    self.first.get_or_insert(FileFirst::Native);
                }
            }
        }
        // A reached open/metadata/read prefix always reaches its own named and
        // held after once, even when metadata or complete-byte policy refused.
        self.post = Some(self.original.finish_once_v3(path));
        if matches!(self.post, Some(Err(_))) {
            self.first.get_or_insert(FileFirst::Native);
        }
        if self.bytes_v1().is_some() {
            Ok(())
        } else {
            Err(BootPreparationClosedV1)
        }
    }

    pub(super) fn bytes_v1(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.policy, Some(Ok(_))) {
            return None;
        }
        self.original.bytes_completed_v3()
    }

    pub(super) fn path_v1(&self) -> Option<&Path> {
        matches!(self.path_allocation, Some(Ok(()))).then_some(self.path.as_path())
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn absent_v1(&self) -> bool {
        self.original.absent_through_post_v3()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(error)) = self.path_allocation.as_ref() {
            return Some(error);
        }
        match self.first? {
            FileFirst::Policy => self
                .policy
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            FileFirst::Native => self.original.failure(),
        }
    }
}

fn require_metadata(
    metadata: Option<&Metadata>,
    maximum: usize,
    private: bool,
) -> Result<usize, BootPreparationPolicyErrorV1> {
    let metadata = metadata.ok_or(BootPreparationPolicyErrorV1(
        "protected file metadata absent",
    ))?;
    let private_mode = matches!(metadata.mode() & 0o7777, 0o400 | 0o600);
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || (private && (!private_mode || metadata.nlink() != 1))
    {
        return Err(BootPreparationPolicyErrorV1(
            "protected BootPreparation file metadata differs",
        ));
    }
    let bytes = usize::try_from(metadata.len())
        .map_err(|_| BootPreparationPolicyErrorV1("protected file extent overflows"))?;
    if bytes == 0 || bytes > maximum {
        return Err(BootPreparationPolicyErrorV1(
            "protected BootPreparation file extent differs",
        ));
    }
    Ok(bytes)
}

// Each actual fixed ancestor occurs once, shared between both read phases.
// Intermediate directories may be0755; the two actual private leaves must be
// the same root-only directory modes used by the existing readiness loader.
pub(super) const DIRECTORIES_V1: &[&str] = &[
    "/",
    "/run",
    "/run/credentials",
    "/run/credentials/aos-sandbox-hostd.service",
    "/var",
    "/var/lib",
    "/var/lib/aos",
    "/var/lib/aos/sandbox",
    "/var/lib/aos/sandbox/runtime-deployment",
    "/var/lib/aos/sandbox/runtime-deployment/readiness",
];

pub(super) struct BootDirectoriesOriginalV1 {
    files: [Option<rustix::io::Result<OwnedFd>>; DIRECTORIES_V1.len()],
    before: [Option<rustix::io::Result<Stat>>; DIRECTORIES_V1.len()],
    policy: [Option<Result<(), BootPreparationPolicyErrorV1>>; DIRECTORIES_V1.len()],
    after: [Option<rustix::io::Result<Stat>>; DIRECTORIES_V1.len()],
    named: [Option<rustix::io::Result<Stat>>; DIRECTORIES_V1.len()],
    compared: [Option<Result<(), BootPreparationPolicyErrorV1>>; DIRECTORIES_V1.len()],
    entered: bool,
    after_entered: bool,
    first: Option<(usize, u8)>,
}

impl BootDirectoriesOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            files: std::array::from_fn(|_| None),
            before: std::array::from_fn(|_| None),
            policy: std::array::from_fn(|_| None),
            after: std::array::from_fn(|_| None),
            named: std::array::from_fn(|_| None),
            compared: std::array::from_fn(|_| None),
            entered: false,
            after_entered: false,
            first: None,
        }
    }

    pub(super) fn observe_once_v1(&mut self) -> Result<(), BootPreparationClosedV1> {
        if self.entered {
            return Err(BootPreparationClosedV1);
        }
        self.entered = true;
        for (index, path) in DIRECTORIES_V1.iter().enumerate() {
            self.files[index] = Some(open(
                *path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ));
            let Some(Ok(file)) = self.files[index].as_ref() else {
                self.first.get_or_insert((index, 0));
                return Err(BootPreparationClosedV1);
            };
            self.before[index] = Some(fstat(file));
            let Some(Ok(stat)) = self.before[index].as_ref() else {
                self.first.get_or_insert((index, 1));
                return Err(BootPreparationClosedV1);
            };
            self.policy[index] = Some(
                if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                    && stat.st_uid == 0
                    && stat.st_mode & 0o022 == 0
                    && (!matches!(index, 3 | 9) || matches!(stat.st_mode & 0o7777, 0o500 | 0o700))
                {
                    Ok(())
                } else {
                    Err(BootPreparationPolicyErrorV1(
                        "protected BootPreparation ancestor differs",
                    ))
                },
            );
            if matches!(self.policy[index], Some(Err(_))) {
                self.first.get_or_insert((index, 2));
                return Err(BootPreparationClosedV1);
            }
        }
        Ok(())
    }

    pub(super) fn observe_after_once_v1(&mut self) -> Result<(), BootPreparationClosedV1> {
        if !self.entered || self.after_entered {
            return Err(BootPreparationClosedV1);
        }
        self.after_entered = true;
        for (index, path) in DIRECTORIES_V1.iter().enumerate() {
            if self.files[index].is_none() {
                continue;
            }
            if let Some(Ok(file)) = self.files[index].as_ref() {
                self.after[index] = Some(fstat(file));
                if matches!(self.after[index], Some(Err(_))) {
                    self.first.get_or_insert((index, 3));
                }
            }
            self.named[index] = Some(statat(rustix::fs::CWD, *path, AtFlags::SYMLINK_NOFOLLOW));
            if matches!(self.named[index], Some(Err(_))) {
                self.first.get_or_insert((index, 4));
            }
            self.compared[index] = Some(
                match (&self.before[index], &self.after[index], &self.named[index]) {
                    (Some(Ok(a)), Some(Ok(b)), Some(Ok(c)))
                        if same_stat(a, b) && same_stat(a, c) =>
                    {
                        Ok(())
                    }
                    _ => Err(BootPreparationPolicyErrorV1(
                        "protected BootPreparation ancestor changed",
                    )),
                },
            );
            if matches!(self.compared[index], Some(Err(_))) {
                self.first.get_or_insert((index, 5));
            }
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(BootPreparationClosedV1)
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let (index, kind) = self.first?;
        match kind {
            0 => self.files[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            1 => self.before[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            2 => self.policy[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            3 => self.after[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            4 => self.named[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
            _ => self.compared[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as &dyn Error),
        }
    }
}

fn same_stat(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
}
