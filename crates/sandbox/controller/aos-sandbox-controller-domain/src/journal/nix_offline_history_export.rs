//! Read-only physical delivery of offline journal DATA, including failed jobs.
//!
//! The genuine V7 launch owns the admission checks. This owner opens only fixed
//! existing names, retains both original locks, and checks two complete stable
//! readbacks. It never reads private candidates, repairs a partial journal,
//! authorizes recovery or changes an original deadline. All partial custody and
//! causes remain resident through the caller's explicit process exit.

use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use rustix::fs::{Mode, OFlags};

use crate::normal_root::{
    NixOfflineApprovedDataErrorV4, NixOfflineJobIdentityDataV5, OfflineNixHistoryExportOriginV7,
    inspect_nix_offline_job_identity_v5, nix_offline_job_has_original_label_v5,
    require_nix_offline_public_static_approval_v3,
};

const PARENT: &str = "/var/lib/aos";
const NAMES: [&str; 6] = [
    "sandbox-nix-floor-provision",
    "installation.lock",
    "provisioning-v4.journal.lock",
    "candidate-public-v3",
    "approved-job-v3",
    "provisioning-v4.journal",
];
const PARENT_SLOT: usize = 0;
const DIRECTORY_SLOT: usize = 1;
const INSTALLATION_LOCK_SLOT: usize = 2;
const JOURNAL_LOCK_SLOT: usize = 3;
const PUBLIC_SLOT: usize = 4;
const JOB_SLOT: usize = 5;
const HISTORY_SLOT: usize = 6;
const MAXIMUM_NAMED: usize = 14;

/// Retains the first actual read-only history-export failure.
#[derive(Debug, thiserror::Error)]
pub enum NixOfflineHistoryExportErrorV7 {
    /// The original launch retains its actual cause separately.
    #[error("offline history export startup is fenced")]
    Startup,
    /// An original open, lock, metadata or allocation operation failed.
    #[error("offline history export I/O failed")]
    Io(#[from] io::Error),
    /// An exact positioned read failed or observed a different extent.
    #[error("offline history export original read failed")]
    Read(#[from] ExactReadFailure),
    /// An original kernel mount observation failed.
    #[error("offline history export mount observation failed")]
    Linux(#[from] aos_linux_descriptors::Error),
    /// The canonical public candidate or static approval comparison failed.
    #[error("offline history export signed DATA differs")]
    Approval(#[from] NixOfflineApprovedDataErrorV4),
    /// An original identity, shape, name, label or readback differs.
    #[error("offline history export original association differs")]
    Rejected,
    /// This attempt already failed, was interrupted or was used.
    #[error("offline history export owner is fenced")]
    Fenced,
}

impl From<rustix::io::Errno> for NixOfflineHistoryExportErrorV7 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

type Error = NixOfflineHistoryExportErrorV7;

/// Owns one read-only snapshot attempt under the original installation locks.
///
/// No path, raw descriptor, caller DTO, provider or callback selects the state.
/// Keep the owner outside unwind handling and use explicit process exit so
/// failure cannot release locks while the same process continues its work.
pub struct NixOfflineHistoryExportNativeV7<'startup> {
    origin: OfflineNixHistoryExportOriginV7<'startup>,
    files: [Option<File>; 7],
    identities: [Option<NixOfflineJobIdentityDataV5>; 7],
    mounts: [Option<MountId>; 7],
    named: Vec<File>,
    public: [[u8; 268]; 2],
    job: [[u8; 1332]; 2],
    history: [Vec<u8>; 2],
    used: bool,
    completed: bool,
    failure: Option<Error>,
}

impl<'startup> NixOfflineHistoryExportNativeV7<'startup> {
    /// Creates empty resident custody from the genuine V7 launch loan.
    #[must_use]
    pub fn new(origin: OfflineNixHistoryExportOriginV7<'startup>) -> Self {
        Self {
            origin,
            files: std::array::from_fn(|_| None),
            identities: [None; 7],
            mounts: [None; 7],
            named: Vec::new(),
            public: [[0; 268]; 2],
            job: [[0; 1332]; 2],
            history: std::array::from_fn(|_| Vec::new()),
            used: false,
            completed: false,
            failure: None,
        }
    }

    /// Captures one complete stable physical journal without changing any file.
    ///
    /// # Errors
    /// Retains actual startup, lock, signature, file, extent and readback causes.
    /// Reuse and interrupted calls remain fenced. Success does not establish
    /// semantic journal validity or authorize a hardware retry.
    pub fn capture_once(&mut self) -> Result<(), &Error> {
        self.completed = false;
        if self.failure.is_some() || self.used {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        self.used = true;
        if let Err(error) = self.capture_inner() {
            return Err(self.failure.get_or_insert(error));
        }
        self.completed = true;

        Ok(())
    }

    /// Borrows only the completed stable physical history DATA.
    ///
    /// Failed, interrupted and repeated attempts expose no snapshot. The DATA
    /// may describe an incomplete job and is never a completion or floor receipt.
    #[must_use]
    pub fn public_history_data(&self) -> Option<&[u8]> {
        (self.completed && self.failure.is_none()).then_some(self.history[0].as_slice())
    }

    /// Borrows the retained first native failure without releasing custody.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    /// Borrows the retained startup cause without releasing its originals.
    pub fn startup_failure(&self) -> Option<&crate::normal_root::OfflineNixPrepareStartupErrorV3> {
        self.origin.failure()
    }

    fn file(&self, index: usize) -> Result<&File, Error> {
        self.files
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Rejected)
    }

    fn open_parent() -> Result<File, Error> {
        Ok(rustix::fs::openat2(
            rustix::fs::CWD,
            PARENT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?
        .into())
    }

    fn open(&mut self, index: usize) -> Result<(), Error> {
        self.files[index] = Some(if index == PARENT_SLOT {
            Self::open_parent()?
        } else {
            let parent = if index == DIRECTORY_SLOT {
                PARENT_SLOT
            } else {
                DIRECTORY_SLOT
            };
            open_nofollow_child(self.file(parent)?, NAMES[index - 1])?.into()
        });
        let file = self.file(index)?;
        let identity = inspect_nix_offline_job_identity_v5(file)?;
        require_shape(index, &identity)?;
        let mount = MountId::from_fd(file.as_fd())?;
        if (index != PARENT_SLOT && !nix_offline_job_has_original_label_v5(file)?)
            || (index > DIRECTORY_SLOT && Some(mount) != self.mounts[DIRECTORY_SLOT])
        {
            return Err(Error::Rejected);
        }
        self.identities[index] = Some(identity);
        self.mounts[index] = Some(mount);

        Ok(())
    }

    fn capture_inner(&mut self) -> Result<(), Error> {
        self.named
            .try_reserve_exact(MAXIMUM_NAMED)
            .map_err(io::Error::other)?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        for index in 0..7 {
            self.open(index)?;
            if matches!(index, INSTALLATION_LOCK_SLOT | JOURNAL_LOCK_SLOT) {
                rustix::fs::flock(
                    self.file(index)?,
                    rustix::fs::FlockOperation::NonBlockingLockExclusive,
                )?;
            }
        }
        let length = self.identities[HISTORY_SLOT].ok_or(Error::Rejected)?.6;
        let length = usize::try_from(length).map_err(|_| Error::Rejected)?;
        for history in &mut self.history {
            history
                .try_reserve_exact(length)
                .map_err(io::Error::other)?;
            history.resize(length, 0);
        }

        self.read_round(0)?;
        let (node, approval) = self.origin.public_originals().map_err(|_| Error::Startup)?;
        require_nix_offline_public_static_approval_v3(
            &self.public[0],
            &self.job[0],
            node,
            approval,
            &mut [0; 1317],
        )?;
        self.recheck_names()?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.read_round(1)?;
        if self.public[0] != self.public[1]
            || self.job[0] != self.job[1]
            || self.history[0] != self.history[1]
        {
            return Err(Error::Rejected);
        }
        self.recheck_names()?;
        self.origin.recheck().map_err(|_| Error::Startup)?;

        Ok(())
    }

    fn read_round(&mut self, round: usize) -> Result<(), Error> {
        read_exact_positioned_retaining_cause(
            self.files[PUBLIC_SLOT].as_ref().ok_or(Error::Rejected)?,
            &mut self.public[round],
        )?;
        read_exact_positioned_retaining_cause(
            self.files[JOB_SLOT].as_ref().ok_or(Error::Rejected)?,
            &mut self.job[round],
        )?;
        read_exact_positioned_retaining_cause(
            self.files[HISTORY_SLOT].as_ref().ok_or(Error::Rejected)?,
            &mut self.history[round],
        )?;
        for index in PUBLIC_SLOT..=HISTORY_SLOT {
            if Some(inspect_nix_offline_job_identity_v5(self.file(index)?)?)
                != self.identities[index]
            {
                return Err(Error::Rejected);
            }
        }

        Ok(())
    }

    fn recheck_names(&mut self) -> Result<(), Error> {
        for index in 0..7 {
            if self.named.len() == MAXIMUM_NAMED {
                return Err(Error::Fenced);
            }
            let named = if index == PARENT_SLOT {
                Self::open_parent()?
            } else {
                let parent = if index == DIRECTORY_SLOT {
                    PARENT_SLOT
                } else {
                    DIRECTORY_SLOT
                };
                open_nofollow_child(self.file(parent)?, NAMES[index - 1])?.into()
            };
            self.named.push(named);
            let named = self.named.last().ok_or(Error::Rejected)?;
            for file in [self.file(index)?, named] {
                if Some(inspect_nix_offline_job_identity_v5(file)?) != self.identities[index]
                    || Some(MountId::from_fd(file.as_fd())?) != self.mounts[index]
                    || (index != PARENT_SLOT && !nix_offline_job_has_original_label_v5(file)?)
                {
                    return Err(Error::Rejected);
                }
            }
        }

        Ok(())
    }
}

fn require_shape(index: usize, identity: &NixOfflineJobIdentityDataV5) -> Result<(), Error> {
    let kind = rustix::fs::FileType::from_raw_mode(identity.4);
    if identity.2 != 0 || identity.3 != 0 {
        return Err(Error::Rejected);
    }
    if index <= DIRECTORY_SLOT {
        return if kind == rustix::fs::FileType::Directory
            && identity.4 & 0o022 == 0
            && (index == PARENT_SLOT || identity.4 & 0o7777 == 0o700)
        {
            Ok(())
        } else {
            Err(Error::Rejected)
        };
    }
    let (mode, length) = match index {
        INSTALLATION_LOCK_SLOT | JOURNAL_LOCK_SLOT => (0o600, Some(0)),
        PUBLIC_SLOT => (0o400, Some(268)),
        JOB_SLOT => (0o400, Some(1332)),
        HISTORY_SLOT => (0o600, None),
        _ => return Err(Error::Rejected),
    };
    if kind != rustix::fs::FileType::RegularFile
        || identity.4 & 0o7777 != mode
        || identity.5 != 1
        || length.is_some_and(|length| identity.6 != length)
        || (length.is_none()
            && (identity.6 == 0
                || identity.6 > super::nix_offline_provisioning::LIMITS.maximum_journal_bytes))
    {
        return Err(Error::Rejected);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_export_refuses_wrong_owner_link_mode_and_extent() {
        let original = (1, 2, 0, 0, 0o100600, 1, 1024, 1, 2, 3, 4);
        assert!(require_shape(HISTORY_SLOT, &original).is_ok());
        for changed in [
            (1, 2, 1, 0, 0o100600, 1, 1024, 1, 2, 3, 4),
            (1, 2, 0, 1, 0o100600, 1, 1024, 1, 2, 3, 4),
            (1, 2, 0, 0, 0o100640, 1, 1024, 1, 2, 3, 4),
            (1, 2, 0, 0, 0o100600, 2, 1024, 1, 2, 3, 4),
            (1, 2, 0, 0, 0o010600, 1, 1024, 1, 2, 3, 4),
            (1, 2, 0, 0, 0o100600, 1, 0, 1, 2, 3, 4),
            (1, 2, 0, 0, 0o100600, 1, 4 * 1024 * 1024 + 1, 1, 2, 3, 4),
        ] {
            assert!(require_shape(HISTORY_SLOT, &changed).is_err());
        }
    }
}
