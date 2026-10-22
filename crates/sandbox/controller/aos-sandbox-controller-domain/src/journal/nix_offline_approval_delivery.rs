//! Fixed-name delivery of independently signed offline approval DATA.
//!
//! The genuine V6 launch lends its original credentials. This owner locks the
//! existing candidate directory, verifies those candidates and signatures, and
//! creates only the absent approval files. It never rewrites a candidate or
//! journal, grants hardware authority, renews a deadline or publishes runtime
//! credentials. Every acquired descriptor and partial secret read stays resident
//! through explicit process exit, including failed or interrupted publication.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::normal_root::{
    NixOfflineApprovedDataErrorV4, NixOfflineEffectApprovalDataV4, NixOfflineEffectApprovalKindV4,
    NixOfflineJobIdentityDataV5, OfflineNixApprovalDeliveryOriginV6,
    decode_nix_offline_effect_approval_data_v4, inspect_nix_offline_job_identity_v5,
    nix_offline_job_has_original_label_v5, require_nix_offline_static_approval_v3,
};

const PARENT: &str = "/var/lib/aos";
const DIRECTORY: &str = "sandbox-nix-floor-provision";
const STATIC_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.approved-static-job.v4\0";
const HISTORY_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.offline-native-history.v4\0";

/// Retains the first actual V6 approval-delivery failure.
#[derive(Debug, thiserror::Error)]
pub enum NixOfflineApprovalDeliveryErrorV6 {
    /// The original selected launch retains its actual failure separately.
    #[error("offline approval delivery startup is fenced")]
    Startup,
    /// An original descriptor, lock, allocation or durability operation failed.
    #[error("offline approval delivery I/O failed")]
    Io(#[from] io::Error),
    /// A positioned read failed or observed a different exact extent.
    #[error("offline approval delivery original read failed")]
    Read(#[from] ExactReadFailure),
    /// An original kernel mount observation failed.
    #[error("offline approval delivery mount observation failed")]
    Linux(#[from] aos_linux_descriptors::Error),
    /// The sole canonical candidate or approval engine rejected the DATA.
    #[error("offline approval delivery signed DATA differs")]
    Approval(#[from] NixOfflineApprovedDataErrorV4),
    /// A fixed name, shape, identity, coordinate or original readback differs.
    #[error("offline approval delivery original association differs")]
    Rejected,
    /// The attempt was already used or interrupted.
    #[error("offline approval delivery owner is fenced")]
    Fenced,
}

impl From<rustix::io::Errno> for NixOfflineApprovalDeliveryErrorV6 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

type Error = NixOfflineApprovalDeliveryErrorV6;

#[derive(Clone, Copy)]
#[repr(usize)]
enum Slot {
    Parent,
    Directory,
    Lock,
    Private,
    Public,
    ExistingJob,
    ExistingEffect,
    Journal,
    PublishedJob,
    PublishedEffect,
}

const SLOTS: [Slot; 10] = [
    Slot::Parent,
    Slot::Directory,
    Slot::Lock,
    Slot::Private,
    Slot::Public,
    Slot::ExistingJob,
    Slot::ExistingEffect,
    Slot::Journal,
    Slot::PublishedJob,
    Slot::PublishedEffect,
];

/// Owns one fixed, create-only delivery attempt under the original job lock.
///
/// It accepts no caller-selected paths, proposal DTOs, raw descriptors or
/// callbacks. Retain this owner outside unwind handling and explicitly exit
/// after wiping secrets, so neither a failed publication nor an unwind drops
/// the original lock and custody while the process continues.
pub struct NixOfflineApprovalDeliveryNativeV6<'startup> {
    origin: OfflineNixApprovalDeliveryOriginV6<'startup>,
    files: [Option<File>; 10],
    identities: [Option<NixOfflineJobIdentityDataV5>; 10],
    mounts: [Option<MountId>; 10],
    named: Vec<File>,
    unexpected: Option<File>,
    private: [Zeroizing<[u8; 336]>; 2],
    public: [[u8; 268]; 2],
    job: [u8; 1332],
    effect: [u8; 304],
    existing_job: [u8; 1332],
    existing_effect: [u8; 304],
    published_job_readback: [u8; 1332],
    published_effect_readback: [u8; 304],
    history: [Vec<u8>; 2],
    used: bool,
    failure: Option<Error>,
}

impl<'startup> NixOfflineApprovalDeliveryNativeV6<'startup> {
    /// Creates empty resident custody from the genuine V6 startup loan.
    #[must_use]
    pub fn new(origin: OfflineNixApprovalDeliveryOriginV6<'startup>) -> Self {
        Self {
            origin,
            files: std::array::from_fn(|_| None),
            identities: [None; 10],
            mounts: [None; 10],
            named: Vec::new(),
            unexpected: None,
            private: std::array::from_fn(|_| Zeroizing::new([0; 336])),
            public: [[0; 268]; 2],
            job: [0; 1332],
            effect: [0; 304],
            existing_job: [0; 1332],
            existing_effect: [0; 304],
            published_job_readback: [0; 1332],
            published_effect_readback: [0; 304],
            history: std::array::from_fn(|_| Vec::new()),
            used: false,
            failure: None,
        }
    }

    /// Validates and durably delivers one independently signed proposal.
    ///
    /// # Errors
    /// Retains the first actual startup, custody, signature, absence or durable
    /// readback failure. Reuse and interrupted calls stay fenced; partial file
    /// creation is neither rolled back nor overwritten by a retry.
    pub fn deliver_once(&mut self) -> Result<(), &Error> {
        if self.failure.is_some() {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        if self.used {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        self.used = true;
        if let Err(error) = self.deliver_inner() {
            return Err(self.failure.get_or_insert(error));
        }

        Ok(())
    }

    /// Borrows the retained first delivery failure without releasing custody.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    /// Borrows the retained original startup cause without releasing custody.
    pub fn startup_failure(&self) -> Option<&crate::normal_root::OfflineNixPrepareStartupErrorV3> {
        self.origin.failure()
    }

    /// Wipes secret snapshots while retaining all original descriptors and locks.
    pub fn wipe_secrets(&mut self) {
        for snapshot in &mut self.private {
            snapshot.zeroize();
        }
    }

    fn file(&self, slot: Slot) -> Result<&File, Error> {
        self.files[slot as usize].as_ref().ok_or(Error::Rejected)
    }

    fn name(&self, slot: Slot) -> Result<&'static str, Error> {
        match slot {
            Slot::Directory => Ok(DIRECTORY),
            Slot::Lock => Ok("installation.lock"),
            Slot::Private => Ok("candidate-private-v3"),
            Slot::Public => Ok("candidate-public-v3"),
            Slot::ExistingJob | Slot::PublishedJob => Ok("approved-job-v3"),
            Slot::ExistingEffect => Ok("approved-effect-v4"),
            Slot::Journal => Ok("provisioning-v4.journal"),
            Slot::PublishedEffect if self.origin.is_recovery_proposal() => {
                Ok("approved-recovery-v4")
            }
            Slot::PublishedEffect => Ok("approved-effect-v4"),
            Slot::Parent => Err(Error::Rejected),
        }
    }

    fn open(&mut self, slot: Slot) -> Result<(), Error> {
        let parent = if matches!(slot, Slot::Directory) {
            Slot::Parent
        } else {
            Slot::Directory
        };
        let file = open_nofollow_child(self.file(parent)?, self.name(slot)?)?;
        self.files[slot as usize] = Some(file.into());
        self.capture(slot)
    }

    fn capture(&mut self, slot: Slot) -> Result<(), Error> {
        let identity = inspect_nix_offline_job_identity_v5(self.file(slot)?)?;
        require_shape(slot, &identity)?;
        let mount = MountId::from_fd(self.file(slot)?.as_fd())?;
        if !matches!(slot, Slot::Parent)
            && !nix_offline_job_has_original_label_v5(self.file(slot)?)?
        {
            return Err(Error::Rejected);
        }
        if !matches!(slot, Slot::Parent | Slot::Directory)
            && self.mounts[Slot::Directory as usize] != Some(mount)
        {
            return Err(Error::Rejected);
        }
        self.identities[slot as usize] = Some(identity);
        self.mounts[slot as usize] = Some(mount);
        Ok(())
    }

    fn require_absent(&mut self, name: &'static str) -> Result<(), Error> {
        match open_nofollow_child(self.file(Slot::Directory)?, name) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(file) => {
                self.unexpected = Some(file.into());
                Err(Error::Rejected)
            }
        }
    }

    fn deliver_inner(&mut self) -> Result<(), Error> {
        self.named.try_reserve_exact(32).map_err(io::Error::other)?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.files[Slot::Parent as usize] = Some(
            rustix::fs::openat2(
                rustix::fs::CWD,
                PARENT,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )?
            .into(),
        );
        self.capture(Slot::Parent)?;
        self.open(Slot::Directory)?;
        self.open(Slot::Lock)?;
        rustix::fs::flock(
            self.file(Slot::Lock)?,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        self.open(Slot::Private)?;
        self.open(Slot::Public)?;
        let (job, effect) = self
            .origin
            .approved_data_originals()
            .map_err(|_| Error::Startup)?;
        self.job.copy_from_slice(job);
        self.effect.copy_from_slice(effect);
        self.read_candidates(0)?;
        let proposed = self.verify_proposal()?;
        self.require_absent("approved-recovery-v4")?;
        if self.origin.is_recovery_proposal() {
            self.prepare_recovery(&proposed)?;
        } else {
            self.require_absent("approved-job-v3")?;
            self.require_absent("approved-effect-v4")?;
            self.require_absent("provisioning-v4.journal")?;
            self.require_absent("provisioning-v4.journal.lock")?;
        }
        self.recheck_names()?;
        self.read_candidates(1)?;
        self.require_candidate_readbacks()?;
        self.origin.recheck().map_err(|_| Error::Startup)?;

        // History buffers, named-descriptor capacity and both initial candidate
        // observations precede publication. A failure leaves partial fixed names
        // fenced under this original lock; no repair or unlink follows.
        if !self.origin.is_recovery_proposal() {
            self.publish(Slot::PublishedJob)?;
        }
        self.publish(Slot::PublishedEffect)?;
        self.recheck_names()?;
        self.read_candidates(1)?;
        self.require_candidate_readbacks()?;
        if self.origin.is_recovery_proposal() {
            self.read_history(1)?;
            if self.history[0] != self.history[1] {
                return Err(Error::Rejected);
            }
        }
        self.origin.recheck().map_err(|_| Error::Startup)?;
        Ok(())
    }

    fn read_candidates(&mut self, round: usize) -> Result<(), Error> {
        let private = self.files[Slot::Private as usize]
            .as_ref()
            .ok_or(Error::Rejected)?;
        read_exact_positioned_retaining_cause(private, &mut self.private[round][..])?;
        let public = self.files[Slot::Public as usize]
            .as_ref()
            .ok_or(Error::Rejected)?;
        read_exact_positioned_retaining_cause(public, &mut self.public[round])?;
        for slot in [Slot::Private, Slot::Public] {
            let file = self.file(slot)?;
            if Some(inspect_nix_offline_job_identity_v5(file)?) != self.identities[slot as usize]
                || !nix_offline_job_has_original_label_v5(file)?
            {
                return Err(Error::Rejected);
            }
        }
        Ok(())
    }

    fn require_candidate_readbacks(&self) -> Result<(), Error> {
        if self.private[0][..] != self.private[1][..] || self.public[0] != self.public[1] {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn verify_proposal(&self) -> Result<NixOfflineEffectApprovalDataV4, Error> {
        let (node, approval) = self.origin.public_originals().map_err(|_| Error::Startup)?;
        require_nix_offline_static_approval_v3(
            &self.private[0][..],
            &self.public[0],
            &self.job,
            node,
            approval,
            &mut [0; 268],
            &mut [0; 1317],
        )?;
        let mut preimage = [0; 281];
        let proposed =
            decode_nix_offline_effect_approval_data_v4(&self.effect, approval, &mut preimage)?;
        let kind = if self.origin.is_recovery_proposal() {
            NixOfflineEffectApprovalKindV4::Recover
        } else {
            NixOfflineEffectApprovalKindV4::Initialize
        };
        if proposed.kind != kind
            || proposed.node != *node
            || proposed.job.as_slice() != &self.public[0][12..28]
            || proposed.digests[0] != digest(STATIC_DOMAIN, &self.job)
        {
            return Err(Error::Rejected);
        }
        Ok(proposed)
    }

    fn prepare_recovery(&mut self, proposed: &NixOfflineEffectApprovalDataV4) -> Result<(), Error> {
        self.open(Slot::ExistingJob)?;
        self.open(Slot::ExistingEffect)?;
        self.open(Slot::Journal)?;
        read_exact_positioned_retaining_cause(
            self.files[Slot::ExistingJob as usize]
                .as_ref()
                .ok_or(Error::Rejected)?,
            &mut self.existing_job,
        )?;
        read_exact_positioned_retaining_cause(
            self.files[Slot::ExistingEffect as usize]
                .as_ref()
                .ok_or(Error::Rejected)?,
            &mut self.existing_effect,
        )?;
        let (_, approval) = self.origin.public_originals().map_err(|_| Error::Startup)?;
        let initial = decode_nix_offline_effect_approval_data_v4(
            &self.existing_effect,
            approval,
            &mut [0; 281],
        )?;
        if self.existing_job != self.job
            || initial.kind != NixOfflineEffectApprovalKindV4::Initialize
            || initial.job != proposed.job
            || initial.node != proposed.node
            || [0, 2, 3]
                .into_iter()
                .any(|index| initial.digests[index] != proposed.digests[index])
        {
            return Err(Error::Rejected);
        }
        let length = self.identities[Slot::Journal as usize]
            .ok_or(Error::Rejected)?
            .6;
        let length = usize::try_from(length).map_err(|_| Error::Rejected)?;
        for buffer in &mut self.history {
            buffer.try_reserve_exact(length).map_err(io::Error::other)?;
            buffer.resize(length, 0);
        }
        self.read_history(0)?;
        self.read_history(1)?;
        if self.history[0] != self.history[1]
            || proposed.digests[4] != digest(HISTORY_DOMAIN, &self.history[0])
        {
            return Err(Error::Rejected);
        }
        // This is physical DATA matching only. V5 still owns canonical replay,
        // the original boot/deadline, recovery ordinal and all hardware permits.
        Ok(())
    }

    fn read_history(&mut self, round: usize) -> Result<(), Error> {
        let file = self.files[Slot::Journal as usize]
            .as_ref()
            .ok_or(Error::Rejected)?;
        read_exact_positioned_retaining_cause(file, &mut self.history[round])?;
        if Some(inspect_nix_offline_job_identity_v5(file)?)
            != self.identities[Slot::Journal as usize]
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn publish(&mut self, slot: Slot) -> Result<(), Error> {
        let fd = rustix::fs::openat(
            self.file(Slot::Directory)?,
            self.name(slot)?,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::RUSR,
        )?;
        self.files[slot as usize] = Some(fd.into());
        let file = self.file(slot)?;
        rustix::fs::fchmod(file, Mode::RUSR)?;
        let mut initial = inspect_nix_offline_job_identity_v5(file)?;
        if initial.6 != 0
            || !nix_offline_job_has_original_label_v5(file)?
            || MountId::from_fd(file.as_fd())?
                != self.mounts[Slot::Directory as usize].ok_or(Error::Rejected)?
        {
            return Err(Error::Rejected);
        }
        initial.6 = if matches!(slot, Slot::PublishedJob) {
            1332
        } else {
            304
        };
        require_shape(slot, &initial)?;
        let mut output = file;
        if matches!(slot, Slot::PublishedJob) {
            output.write_all(&self.job)?;
        } else {
            output.write_all(&self.effect)?;
        }
        file.sync_all()?;
        self.file(Slot::Directory)?.sync_all()?;
        // Freeze the post-write original before reading it. Capturing after
        // readback could bless an intervening mutation as the new baseline.
        self.capture(slot)?;
        let file = self.files[slot as usize].as_ref().ok_or(Error::Rejected)?;
        if matches!(slot, Slot::PublishedJob) {
            read_exact_positioned_retaining_cause(file, &mut self.published_job_readback)?;
            if self.published_job_readback != self.job {
                return Err(Error::Rejected);
            }
        } else {
            read_exact_positioned_retaining_cause(file, &mut self.published_effect_readback)?;
            if self.published_effect_readback != self.effect {
                return Err(Error::Rejected);
            }
        }
        if Some(inspect_nix_offline_job_identity_v5(file)?) != self.identities[slot as usize]
            || !nix_offline_job_has_original_label_v5(file)?
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn recheck_names(&mut self) -> Result<(), Error> {
        for slot in SLOTS {
            let Some(original) = self.identities[slot as usize] else {
                continue;
            };
            if self.named.len() == 32 {
                return Err(Error::Fenced);
            }
            let fd = if matches!(slot, Slot::Parent) {
                rustix::fs::openat2(
                    rustix::fs::CWD,
                    PARENT,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
                )?
            } else {
                let parent = if matches!(slot, Slot::Directory) {
                    Slot::Parent
                } else {
                    Slot::Directory
                };
                open_nofollow_child(self.file(parent)?, self.name(slot)?)?
            };
            self.named.push(fd.into());
            let named = self.named.last().ok_or(Error::Rejected)?;
            for file in [self.file(slot)?, named] {
                if inspect_nix_offline_job_identity_v5(file)? != original
                    || Some(MountId::from_fd(file.as_fd())?) != self.mounts[slot as usize]
                    || (!matches!(slot, Slot::Parent)
                        && !nix_offline_job_has_original_label_v5(file)?)
                {
                    return Err(Error::Rejected);
                }
            }
        }
        Ok(())
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn require_shape(slot: Slot, identity: &NixOfflineJobIdentityDataV5) -> Result<(), Error> {
    let kind = rustix::fs::FileType::from_raw_mode(identity.4);
    if identity.2 != 0 || identity.3 != 0 {
        return Err(Error::Rejected);
    }
    if matches!(slot, Slot::Parent | Slot::Directory) {
        if kind != rustix::fs::FileType::Directory
            || identity.4 & 0o022 != 0
            || (matches!(slot, Slot::Directory) && identity.4 & 0o7777 != 0o700)
        {
            return Err(Error::Rejected);
        }
        return Ok(());
    }
    let (mode, length) = match slot {
        Slot::Lock => (0o600, Some(0)),
        Slot::Private => (0o600, Some(336)),
        Slot::Public => (0o400, Some(268)),
        Slot::ExistingJob | Slot::PublishedJob => (0o400, Some(1332)),
        Slot::ExistingEffect | Slot::PublishedEffect => (0o400, Some(304)),
        Slot::Journal => (0o600, None),
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
    fn approval_delivery_requires_private_single_link_original_files() {
        let private = (1, 2, 0, 0, 0o100600, 1, 336, 1, 2, 3, 4);
        assert!(require_shape(Slot::Private, &private).is_ok());

        let mut changed = private;
        changed.2 = 1;
        assert!(require_shape(Slot::Private, &changed).is_err());
        changed = private;
        changed.3 = 1;
        assert!(require_shape(Slot::Private, &changed).is_err());
        changed = private;
        changed.4 = 0o100640;
        assert!(require_shape(Slot::Private, &changed).is_err());
        changed = private;
        changed.5 = 2;
        assert!(require_shape(Slot::Private, &changed).is_err());
        changed = private;
        changed.4 = 0o010600;
        assert!(require_shape(Slot::Private, &changed).is_err());
        assert!(require_shape(Slot::Public, &private).is_err());
        assert!(require_shape(Slot::PublishedJob, &private).is_err());
    }

    #[test]
    fn approval_delivery_bounds_the_actual_history_before_allocation() {
        let mut history = (1, 2, 0, 0, 0o100600, 1, 1, 1, 2, 3, 4);
        assert!(require_shape(Slot::Journal, &history).is_ok());
        history.6 = super::super::nix_offline_provisioning::LIMITS.maximum_journal_bytes;
        assert!(require_shape(Slot::Journal, &history).is_ok());

        history.6 += 1;
        assert!(require_shape(Slot::Journal, &history).is_err());
        history.6 = 0;
        assert!(require_shape(Slot::Journal, &history).is_err());
    }
}
