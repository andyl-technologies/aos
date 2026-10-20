//! Retains fixed-service final executable and permanent FD-coverage mechanics.
//!
//! Packet fields are comparison DATA from the actual private startup channel.
//! The enclosing original owns every packet/file and the sole ledger. Neither
//! this private reservoir nor a decoded budget commitment can recreate F.

use std::error::Error;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{
    FIXED_SERVICE_FINAL_TRANSFER_BYTES, FIXED_SERVICE_ORIGIN_HEADER_BYTES,
};
use aos_sandbox_linux::inventory::MountId;
use rustix::fs::{FileType, Mode, OFlags, Stat, StatFs};


#[derive(Clone, Copy)]
struct TransferFields {
    nofile: u64,
    permanent_peak: u64,
    persistent_usage: ResourceVector,
}

#[derive(Clone, Copy)]
enum Failure {
    Order,
    Packet,
    Limits,
    DeliveredStat,
    DeliveredFilesystem,
    DeliveredFlags,
    DeliveredMount,
    SelfOpen,
    SelfStat,
    SelfFilesystem,
    SelfFlags,
    SelfMount,
    Physical,
}

#[derive(Default)]
struct ExecutableReadback {
    stat: Option<Result<Stat, rustix::io::Errno>>,
    filesystem: Option<Result<StatFs, rustix::io::Errno>>,
    flags: Option<Result<OFlags, rustix::io::Errno>>,
    mount: Option<Result<MountId, aos_sandbox_linux::Error>>,
}

/// Retains the final transfer's actual kernel checks without moving its file.
#[derive(Default)]
pub(crate) struct FixedServiceExecTransferReadbackV1<E> {
    first: Option<Failure>,
    closed: Option<E>,
    fields: Option<Result<TransferFields, E>>,
    entered: bool,
    limit: Option<rustix::process::Rlimit>,
    limit_check: Option<Result<(), E>>,
    delivered: ExecutableReadback,
    self_executable: Option<Result<OwnedFd, rustix::io::Errno>>,
    own: ExecutableReadback,
    physical: Option<Result<(), E>>,
}

impl<E: Default + Copy + Error + 'static> FixedServiceExecTransferReadbackV1<E> {
    /// Checks only retained packet DATA before the first new-mm startup debit.
    ///
    /// # Errors
    /// Retains malformed, inconsistent or repeated transfer refusal. The parent
    /// separately authenticates the same PID1, invocation, process and cgroup.
    pub(crate) fn prepare_once(
        &mut self,
        packet: &[u8],
        ceiling: ResourceVector,
        installed_nofile: u64,
    ) -> Result<(), E> {
        if self.fields.is_some() || self.first.is_some() {
            return Err(self.fail(Failure::Order));
        }
        self.fields = Some((|| {
            if packet.len() != FIXED_SERVICE_FINAL_TRANSFER_BYTES || packet[56..88] == [0; 32]
                || read_u64::<E>(&packet[120..128])? != 1
            {
                return Err(E::default());
            }
            // BudgetSHA commits the actual PID1 AOSSFB01 Budget368 flight. It is opaque
            // audit DATA here, never reconstructed into another allowance.
            let nofile = read_u64::<E>(&packet[88..96])?;
            let inherited_high = read_u64::<E>(&packet[96..104])?;
            let permanent_peak = read_u64::<E>(&packet[104..112])?;
            let executor_requested_memory = read_u64::<E>(&packet[112..120])?;
            if nofile < 3 || nofile != installed_nofile
                || inherited_high.checked_add(nofile) != Some(permanent_peak)
                || permanent_peak > ceiling.get(D::OpenFiles)
                || executor_requested_memory > ceiling.get(D::MemoryBytes)
            {
                return Err(E::default());
            }
            let persistent_usage = read_vector::<E>(&packet[FIXED_SERVICE_ORIGIN_HEADER_BYTES..FIXED_SERVICE_FINAL_TRANSFER_BYTES])?;
            for dimension in D::ALL {
                if persistent_usage.get(dimension) > ceiling.get(dimension) {
                    return Err(E::default());
                }
            }
            if persistent_usage.get(D::OpenFiles) != permanent_peak
                || persistent_usage.get(D::CpuMicrosPerPeriod) != ceiling.get(D::CpuMicrosPerPeriod)
                || persistent_usage.get(D::Pids) != 1
                || persistent_usage.get(D::ConcurrentOperations) != 1
            {
                return Err(E::default());
            }
            // This is the actual same-flight sticky usage, not an optional zero
            // or a refund of the old-mm audit. Only proven disposed private-mm
            // bytes are absent; namespace/tmpfs/metadata debt remains present.
            Ok(TransferFields { nofile, permanent_peak, persistent_usage })
        })());
        if !matches!(self.fields, Some(Ok(_))) {
            return Err(self.fail(Failure::Packet));
        }
        Ok(())
    }

    /// Returns only the already checked permanent debt for the parent's debit.
    ///
    /// # Errors
    /// Refuses an absent or failed transfer, without granting FD coverage.
    pub(crate) fn permanent_open_files(&self) -> Result<u64, E> {
        self.fields.as_ref().and_then(|result| result.as_ref().ok())
            .map(|fields| fields.permanent_peak).ok_or(E::default())
    }

    /// Returns actual sticky DATA only for initialization of the SAME ledger.
    ///
    /// # Errors
    /// Rejects an absent or failed original transfer. The caller must debit all
    /// dimensions before its fresh startup work; this creates no second account.
    pub(crate) fn persistent_usage(&self) -> Result<ResourceVector, E> {
        self.fields.as_ref().and_then(|result| result.as_ref().ok())
            .map(|fields| fields.persistent_usage).ok_or(E::default())
    }

    /// Observes the same delivered executable only after full startup payment.
    ///
    /// The O_PATH original is deliberately inspected without content reads.
    /// Actual PID1 command/image provenance and the enclosing Source process,
    /// label, containment and final peer posts remain separate requirements.
    ///
    /// # Errors
    /// Retains the actual first native cause and every acquired self descriptor.
    /// Missing, mutable, foreign-mount or unequal executable observations close
    /// this one-shot reservoir. No caller path or success assertion is accepted.
    pub(crate) fn capture_once(&mut self, executable: &std::fs::File) -> Result<(), E> {
        if self.entered || self.first.is_some() || !matches!(self.fields, Some(Ok(_))) {
            return Err(self.fail(Failure::Order));
        }
        self.entered = true;
        let fields = self.fields.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
        self.limit = Some(rustix::process::getrlimit(rustix::process::Resource::Nofile));
        self.limit_check = Some(if self.limit.is_some_and(|limit|
            limit.current == Some(fields.nofile) && limit.maximum == Some(fields.nofile))
        { Ok(()) } else { Err(E::default()) });
        if !matches!(self.limit_check, Some(Ok(()))) {
            return Err(self.fail(Failure::Limits));
        }

        self.delivered.stat = Some(rustix::fs::fstat(executable));
        self.delivered.filesystem = Some(rustix::fs::fstatfs(executable));
        self.delivered.flags = Some(rustix::fs::fcntl_getfl(executable));
        self.delivered.mount = Some(MountId::from_fd(executable.as_fd()));
        if !matches!(self.delivered.stat, Some(Ok(_))) { return Err(self.fail(Failure::DeliveredStat)); }
        if !matches!(self.delivered.filesystem, Some(Ok(_))) { return Err(self.fail(Failure::DeliveredFilesystem)); }
        if !matches!(self.delivered.flags, Some(Ok(_))) { return Err(self.fail(Failure::DeliveredFlags)); }
        if !matches!(self.delivered.mount, Some(Ok(_))) { return Err(self.fail(Failure::DeliveredMount)); }

        // This fixed kernel link names only the calling process's executable;
        // it is not a path supplied by Root, a decoded profile or a request.
        self.self_executable = Some(rustix::fs::open(
            "/proc/self/exe", OFlags::PATH | OFlags::CLOEXEC, Mode::empty(),
        ));
        let own = match self.self_executable.as_ref() {
            Some(Ok(own)) => own,
            _ => return Err(self.fail(Failure::SelfOpen)),
        };
        self.own.stat = Some(rustix::fs::fstat(own));
        self.own.filesystem = Some(rustix::fs::fstatfs(own));
        self.own.flags = Some(rustix::fs::fcntl_getfl(own));
        self.own.mount = Some(MountId::from_fd(own.as_fd()));
        if !matches!(self.own.stat, Some(Ok(_))) { return Err(self.fail(Failure::SelfStat)); }
        if !matches!(self.own.filesystem, Some(Ok(_))) { return Err(self.fail(Failure::SelfFilesystem)); }
        if !matches!(self.own.flags, Some(Ok(_))) { return Err(self.fail(Failure::SelfFlags)); }
        if !matches!(self.own.mount, Some(Ok(_))) { return Err(self.fail(Failure::SelfMount)); }
        self.physical = Some(require_same_executable(&self.delivered, &self.own));
        if !matches!(self.physical, Some(Ok(()))) {
            return Err(self.fail(Failure::Physical));
        }
        Ok(())
    }

    pub(crate) fn complete(&self) -> bool {
        self.first.is_none() && self.entered && matches!(self.physical, Some(Ok(())))
    }

    fn fail(&mut self, site: Failure) -> E {
        self.first.get_or_insert(site);
        self.closed.get_or_insert(E::default());
        E::default()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Order => None,
            Failure::Packet => failure(&self.fields),
            Failure::Limits => failure(&self.limit_check),
            Failure::DeliveredStat => failure(&self.delivered.stat),
            Failure::DeliveredFilesystem => failure(&self.delivered.filesystem),
            Failure::DeliveredFlags => failure(&self.delivered.flags),
            Failure::DeliveredMount => failure(&self.delivered.mount),
            Failure::SelfOpen => failure(&self.self_executable),
            Failure::SelfStat => failure(&self.own.stat),
            Failure::SelfFilesystem => failure(&self.own.filesystem),
            Failure::SelfFlags => failure(&self.own.flags),
            Failure::SelfMount => failure(&self.own.mount),
            Failure::Physical => failure(&self.physical),
        }.or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn require_same_executable<E: Default>(delivered: &ExecutableReadback, own: &ExecutableReadback) -> Result<(), E> {
    let mut identity = None;
    for observation in [delivered, own] {
        let stat = observation.stat.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let filesystem = observation.filesystem.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let flags = observation.flags.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let mount = observation.mount.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7222 != 0
            || stat.st_mode & 0o111 == 0 || stat.st_size <= 0
            || filesystem.f_type as u64 != 0xe0f5_e1e2
            || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND)
        {
            return Err(E::default());
        }
        let observed = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mode, stat.st_uid,
            stat.st_gid, stat.st_ctime, stat.st_ctime_nsec, mount);
        if identity.is_some_and(|identity| identity != observed) {
            return Err(E::default());
        }
        identity = Some(observed);
    }
    Ok(())
}

fn failure<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}


// These checked scalar/vector decoders describe DATA only. Their error value
// is a typed projection retained by the enclosing original; it grants nothing.
pub(crate) fn read_u64<E: Default>(bytes: &[u8]) -> Result<u64, E> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| E::default())?))
}

pub(crate) fn read_vector<E: Default>(bytes: &[u8]) -> Result<ResourceVector, E> {
    if bytes.len() != D::COUNT * 8 {
        return Err(E::default());
    }

    let mut values = [0; D::COUNT];
    for (index, value) in values.iter_mut().enumerate() {
        *value = read_u64::<E>(&bytes[index * 8..][..8])?;
    }
    Ok(ResourceVector::new(values))
}
