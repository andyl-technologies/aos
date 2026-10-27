//! Retains the selected installation before its first config or daemon resource.

use super::*;

#[derive(Default)]
pub(crate) struct GuestOpenSshInstallOriginalV1 {
    pub(super) daemon_start: crate::openssh_gate_linux::OpenSshDaemonStartupOriginalV1,
    pub(super) daemon: Option<SelectedRunningOpenSshGateV1>,
    pub(super) selected: crate::openssh_gate_linux::SelectedDaemonStartupOriginalV1,
    pub(super) claim: Option<OpenSshGateClaimV1>,
    pub(super) config: ProtectedGateWriteOriginalV1,
    pub(super) record: ProtectedGateWriteOriginalV1,
    pub(super) body: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) entered: bool,
    pub(super) execution: Option<[u8; 16]>,
    pub(super) current: GateStartupCurrentV1,
}

impl GuestOpenSshInstallOriginalV1 {
    pub(crate) fn poll_failed_retirement_v1(&mut self, ledger: &Ledger)
        -> Result<bool, GuestProcessEffectErrorV1>
    {
        let execution = self.execution.ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        ledger.request_ssh_retirement_v1(execution);
        match self.daemon.as_mut() {
            Some(daemon) => daemon.poll_retirement(ledger),
            None => self.selected.poll_retirement(ledger, execution),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // A failed current gate short-circuits before the next native primary;
        // independent native posts cannot replace that earlier actual cause.
        self.current
            .failure()
            .or_else(|| self.config.failure())
            .or_else(|| self.daemon_start.failure())
            .or_else(|| self.selected.failure())
            .or_else(|| self.record.failure())
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

// Successful scalar observations own no native prefix and reuse one fixed
// destination. A failure is sticky; receipt polling cannot grow a history or
// restart the protected loop's original pre-receive BOOTTIME interval.
#[derive(Default)]
pub(super) struct GateStartupCurrentV1 {
    wall: Option<rustix::time::Timespec>,
    boottime: Option<rustix::time::Timespec>,
    result: Option<Result<(), GuestProcessEffectErrorV1>>,
    cutoff: Option<u64>,
}

impl GateStartupCurrentV1 {
    pub(super) fn bind_original_cutoff_v1(&mut self, cutoff: u64, process: &ProcessRecord)
        -> Result<(), GuestProcessEffectErrorV1>
    {
        if self.cutoff.is_some() || cutoff == 0 {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        let lifetime = process.lifetime.as_ref().ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        self.cutoff = Some(cutoff.min(lifetime.deadline_boottime_nanoseconds));
        Ok(())
    }

    pub(super) fn require_next(
        &mut self,
        ledger: &Ledger,
        process: &ProcessRecord,
        expires_at: i64,
        deadline: Instant,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.failure().is_some() || self.cutoff.is_none() {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        let previous_wall = self.wall;
        let previous_boot = self.boottime;
        self.wall = Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime));
        self.boottime = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.result = Some((|| {
            check_deadline(deadline)?;
            let wall = self.wall
                .as_ref()
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            let boot = self.boottime.as_ref().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            let boot_ns = u64::try_from(boot.tv_sec).ok()
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .and_then(|seconds| u64::try_from(boot.tv_nsec).ok()
                    .filter(|nanos| *nanos < 1_000_000_000)
                    .and_then(|nanos| seconds.checked_add(nanos)))
                .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
            if wall.tv_sec < 0 || !(0..1_000_000_000).contains(&wall.tv_nsec)
                || wall.tv_sec >= expires_at
                || boot_ns >= self.cutoff.ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
                || previous_wall.is_some_and(|previous|
                    (wall.tv_sec, wall.tv_nsec) < (previous.tv_sec, previous.tv_nsec))
                || previous_boot.is_some_and(|previous|
                    (boot.tv_sec, boot.tv_nsec) < (previous.tv_sec, previous.tv_nsec))
            {
                return Err(GuestProcessEffectErrorV1::InvalidRequest);
            }
            crate::process::require_owned_gate_lifetime_v1(ledger, process)
        })());
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(GuestProcessEffectErrorV1::AmbiguousEffect)
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
    }
}

#[derive(Default)]
pub(super) struct ProtectedGateWriteOriginalV1 {
    ancestors: [Option<std::io::Result<fs::Metadata>>; 3],
    previous: Option<std::io::Result<fs::Metadata>>,
    file: Option<std::io::Result<File>>,
    write: Option<std::io::Result<usize>>,
    sync: Option<std::io::Result<()>>,
    mode: Option<std::io::Result<()>>,
    rename: Option<std::io::Result<()>>,
    directory: Option<std::io::Result<File>>,
    directory_sync: Option<std::io::Result<()>>,
    named: Option<std::io::Result<fs::Metadata>>,
    after: Option<std::io::Result<fs::Metadata>>,
    primary: Option<Result<(), GuestProcessEffectErrorV1>>,
    completed: bool,
    entered: bool,
}

impl ProtectedGateWriteOriginalV1 {
    pub(super) fn install_once(
        &mut self,
        target: &str,
        bytes: &[u8],
        mode: u32,
        before_effect: &mut dyn FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.entered {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        self.entered = true;
        if bytes.len() > aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_INSTALL_RECORD_BYTES_V1 {
            self.primary = Some(Err(GuestProcessEffectErrorV1::InvalidRequest));
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        self.primary = Some(self.install_inner(target, bytes, mode, before_effect));
        // Both actual posts remain owed after a primary refusal. They retain
        // the renamed original file as well as the final literal name.
        self.after = self
            .file
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(File::metadata);
        self.named = Some(fs::symlink_metadata(target));
        self.completed = match (&self.primary, &self.after, &self.named) {
            (Some(Ok(())), Some(Ok(after)), Some(Ok(named))) => {
                after.dev() == named.dev()
                    && after.ino() == named.ino()
                    && after.len() == bytes.len() as u64
                    && named.len() == after.len()
                    && after.mode() & 0o777 == mode
                    && named.mode() == after.mode()
                    && after.uid() == 0
                    && named.uid() == 0
            }
            _ => false,
        };
        if self.completed {
            // Only the fully compared write+directory durability phase may
            // physically retire these original temporary handles.
            self.file.take();
            self.directory.take();
            Ok(())
        } else {
            Err(GuestProcessEffectErrorV1::AmbiguousEffect)
        }
    }

    fn install_inner(
        &mut self,
        target: &str,
        bytes: &[u8],
        mode: u32,
        before_effect: &mut dyn FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        for (index, directory) in ["/etc", "/etc/aos", DIRECTORY].into_iter().enumerate() {
            self.ancestors[index] = Some(fs::symlink_metadata(directory));
            let Some(Ok(metadata)) = self.ancestors[index].as_ref() else {
                return Err(closed());
            };
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
            }
        }
        self.previous = Some(fs::symlink_metadata(target));
        match self.previous.as_ref() {
            Some(Ok(metadata))
                if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => {}
            Some(Err(cause)) if cause.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(GuestProcessEffectErrorV1::UnprotectedLedger),
        }
        let target = Path::new(target);
        let temporary = target.with_extension("next");
        before_effect()?;
        self.file = Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(O_CLOEXEC | O_NOFOLLOW)
                .open(&temporary),
        );
        let Some(Ok(file)) = self.file.as_mut() else {
            return Err(closed());
        };
        before_effect()?;
        self.write = Some(file.write(bytes));
        if !matches!(self.write, Some(Ok(count)) if count == bytes.len()) {
            return Err(closed());
        }
        before_effect()?;
        self.sync = Some(file.sync_all());
        if !matches!(self.sync, Some(Ok(()))) {
            return Err(closed());
        }
        before_effect()?;
        self.mode = Some(fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(mode),
        ));
        if !matches!(self.mode, Some(Ok(()))) {
            return Err(closed());
        }
        before_effect()?;
        self.rename = Some(fs::rename(&temporary, target));
        if !matches!(self.rename, Some(Ok(()))) {
            return Err(closed());
        }
        self.directory = Some(File::open(DIRECTORY));
        let Some(Ok(directory)) = self.directory.as_ref() else {
            return Err(closed());
        };
        before_effect()?;
        self.directory_sync = Some(directory.sync_all());
        if matches!(self.directory_sync, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ancestors
            .iter()
            .find_map(|result| result.as_ref()?.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.previous
                    .as_ref()?
                    .as_ref()
                    .err()
                    .filter(|cause| cause.kind() != std::io::ErrorKind::NotFound)
                    .map(|cause| cause as _)
            })
            .or_else(|| self.file.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.write.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sync.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mode.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.rename.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.directory
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.directory_sync
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.primary
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.named.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

fn closed() -> GuestProcessEffectErrorV1 {
    GuestProcessEffectErrorV1::AmbiguousEffect
}
