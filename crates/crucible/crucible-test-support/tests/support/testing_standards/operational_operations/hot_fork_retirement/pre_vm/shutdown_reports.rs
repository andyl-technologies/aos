//! Binds shutdown reports to original prebirth funding and immutable cells.
//!
//! These facts classify existing cleanup owners; reports grant no native role,
//! new operation, successful return, or physical resource-release authority.

use super::Companion;

pub(in super::super) const CELLS: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/launch_cleanup/shutdown_journal.rs",
    required: &[
        (
            r###"struct JournalAllocation {
    attempts: [OnceLock<QemuShutdownAttempt>; ATTEMPTS],
    failures: [OnceLock<QemuShutdownFailure>; FAILURES],
    original_observations: [OnceLock<HostSupervisionError>; ORIGINAL_OBSERVATIONS],
    // Every retained output and its physical allocation closes before this loan.
    _finalizer: Option<RetainedCleanupFinalizer>,
}"###,
            1,
        ),
        (
            r###"pub(super) fn new(finalizer: RetainedCleanupFinalizer) -> Self {
        Self::allocate(Some(finalizer))
    }"###,
            1,
        ),
        (
            r###"fn allocate(finalizer: Option<RetainedCleanupFinalizer>) -> Self {
        Self {
            shared: Some(Arc::new(JournalAllocation {
                attempts: std::array::from_fn(|_| OnceLock::new()),
                failures: std::array::from_fn(|_| OnceLock::new()),
                original_observations: std::array::from_fn(|_| OnceLock::new()),
                _finalizer: finalizer,
            })),
        }
    }"###,
            1,
        ),
        (
            r###"fn allocation_layout() -> Option<Layout> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<JournalAllocation>())
            .ok()?;
        Some(allocation.pad_to_align())
    }"###,
            1,
        ),
        (
            r###"pub(super) fn peak_bytes() -> Option<u64> {
        Self::allocation_layout()?
            .size()
            .checked_add(std::mem::size_of::<JournalAllocation>())?
            .checked_add(std::mem::size_of::<QemuShutdownFailure>())?
            .checked_add(std::mem::size_of::<QemuShutdownReport>())?
            .checked_add(std::mem::size_of::<QemuShutdownObservations>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()
    }"###,
            1,
        ),
        (
            r###"pub(crate) fn record_attempt(&self, index: usize, output: QemuShutdownAttempt) {
        assert!(
            self.available(),
            "shutdown outputs require admitted storage"
        );
        assert!(
            self.attempts()[index].set(output).is_ok(),
            "each shutdown rung publishes its actual output once"
        );
    }"###,
            1,
        ),
        (
            r###"pub(crate) fn record_failure(&self, index: usize, output: QemuShutdownFailure) {
        assert!(
            self.available(),
            "shutdown failures require admitted storage"
        );
        assert!(
            self.failures()[index].set(output).is_ok(),
            "each shutdown refusal retains its actual error once"
        );
    }"###,
            1,
        ),
        (
            r###"pub(crate) fn report(&self, reaped: bool, leaked: bool) -> QemuShutdownReport {
        let attempts = self
            .attempts()
            .iter()
            .enumerate()
            .fold(0, |mask, (index, cell)| {
                mask | (u8::from(cell.get().is_some()) << index)
            });
        let failures = self
            .failures()
            .iter()
            .enumerate()
            .fold(0, |mask, (index, cell)| {
                mask | (u8::from(cell.get().is_some()) << index)
            });

        QemuShutdownReport {
            attempts: QemuShutdownAttempts {
                journal: self.clone(),
                mask: attempts,
            },
            failures: QemuShutdownFailures {
                journal: self.clone(),
                mask: failures,
            },
            reaped,
            leaked,
        }
    }"###,
            1,
        ),
        (
            r###"impl Drop for ShutdownJournal {
    fn drop(&mut self) {
        if let Some(journal) = self.shared.take() {
            // No Weak or raw aliases escape. This actual header closes before
            // moved errors and the independent finalizer discharge accounting.
            drop(Arc::into_inner(journal));
        }
    }
}"###,
            1,
        ),
        (
            r###"pub(crate) fn original_observations(
        &self,
        observations: &[(Option<HostSupervisionError>, Option<HostSupervisionError>); 5],
    ) -> QemuShutdownObservations {
        let mut mask = 0;
        for (index, error) in observations
            .iter()
            .flat_map(|(before, after)| [before, after])
            .enumerate()
        {
            if let Some(error) = error {
                let shared = self.shared.as_ref().unwrap_or_else(|| {
                    unreachable!("shutdown observations require admitted storage")
                });
                let retained = shared.original_observations[index].get_or_init(|| *error);
                assert_eq!(
                    retained, error,
                    "each shutdown bracket retains its first refusal"
                );
                mask |= 1 << index;
            }
        }
        QemuShutdownObservations {
            journal: self.clone(),
            mask,
        }
    }"###,
            1,
        ),
        (
            r###"pub struct QemuShutdownObservations {
    journal: ShutdownJournal,
    mask: u16,
}

impl QemuShutdownObservations {
    /// Returns a rung's independently retained precheck and postcheck refusals.
    ///
    /// Returns `None` when `index` is outside the five-rung shutdown ladder.
    #[must_use]
    pub fn get(
        &self,
        index: usize,
    ) -> Option<(Option<HostSupervisionError>, Option<HostSupervisionError>)> {
        if index >= ORIGINAL_OBSERVATIONS / 2 {
            return None;
        }
        let observation = |offset: usize| {
            let cell = index * 2 + offset;
            if self.mask & (1 << cell) == 0 {
                return None;
            }
            self.journal
                .shared
                .as_ref()
                .and_then(|shared| shared.original_observations[cell].get())
                .copied()
        };
        Some((observation(0), observation(1)))
    }

    /// Iterates over all five rungs in escalation order, including empty pairs.
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = (Option<HostSupervisionError>, Option<HostSupervisionError>)>
    {
        (0..ORIGINAL_OBSERVATIONS / 2).filter_map(|index| self.get(index))
    }
}"###,
            1,
        ),
        (r###"const ORIGINAL_OBSERVATIONS: usize = 10;"###, 1),
        (r###"const ATTEMPTS: usize = 4;"###, 1),
        (r###"const FAILURES: usize = 6;"###, 1),
        (r###"self.journal.failure(self.index)"###, 1),
        (r###"Some(self.deref())"###, 1),
    ],
};

pub(in super::super) const ALLOCATION: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/launch_cleanup/retained_record.rs",
    required: &[
        (
            r###"pub(super) fn new(mut record: CleanupFinalizer) -> Self {
        let registrar = record
            .authority
            .get_mut()
            .ok()
            .and_then(|authority| authority.registrar.as_ref().map(Arc::downgrade));
        let registration_identity = record.target.zip(registrar);
        let finalizer = RetainedCleanupFinalizer::new(record);
        let retirement_storage = ControllerReturnStorage {
            cause: SharedOperationalCause::new(ControllerReturnCause::new(finalizer.clone())),
            journal: ControllerReturnJournal::new(finalizer.clone()),
        };

        Self {
            shared: Some(Arc::new(CleanupRecord {
                shutdown_storage: Mutex::new(Some(ShutdownJournal::new(finalizer.clone()))),
                finalizer,
                retirement_storage: Mutex::new(Some(retirement_storage)),
                retirement_claimed: AtomicBool::new(false),
                registration_identity,
            })),
        }
    }"###,
            1,
        ),
        (
            r###"pub(super) fn allocation_peak_bytes() -> Option<u64> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<CleanupRecord>())
            .ok()?;
        let root_peak: u64 = allocation
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<CleanupRecord>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()?;
        root_peak
            .checked_add(RetainedCleanupFinalizer::allocation_peak_bytes()?)?
            .checked_add(ControllerReturnCause::peak_bytes()?)?
            .checked_add(ControllerReturnJournal::peak_bytes()?)?
            .checked_add(ShutdownJournal::peak_bytes()?)
    }"###,
            1,
        ),
    ],
};

pub(in super::super) const SOURCE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/launch_cleanup.rs",
    required: &[
        (
            r###"pub(crate) fn new_source(
        registration: Option<&RamControlRegistration>,
        admission: &crate::linux_attempt_host::InstalledSourceAdmission,
    ) -> Result<Self, crate::linux_attempt_host::OriginalActorAccountError> {
        admission.check()?;
        let bytes = Self::retained_control_bytes()
            .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?;
        let control = admission
            .host_purpose()
            .reserve_controls(0, bytes)
            .map_err(crate::linux_attempt_host::OriginalActorAccountError::from)?;
        Ok(Self {
            inner: RetainedCleanupRecord::new(CleanupFinalizer {
                target: registration.map(|registration| registration.target),
                authority: Mutex::new(CleanupAuthority {
                    registrar: registration.map(|registration| Arc::clone(&registration.registrar)),
                    published_retirement: None,
                    published: false,
                    resources: registration
                        .map_or(admission.resources(), |registration| registration.resources),
                }),
                source_purpose: Mutex::new(Some(admission.host_purpose().clone())),
                installed_incarnation: Mutex::new(None),
                target_binding: Mutex::new(None),
                target_workspace: Mutex::new(None),
                #[cfg(target_os = "linux")]
                source_spawn_control: Mutex::new(None),
                #[cfg(target_os = "linux")]
                preexec_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_preexec: OnceLock::new(),
                #[cfg(target_os = "linux")]
                preexec_failure: OnceLock::new(),
                #[cfg(target_os = "linux")]
                child_return_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_child: OnceLock::new(),
                child_started: AtomicBool::new(false),
                child_reaped: AtomicBool::new(false),
                pending_joins: AtomicUsize::new(0),
                pending_imports: AtomicUsize::new(0),
                external_basis: Mutex::new(None),
                source_control: Some(control),
            }),
        })
    }"###,
            1,
        ),
        (
            r###"pub(crate) fn claim_shutdown_journal(&self) -> Option<ShutdownJournal> {
        self.inner.shutdown_storage.try_lock().ok()?.take()
    }"###,
            1,
        ),
        (
            r###"shutdown_storage: Mutex<Option<ShutdownJournal>>,"###,
            1,
        ),
        (r###"RetainedCleanupRecord::allocation_peak_bytes()"###, 1),
    ],
};

pub(in super::super) const NODE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/node.rs",
    required: &[
        (
            r###"let launch_cleanup = child.launch_cleanup.clone();"###,
            1,
        ),
        (
            r###"let child_shutdown = shutdown_continuation::ChildShutdown::for_launch(launch_cleanup.as_ref());"###,
            1,
        ),
        (r###"shutdown_policy, child_shutdown, async_policy,"###, 1),
    ],
};

pub(in super::super) const FORK: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/node/hot_fork_ram_stage.rs",
    required: &[(
        r###"pub(super) fn take_shutdown(
        &mut self,
    ) -> Result<super::shutdown_continuation::ChildShutdown, QemuNodeChannelError> {
        let history = self
            .return_history
            .take()
            .ok_or_else(|| failure("RAM cleanup journal already moved"))?;
        Ok(super::shutdown_continuation::ChildShutdown::from_ram(
            history,
            self.cleanup_original.take(),
            &self.cleanup,
        ))
    }"###,
        1,
    )],
};
