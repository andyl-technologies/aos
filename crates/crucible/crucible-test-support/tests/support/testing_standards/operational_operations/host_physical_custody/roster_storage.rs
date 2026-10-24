//! Binds real roster allocation charges, exact upgrade exclusion and physical free.
//!
//! Component evidence grants no Main, Source, native account or action authority.

use super::Companion;

pub(super) const STORAGE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/original_roster/storage.rs",
    required: &[
        (
            r#"pub(super) struct RosterOwner {
    shared: Arc<Mutex<NativeRoster>>,
    funding: Option<NativeRosterAllocationFunding>,
}"#,
            1,
        ),
        (
            r#"pub(super) struct RosterWeak {
    shared: Weak<Mutex<NativeRoster>>,
    funding: Option<NativeRosterAllocationFunding>,
}"#,
            1,
        ),
        (
            r#"pub(super) fn downgrade(&self) -> RosterWeak {
        RosterWeak {
            shared: Arc::downgrade(&self.shared),
            funding: self.funding.clone(),
        }
    }"#,
            1,
        ),
        (
            r#"pub(super) fn retire_body(
        &mut self,
        verify: impl FnOnce(&NativeRoster) -> Result<(), OriginalActorAccountError>,
        consume: impl FnOnce(&mut NativeRoster),
    ) -> Result<(), OriginalActorAccountError> {
        let Some(funding) = self.funding.as_ref() else {
            let state = Arc::get_mut(&mut self.shared)
                .ok_or(OriginalActorAccountError::Unavailable)?
                .get_mut()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            verify(state)?;
            consume(state);
            return Ok(());
        };

        let mut state = self
            .shared
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        verify(&state)?;
        let gate = funding
            .try_open()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        if Arc::strong_count(&self.shared) != 1 {
            return Err(OriginalActorAccountError::Unavailable);
        }

        // Every upgrade holds this same gate through actual Arc acquisition.
        // No raw Arc or independently clonable strong handle escapes. Once
        // sealed, this observed sole strong owner therefore remains exclusive.
        // Existing Weak owners keep the whole allocation funded by Main.
        gate.seal();
        consume(&mut state);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn upgrade(&self) -> Option<RosterOwner> {
        let gate = self
            .funding
            .as_ref()
            .map(NativeRosterAllocationFunding::try_open)
            .transpose()
            .ok()?;
        let shared = self.shared.upgrade()?;
        let funding = self.funding.clone();
        drop(gate);
        Some(RosterOwner { shared, funding })
    }"#,
            1,
        ),
    ],
};

pub(super) const FUNDING: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose/source_host/roster_allocation.rs",
    required: &[
        (
            r#"pub fn reserve_roster_allocation(
        &self,
        allocation_bytes: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<NativeRosterAllocationFunding, ServiceBirthError> {
        self.verify_native_preparation(original)?;
        self.check()?;
        let extent = funding_extent(allocation_bytes)?;
        let metadata = self
            .owner
            .owner
            .reserve_metadata(extent)
            .map_err(ServiceBirthError::from)?;

        let funding = construct(AllocationPayer::Main {
            _issuer: Arc::clone(&self.owner),
            _metadata: metadata,
        });
        self.verify_native_preparation(original)?;
        Ok(funding)
    }"#,
            1,
        ),
        (
            r#"pub fn try_open(&self) -> Result<NativeRosterUpgradeGate<'_>, HostServiceError> {
        let held = self
            .held
            .sealed
            .try_lock()
            .map_err(|_| HostServiceError::Unavailable)?;
        if *held {
            return Err(HostServiceError::Unavailable);
        }
        Ok(NativeRosterUpgradeGate { _held: held })
    }"#,
            1,
        ),
        (
            r#"pub fn seal(mut self) {
        *self._held = true;
    }"#,
            1,
        ),
        (
            r#"fn funding_extent(allocation_bytes: u64) -> Result<u64, ServiceBirthError> {
    let (layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<AllocationState>())
    .map_err(|_| ServiceBirthError::from(HostServiceError::Unavailable))?;
    u64::try_from(layout.pad_to_align().size())
        .ok()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AllocationState>() as u64))
        .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
        .and_then(|bytes| bytes.checked_add(allocation_bytes))
        .filter(|_| allocation_bytes != 0)
        .ok_or_else(|| ServiceBirthError::from(HostServiceError::Unavailable))
}"#,
            1,
        ),
    ],
};
