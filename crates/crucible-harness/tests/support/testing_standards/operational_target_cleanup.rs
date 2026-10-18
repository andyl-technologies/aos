//! Shares exact saved-Target cleanup obligations between both wait scanners.
//!
//! These source clauses bind one prepaid cleanup cell and its physical return.
//! Compile-time projections keep each consumer on the same complete contract.

/// Binds the actual saved owner, once-only entry and final physical return cuts.
pub(super) const OBLIGATIONS: [&str; 16] = [
    r#"cleanup: Option<Arc<TargetCleanup>>,"#,
    r#"pub(super) struct TargetCleanup {
    preparation: Arc<HostOperationGuard>,
    completed: bool,
    entered: std::sync::OnceLock<
        Result<
            Arc<HostOperationGuard>,
            crucible_linux_resource::host_supervision::HostSupervisionError,
        >,
    >,
}"#,
    r#"fn new(preparation: Arc<HostOperationGuard>) -> Self {
    Self { preparation, completed: false, entered: std::sync::OnceLock::new(), }
}"#,
    r#"pub(super) fn guard(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    let entered = self.entered.get_or_init(|| {
        self.preparation.begin_original_cleanup_control().map(Arc::new)
    });
    let guard = entered.as_ref()
        .map_err(|source| OriginalActorAccountError::from(*source))?;
    guard.wait_slice()?;
    Ok(Arc::clone(guard))
}"#,
    r#"let (layout, _) = std::alloc::Layout::new::<(usize, usize)>()
    .extend(std::alloc::Layout::new::<TargetCleanup>()).ok()?;
bytes.checked_add(u64::try_from(layout.pad_to_align().size()).ok()?)"#,
    r#"let preparation = Arc::new(normal.begin_native_preparation()?);
slot.fork_target.cleanup = Some(Arc::new(TargetCleanup::new(Arc::clone(&preparation))));
slot.fork_target.preparation = Some(Arc::clone(&preparation));
slot.fork_target.next_epoch = epoch;
slot.fork_target.occupied = Some(epoch);
slot.fork_target.reserved_process_generation = Some(process_generation);"#,
    r#"pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    self.cleanup.as_ref().ok_or(OriginalActorAccountError::Unavailable)?.guard()
}"#,
    r#"pub(super) fn retry_unsettled_target(slot: &mut NativeSlot) -> Result<(), QemuVmRealizationError> {
    retry_unsettled_target_raw(slot).map_err(QemuForkTargetConstructionError::into_realization)
}"#,
    r#"fn retry_unsettled_target_raw(slot: &mut NativeSlot,) -> Result<(), QemuForkTargetConstructionError> {
    let target = &mut slot.fork_target;
    if target.unsettled.is_none() { return Ok(()); }
    let cleanup = target.cleanup().map_err(QemuForkTargetConstructionError::Original)?;
    let work = target.unsettled.as_mut()
        .ok_or(QemuForkTargetConstructionError::Original(OriginalActorAccountError::Unavailable,))?
        .finish(&cleanup);
    if let Err(first) = work {
        if target.unsettled.as_ref().is_some_and(RetainedNativeHost::bodies_returned) {
            target.unsettled = None;
            target.envelope = None;
            target.physical_closed = true;
        }
        return Err(QemuForkTargetConstructionError::Physical(first));
    }
    target.unsettled = None;
    target.envelope = None;
    target.physical_closed = true;
    drop(cleanup);
    finish_target_control_return(slot)
}"#,
    r#"fn finish_target_control_return(slot: &mut NativeSlot,) -> Result<(), QemuForkTargetConstructionError> {
    let target = &mut slot.fork_target;
    if let Some(pin) = target.control.as_mut() {
        let cleanup = target.cleanup.as_ref()
            .ok_or(QemuForkTargetConstructionError::Original(OriginalActorAccountError::Unavailable,))?
            .guard().map_err(QemuForkTargetConstructionError::Original)?;
        let work = pin.close();
        let post = cleanup.wait_slice();
        match work {
            Ok(()) => {
                target.control = None;
                post.map_err(|first| QemuForkTargetConstructionError::Original(first.into()))?;
            }
            Err(source) => {
                return Err(QemuForkTargetConstructionError::Original(
                    OriginalActorAccountError::NativeControlBoundary { source, original: post.err(), },
                ));
            }
        }
    }
    target.control = None;
    close_target_slot(slot).map_err(QemuForkTargetConstructionError::Original)
}"#,
    r#"fn close_target_slot(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    let target = &mut slot.fork_target;
    let epoch = target.occupied.ok_or(OriginalActorAccountError::Unavailable)?;
    if !target.physical_closed
        || target.unsettled.is_some()
        || target.control.is_some()
        || target.process_generation.is_some_and(|generation| {
            slot.digest_purposes.iter().any(|purpose| purpose.belongs_to_process(generation))
        })
        || slot.installed_process.as_ref()
            .is_some_and(|purpose| purpose.fork_target_incarnation_is_retained())
    { return Err(OriginalActorAccountError::Unavailable); }"#,
    r#"if let Some(binding) = target.process_binding.as_mut() {
    binding.close().map_err(|_| OriginalActorAccountError::Unavailable)?;
}
target.process_binding = None;
let cell = target.cleanup.as_mut().ok_or(OriginalActorAccountError::Unavailable)?;
let unique = Arc::get_mut(cell).ok_or(OriginalActorAccountError::Unavailable)?;"#,
    r#"let preparation = target.preparation.as_ref().ok_or(OriginalActorAccountError::Unavailable)?;
if !Arc::ptr_eq(preparation, &unique.preparation)
    || Arc::strong_count(preparation) != 2
    || Arc::weak_count(preparation) != 0
{ return Err(OriginalActorAccountError::Unavailable); }"#,
    r#"if let Err(post) = unique.complete_for_return() {
    let first = *target.cleanup_completion_failure.get_or_insert(post);
    return Err(OriginalActorAccountError::TargetCleanupBoundary {
        source: first, post: (post != first).then_some(post),
    });
}"#,
    r#"drop(target.cleanup.take());
let preparation = target.preparation.as_mut().ok_or(OriginalActorAccountError::Unavailable)?;
Arc::get_mut(preparation).ok_or(OriginalActorAccountError::Unavailable)?;
target.preparation = None;
target.process_generation = None;
target.reserved_process_generation = None;
target.ram_registration_generation = None;
target.born = false;
target.physical_closed = false;
target.returned_epoch = epoch;
target.occupied = None;
match target.cleanup_completion_failure.take() {
    Some(source) => { Err(OriginalActorAccountError::TargetCleanupBoundary { source, post: None }) }
    None => Ok(()),
}"#,
    r#"fn complete_for_return(&mut self,) -> Result<(), crucible_linux_resource::host_supervision::HostSupervisionError> {
    use crucible_linux_resource::host_supervision::{HostOperationClass, HostOperationState, HostSupervisionError,};
    let cleanup = self.entered.get_mut().ok_or(HostSupervisionError::Unavailable)?
        .as_mut().map_err(|first| *first)?;
    let guard = Arc::get_mut(cleanup).ok_or(HostSupervisionError::BorrowedOperation)?;
    let observed = if self.completed {
        guard.status()
    } else {
        let (completed, result) = guard.complete_observed();
        self.completed |= completed;
        result
    }?;
    if !self.completed || observed.class != HostOperationClass::Cleanup || observed.state != HostOperationState::Completed {
        return Err(HostSupervisionError::Unavailable);
    }
    Ok(())
}"#,
];

/// Rejects additional origins, cleanup entries, cell births or waits.
pub(super) const COUNTS: [(&str, usize); 14] = [
    ("fn retry_unsettled_target(", 1),
    ("fn retry_unsettled_target_raw(", 1),
    ("fn finish_target_control_return(", 1),
    ("unique.complete_for_return()", 1),
    ("guard.complete_observed()", 1),
    ("guard.status()", 1),
    ("target.returned_epoch = epoch;", 1),
    ("begin_original_cleanup_control()", 1),
    ("begin_native_preparation()", 1),
    ("get_or_init(", 1),
    ("TargetCleanup::new(", 1),
    // Includes the existing no-birth return check on the same saved Cleanup.
    ("wait_slice()", 9),
    ("HostOperationSupervisor::new(", 0),
    ("begin(", 0),
];

/// Pairs every clause with one occurrence, then appends the exact census.
pub(super) const REQUIRED: [(&str, usize); OBLIGATIONS.len() + COUNTS.len()] = {
    let mut required = [("", 0); OBLIGATIONS.len() + COUNTS.len()];
    let mut index = 0;
    while index < OBLIGATIONS.len() {
        required[index] = (OBLIGATIONS[index], 1);
        index += 1;
    }

    let mut count_index = 0;
    while count_index < COUNTS.len() {
        required[OBLIGATIONS.len() + count_index] = COUNTS[count_index];
        count_index += 1;
    }
    required
};
