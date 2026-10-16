//! Shares exact saved-Target cleanup obligations between both wait scanners.
//!
//! These source clauses bind one prepaid cleanup cell and its physical return.
//! Compile-time projections keep each consumer on the same complete contract.

/// Binds the actual saved owner, once-only entry and final physical return cuts.
pub(super) const OBLIGATIONS: [&str; 14] = [
    r#"cleanup: Option<Arc<TargetCleanup>>,"#,
    r#"pub(super) struct TargetCleanup {
    preparation: Arc<HostOperationGuard>,
    entered: std::sync::OnceLock<
        Result<
            Arc<HostOperationGuard>,
            crucible_linux_resource::host_supervision::HostSupervisionError,
        >,
    >,
}"#,
    r#"fn new(preparation: Arc<HostOperationGuard>) -> Self {
    Self { preparation, entered: std::sync::OnceLock::new(), }
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
slot.fork_target.preparation = Some(preparation);
slot.fork_target.next_epoch = epoch;
slot.fork_target.occupied = Some(epoch);"#,
    r#"pub(super) fn cleanup(&self) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
    self.cleanup.as_ref().ok_or(OriginalActorAccountError::Unavailable)?.guard()
}"#,
    r#"pub(super) fn retry_unsettled_target(slot: &mut NativeSlot) -> Result<(), QemuVmRealizationError> {
    let target = &mut slot.fork_target;
    if target.unsettled.is_none() { return Ok(()); }
    let cleanup = target.cleanup().map_err(original_error)?;
    target.unsettled.as_mut()
        .ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?
        .finish(&cleanup)?;
    target.unsettled = None;
    target.envelope = None;
    target.physical_closed = true;"#,
    r#"if let Some(pin) = target.control.as_mut() {
    pin.close().map_err(|source| {
        original_error(OriginalActorAccountError::NativeControlBoundary {
            source, original: cleanup.wait_slice().err(),
        })
    })?;
}
target.control = None;
drop(cleanup);
close_target_slot(slot).map_err(original_error)"#,
    r#"fn close_target_slot(slot: &mut NativeSlot) -> Result<(), OriginalActorAccountError> {
    let target = &mut slot.fork_target;
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
    r#"let cleanup = unique.entered.get_mut().ok_or(OriginalActorAccountError::Unavailable)?
    .as_mut().map_err(|source| OriginalActorAccountError::from(*source))?;
Arc::get_mut(cleanup).ok_or(OriginalActorAccountError::Unavailable)?.complete()?;"#,
    r#"drop(target.cleanup.take());
let preparation = target.preparation.as_mut().ok_or(OriginalActorAccountError::Unavailable)?;
Arc::get_mut(preparation).ok_or(OriginalActorAccountError::Unavailable)?;
target.preparation = None;
target.process_generation = None;
target.reserved_process_generation = None;
target.ram_registration_generation = None;
target.born = false;
target.physical_closed = false;
target.occupied = None;
Ok(())"#,
];

/// Rejects additional origins, cleanup entries, cell births or waits.
pub(super) const COUNTS: [(&str, usize); 8] = [
    ("fn retry_unsettled_target(", 1),
    ("begin_original_cleanup_control()", 1),
    ("begin_native_preparation()", 1),
    ("get_or_init(", 1),
    ("TargetCleanup::new(", 1),
    ("wait_slice()", 8),
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
