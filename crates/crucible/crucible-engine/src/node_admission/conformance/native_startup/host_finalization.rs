//! Keeps the original three host finalizations ahead of every private boot.
//!
//! The same private allocation is weakly attached to all three Source births
//! before an admission escapes. A failed or unwinding finalization aborts the
//! whole roster; its partial owners remain retained and no later member can be
//! issued. Successful completion is an allocation-phase barrier, not a native
//! startup, activation, Report or Capture permission.

use std::{
    cell::Cell,
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use super::{
    InstalledConformancePlan, PacketCompleteSemanticSource, RuntimeError,
    WeakInstalledConformancePlan,
};

const COMPLETE: u8 = 0b111;

/// Contains the only returning/failed phase state used by the production gate.
struct HostPhase {
    completed: Cell<u8>,
    active: Cell<Option<usize>>,
    aborted: Cell<bool>,
}

impl HostPhase {
    fn new() -> Self {
        Self {
            completed: Cell::new(0),
            active: Cell::new(None),
            aborted: Cell::new(false),
        }
    }

    fn begin(&self, index: usize) -> Result<(), RuntimeError> {
        if self.aborted.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        if index >= 3 || self.completed.get() & (1 << index) != 0 {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.active.get().is_some() {
            self.abort();
            return Err(RuntimeError::OwnerBusy);
        }
        self.active.set(Some(index));
        Ok(())
    }

    fn finish(&self, index: usize) -> Result<(), RuntimeError> {
        if self.aborted.get() || self.active.get() != Some(index) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.completed.set(self.completed.get() | (1 << index));
        self.active.set(None);
        Ok(())
    }

    fn ready(&self) -> Result<(), RuntimeError> {
        if self.aborted.get() || self.active.get().is_some() || self.completed.get() != COMPLETE {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    fn abort(&self) {
        self.aborted.set(true);
    }

    fn abandon(&self) {
        if self.ready().is_err() {
            self.abort();
        }
    }
}

struct HostOrigin {
    process: u32,
    thread: ThreadId,
}

impl HostOrigin {
    fn current() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
        }
    }

    fn authenticate(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }
}

// Weak ownership keeps an abandoned allocation identity from being recycled.
// Byte equality, a numeric index and an equivalent newly built Source cannot
// substitute for this actual same-roster allocation association.
fn same_owner<T>(expected: &Weak<T>, actual: &T) -> bool {
    std::ptr::eq(expected.as_ptr(), actual) && expected.strong_count() != 0
}

/// Binds the fixed host phase to its original plan, process, thread and Sources.
pub(crate) struct OriginalHostFinalizationBarrier {
    origin: HostOrigin,
    plan: WeakInstalledConformancePlan,
    sources: [Weak<PacketCompleteSemanticSource>; 3],
    phase: HostPhase,
}

impl OriginalHostFinalizationBarrier {
    pub(super) fn new(
        plan: &InstalledConformancePlan,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
    ) -> Self {
        Self {
            origin: HostOrigin::current(),
            plan: plan.downgrade(),
            sources: sources.each_ref().map(Rc::downgrade),
            phase: HostPhase::new(),
        }
    }

    pub(super) fn allocation_requested_bytes() -> usize {
        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<Self>()
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<OriginalHostFinalizationLease>()
            + size_of::<Result<OriginalHostFinalizationLease, RuntimeError>>()
            + size_of::<[Weak<PacketCompleteSemanticSource>; 3]>()
            + size_of::<OriginalHostFinalizationSource>()
            + 2 * size_of::<Rc<Self>>()
    }

    fn authenticate_source(
        &self,
        index: usize,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.origin.authenticate()?;
        let expected = self
            .sources
            .get(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if self.plan.0.strong_count() == 0 || !same_owner(expected, source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn begin(
        self: &Rc<Self>,
        index: usize,
        plan: &InstalledConformancePlan,
        source: &PacketCompleteSemanticSource,
    ) -> Result<OriginalHostFinalizationLease, RuntimeError> {
        let result = (|| {
            self.authenticate_source(index, source)?;
            if !same_owner(&self.plan.0, &*plan.0) {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.phase.begin(index)
        })();
        if let Err(error) = result {
            self.phase.abandon();
            return Err(error);
        }
        Ok(OriginalHostFinalizationLease {
            barrier: Rc::clone(self),
            index,
            finished: false,
        })
    }

    pub(super) fn authenticate_ready(
        &self,
        index: usize,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_source(index, source)?;
        self.phase.ready()
    }

    // Called only during infallible attachment of the three validated slots.
    pub(crate) fn source_link(self: &Rc<Self>, index: usize) -> OriginalHostFinalizationSource {
        OriginalHostFinalizationSource {
            barrier: Rc::downgrade(self),
            index,
        }
    }

    pub(super) fn abandon(&self) {
        self.phase.abandon();
    }
}

/// Retains the common gate after a member moves from Core into its Source.
///
/// This is private lifetime custody, never a standalone permission or a
/// replacement for that member's installed-authority authentication.
pub(crate) struct OriginalHostFinalizationSource {
    barrier: Weak<OriginalHostFinalizationBarrier>,
    index: usize,
}

impl OriginalHostFinalizationSource {
    /// Counts the fixed gate-upgrade and scalar authentication views.
    pub(crate) fn authentication_scratch_data() -> usize {
        // Weak::upgrade and slice::get each return their own concrete wrapper;
        // the successfully extracted owners/views coexist with those results.
        size_of::<Rc<OriginalHostFinalizationBarrier>>()
            + size_of::<Option<Rc<OriginalHostFinalizationBarrier>>>()
            + size_of::<Result<Rc<OriginalHostFinalizationBarrier>, RuntimeError>>()
            + size_of::<Option<&Weak<PacketCompleteSemanticSource>>>()
            + size_of::<Result<&Weak<PacketCompleteSemanticSource>, RuntimeError>>()
            + size_of::<&Weak<PacketCompleteSemanticSource>>()
            + size_of::<Result<(), RuntimeError>>()
            // Actual completed/active/index scalar views, not Result stand-ins.
            + size_of::<u8>()
            + size_of::<Option<usize>>()
            + size_of::<usize>()
    }

    /// Checks the same original Source and the completed nonaborted host roster.
    ///
    /// # Errors
    /// Refuses an abandoned, foreign, incomplete or aborted shared owner.
    pub(crate) fn authenticate_ready(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        let barrier = self
            .barrier
            .upgrade()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        barrier.authenticate_ready(self.index, source)
    }
}

pub(super) struct OriginalHostFinalizationLease {
    barrier: Rc<OriginalHostFinalizationBarrier>,
    index: usize,
    finished: bool,
}

impl OriginalHostFinalizationLease {
    pub(super) fn finish(mut self) -> Result<(), RuntimeError> {
        self.barrier.origin.authenticate()?;
        self.barrier.phase.finish(self.index)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for OriginalHostFinalizationLease {
    fn drop(&mut self) {
        if !self.finished {
            // Includes ordinary Err returns and unwinding callbacks. No partial
            // Source owner is dropped or reset to make the next index eligible.
            self.barrier.phase.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These controls exercise production phase/identity helpers. They create no
    // installed authority, Source, Child, native endpoint or backend permission.
    #[test]
    fn all_three_host_finalizations_precede_release_and_repetition_refuses() {
        let phase = HostPhase::new();
        for index in 0..3 {
            assert!(phase.ready().is_err());
            phase.begin(index).unwrap();
            assert!(phase.ready().is_err());
            phase.finish(index).unwrap();
        }
        phase.ready().unwrap();
        assert!(matches!(
            phase.begin(1),
            Err(RuntimeError::DuplicateOperation)
        ));
        phase.ready().unwrap();
    }

    #[test]
    fn abort_keeps_partial_owner_and_refuses_before_next_effect() {
        let phase = HostPhase::new();
        let partial_owner = vec![1u8, 2, 3];
        let effects = Cell::new(0);
        phase.begin(0).unwrap();
        phase.abort();

        let result = phase.begin(1).map(|()| effects.set(effects.get() + 1));

        assert!(result.is_err());
        assert_eq!(effects.get(), 0);
        assert_eq!(partial_owner, [1, 2, 3]);
        assert!(phase.ready().is_err());
    }

    #[test]
    fn incomplete_drop_and_reentrant_finalization_cannot_release() {
        let phase = HostPhase::new();
        phase.begin(0).unwrap();
        phase.finish(0).unwrap();
        phase.abandon();
        assert!(phase.begin(1).is_err());
        assert!(phase.ready().is_err());

        let active = HostPhase::new();
        active.begin(0).unwrap();
        assert!(active.begin(1).is_err());
        assert!(active.finish(0).is_err());
        assert!(active.ready().is_err());
    }

    // An inert private gate cannot authenticate a Source or installed plan.
    // It isolates the SAME production lease Drop without creating authority.
    fn inert_barrier() -> Rc<OriginalHostFinalizationBarrier> {
        Rc::new(OriginalHostFinalizationBarrier {
            origin: HostOrigin::current(),
            plan: WeakInstalledConformancePlan(Weak::new()),
            sources: std::array::from_fn(|_| Weak::new()),
            phase: HostPhase::new(),
        })
    }

    #[test]
    fn barrier_capacity_keeps_real_and_expired_shell_without_opening_a_phase() {
        use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
        let barrier = inert_barrier();
        let alias = OriginalHostFinalizationSource {
            barrier: Rc::downgrade(&barrier),
            index: 0,
        };
        let mut live = OriginalOwnerCapacityMetadataData::new(1, None);

        barrier.record_retained_capacity_data(&mut live).unwrap();
        let expected = live.finish();

        assert_eq!(expected.shared_backing_views, 1);
        assert_eq!(expected.capacity_records, 1);
        assert_eq!(
            expected.shared_value_bytes,
            size_of::<OriginalHostFinalizationBarrier>()
        );
        assert_eq!(
            expected.maximum_shared_value_alignment,
            std::mem::align_of::<OriginalHostFinalizationBarrier>()
        );
        assert_eq!(Rc::strong_count(&barrier), 1);
        assert!(barrier.phase.ready().is_err());
        assert_eq!(barrier.phase.completed.get(), 0);
        assert_eq!(barrier.phase.active.get(), None);
        assert!(!barrier.phase.aborted.get());
        drop(barrier);
        let mut expired = OriginalOwnerCapacityMetadataData::new(1, None);

        alias.record_retained_capacity_data(&mut expired).unwrap();

        assert_eq!(expired.finish(), expected);
        assert!(alias.barrier.upgrade().is_none());
    }

    #[test]
    fn actual_phase_lease_drop_and_unwind_latch_before_another_effect() {
        for unwind in [false, true] {
            let barrier = inert_barrier();
            let partial_owner = vec![9u8, 8, 7];
            barrier.phase.begin(0).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lease = OriginalHostFinalizationLease {
                    barrier: Rc::clone(&barrier),
                    index: 0,
                    finished: false,
                };
                if unwind {
                    panic!("modeled finalization callback unwind");
                }
            }));

            assert_eq!(result.is_err(), unwind);
            assert!(barrier.phase.begin(1).is_err());
            assert!(barrier.phase.ready().is_err());
            assert_eq!(partial_owner, [9, 8, 7]);
        }
    }

    #[test]
    fn only_finished_production_leases_can_release_all_three() {
        let barrier = inert_barrier();
        let source_alias = barrier.source_link(0);
        for index in 0..3 {
            barrier.phase.begin(index).unwrap();
            OriginalHostFinalizationLease {
                barrier: Rc::clone(&barrier),
                index,
                finished: false,
            }
            .finish()
            .unwrap();
            assert_eq!(barrier.phase.ready().is_ok(), index == 2);
        }
        // A completed gate is not revoked by dropping its Core admission.
        barrier.abandon();
        barrier.phase.ready().unwrap();
        drop(barrier);
        // An alias cannot manufacture an owner after the last strong holder.
        assert!(source_alias.barrier.upgrade().is_none());
    }

    #[test]
    fn wrong_member_index_cannot_finish_or_recover_a_failed_phase() {
        let barrier = inert_barrier();
        barrier.phase.begin(0).unwrap();

        let result = OriginalHostFinalizationLease {
            barrier: Rc::clone(&barrier),
            index: 1,
            finished: false,
        }
        .finish();

        assert!(result.is_err());
        assert!(barrier.phase.begin(2).is_err());
        assert!(barrier.phase.ready().is_err());
    }

    #[test]
    fn foreign_allocation_and_process_or_thread_cannot_substitute_origin() {
        let original = Rc::new(7);
        let foreign = Rc::new(7);
        let weak = Rc::downgrade(&original);
        assert!(same_owner(&weak, &*original));
        assert!(!same_owner(&weak, &*foreign));
        drop(original);
        assert!(!same_owner(&weak, &*foreign));

        let mut origin = HostOrigin::current();
        origin.process = origin.process.wrapping_add(1);
        assert!(matches!(
            origin.authenticate(),
            Err(RuntimeError::ForeignAuthority)
        ));
        let origin = HostOrigin::current();
        assert!(
            std::thread::spawn(move || origin.authenticate().is_err())
                .join()
                .unwrap()
        );
    }
}

mod settled17;

impl OriginalHostFinalizationBarrier {
    /// Records this strong view and every original nested weak allocation shell.
    ///
    /// # Errors
    /// Refuses exhausted rows, invalid layout or unready physical backing. This
    /// walk does not inspect phase currentness or upgrade plan/Source custody.
    pub(crate) fn record_retained_capacity_data(
        self: &Rc<Self>,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            origin,
            plan,
            sources,
            phase,
        } = self.as_ref();
        let HostOrigin { process, thread } = origin;
        let HostPhase {
            completed,
            active,
            aborted,
        } = phase;

        fn fixed_cell<T: Copy>(_: &Cell<T>) {}

        census.observe_inline_data(process);
        census.observe_inline_data(thread);
        fixed_cell(completed);
        fixed_cell(active);
        fixed_cell(aborted);

        census.observe_shared_allocation_data(self)?;
        plan.record_retained_capacity_data(census)?;
        for source in sources {
            census.observe_weak_allocation_data(source)?;
        }
        Ok(())
    }
}

impl OriginalHostFinalizationSource {
    /// Records the weak barrier shell without borrowing its destroyed payload.
    ///
    /// # Errors
    /// Refuses exhausted rows, invalid layout or unavailable physical backing.
    pub(crate) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self { barrier, index } = self;
        census.observe_inline_data(index);
        census.observe_weak_allocation_data(barrier)
    }
}

impl OriginalHostFinalizationBarrier {
    /// Names actual nested shared-barrier and fixed-cell borrowed views.
    pub(crate) fn retained_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&HostOrigin>()
            + size_of::<&HostPhase>()
            + size_of::<&Cell<u8>>()
            + size_of::<&Cell<Option<usize>>>()
            + size_of::<&Cell<bool>>()
            + size_of::<&WeakInstalledConformancePlan>()
            + size_of::<&Weak<PacketCompleteSemanticSource>>()
    }
}
