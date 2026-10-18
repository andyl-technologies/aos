//! Observes retained read-handle aliases after live currentness may have ended.

#[path = "retained_storage/checkpoint_cache17.rs"]
mod checkpoint_cache17;

use super::*;
use crate::node_adapters::cnp::semantic::{
    CnpRetainedStorageReport, retained_storage::Counter, unknown,
};
use crate::node_contract::OperationFailure;

impl CnpSemanticSourceRead {
    /// Counts actual shared backing retained by this same original read handle.
    ///
    /// The containing handle's inline slot is caller-owned. Actual ReadOwner,
    /// registrar and executable roots are conservatively counted per view; equal
    /// labels never discharge another view. This method remains usable after
    /// revocation and invokes no live source, registrar renewal or kernel query.
    /// It grants no source, reclamation, process-currentness or native authority.
    ///
    /// # Errors
    /// Refuses foreign creator processes/threads, unsupported SDK metadata or
    /// arithmetic/traversal/storage bounds. Opaque lease workers remain unknown.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        if self.process != std::process::id() {
            return Err(super::super::super::refused(
                "original source read has another creator",
            ));
        }
        self.executable.ensure_origin().map_err(unknown)?;
        let Self {
            process: _,
            owner,
            registration,
            kernel: _,
            executable,
        } = self;
        let mut counter = Counter::new(maximum);
        counter.rc(owner)?;
        counter.metadata(
            &registration
                .retained_metadata_facts_data()
                .map_err(unknown)?,
        )?;
        if counter.rc(executable)? {
            executable.charge_retained_storage_data(&mut counter)?;
        }
        self.executable.ensure_origin().map_err(unknown)?;
        Ok(counter.finish())
    }
}

impl CnpSemanticSourceRead {
    /// Quotes this read walk's compiled local counter and metadata view layouts.
    ///
    /// The caller admits this fixed window before entering the walk. Recursive
    /// compiler/SDK frames, allocator rounding and kernel resources are separate.
    pub fn retained_requested_storage_precredit_scratch_data() -> usize {
        std::mem::size_of::<
            crate::node_adapters::cnp::semantic::retained_storage::preparation::PreparationCounter,
        >() + std::mem::size_of::<
            crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts,
        >() + crucible_node_provider::retained_metadata::original_metadata_observer_layout_bytes()
    }

    /// Observes this original read owner without allocating failure diagnostics.
    ///
    /// The containing handle is caller-owned. Unknown executable backing remains
    /// explicit, including after revocation; this grants no currentness or work.
    ///
    /// # Errors
    /// Refuses another creator, unsupported metadata or checked storage bounds.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, crate::node_contract::RuntimeError> {
        use crate::node_adapters::cnp::semantic::retained_storage::preparation::PreparationCounter;
        use crate::node_contract::RuntimeError;

        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.executable
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.owner.storage_precredit_data()?;
        let Self {
            process: _,
            owner,
            registration,
            kernel: _,
            executable,
        } = self;
        let mut counter = PreparationCounter::new(maximum);
        counter.rc(owner)?;
        counter.metadata(
            &registration
                .retained_metadata_facts_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?,
        )?;
        if counter.rc(executable)? {
            executable.charge_retained_storage_precredit_data(&mut counter)?;
        }
        self.executable
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.owner.storage_precredit_data()?;
        Ok(counter.finish())
    }
}

impl ReadOwner {
    pub(in crate::node_adapters::cnp::semantic) fn storage_precredit_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        if self.busy.get() {
            return Err(crate::node_contract::RuntimeError::OwnerBusy);
        }
        Ok(())
    }
}

/// Retains the original native read through query validation and final fences.
pub(in crate::node_adapters::cnp::semantic) struct OriginalFreshQueryReadCall<'a> {
    original: &'a CnpSemanticSourceRead,
    call: Option<ReadCall>,
    fence: Option<OriginalFreshQueryOwnerFence>,
}

// The same real owner fence is used by production completion and the causal
// callback-revocation control. A successful callback cannot disarm a stale read.
struct OriginalFreshQueryOwnerFence {
    process: u32,
    owner: Option<Rc<ReadOwner>>,
    finished: bool,
}

impl OriginalFreshQueryOwnerFence {
    fn new(owner: Rc<ReadOwner>) -> Self {
        Self {
            process: std::process::id(),
            owner: Some(owner),
            finished: false,
        }
    }

    fn complete(
        mut self,
        final_currency: impl FnOnce() -> Result<(), crate::node_contract::RuntimeError>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = self.owner.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        owner.original_fresh_query_custody_data()?;
        final_currency()?;
        owner.original_fresh_query_custody_data()?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for OriginalFreshQueryOwnerFence {
    fn drop(&mut self) {
        if self.process != std::process::id() {
            std::mem::forget(self.owner.take());
        } else if !self.finished
            && let Some(owner) = &self.owner
        {
            owner.revoke();
        }
    }
}

impl CnpSemanticSourceRead {
    pub(crate) fn original_fresh_query_call_scratch_data() -> usize {
        std::mem::size_of::<OriginalFreshQueryReadCall<'_>>()
            + std::mem::size_of::<OriginalFreshQueryOwnerFence>()
            + super::super::executable_guard::FreshCurrentScratch::declared_scratch_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn begin_original_fresh_query_call_data(
        &self,
        scratch: &mut super::super::executable_guard::FreshCurrentScratch,
    ) -> Result<OriginalFreshQueryReadCall<'_>, crate::node_contract::RuntimeError> {
        self.ensure_original_fresh_current(scratch)?;
        Ok(OriginalFreshQueryReadCall {
            original: self,
            call: Some(
                ReadCall::begin(Rc::clone(&self.owner))
                    .map_err(|_| crate::node_contract::RuntimeError::OwnerBusy)?,
            ),
            fence: Some(OriginalFreshQueryOwnerFence::new(Rc::clone(&self.owner))),
        })
    }
}

impl OriginalFreshQueryReadCall<'_> {
    /// Rechecks currentness while this exact original call remains armed.
    ///
    /// The ordinary idle-current API deliberately refuses busy owners. Only
    /// this unforgeable in-flight token can use the owner-aware check; neither
    /// the ReadCall nor its sticky final owner fence is released before send.
    ///
    /// # Errors
    /// Refuses a foreign, finished, revoked or no-longer-busy original token,
    /// stale registrar, changed descriptor/kernel identity or scratch failure.
    pub(in crate::node_adapters::cnp::semantic) fn ensure_original_fresh_current_before_effect_data(
        &self,
        scratch: &mut super::super::executable_guard::FreshCurrentScratch,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.original.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let call = self.call.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let fence = self.fence.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        authenticate_armed_original_read(call, &self.original.owner, fence)?;
        self.original.executable.storage_origin_precredit_data()?;
        self.original
            .registration
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.original
            .executable
            .ensure_fresh_current(&self.original.kernel, scratch)?;
        self.original
            .registration
            .ensure_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        authenticate_armed_original_read(call, &self.original.owner, fence)?;
        self.original
            .executable
            .ensure_fresh_current(&self.original.kernel, scratch)?;
        authenticate_armed_original_read(call, &self.original.owner, fence)
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete(
        mut self,
        scratch: &mut super::super::executable_guard::FreshCurrentScratch,
        final_currency: impl FnOnce() -> Result<(), crate::node_contract::RuntimeError>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.original.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.call
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .finish(true);
        self.fence
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .complete(|| {
                self.original.ensure_original_fresh_current(scratch)?;
                final_currency()?;
                // Recheck the actual kernel/descriptor/registrar after callbacks,
                // while the sticky original owner fence is still armed.
                self.original.ensure_original_fresh_current(scratch)
            })
    }
}

impl Drop for OriginalFreshQueryReadCall<'_> {
    fn drop(&mut self) {
        if self.original.process != std::process::id() {
            std::mem::forget(self.call.take());
            std::mem::forget(self.fence.take());
        }
    }
}

impl ReadOwner {
    pub(in crate::node_adapters::cnp::semantic) fn original_fresh_query_custody_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        if self.busy.get() {
            return Err(crate::node_contract::RuntimeError::OwnerBusy);
        }
        if !self.current.get() {
            return Err(crate::node_contract::RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod fresh_host_tests {
    use super::*;
    use crate::node_contract::RuntimeError;
    use crucible_node_contract::U64;

    #[test]
    fn retired_owner_remains_data_observable_without_reentering_fresh_query() {
        let owner = ReadOwner::new(U64::new(19));
        assert_eq!(owner.storage_precredit_data(), Ok(()));
        assert_eq!(owner.original_fresh_query_custody_data(), Ok(()));

        owner.revoke();
        assert_eq!(owner.storage_precredit_data(), Ok(()));
        assert_eq!(
            owner.original_fresh_query_custody_data(),
            Err(RuntimeError::OwnerUnavailable)
        );

        owner.busy.set(true);
        assert_eq!(owner.storage_precredit_data(), Err(RuntimeError::OwnerBusy));
        owner.busy.set(false);
        assert_eq!(owner.storage_precredit_data(), Ok(()));
        assert_eq!(
            owner.original_fresh_query_custody_data(),
            Err(RuntimeError::OwnerUnavailable)
        );
    }
}

#[cfg(test)]
mod fresh_currency_tests {
    use super::*;
    use crate::node_contract::RuntimeError;
    use crucible_node_contract::U64;

    #[test]
    fn successful_final_callback_cannot_disarm_revoked_original_owner() {
        let owner = Rc::new(ReadOwner::new(U64::new(23)));
        let retained_result = Some(vec![4_u8, 5, 6]);
        let baseline = retained_result.clone();

        ReadCall::begin(Rc::clone(&owner)).unwrap().finish(true);
        assert_eq!(
            OriginalFreshQueryOwnerFence::new(Rc::clone(&owner)).complete(|| Ok(())),
            Ok(())
        );
        assert_eq!(owner.original_fresh_query_custody_data(), Ok(()));

        let call = ReadCall::begin(Rc::clone(&owner)).unwrap();
        let fence = OriginalFreshQueryOwnerFence::new(Rc::clone(&owner));
        call.finish(true);
        let called = Cell::new(false);
        let result = fence.complete(|| {
            called.set(true);
            owner.revoke();
            Ok(())
        });

        assert!(called.get());
        assert_eq!(result, Err(RuntimeError::OwnerUnavailable));
        assert!(!owner.busy.get());
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
        assert_eq!(retained_result, baseline);
        assert_eq!(owner.storage_precredit_data(), Ok(()));
        assert_eq!(
            owner.original_fresh_query_custody_data(),
            Err(RuntimeError::OwnerUnavailable)
        );
    }
}

// The capability check is shared by the actual owning-call recheck and its
// pure causal control. It does not clear busy, replace an owner or finish a call.
fn authenticate_armed_original_read(
    call: &ReadCall,
    owner: &Rc<ReadOwner>,
    fence: &OriginalFreshQueryOwnerFence,
) -> Result<(), crate::node_contract::RuntimeError> {
    use crate::node_contract::RuntimeError;
    if fence.process != std::process::id()
        || !Rc::ptr_eq(&call.owner, owner)
        || !fence
            .owner
            .as_ref()
            .is_some_and(|held| Rc::ptr_eq(held, owner))
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    if call.finished || fence.finished || !owner.busy.get() || !owner.current.get() {
        return Err(RuntimeError::OwnerUnavailable);
    }
    Ok(())
}

impl CnpSemanticSourceRead {
    /// Names additional owning-token recheck loans without changing idle guards.
    /// Names the actual borrowed original call and mutable scratch captures.
    pub(crate) fn original_fresh_query_callback_views_data() -> usize {
        std::mem::size_of::<&OriginalFreshQueryReadCall<'static>>()
            + std::mem::size_of::<&mut super::super::executable_guard::FreshCurrentScratch>()
    }

    pub(crate) fn original_fresh_query_armed_recheck_counter_scratch_data() -> usize {
        std::mem::size_of::<&ReadCall>()
            + std::mem::size_of::<Option<&ReadCall>>()
            + std::mem::size_of::<Result<&ReadCall, crate::node_contract::RuntimeError>>()
            + std::mem::size_of::<&OriginalFreshQueryOwnerFence>()
            + std::mem::size_of::<Option<&OriginalFreshQueryOwnerFence>>()
            + std::mem::size_of::<
                Result<&OriginalFreshQueryOwnerFence, crate::node_contract::RuntimeError>,
            >()
            + std::mem::size_of::<&Rc<ReadOwner>>()
            + std::mem::size_of::<Option<&Rc<ReadOwner>>>()
            + std::mem::size_of::<Result<(), crate::node_contract::RuntimeError>>()
    }
}

#[cfg(test)]
mod armed_original_read_tests {
    use super::*;
    use crate::node_contract::RuntimeError;

    #[test]
    fn active_same_owner_recheck_preserves_busy_and_refuses_foreign_revoked_and_finished() {
        let owner = Rc::new(ReadOwner::new(U64::new(71)));
        let foreign = Rc::new(ReadOwner::new(U64::new(71)));
        let call = ReadCall::begin(Rc::clone(&owner)).unwrap();
        let fence = OriginalFreshQueryOwnerFence::new(Rc::clone(&owner));

        authenticate_armed_original_read(&call, &owner, &fence).unwrap();
        assert!(owner.busy.get());
        assert!(!call.finished && !fence.finished);
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
        assert_eq!(
            owner.original_fresh_query_custody_data(),
            Err(RuntimeError::OwnerBusy)
        );
        authenticate_armed_original_read(&call, &owner, &fence).unwrap();
        assert!(authenticate_armed_original_read(&call, &foreign, &fence).is_err());
        let foreign_fence = OriginalFreshQueryOwnerFence::new(Rc::clone(&foreign));
        assert!(authenticate_armed_original_read(&call, &owner, &foreign_fence).is_err());
        let expired = OriginalFreshQueryOwnerFence {
            process: std::process::id(),
            owner: Some(Rc::clone(&owner)),
            finished: true,
        };
        assert!(authenticate_armed_original_read(&call, &owner, &expired).is_err());
        assert!(owner.busy.get());

        let finished_owner = Rc::new(ReadOwner::new(U64::new(72)));
        let mut finished_call = ReadCall::begin(Rc::clone(&finished_owner)).unwrap();
        let finished_fence = OriginalFreshQueryOwnerFence::new(Rc::clone(&finished_owner));
        // Private DATA state injection isolates the finished-bit branch while
        // the real owner is still busy/current; no native read is fabricated.
        finished_call.finished = true;
        assert!(
            authenticate_armed_original_read(&finished_call, &finished_owner, &finished_fence)
                .is_err()
        );
        assert!(finished_owner.busy.get());
        finished_call.finish(false);
        assert!(!finished_owner.busy.get());

        owner.revoke();
        assert!(authenticate_armed_original_read(&call, &owner, &fence).is_err());
        assert!(owner.busy.get());
        call.finish(false);
        assert!(!owner.busy.get());
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
        // Kernel/descriptor/registrar checks require a genuine native read and
        // are not manufactured by this DATA fixture. Production invokes those
        // checks between repeated calls to this same private token predicate.
    }
}
