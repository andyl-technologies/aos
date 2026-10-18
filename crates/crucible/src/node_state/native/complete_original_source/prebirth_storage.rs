//! Counts the same verified archive and its untouched archive-ticketed Host.
//!
//! Historical source identity and prebirth owner data confer no native, graph,
//! restoration or allocation authority. The fixed counter is separately named;
//! recursive observer/compiler frames and physical allocator peak are excluded.

use super::collecting::CollectingTargetPhase;
use super::*;
use crate::node_contract::HostSchedulingSource;

impl CompleteOriginalSource {
    pub(super) fn authenticate_collecting_prebirth_storage_phase(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        let CompleteOriginalSourcePurpose::Collecting { target, .. } = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        if !matches!(
            *target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?,
            CollectingTargetPhase::Unbound
        ) || self.target_started.get()
            || self
                .target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || !self.host_issued.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let owners = self.archive.owners();
        let issued = self.native_issued.get();
        let host = &self.host.selection_data().owner.owner.id;
        if owners.len() != issued.len() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut host_count = 0usize;
        for (index, row) in owners.iter().enumerate() {
            host_count += usize::from(&row.owner == host);
            if issued[index] != (&row.owner != host) {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        if host_count != 1 {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_birth()
    }
}

impl CompleteOriginalSource {
    /// Names the actual unbound/all-issued prebirth phase guard workspace.
    pub(super) fn collecting_prebirth_phase_counter_scratch_data() -> usize {
        use std::cell::Ref;
        use std::mem::size_of;

        size_of::<&Self>()
            + size_of::<&CompleteOriginalSourcePurpose>()
            + size_of::<Ref<'static, CollectingTargetPhase>>()
            + size_of::<Result<Ref<'static, CollectingTargetPhase>, std::cell::BorrowError>>()
            + size_of::<Ref<'static, Option<Rc<()>>>>()
            + size_of::<Result<Ref<'static, Option<Rc<()>>>, std::cell::BorrowError>>()
            + size_of::<&[NativeOwnerState]>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, NativeOwnerState>>>()
            + size_of::<(usize, &NativeOwnerState)>()
            + size_of::<&Id>()
            + size_of::<[bool; 4]>()
            + size_of::<usize>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl CompleteOriginalRestorationSource {
    /// Authenticates the exact unstarted collecting archive and fresh Host pair.
    ///
    /// All four tickets must already be issued while collecting remains Unbound.
    /// This origin-only check does not hash, allocate, call a policy or query a
    /// live runtime. It never starts or renews target binding or any ticket.
    ///
    /// # Errors
    /// Refuses foreign custody, ordinary/spent collecting phases, busy loans,
    /// missing ticket issuance or another/nonfresh archive-ticketed Host source.
    pub fn authenticate_original_prebirth_host_data(
        &self,
        host: &Rc<HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        self.inner
            .authenticate_collecting_prebirth_storage_phase()?;
        host.authenticate_archive_report_startup_data(&self.inner)?;
        self.inner.authenticate_collecting_prebirth_storage_phase()
    }

    /// Counts actual verified archive backing and its same fresh Host once.
    ///
    /// The actual source Rc/header, archive/content/admin/Host record/reference
    /// and retained weak Plan views use the existing concrete owning walker.
    /// The fresh Host Rc/header and its independent metadata clones are added;
    /// only its authenticated alias of this SAME source allocation is excluded.
    /// The actual three-usize local counter is included before observer work.
    /// Other caller roots and recursive/compiler frames remain separate terms.
    ///
    /// # Errors
    /// Refuses a changed/foreign/busy pair or any unsupported owner, checked
    /// overflow, or a total beyond `maximum`. Failure retains original owners.
    pub fn retained_original_prebirth_storage_data(
        &self,
        host: &Rc<HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_prebirth_host_data(host)?;
        let mut parts = [0usize; 3];
        if std::mem::size_of_val(&parts) > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        parts[0] = std::mem::size_of_val(&parts);
        parts[1] = self.inner.capture_owned_storage()?;
        parts[2] = host.retained_archive_prebirth_host_storage_data(&self.inner, maximum)?;
        parts[0] = parts[0]
            .checked_add(parts[1])
            .and_then(|n| n.checked_add(parts[2]))
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.authenticate_original_prebirth_host_data(host)?;
        Ok(parts[0])
    }
}

impl CompleteOriginalRestorationSource {
    /// Counts the genuine current17 archive before its Host source exists.
    ///
    /// The actual once-issued Host ticket and all three native tickets must
    /// still belong to this unbound collecting Source. The walk includes the
    /// completed cold collection and every retained decoder/ancestry owner;
    /// it performs no currentness callback or native effect.
    ///
    /// # Errors
    /// Refuses foreign ticket/source identity, another family, missing original
    /// issuance, started target binding, busy ownership or the supplied bound.
    pub fn retained_original_host17_preconstruction_storage_data(
        &self,
        ticket: &CompleteOriginalHostTicket,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.inner
            .authenticate_collecting_prebirth_storage_phase()?;
        ticket.authenticate_birth()?;
        if !Rc::ptr_eq(&self.inner, &ticket.source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        ticket.restored_record_data()?;
        let bytes = self.inner.capture_owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.inner
            .authenticate_collecting_prebirth_storage_phase()?;
        Ok(bytes)
    }

    /// Names actual Source, archive, content and cold-collection owning counters.
    ///
    /// Archive Manifest, administrative journal and Host record visits share the
    /// same defining closed typed roster. Their sequential walks never replace
    /// the separately named content, checkpoint or cold-decoder owner counters.
    pub fn original_host17_preconstruction_counter_scratch_data() -> usize {
        use crate::node_contract::HostSchedulingRestoredContinuationRecord17;
        use crucible_node_provider::protocol_snapshot::restored_settled17::RestoredSettledNativeImportGeometryData;
        use std::cell::Ref;
        use std::mem::size_of;

        CompleteOriginalSource::collecting_prebirth_phase_counter_scratch_data()
            + NativeArchiveRecord::original_archive_owned_counter_scratch_data()
            + VerifiedStateContent::capture_owned_counter_scratch_data()
            + Self::historical_coordinator_checkpoint17_counter_scratch_data()
            + RetainedCold17Collection::retained_counter_scratch_data()
            + CompleteOriginalSource::original_target_plan_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CompleteOriginalSource>()
            + size_of::<(&Rc<CompleteOriginalSource>, &Rc<CompleteOriginalSource>)>()
            + size_of::<&CompleteOriginalHostTicket>()
            + size_of::<&CompleteOriginalSourcePurpose>()
            + size_of::<&host_record::CompleteHostArchiveRecord>()
            + size_of::<&HostSchedulingRestoredContinuationRecord17>()
            // Census/wrapper totals and ceiling coexist with Host root/backing.
            + size_of::<[usize; 3]>()
            + size_of::<(usize, usize)>()
            + size_of::<Ref<'static, Option<Rc<()>>>>()
            + size_of::<Ref<'static, CollectingTargetPhase>>()
            + size_of::<Ref<'static, Option<RetainedCold17Collection>>>()
            + size_of::<Result<Ref<'static, Option<Rc<()>>>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, CollectingTargetPhase>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, Option<RetainedCold17Collection>>, std::cell::BorrowError>>()
            + size_of::<Option<&RetainedCold17Collection>>()
            + size_of::<&[NativeOwnerState]>()
            + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, NativeOwnerState>>>()
            + size_of::<(usize, &NativeOwnerState)>()
            + size_of::<&NativeOwnerState>()
            + size_of::<[bool; 4]>()
            + size_of::<&Id>()
            + size_of::<std::iter::Flatten<std::slice::Iter<
                'static,
                Option<CompleteRestoredSettledNativeRestorationData>,
            >>>()
            + size_of::<&CompleteRestoredSettledNativeRestorationData>()
            + size_of::<&RestoredSettledNativeImportGeometryData>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<Result<&HostSchedulingRestoredContinuationRecord17, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<usize, crucible_node_provider::ProviderError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
    }
}

impl CompleteOriginalRestorationSource {
    /// Counts the actual current17 Source output, including a refused prebirth.
    ///
    /// The Source must come from its genuine completed signed load. Ticket
    /// issuance may be absent, partial or complete; these immutable backing and
    /// once ledgers are observed without renewing that phase. The count excludes
    /// this borrowed wrapper header, already inline in the caller's output slot.
    ///
    /// # Errors
    /// Refuses foreign custody, another historical family, busy nested ownership,
    /// checked overflow or actual retained backing above `maximum`.
    pub fn retained_restored_settled_prebirth_output_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.restored_host_record_data()?;
        let bytes = self.inner.capture_owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.restored_host_record_data()?;
        Ok(bytes)
    }
}
