//! Observes the actual preparation before fresh-query ownership is constructed.
//!
//! The fixed identity bank is caller-owned scratch. Data observations do not
//! renew process currentness, invoke semantic authentication or admit a Query.
//! Source, SDK and installed owners retain their own typed observer obligations.

use std::{
    cell::{RefCell, RefMut},
    mem::size_of,
    thread::ThreadId,
};

use crucible_node_provider::{
    connection::OriginalRetainedSupervisor, handshake::OriginalExtensionRegistryOwner,
    retained_metadata::RetainedCommonProtocolData,
};

use crate::node_contract::RuntimeError;

use super::{super::CnpSemanticPreparation, CnpRetainedStorageReport};

mod counter;
pub(in crate::node_adapters::cnp::semantic) use counter::{PreparationCounter, metadata_failure};

/// Owns the fixed traversal bank for one synchronous preparation observation.
///
/// The creator allocates this value before admitting the observer window. Its
/// actual inline extent is a separate simultaneous term beside the preparation,
/// recursive SDK observer frames and any installed owner's declared scratch.
/// It retains no process, Source, SDK owner or allocation permission.
pub struct CnpPreparationStorageScratch {
    process: u32,
    thread: ThreadId,
    counter: RefCell<PreparationCounter>,
}

impl CnpPreparationStorageScratch {
    /// Returns the actual fixed scratch layout, including its borrow and origin fields.
    pub const fn requested_bytes() -> usize {
        size_of::<Self>()
    }

    /// Constructs fixed scratch within an independently admitted scratch allowance.
    ///
    /// This performs no heap allocation or process operation. The caller still
    /// accounts for its actual storage placement and compiler traversal frames.
    ///
    /// # Errors
    /// Returns `ResourceLimit` before constructing the bank if its actual layout
    /// exceeds the supplied scratch allowance.
    pub fn new(maximum_scratch_bytes: usize) -> Result<Self, RuntimeError> {
        if Self::requested_bytes() > maximum_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            counter: RefCell::new(PreparationCounter::new(0)),
        })
    }

    fn loan(&self, maximum: usize) -> Result<CounterLoan<'_>, RuntimeError> {
        // A fork-inherited bank must not touch thread-local state or a RefCell.
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let mut counter = self
            .counter
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        counter.reset(maximum);
        Ok(CounterLoan(counter))
    }
}

struct CounterLoan<'a>(RefMut<'a, PreparationCounter>);

impl Drop for CounterLoan<'_> {
    fn drop(&mut self) {
        self.0.reset(0);
    }
}

impl CnpSemanticPreparation {
    /// Observes this preparation's actual guard, SDK and independent response owners.
    ///
    /// Checks raw process and original executable thread custody before borrowing
    /// scratch, SDK journals or installed owners. It counts the preparation root
    /// once, then its separately owned Discover/Realize heaps and actual boxed
    /// process/slot owners. Equal response contents receive no alias discount.
    ///
    /// Supply only a previously retained registry owner from this same original
    /// handshake. `None` leaves an erased extension callback explicitly unknown;
    /// this method never constructs a registry owner or invokes reauthentication.
    /// A known supervisor loan must be the non-cloneable owner retained by the
    /// actual connection constructor. Its callback-free SDK observer verifies
    /// the same installed Rc. The caller separately counts that owner's inline
    /// handle in its actual containing holder; this borrowed loan is not a new
    /// owning row. Missing typed ownership keeps an erased witness unresolved.
    ///
    /// The typed callbacks must observe backing without formatting errors,
    /// serialization, I/O, currentness renewal or heap allocation. Legacy
    /// `OperationFailure` observers are deliberately not called by this path.
    ///
    /// The caller separately quotes the fixed SDK headers through
    /// `CnpController::original_restoration_host_metadata_counter_scratch_data()` and
    /// the actual Source/installed owner scratch before entering this walk.
    ///
    /// The result excludes this scratch bank, installed nested observer scratch,
    /// compiler frames, allocator rounding and kernel/native ownership. Query
    /// quotes/owners and their controller growth remain separately observed
    /// prospective or retained rows. This result grants no Fresh or Core rights.
    ///
    /// # Errors
    /// Refuses foreign origins, busy scratch/owner loans, active or populated semantic
    /// runtime custody, inconsistent SDK originals, unsupported typed storage or checked
    /// storage/traversal bounds. Partial reports retain all unresolved owners.
    pub fn retained_requested_storage_precredit_data(
        &self,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.retained_storage_selected_precredit_data(scratch, registry, supervisor, None, maximum)
    }

    /// Observes preparation owners beneath the same closed initial Source phase.
    ///
    /// The caller supplies each preparation's actual original roster Source.
    /// Its exact Rc/root and every existing initial Source owner are counted;
    /// an absent input-static allocation grants no Input or Capture rights.
    /// Ordinary preparation observation keeps its strict complete-source walk.
    ///
    /// # Errors
    /// Refuses a foreign Source allocation or any ordinary origin, typed-owner,
    /// scratch, metadata or requested-storage failure.
    pub fn retained_initial_lifecycle_requested_storage_precredit_data(
        &self,
        source: &std::rc::Rc<super::super::PacketCompleteSemanticSource>,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.retained_storage_selected_precredit_data(
            scratch,
            registry,
            supervisor,
            Some(source),
            maximum,
        )
    }

    fn retained_storage_selected_precredit_data(
        &self,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        initial_source: Option<&std::rc::Rc<super::super::PacketCompleteSemanticSource>>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.guard.preparation_storage_origin_precredit_data()?;
        let mut loan = scratch.loan(maximum)?;
        let counter = &mut *loan.0;
        let Self {
            guard,
            discovery,
            realization,
        } = self;

        counter.add(size_of::<Self>())?;
        charge_responses(discovery, realization, counter)?;
        match initial_source {
            Some(source) => guard.charge_initial_lifecycle_retained_storage_precredit_data(
                registry, supervisor, source, counter,
            )?,
            None => guard.charge_retained_storage_precredit_data(registry, supervisor, counter)?,
        }
        guard.preparation_storage_origin_precredit_data()?;
        Ok(counter.finish())
    }
}

/// Visits each independently owned response once, without an SDK journal alias.
pub(in crate::node_adapters::cnp::semantic) fn charge_responses(
    discovery: &crucible_node_provider::bodies::DiscoverResult,
    realization: &crucible_node_provider::bodies::RealizeResult,
    counter: &mut PreparationCounter,
) -> Result<(), RuntimeError> {
    for value in [
        RetainedCommonProtocolData::Discover(discovery),
        RetainedCommonProtocolData::Realize(realization),
    ] {
        counter.metadata(
            &value
                .observe_retained_metadata()
                .map_err(metadata_failure)?,
        )?;
    }
    Ok(())
}

impl CnpRetainedStorageReport {
    /// Returns a complete data sum with an allocation-free refusal representation.
    ///
    /// # Errors
    /// Returns `UnsupportedFacet` if any actual backing owner is unresolved.
    /// A complete sum supplies no process currentness or allocation permission.
    pub fn complete_requested_bytes_precredit_data(&self) -> Result<usize, RuntimeError> {
        if !self.unknowns.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(self.known_requested_bytes)
    }
}

#[cfg(test)]
mod tests;

impl crate::node_adapters::cnp::semantic::CnpSemanticConformanceNode {
    /// Observes this same inactive node and its independently boxed preparation.
    ///
    /// The fixed scratch and nested Source/SDK counters remain caller terms.
    /// This raw owning walk accepts only the closed dormant common-custody
    /// state. It grants no graph, currentness, activation or operation right.
    ///
    /// # Errors
    /// Refuses foreign or busy custody, populated runtime state, unknown owning
    /// leaves or checked storage beyond the ceiling.
    pub fn retained_requested_storage_precredit_data(
        &self,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.0
            .original_retained_node_precredit_data(scratch, registry, supervisor, maximum)
    }

    /// Counts the same node's retained process and protocol descriptor views.
    ///
    /// # Errors
    /// Refuses unknown, foreign, busy or populated custody without granting use.
    pub fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.0
            .preparation
            .retained_descriptor_views_precredit_data()
    }
}

impl crate::node_adapters::cnp::semantic::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn original_retained_node_precredit_data(
        &self,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        self.original_retained_node_selected_precredit_data(
            scratch, registry, supervisor, None, maximum,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_retained_node_selected_precredit_data(
        &self,
        scratch: &CnpPreparationStorageScratch,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        initial_source: Option<&std::rc::Rc<super::super::PacketCompleteSemanticSource>>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        use crate::node_contract::RuntimeOwnedStorage;
        let Self {
            preparation: _,
            route: _,
            exact_profile: _,
            affinity: _,
            retained_registry: _,
            retained_supervisor: _,
            retained_operational: _,
        } = self;
        let node = self;
        node.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        let registry = registry.or(node.retained_registry.as_ref());
        let supervisor = supervisor.or(node.retained_supervisor.as_ref());
        if let Some(operational) = &node.retained_operational {
            let native = node
                .preparation
                .guard
                .custody
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let witness = native
                .protocol_supervisor
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            witness
                .as_ref()
                .ok_or(RuntimeError::ForeignAuthority)?
                .authenticate_original_operational_handle_data(operational)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        let mut loan = scratch.loan(maximum)?;
        let counter = &mut *loan.0;
        counter.add(size_of::<Self>())?;
        counter.add(size_of::<CnpSemanticPreparation>())?;
        counter.add(node.route.owned_storage()?)?;
        counter.add(node.exact_profile.allocated_capacity())?;
        charge_responses(
            &node.preparation.discovery,
            &node.preparation.realization,
            counter,
        )?;
        match initial_source {
            Some(source) => node
                .preparation
                .guard
                .charge_initial_lifecycle_retained_storage_precredit_data(
                    registry, supervisor, source, counter,
                )?,
            None => node
                .preparation
                .guard
                .charge_retained_storage_precredit_data(registry, supervisor, counter)?,
        }
        node.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        Ok(counter.finish())
    }
}
