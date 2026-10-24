//! Owns the closed retention-only supervisor used by original host preparations.
//!
//! The erased operational callback and the direct metadata handle share the same
//! concrete Rc. Generic supervisors retain their existing unsupported boundary.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};

const INCIDENT_CAPACITY: usize = 1024;

struct RetainedSupervisor {
    incidents: RefCell<Vec<ConnectionIncident>>,
    state: OriginalSupervisorState,
    pending: RefCell<Option<ConnectionIncident>>,
}

/// Retains the actual SDK-owned incident supervisor without an erased data callback.
///
/// This owner has no decoder, clone or portable constructor. It supplies data
/// coverage for the retention-only family, not reconciliation or native custody.
pub struct OriginalRetainedSupervisor {
    supervisor: Rc<RetainedSupervisor>,
}

impl OriginalRetainedSupervisor {
    /// Reports the fixed requested bank, concrete shared owner and handle storage.
    ///
    /// This layout data precedes reservation and grants no allocation permission.
    /// Shared headers use the selected Rust 1.98.1 Rc requested-layout contract
    /// and actual concrete payload alignment. This excludes allocator and
    /// compiler/recursive stack overhead. Actual allocator capacity remains
    /// part of the retained observation.
    ///
    /// # Errors
    /// Refuses checked layout overflow.
    pub fn reservation_requested_bytes() -> Result<usize, ProviderError> {
        let shared_header =
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RetainedSupervisor>(),
            )?;
        std::mem::size_of::<ConnectionIncident>()
            .checked_mul(INCIDENT_CAPACITY)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RetainedSupervisor>()))
            .and_then(|bytes| bytes.checked_add(shared_header))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Rc<dyn ConnectionSupervisor>>())
            })
            .ok_or(ProviderError::ResourceExhausted(
                "original supervisor layout overflow",
            ))
    }

    /// Reports explicit observer, result, bank, view and phase header scratch.
    ///
    /// The caller admits these headers before observing actual backing. Compiler
    /// call frames, recursion, allocator and physical overhead remain separate.
    pub const fn metadata_counter_scratch_data() -> usize {
        std::mem::size_of::<MetadataObserver<'static>>()
            + std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + std::mem::size_of::<std::cell::Ref<'static, Vec<ConnectionIncident>>>()
            + std::mem::size_of::<OriginalSupervisorProtocolView<'static>>()
            + std::mem::size_of::<ResetPhase<'static>>()
            + std::mem::size_of::<std::cell::Ref<'static, Option<ConnectionIncident>>>()
    }

    // Retention invokes the real callback wrapper, whereas the ordinary direct
    // metadata walk above deliberately invokes no erased callback. Keep their
    // fixed working views separate so old metadata quotes retain their meaning.
    pub(super) const fn retention_callback_counter_scratch_data() -> usize {
        Self::metadata_counter_scratch_data()
            + std::mem::size_of::<&RetainedSupervisor>()
            + std::mem::size_of::<
                &mut dyn FnMut(
                    OriginalSupervisorProtocolView<'static>,
                ) -> Result<(), ProviderError>,
            >()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }

    /// Observes the actual known retained supervisor before a connection exists.
    ///
    /// Charges its real shared payload/header view and actual incident bank
    /// capacity. The enclosing owner handle is counted by its containing holder.
    /// This invokes no erased callback, serializer, allocation or I/O and grants
    /// no budget, source association or installed-controller authority.
    ///
    /// # Errors
    /// Refuses foreign origin, an active/incomplete callback or inspection,
    /// conflicting loans or bounded metadata traversal exhaustion.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_retained_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    /// Constructs the fixed incident bank and its same-concrete operational handle.
    ///
    /// The caller admits this allocation before construction. The returned erased
    /// handle must be installed on the actual controller; equality is checked
    /// before the controller's direct metadata observer visits any fields.
    ///
    /// # Errors
    /// Refuses an unavailable fixed incident-bank reservation.
    pub fn reserve() -> Result<(Rc<dyn ConnectionSupervisor>, Self), ProviderError> {
        let mut incidents = Vec::new();
        incidents
            .try_reserve_exact(INCIDENT_CAPACITY)
            .map_err(|_| ProviderError::ResourceExhausted("original incident bank reservation"))?;
        let supervisor = Rc::new(RetainedSupervisor {
            incidents: RefCell::new(incidents),
            state: OriginalSupervisorState::new(),
            pending: RefCell::new(None),
        });
        let operational: Rc<dyn ConnectionSupervisor> = supervisor.clone();
        Ok((operational, Self { supervisor }))
    }

    /// Reports whether the same retained bank and partial callback slot are empty.
    ///
    /// # Errors
    /// Refuses a foreign creator, conflicting borrow or active callback/inspection.
    pub fn is_empty_data(&self) -> Result<bool, ProviderError> {
        self.supervisor.check_idle()?;
        let incidents = self
            .supervisor
            .incidents
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original supervisor incidents borrowed"))?;
        Ok(incidents.is_empty())
    }

    pub(crate) fn authenticate<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        self.supervisor.check_idle()?;
        if !std::ptr::addr_eq(
            Rc::as_ptr(&self.supervisor),
            Rc::as_ptr(&connection.supervisor),
        ) {
            return Err(ProviderError::Correlation(
                "original retained supervisor differs",
            ));
        }
        Ok(())
    }

    /// Checks the concrete retained association without renewing effect authority.
    pub(crate) fn authenticate_original_connection_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        self.authenticate_original_handle_data(&connection.supervisor)
    }

    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { supervisor } = self;
        supervisor.check_idle()?;
        let RetainedSupervisor {
            incidents,
            state,
            pending: _,
        } = supervisor.as_ref();
        let incidents = incidents
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original supervisor incidents borrowed"))?;
        observer.shared_original(MetadataSharedKind::HostSupervisor, supervisor.as_ref())?;
        state.inspection_in_progress.set(true);
        let _inspection = ResetPhase(&state.inspection_in_progress);
        OriginalSupervisorProtocolView {
            state,
            incidents: &incidents,
        }
        .observe_owned11_metadata(observer)?;
        // No external callback runs inside this loan; pending must still be empty.
        supervisor.check_pending()
    }
}

impl RetainedSupervisor {
    fn check_pending(&self) -> Result<(), ProviderError> {
        if self
            .pending
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original incident callback borrowed"))?
            .is_some()
        {
            return Err(ProviderError::Conflict(
                "original incident callback incomplete",
            ));
        }
        Ok(())
    }

    fn check_idle(&self) -> Result<(), ProviderError> {
        self.state.ensure_origin()?;
        if self.state.inspection_in_progress.get() || self.state.callback_in_progress.get() {
            return Err(ProviderError::Conflict(
                "original supervisor callback active",
            ));
        }
        self.check_pending()
    }
}

impl ConnectionSupervisor for RetainedSupervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        // Origin is checked before even borrowing another creator's state.
        if self.state.ensure_origin().is_err() {
            panic!("original incident creator differs");
        }
        // The trait cannot return a refusal. Preserve the incoming owner before
        // phase/capacity checks; a caught panic leaves the partial owner visible.
        let mut pending = self.pending.borrow_mut();
        assert!(pending.is_none(), "original incident callback cannot renew");
        *pending = Some(incident);
        let _callback = match self.state.begin_quarantine_callback() {
            Ok(callback) => callback,
            Err(_) => panic!("original incident callback phase refused"),
        };
        let mut incidents = self.incidents.borrow_mut();
        assert!(
            incidents.len() < INCIDENT_CAPACITY,
            "fixed original incident credit"
        );
        if let Some(incident) = pending.take() {
            incidents.push(incident);
        }
    }

    fn with_original_protocol_state(
        &self,
        inspect: &mut dyn FnMut(OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.check_idle()?;
        self.state
            .with_original_incidents(&self.incidents, &mut |view| {
                let result = inspect(view);
                self.check_pending()?;
                result
            })
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual retained supervisor ownership assertions"
)]
mod tests {
    use super::*;

    fn incident() -> ConnectionIncident {
        ConnectionIncident {
            session: Id::new("session").unwrap(),
            incarnation: Id::new("incarnation").unwrap(),
            connection: Id::new("connection").unwrap(),
            failure: ConnectionFailure::Protocol,
            transport_fenced: false,
            outgoing: Vec::with_capacity(3),
            incoming: Vec::with_capacity(5),
        }
    }

    #[test]
    fn same_concrete_operational_handle_retains_real_incident_capacities() {
        let (operational, owner) = OriginalRetainedSupervisor::reserve().unwrap();
        assert!(std::ptr::addr_eq(
            Rc::as_ptr(&operational),
            Rc::as_ptr(&owner.supervisor)
        ));
        assert!(owner.is_empty_data().unwrap());
        operational.quarantine(incident());
        assert!(!owner.is_empty_data().unwrap());

        let mut observer = MetadataObserver::new();
        owner.observe_retained_metadata(&mut observer).unwrap();
        let facts = observer.finish();
        assert!(
            facts.vector_capacity_bytes
                >= INCIDENT_CAPACITY * std::mem::size_of::<ConnectionIncident>()
        );
        let originals = owner.supervisor.incidents.borrow();
        assert_eq!(originals[0].outgoing.capacity(), 3);
        assert_eq!(originals[0].incoming.capacity(), 5);
    }

    #[test]
    fn inspection_reentry_retains_partial_incident_and_refuses_complete_observation() {
        let (operational, owner) = OriginalRetainedSupervisor::reserve().unwrap();
        let result = operational.with_original_protocol_state(&mut |_| {
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                operational.quarantine(incident());
            }));
            assert!(refused.is_err());
            Ok(())
        });
        assert!(result.is_err());
        assert!(owner.supervisor.pending.borrow().is_some());
        assert!(owner.is_empty_data().is_err());
        assert!(
            owner
                .observe_retained_metadata(&mut MetadataObserver::new())
                .is_err()
        );
    }

    #[test]
    fn foreign_concrete_handle_cannot_match_installed_retention_owner() {
        let (installed, owner) = OriginalRetainedSupervisor::reserve().unwrap();
        let (foreign, _) = OriginalRetainedSupervisor::reserve().unwrap();
        assert!(std::ptr::addr_eq(
            Rc::as_ptr(&installed),
            Rc::as_ptr(&owner.supervisor)
        ));
        assert!(!std::ptr::addr_eq(
            Rc::as_ptr(&foreign),
            Rc::as_ptr(&owner.supervisor)
        ));
        assert!(OriginalRetainedSupervisor::reservation_requested_bytes().unwrap() > 0);
    }
    #[test]
    fn foreign_creator_refuses_before_mutating_pending_or_incident_bank() {
        let (operational, mut owner) = OriginalRetainedSupervisor::reserve().unwrap();
        drop(operational);
        Rc::get_mut(&mut owner.supervisor).unwrap().state.creator =
            std::process::id().wrapping_add(1);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.supervisor.quarantine(incident());
        }));
        assert!(refused.is_err());
        assert!(owner.supervisor.pending.borrow().is_none());
        assert!(owner.supervisor.incidents.borrow().is_empty());
    }
}

impl OriginalRetainedSupervisor {
    pub(crate) fn authenticate_original_handle_data(
        &self,
        operational: &Rc<dyn ConnectionSupervisor>,
    ) -> Result<(), ProviderError> {
        self.supervisor.check_idle()?;
        if !std::ptr::addr_eq(Rc::as_ptr(&self.supervisor), Rc::as_ptr(operational)) {
            return Err(ProviderError::Correlation(
                "original host startup supervisor differs",
            ));
        }
        Ok(())
    }
}

#[path = "retained_supervisor_settled.rs"]
mod settled;
pub use settled::RetainedSupervisorHistoricalData;
pub(crate) use settled::{
    ConnectionIncidentHistoryData, connection_incident_settled_history_data,
    observe_settled_connection_incident_metadata_data,
};
