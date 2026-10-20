//! Lends an original supervisor's actual incident owners under a bounded callback.
//!
//! The loan describes retained data. Current source, installed implementation and
//! signed factory checks remain separate; it grants no restoration authority.

use super::*;
use serde::{Serialize, Serializer};
use std::{
    cell::{Cell, RefCell},
    thread::ThreadId,
};

/// Retains the original creator and callback phases for one concrete supervisor.
///
/// Concrete source supervisors keep this beside their actual incident Vec. The
/// state has no portable constructor, serializer, clone or permission bit.
pub struct OriginalSupervisorState {
    creator: u32,
    thread: ThreadId,
    inspection_in_progress: Cell<bool>,
    callback_in_progress: Cell<bool>,
}

impl Default for OriginalSupervisorState {
    fn default() -> Self {
        Self::new()
    }
}

impl OriginalSupervisorState {
    /// Records the actual creating process and thread without allocating a bank.
    pub fn new() -> Self {
        Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            inspection_in_progress: Cell::new(false),
            callback_in_progress: Cell::new(false),
        }
    }

    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "original supervisor creator differs",
            ));
        }
        Ok(())
    }

    /// Lends the same actual incident Vec while rejecting callbacks or reentry.
    ///
    /// The immutable borrow and origin guards survive the entire inspection,
    /// including bounded serialization. Unwind releases only the inspection
    /// guard; the supervisor still owns its original Vec and every incident.
    ///
    /// # Errors
    /// Refuses a foreign creator, active callback/inspection or conflicting Vec
    /// borrow, and propagates inspection refusal without copying owners.
    pub fn with_original_incidents(
        &self,
        incidents: &RefCell<Vec<ConnectionIncident>>,
        inspect: &mut dyn FnMut(OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.callback_in_progress.get() || self.inspection_in_progress.get() {
            return Err(ProviderError::Conflict(
                "original supervisor callback active",
            ));
        }
        let incidents = incidents
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original supervisor incidents borrowed"))?;
        self.inspection_in_progress.set(true);
        let _inspection = ResetPhase(&self.inspection_in_progress);
        inspect(OriginalSupervisorProtocolView {
            state: self,
            incidents: &incidents,
        })
    }

    /// Brackets the concrete supervisor's actual quarantine callback phase.
    ///
    /// The caller retains an incoming incident outside any fallible entry until
    /// this guard is obtained, then transfers it to the same retained bank.
    ///
    /// # Errors
    /// Refuses another creator or any active inspection/quarantine callback.
    pub fn begin_quarantine_callback(
        &self,
    ) -> Result<OriginalSupervisorCallback<'_>, ProviderError> {
        self.ensure_origin()?;
        if self.inspection_in_progress.get() || self.callback_in_progress.get() {
            return Err(ProviderError::Conflict(
                "original supervisor callback active",
            ));
        }
        self.callback_in_progress.set(true);
        Ok(OriginalSupervisorCallback {
            _phase: ResetPhase(&self.callback_in_progress),
        })
    }
}

struct ResetPhase<'a>(&'a Cell<bool>);
impl Drop for ResetPhase<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// Retains the actual quarantine phase until its original callback exits.
#[must_use = "the original callback phase must remain guarded"]
pub struct OriginalSupervisorCallback<'a> {
    _phase: ResetPhase<'a>,
}

/// Borrows a concrete supervisor's actual retained Vec under its origin guard.
///
/// Fields cannot be assembled from decoded data or copied capacity claims. The
/// concrete measured implementation supplies its own original bank to the loan.
pub struct OriginalSupervisorProtocolView<'a> {
    state: &'a OriginalSupervisorState,
    incidents: &'a Vec<ConnectionIncident>,
}

impl OriginalSupervisorProtocolView<'_> {
    fn authenticate(&self) -> Result<(), ProviderError> {
        self.state.ensure_origin()?;
        if !self.state.inspection_in_progress.get() || self.state.callback_in_progress.get() {
            return Err(ProviderError::Conflict(
                "original supervisor loan phase changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate()?;
        observer.vector::<ConnectionIncident>(self.incidents.capacity())?;
        for incident in self.incidents {
            let ConnectionIncident {
                session,
                incarnation,
                connection,
                failure: _,
                transport_fenced,
                outgoing,
                incoming,
            } = incident;
            observer.observe(session)?;
            observer.observe(incarnation)?;
            observer.observe(connection)?;
            observer.observe(transport_fenced)?;
            observer.observe(outgoing)?;
            observer.observe(incoming)?;
        }
        Ok(())
    }
}

struct IncidentView<'a>(&'a ConnectionIncident);
impl Serialize for IncidentView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let incident = self.0;
        let failure = match incident.failure {
            ConnectionFailure::Read => "read",
            ConnectionFailure::Write => "write",
            ConnectionFailure::Protocol => "protocol",
            ConnectionFailure::Authority => "authority",
            ConnectionFailure::Closed => "closed",
        };
        (
            &incident.session,
            &incident.incarnation,
            &incident.connection,
            failure,
            incident.transport_fenced,
            &incident.outgoing,
            &incident.incoming,
        )
            .serialize(serializer)
    }
}

impl Serialize for OriginalSupervisorProtocolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.authenticate().map_err(serde::ser::Error::custom)?;
        let incidents =
            crate::protocol_snapshot::Sequence(|| self.incidents.iter().map(IncidentView));
        (
            "source-private.original-supervisor/11",
            self.state.creator,
            "same-original-thread",
            self.state.inspection_in_progress.get(),
            self.state.callback_in_progress.get(),
            (self.incidents.capacity(), incidents),
        )
            .serialize(serializer)
    }
}

/// Retains the exact installed supervisor and original controller actor.
///
/// This opaque witness supplies historical data only. Source custody retains it
/// beside the owning controller and independently authenticates the source path.
pub struct OriginalProtocolSupervisor {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    supervisor: Rc<dyn ConnectionSupervisor>,
}

// Name the actual callback working state so its fixed admission follows the
// same fields as the implementation rather than an estimated erased closure.
struct OriginalProtocolInspection<'a> {
    called: bool,
    original_error: Option<ProviderError>,
    inspect: &'a mut dyn FnMut(OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError>,
}

impl OriginalProtocolInspection<'_> {
    fn observe(&mut self, view: OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError> {
        if self.called {
            return Err(ProviderError::Conflict("supervisor inspection repeated"));
        }
        self.called = true;
        match (self.inspect)(view) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.original_error = Some(error);
                Err(ProviderError::Correlation("supervisor inspection refused"))
            }
        }
    }
}

impl OriginalProtocolSupervisor {
    /// Counts fixed witness retention and known-supervisor inspection working state.
    ///
    /// The actual witness contains aliases of already retained actor/supervisor
    /// allocations, not new heap ownership. This names its local/result headers,
    /// the actual callback state and capture, and the concrete retained family's
    /// incident/view/phase loans. Other supervisor implementations require their
    /// own independently admitted callback work. No witness or owner is created.
    pub const fn retention_counter_scratch_data() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Result<Self, ProviderError>>()
            + std::mem::size_of::<OriginalProtocolInspection<'static>>()
            + std::mem::size_of::<&mut OriginalProtocolInspection<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + OriginalRetainedSupervisor::retention_callback_counter_scratch_data()
    }

    /// Authenticates the actual operational handle retained beside this witness.
    ///
    /// This read-only identity check clones no owner and invokes no supervisor
    /// callback. It grants no connection, construction or execution authority.
    ///
    /// # Errors
    /// Refuses a changed creating process/thread or a different supervisor Rc.
    pub fn authenticate_original_operational_handle_data(
        &self,
        operational: &Rc<dyn ConnectionSupervisor>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        if !Rc::ptr_eq(&self.supervisor, operational) {
            return Err(ProviderError::Correlation(
                "original operational supervisor differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || !Rc::ptr_eq(&self.supervisor, &connection.supervisor)
        {
            return Err(ProviderError::Correlation(
                "original supervisor/controller differs",
            ));
        }
        Ok(())
    }

    /// Checks the same actor and supervisor after registration has been revoked.
    ///
    /// This raw association grants no live connection or callback authority.
    pub(crate) fn authenticate_original_connection_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.protocol_owner.ensure_current()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || !Rc::ptr_eq(&self.supervisor, &connection.supervisor)
        {
            return Err(ProviderError::Correlation(
                "raw original supervisor/controller differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_original_header(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::HostSupervisor,
            self.supervisor.as_ref(),
        )
    }

    pub(crate) fn observe_original_actor(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        observer.shared_value(self.actor.as_ref())
    }

    pub(crate) fn with_original_state(
        &self,
        inspect: &mut dyn FnMut(OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        let mut inspection = OriginalProtocolInspection {
            called: false,
            original_error: None,
            inspect,
        };
        let result = self
            .supervisor
            .with_original_protocol_state(&mut |view| inspection.observe(view));
        if let Some(error) = inspection.original_error {
            return Err(error);
        }
        result?;
        if !inspection.called {
            return Err(ProviderError::Correlation("supervisor inspection missing"));
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn retain_original_protocol_supervisor(
        &self,
    ) -> Result<OriginalProtocolSupervisor, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let witness = OriginalProtocolSupervisor {
            actor: Rc::clone(&self.protocol_owner),
            supervisor: Rc::clone(&self.supervisor),
        };
        witness.with_original_state(&mut |view| view.authenticate())?;
        Ok(witness)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "original loan ownership assertions")]
#[path = "supervisor_state_tests.rs"]
mod tests;

#[path = "retained_supervisor.rs"]
mod retained_supervisor;
pub use retained_supervisor::OriginalRetainedSupervisor;

#[cfg(test)]
mod operational_handle_tests {
    use super::*;

    #[test]
    fn original_operational_handle_refuses_foreign_rc_and_actor_without_owner_changes() {
        struct NeverCalled;

        impl ConnectionSupervisor for NeverCalled {
            fn quarantine(&self, _: ConnectionIncident) {
                panic!("identity inspection must not invoke supervisor callbacks");
            }
        }

        let operational: Rc<dyn ConnectionSupervisor> = Rc::new(NeverCalled);
        let foreign: Rc<dyn ConnectionSupervisor> = Rc::new(NeverCalled);
        let witness = OriginalProtocolSupervisor {
            actor: Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
            supervisor: Rc::clone(&operational),
        };
        let count = Rc::strong_count(&operational);
        let actor_count = Rc::strong_count(&witness.actor);

        assert!(
            witness
                .authenticate_original_operational_handle_data(&operational)
                .is_ok()
        );
        assert!(
            witness
                .authenticate_original_operational_handle_data(&foreign)
                .is_err()
        );
        assert_eq!(Rc::strong_count(&operational), count);
        assert_eq!(Rc::strong_count(&witness.actor), actor_count);
        assert!(Rc::ptr_eq(&witness.supervisor, &operational));

        let foreign_actor = std::thread::spawn(crate::protocol_snapshot::ProtocolCaptureOwner::new)
            .join()
            .unwrap();
        let foreign_witness = OriginalProtocolSupervisor {
            actor: Rc::new(foreign_actor),
            supervisor: Rc::clone(&operational),
        };
        assert!(
            foreign_witness
                .authenticate_original_operational_handle_data(&operational)
                .is_err()
        );
        assert!(Rc::ptr_eq(&foreign_witness.supervisor, &operational));
        assert_eq!(Rc::strong_count(&operational), count + 1);
    }
}

impl OriginalSupervisorState {
    /// Borrows actual historical phase data without changing the live state.
    ///
    /// The creator process is historical DATA. The Rust thread identity is an
    /// explicitly nonportable role, never a decoder input for a new owner.
    pub fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            creator,
            thread: _,
            inspection_in_progress,
            callback_in_progress,
        } = self;
        (
            "source-private.supervisor-phase-restored-settled/17",
            *creator,
            "nonportable-original-thread",
            inspection_in_progress.get(),
            callback_in_progress.get(),
        )
    }

    /// Names the fixed phase projection and its actual borrowed fields.
    pub fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<(&u32, &ThreadId, &Cell<bool>, &Cell<bool>)>()
            + std::mem::size_of::<(&str, u32, &str, bool, bool)>()
    }
}

impl OriginalProtocolSupervisor {
    pub(crate) fn authenticate_settled_history_parent_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || !Rc::ptr_eq(&self.supervisor, &connection.supervisor)
        {
            return Err(ProviderError::Correlation(
                "historical supervisor parent differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { actor, supervisor } = self;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            actor.as_ref(),
        )?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::HostSupervisor,
            supervisor.as_ref(),
        )
    }
}

pub(crate) use retained_supervisor::{
    ConnectionIncidentHistoryData, connection_incident_settled_history_data,
    observe_settled_connection_incident_metadata_data,
};

pub use retained_supervisor::RetainedSupervisorHistoricalData;

#[cfg(test)]
mod retention_working_state_tests {
    use super::*;

    #[test]
    fn actual_retained_inspection_preserves_first_error_and_refuses_repeated_callback() {
        let (operational, owner) = OriginalRetainedSupervisor::reserve().unwrap();
        let calls = Cell::new(0usize);
        let mut inspect = |view: OriginalSupervisorProtocolView<'_>| {
            view.authenticate()?;
            calls.set(calls.get() + 1);
            Err(ProviderError::Conflict("original retention refusal"))
        };
        let mut working = OriginalProtocolInspection {
            called: false,
            original_error: None,
            inspect: &mut inspect,
        };

        let refused = operational.with_original_protocol_state(&mut |view| working.observe(view));
        assert!(matches!(
            refused,
            Err(ProviderError::Correlation("supervisor inspection refused"))
        ));
        assert!(working.called);
        assert!(matches!(
            working.original_error.as_ref(),
            Some(ProviderError::Conflict("original retention refusal"))
        ));
        assert_eq!(calls.get(), 1);
        assert!(owner.is_empty_data().unwrap());

        // A second genuine view cannot repeat the callback or overwrite its
        // retained error; the real inspection phase is still released normally.
        let repeated = operational.with_original_protocol_state(&mut |view| working.observe(view));
        assert!(matches!(
            repeated,
            Err(ProviderError::Conflict("supervisor inspection repeated"))
        ));
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            working.original_error.as_ref(),
            Some(ProviderError::Conflict("original retention refusal"))
        ));
        assert!(owner.is_empty_data().unwrap());
    }
}
