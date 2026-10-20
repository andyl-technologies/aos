//! Observes actual launched custody before its initial protocol lifecycle.
//!
//! The same typed preparation walker counts these private owners. A live guard
//! is never treated as empty launch storage; unsupported slot/SDK/source leaves
//! keep their original Unknown flags and refuse a complete requested-byte row.

use std::mem::size_of;

use crucible_node_transport::{
    connection::OriginalRetainedSupervisor, handshake::OriginalExtensionRegistryOwner,
};

use super::CnpSemanticLaunchGuard;
use crate::{
    node_adapters::cnp::semantic::retained_storage::preparation::PreparationCounter,
    node_contract::RuntimeError,
};

impl CnpSemanticLaunchGuard {
    /// Counts the concrete fixed bank used by the raw launched-guard observer.
    ///
    /// SDK and installed Source nested observer headers, compiler frames,
    /// allocator physical overhead and kernel resources remain separate terms.
    pub const fn original_initial_lifecycle_storage_counter_scratch_data() -> usize {
        size_of::<PreparationCounter>()
            + size_of::<Option<&OriginalExtensionRegistryOwner>>()
            + size_of::<Option<&OriginalRetainedSupervisor>>()
            // The initial preparation walk also lends its exact roster Source.
            + size_of::<Option<&std::rc::Rc<super::super::PacketCompleteSemanticSource>>>()
            + super::CnpSemanticLaunchReservation::unlaunched_descriptor_counter_scratch_data()
    }

    /// Counts the same actual launched process, slot and retained protocol owners.
    ///
    /// This performs only the existing typed owning-data walk. It does not
    /// renew executable/kernel/Source currentness or invoke a legacy formatted
    /// callback. Before attachment the independently owned SDK is observed by
    /// its own holder: its supervisor loan is not assigned to an empty guard.
    /// Once attached, the direct known supervisor and actual registry must
    /// correspond to that same real controller and handshake.
    ///
    /// Callers admit the fixed bank and all nested observers before entering.
    /// The result includes this actual guard's inline root and its independent
    /// boxed custody and slot storage, with the walk's real identity dedup.
    ///
    /// # Errors
    /// Refuses foreign or busy origins, active or populated runtime custody, unavailable
    /// typed owners, unsupported erased callbacks or a complete row above the
    /// requested ceiling. A live or partial guard is never silently omitted.
    pub fn original_initial_lifecycle_retained_storage_precredit_data(
        &self,
        registry: Option<&OriginalExtensionRegistryOwner>,
        supervisor: Option<&OriginalRetainedSupervisor>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.preparation_storage_origin_precredit_data()?;
        let custody = self
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attached = custody.controller.is_some();
        if !attached && registry.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }

        let mut counter = PreparationCounter::new(maximum);
        counter.add(size_of::<Self>())?;
        self.charge_retained_storage_precredit_data(
            registry,
            if attached { supervisor } else { None },
            &mut counter,
        )?;
        let complete = counter.finish().complete_requested_bytes_precredit_data()?;
        self.preparation_storage_origin_precredit_data()?;
        Ok(complete)
    }
}

impl CnpSemanticLaunchGuard {
    /// Counts actual selected process, executable, control and slot descriptors.
    ///
    /// Source, authority, policy, group and supervisor owners are separate
    /// concrete holder/Source rows. No descriptor is inferred from heap bytes.
    /// Aliased actual views are conservatively counted without dedup refunds.
    ///
    /// # Errors
    /// Refuses foreign or unknown slots, legacy Child streams, opaque executable
    /// workers, unsupported controller families or checked-count overflow.
    pub fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.preparation_storage_origin_precredit_data()?;
        let native = self
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if native.child.is_some() || native.rejected_control.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut total = self
            .slot
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_descriptor_views_precredit_data()?
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if let Some(child) = &native.original_child {
            total = total
                .checked_add(child.retained_descriptor_views_precredit_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(executable) = &native.executable_guard {
            total = total
                .checked_add(executable.retained_descriptor_views_precredit_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(controller) = &native.controller {
            total = total
                .checked_add(
                    controller
                        .retained_descriptor_count_data()
                        .map_err(|_| RuntimeError::ForeignAuthority)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        self.preparation_storage_origin_precredit_data()?;
        Ok(total)
    }
}

impl super::CnpSemanticLaunchReservation {
    /// Counts actual descriptors in the same retained original reservation.
    ///
    /// # Errors
    /// Refuses a foreign, busy, unsupported or transferred custody row. An
    /// unattempted selected reservation uses its exact empty-phase census;
    /// attempted or authenticated custody keeps the launched guard's checks.
    pub fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        if self.original_host_startup_unlaunched_data() {
            return self.unlaunched_descriptor_views_precredit_data();
        }
        self.original_host_startup_guard_data()
            .retained_descriptor_views_precredit_data()
    }
}

impl crate::node_adapters::cnp::CnpSemanticPreparation {
    /// Counts the actual guard-owned descriptors after its input slots move.
    ///
    /// # Errors
    /// Refuses foreign, busy, unknown or unsupported retained custody.
    pub fn retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        self.guard.retained_descriptor_views_precredit_data()
    }
}

impl CnpSemanticLaunchGuard {
    /// Counts the closed selected currentness phase's temporary descriptors.
    ///
    /// fresh_fences retains its opened current executable while its terminal
    /// ensure_fresh_current retains a stat File and opens the proc directory.
    /// Those three actual descriptors coexist. The private-host executable
    /// check opens one descriptor in a separate phase and fits this ceiling.
    pub const fn original_initial_lifecycle_transient_descriptor_data() -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::{
        CnpSemanticLaunchReservation, CnpSemanticProcessCustody, CnpSemanticProcessSlot,
    };
    use crucible_node_format::{U64, canonical};
    use std::{cell::Cell, os::unix::net::UnixStream, path::PathBuf, rc::Rc};

    struct SocketSlot {
        socket: UnixStream,
        dropped: Rc<Cell<bool>>,
    }

    impl Drop for SocketSlot {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl CnpSemanticProcessSlot for SocketSlot {
        fn identity(&self) -> U64 {
            U64::new(2001)
        }

        fn retain(&mut self, _: CnpSemanticProcessCustody) {
            panic!("data-only controls must not create or transfer Child");
        }

        fn retained_descriptor_views_precredit_data(&self) -> Result<Option<usize>, RuntimeError> {
            use std::os::fd::AsRawFd;
            assert!(self.socket.as_raw_fd() >= 0);
            Ok(Some(1))
        }
    }

    struct UnknownSocketSlot {
        _socket: UnixStream,
        dropped: Rc<Cell<bool>>,
    }

    impl Drop for UnknownSocketSlot {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl CnpSemanticProcessSlot for UnknownSocketSlot {
        fn identity(&self) -> U64 {
            U64::new(2002)
        }

        fn retain(&mut self, _: CnpSemanticProcessCustody) {
            panic!("unknown data must not transfer Child");
        }
    }

    fn reservation(slot: Box<dyn CnpSemanticProcessSlot>) -> CnpSemanticLaunchReservation {
        CnpSemanticLaunchReservation::reserve_original_native_startup(
            PathBuf::from("/tmp/aos-initial-lifecycle-unlaunched-data"),
            canonical::content_ref(
                b"actual declared unlaunched executable",
                "application/octet-stream",
            )
            .unwrap(),
            slot,
        )
    }

    #[test]
    fn original_initial_descriptor_census_counts_real_slot_without_launch_permission() {
        let (socket, peer) = UnixStream::pair().unwrap();
        let dropped = Rc::new(Cell::new(false));
        let original = reservation(Box::new(SocketSlot {
            socket,
            dropped: Rc::clone(&dropped),
        }));

        assert_eq!(
            original.retained_descriptor_views_precredit_data().unwrap(),
            1
        );
        assert_eq!(
            original
                .original_host_startup_guard_data()
                .retained_descriptor_views_precredit_data(),
            Err(RuntimeError::OwnerUnavailable)
        );
        let identity = original.original_host_launch_identity_data().unwrap();
        assert!(
            identity
                .begin(original.original_host_startup_guard_data())
                .is_err()
        );
        assert!(original.original_host_startup_unlaunched_data());
        assert!(!dropped.get());
        drop(peer);
        assert_eq!(
            original.retained_descriptor_views_precredit_data().unwrap(),
            1
        );
    }

    #[test]
    fn original_initial_descriptor_census_refuses_busy_owner_without_reopening_read_rights() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let dropped = Rc::new(Cell::new(false));
        let original = reservation(Box::new(SocketSlot {
            socket,
            dropped: Rc::clone(&dropped),
        }));
        let native = original
            .original_host_startup_guard_data()
            .custody
            .as_ref()
            .unwrap();
        let call = super::super::ReadCall::begin(Rc::clone(&native.read_owner)).unwrap();

        assert_eq!(
            original.retained_descriptor_views_precredit_data(),
            Err(RuntimeError::OwnerBusy)
        );
        drop(call);

        assert_eq!(original.retained_descriptor_views_precredit_data(), Ok(1));
        assert!(
            native
                .read_owner
                .authenticate_original_host_startup_data()
                .is_err()
        );
        assert!(!dropped.get());
        assert!(original.original_host_startup_unlaunched_data());
    }

    #[test]
    fn original_initial_descriptor_census_refuses_erased_unknown_without_losing_real_socket() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let dropped = Rc::new(Cell::new(false));
        let original = reservation(Box::new(UnknownSocketSlot {
            _socket: socket,
            dropped: Rc::clone(&dropped),
        }));

        assert_eq!(
            original.retained_descriptor_views_precredit_data(),
            Err(RuntimeError::UnsupportedFacet)
        );
        assert!(!dropped.get());
        assert!(original.original_host_startup_unlaunched_data());
        drop(original);
        assert!(dropped.get());
    }

    #[test]
    fn original_initial_descriptor_data_keeps_quarantined_backing_without_restoring_read_authority()
    {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let dropped = Rc::new(Cell::new(false));
        let original = reservation(Box::new(SocketSlot {
            socket,
            dropped: Rc::clone(&dropped),
        }));
        let guard = original.original_host_startup_guard_data();
        let native = guard.custody.as_ref().unwrap();
        native
            .read_owner
            .authenticate_original_host_startup_data()
            .unwrap();
        native.read_owner.revoke();

        assert!(
            native
                .read_owner
                .authenticate_original_host_startup_data()
                .is_err()
        );
        assert_eq!(
            original.retained_descriptor_views_precredit_data().unwrap(),
            1
        );
        assert!(!dropped.get());
        assert!(original.original_host_startup_unlaunched_data());
    }
}
