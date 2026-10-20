//! Binds a selected host Hello to the same preallocated original child custody.
//!
//! The identity retains only the original read-owner edge. Its constructor is
//! private to selected reservations; equal PIDs or labels cannot recreate it.
//! A failed Hello permanently fences that same owner's unfinished read call.

use super::*;
use crate::node_contract::RuntimeError;
use std::{rc::Weak, thread::ThreadId};

pub(in crate::node_adapters::cnp::semantic) struct OriginalHostLaunchIdentity {
    owner: Weak<current::ReadOwner>,
    creator: u32,
    thread: ThreadId,
}

impl CnpSemanticLaunchReservation {
    pub(in crate::node_adapters::cnp::semantic) fn original_host_startup_counter_scratch_data()
    -> usize {
        std::mem::size_of::<OriginalHostLaunchIdentity>()
            + std::mem::size_of::<OriginalHostLaunchCall<'static>>()
            + std::mem::size_of::<ReadCall>()
            + std::mem::size_of::<crucible_node_transport::client::ClientPeer>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_host_launch_identity_data(
        &self,
    ) -> Result<OriginalHostLaunchIdentity, RuntimeError> {
        self.original_host_startup_guard_data()
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.original_host_startup_unlaunched_data() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let custody = self
            .original_host_startup_guard_data()
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if custody.has_original_child() || custody.provider_pid != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        custody
            .read_owner
            .authenticate_original_host_startup_data()?;
        Ok(OriginalHostLaunchIdentity {
            owner: Rc::downgrade(&custody.read_owner),
            creator: std::process::id(),
            thread: std::thread::current().id(),
        })
    }
}

impl OriginalHostLaunchIdentity {
    pub(in crate::node_adapters::cnp::semantic) fn retained_requested_storage_data(&self) -> usize {
        Self::retained_requested_storage_bound_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_requested_storage_bound_data() -> usize
    {
        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<current::ReadOwner>()
    }

    fn authenticate<'a>(
        &self,
        actual: &'a CnpSemanticLaunchGuard,
    ) -> Result<&'a CnpSemanticProcessCustody, RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        actual
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let custody = actual
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&self.owner, &Rc::downgrade(&custody.read_owner))
            || custody.child.is_some()
            || custody.original_child.is_none()
            || custody.controller.is_some()
            || custody.handshake.is_some()
            || custody.extension_handshake.is_some()
            || custody.source.is_some()
            || custody.runtime.is_some()
            || custody.killed
            || custody.reaped.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        custody
            .read_owner
            .authenticate_original_host_startup_data()?;
        use std::os::unix::ffi::OsStrExt;
        if custody.directory.as_os_str().as_bytes().len() > 4096 {
            return Err(RuntimeError::ResourceLimit);
        }
        // Preserve the existing private-directory, process-group, retained
        // kernel and full executable fences. This same selected reservation
        // installed the bounded-birth executable path before this identity.
        custody
            .authenticate_process()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        custody
            .read_owner
            .authenticate_original_host_startup_data()?;
        Ok(custody)
    }

    pub(in crate::node_adapters::cnp::semantic) fn begin<'a>(
        &'a self,
        actual: &'a CnpSemanticLaunchGuard,
    ) -> Result<OriginalHostLaunchCall<'a>, RuntimeError> {
        let custody = self.authenticate(actual)?;
        let call =
            ReadCall::begin(Rc::clone(&custody.read_owner)).map_err(|_| RuntimeError::OwnerBusy)?;
        Ok(OriginalHostLaunchCall {
            identity: self,
            actual,
            call: Some(call),
        })
    }
}

pub(in crate::node_adapters::cnp::semantic) struct OriginalHostLaunchCall<'a> {
    identity: &'a OriginalHostLaunchIdentity,
    actual: &'a CnpSemanticLaunchGuard,
    call: Option<ReadCall>,
}

impl OriginalHostLaunchCall<'_> {
    pub(in crate::node_adapters::cnp::semantic) fn peer_data(
        &self,
    ) -> Result<crucible_node_transport::client::ClientPeer, RuntimeError> {
        let custody = self
            .actual
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let kernel = custody
            .kernel_identity
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok(crucible_node_transport::client::ClientPeer {
            pid: custody.provider_pid,
            uid: kernel.original_host_uid_data(),
            executable: custody.expected_executable.clone(),
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete(mut self) -> Result<(), RuntimeError> {
        self.call
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .finish(true);
        // This check follows every installed currency callback. A callback that
        // revokes the same owner cannot turn a finished read into fresh proof.
        if let Err(error) = self.identity.authenticate(self.actual) {
            if let Some(owner) = self.identity.owner.upgrade() {
                owner.revoke();
            }
            return Err(error);
        }
        Ok(())
    }
}

/// Keeps the same selected read owner through initial attachment and preparation.
///
/// This private identity has no PID constructor, serializer or public issuer.
/// Source consumes its installed action before retaining this same-owner edge.
#[derive(Clone)]
pub(in crate::node_adapters::cnp::semantic) struct OriginalHostInitialLifecycleGuardIdentity {
    owner: Weak<current::ReadOwner>,
    creator: u32,
    thread: ThreadId,
}

impl OriginalHostLaunchIdentity {
    pub(in crate::node_adapters::cnp::semantic) fn retain_initial_lifecycle_data(
        &self,
        actual: &CnpSemanticLaunchGuard,
        source: &crate::node_adapters::cnp::PacketCompleteSemanticSource,
    ) -> Result<OriginalHostInitialLifecycleGuardIdentity, RuntimeError> {
        let retained = OriginalHostInitialLifecycleGuardIdentity {
            owner: Weak::clone(&self.owner),
            creator: self.creator,
            thread: self.thread,
        };
        let custody = retained.authenticate_data(actual, source)?;
        if custody.controller.is_some()
            || custody.source.is_some()
            || custody.handshake.is_some()
            || custody.extension_handshake.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(retained)
    }
}

impl OriginalHostInitialLifecycleGuardIdentity {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_data<'a>(
        &self,
        actual: &'a CnpSemanticLaunchGuard,
        source: &crate::node_adapters::cnp::PacketCompleteSemanticSource,
    ) -> Result<&'a CnpSemanticProcessCustody, RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        actual
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let custody = actual
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Weak::ptr_eq(&self.owner, &Rc::downgrade(&custody.read_owner))
            || custody.child.is_some()
            || custody.original_child.is_none()
            || custody.runtime.is_some()
            || custody.killed
            || custody.reaped.is_some()
            || custody.source.as_ref().is_some_and(|installed| {
                !std::ptr::eq(
                    Rc::as_ptr(installed).cast::<()>(),
                    std::ptr::from_ref(source).cast::<()>(),
                )
            })
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        custody
            .read_owner
            .authenticate_original_host_startup_data()?;
        Ok(custody)
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_current(
        &self,
        actual: &CnpSemanticLaunchGuard,
        source: &crate::node_adapters::cnp::PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        let custody = self.authenticate_data(actual, source)?;
        // Actual selected bounded acquisition was installed before Child.
        // Keep the same full directory/process-group/kernel/executable fences.
        custody
            .authenticate_process()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        self.authenticate_data(actual, source)?;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn begin_socket<'a>(
        &'a self,
        actual: &'a CnpSemanticLaunchGuard,
        source: &'a crate::node_adapters::cnp::PacketCompleteSemanticSource,
    ) -> Result<OriginalHostInitialSocketCall<'a>, RuntimeError> {
        self.authenticate_current(actual, source)?;
        let custody = self.authenticate_data(actual, source)?;
        if custody.controller.is_some() || custody.source.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let call =
            ReadCall::begin(Rc::clone(&custody.read_owner)).map_err(|_| RuntimeError::OwnerBusy)?;
        Ok(OriginalHostInitialSocketCall {
            identity: self,
            actual,
            source,
            call: Some(call),
        })
    }

    pub(in crate::node_adapters::cnp::semantic) fn revoke(&self) {
        if self.creator == std::process::id()
            && self.thread == std::thread::current().id()
            && let Some(owner) = self.owner.upgrade()
        {
            owner.revoke();
        }
    }
}

pub(in crate::node_adapters::cnp::semantic) struct OriginalHostInitialSocketCall<'a> {
    identity: &'a OriginalHostInitialLifecycleGuardIdentity,
    actual: &'a CnpSemanticLaunchGuard,
    source: &'a crate::node_adapters::cnp::PacketCompleteSemanticSource,
    call: Option<ReadCall>,
}

impl OriginalHostInitialSocketCall<'_> {
    pub(in crate::node_adapters::cnp::semantic) fn complete(mut self) -> Result<(), RuntimeError> {
        self.call
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .finish(true);
        if let Err(error) = self.identity.authenticate_current(self.actual, self.source) {
            self.identity.revoke();
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{U64, canonical};

    struct UnlaunchedSlot;

    impl CnpSemanticProcessSlot for UnlaunchedSlot {
        fn identity(&self) -> U64 {
            U64::new(997)
        }

        fn retain(&mut self, _: CnpSemanticProcessCustody) {
            panic!("these data controls must never create or transfer a Child");
        }
    }

    fn selected() -> CnpSemanticLaunchReservation {
        CnpSemanticLaunchReservation::reserve_original_native_startup(
            PathBuf::from("/tmp/aos-host-sdk-unlaunched-data"),
            canonical::content_ref(b"same declared executable", "application/octet-stream")
                .unwrap(),
            Box::new(UnlaunchedSlot),
        )
    }

    #[test]
    fn original_host_launch_identity_keeps_real_unlaunched_owner_without_child_permission() {
        let reservation = selected();
        let identity = reservation.original_host_launch_identity_data().unwrap();
        let actual = reservation.original_host_startup_guard_data();
        let owner = &actual.custody.as_ref().unwrap().read_owner;
        assert!(Weak::ptr_eq(&identity.owner, &Rc::downgrade(owner)));
        let before = owner.clone();
        assert!(identity.begin(actual).is_err());
        owner.authenticate_original_host_startup_data().unwrap();
        assert!(Rc::ptr_eq(owner, &before));
        assert!(reservation.original_host_startup_unlaunched_data());
        let custody = actual.custody.as_ref().unwrap();
        assert_eq!(custody.provider_pid, 0);
        assert!(!custody.has_original_child());
        assert!(custody.kernel_identity.is_none());
        assert!(custody.executable_guard.is_none());
        assert!(identity.retained_requested_storage_data() > 0);
    }

    #[test]
    fn original_host_launch_identity_refuses_same_labels_from_another_or_legacy_reservation() {
        let first = selected();
        let second = selected();
        let identity = first.original_host_launch_identity_data().unwrap();
        assert_eq!(
            first.original_host_startup_guard_data().supervision_id(),
            second.original_host_startup_guard_data().supervision_id()
        );
        assert!(!Weak::ptr_eq(
            &identity.owner,
            &Rc::downgrade(
                &second
                    .original_host_startup_guard_data()
                    .custody
                    .as_ref()
                    .unwrap()
                    .read_owner
            )
        ));
        assert!(matches!(
            identity.begin(second.original_host_startup_guard_data()),
            Err(RuntimeError::ForeignAuthority)
        ));
        second
            .original_host_startup_guard_data()
            .custody
            .as_ref()
            .unwrap()
            .read_owner
            .authenticate_original_host_startup_data()
            .unwrap();
        first
            .original_host_startup_guard_data()
            .custody
            .as_ref()
            .unwrap()
            .read_owner
            .authenticate_original_host_startup_data()
            .unwrap();

        let legacy = CnpSemanticLaunchReservation::reserve_complete_bytes(
            PathBuf::from("/tmp/aos-host-sdk-unlaunched-data"),
            canonical::content_ref(b"same declared executable", "application/octet-stream")
                .unwrap(),
            Box::new(UnlaunchedSlot),
        );
        assert!(matches!(
            legacy.original_host_launch_identity_data(),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(first.original_host_startup_unlaunched_data());
        assert!(second.original_host_startup_unlaunched_data());
    }
}

#[path = "host_startup/settled17.rs"]
mod settled17;
