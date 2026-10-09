//! Installed sole reader enrollment and immutable observational reply custody.
//!
//! This staged profile accepts historical administration queries only. Execution,
//! initialization effects and other requests remain retained and refused until
//! their original journal reducers are connected. The role never supplies Ready.

use std::sync::Arc;

use crucible_protocol::node_control::{
    NativeAdministrativePreparation, NativeCommandError, NativeFrame,
};

use super::NativeNodeControl;
use crate::native_node_control::administrative_inbox::NativeAdministrativeInbox;
use crate::native_node_control::administrative_mailbox::{
    NativeAdministrativeClass, NativeAdministrativeReceive,
};
use crate::native_node_control::{
    administration_abi, administration_custody::AdministrationCustody,
};
use crate::runtime::worker_quiescence::LiveWorkerQuiescence;

impl NativeNodeControl {
    pub(crate) fn with_administration(
        mut self,
        preparation: NativeAdministrativePreparation,
        actor: Arc<NativeAdministrativeInbox>,
    ) -> Result<Self, NativeCommandError> {
        let register = administration_abi::resolve_register_administration().ok_or(
            NativeCommandError::Invalid("native reader enrollment unavailable"),
        )?;
        let query = administration_abi::resolve_query_administration().ok_or(
            NativeCommandError::Invalid("native reader history unavailable"),
        )?;
        let identity = actor
            .socket_identity()
            .map_err(|_| NativeCommandError::Conflict)?;
        if preparation
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()?
            != self.prepared_scope_hash
            || actor.scope() != &self.prepared_scope_hash
            || actor
                .descriptor()
                .map_err(|_| NativeCommandError::Conflict)?
                != preparation.descriptor_slot
            || identity != (preparation.socket_device, preparation.socket_inode)
            || self.channel.is_some()
            || self.administrative_actor.is_some()
        {
            return Err(NativeCommandError::Conflict);
        }
        self.administration = Some(AdministrationCustody::new(preparation, register, query)?);
        self.administrative_actor = Some(actor);
        Ok(self)
    }

    pub(crate) fn registered_administration_commitment(&self) -> Option<[u8; 32]> {
        Some(
            self.administration
                .as_ref()?
                .retained_original()?
                .role_commitment,
        )
    }

    pub(super) fn start_administration_reader(
        &'static self,
        modeled_workers: Arc<LiveWorkerQuiescence>,
    ) -> Result<(), std::io::Error> {
        let actor = self
            .administrative_actor
            .as_ref()
            .ok_or_else(|| std::io::Error::other("original administrative actor is absent"))?;
        if !Arc::ptr_eq(actor.modeled_workers(), &modeled_workers) {
            return Err(std::io::Error::other(
                "modeled workers differ from the installed original actor",
            ));
        }
        let mut worker = self
            .protocol_worker
            .lock()
            .map_err(|_| std::io::Error::other("original reader handle is poisoned"))?;
        if worker.is_some() {
            return Err(std::io::Error::other("original reader already started"));
        }
        let (started, startup) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name("crucible-native-administration".into())
            .spawn(move || self.run_administration_reader(started))?;
        *worker = Some(handle);
        drop(worker);
        startup
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| {
                std::io::Error::other("original native reader enrollment reply is unavailable")
            })?
            .map_err(|_| std::io::Error::other("source refused original native reader enrollment"))
    }

    pub(crate) fn with_construction_reducer(mut self) -> Result<Self, NativeCommandError> {
        let actor = self
            .administrative_actor
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        self.construction = Some(
            super::super::construction_reducer::NativeConstructionReducer::new(
                Arc::clone(actor),
                Arc::clone(
                    self.initialization
                        .as_ref()
                        .ok_or(NativeCommandError::Conflict)?,
                ),
                self.preparation_successor.as_ref().map(Arc::clone),
                1024,
            )?,
        );
        Ok(self)
    }

    fn run_administration_reader(
        &'static self,
        started: std::sync::mpsc::SyncSender<Result<(), NativeCommandError>>,
    ) {
        let Some(custody) = &self.administration else {
            return;
        };
        let Some(actor) = &self.administrative_actor else {
            return;
        };
        let result = custody.register_current_reader().and_then(|original| {
            let recovered = custody.query_original()?;
            if recovered != original {
                return Err(NativeCommandError::Conflict);
            }
            Ok(())
        });
        let failed = result.is_err();
        // All native/custody locks are released before the manifest thread sees
        // startup completion. It may only copy the retained original record.
        if started.send(result).is_err() || failed {
            self.fail_administration();
            return;
        }
        let Ok(descriptor) = actor.descriptor() else {
            self.fail_administration();
            return;
        };
        let mut pending_construction = None;
        loop {
            if self
                .construction
                .as_ref()
                .is_some_and(|construction| construction.recover().is_err())
            {
                self.fail_administration();
                return;
            }
            if let (Some(construction), Some(cursor)) = (&self.construction, pending_construction) {
                match construction.try_admit(actor, cursor) {
                    Ok(true) => {
                        pending_construction = None;
                        if let Some(notify) = self.protocol_notify
                            && notify() != 0
                        {
                            self.fail_administration();
                            return;
                        }
                    }
                    Ok(false) => {}
                    Err(_) => {
                        self.fail_administration();
                        return;
                    }
                }
            }
            let mut readiness = libc::pollfd {
                fd: descriptor,
                // Original-cursor retries cannot admit a later packet, even
                // when the socket already contains more administrative input.
                events: if pending_construction.is_some() {
                    0
                } else {
                    libc::POLLIN
                },
                revents: 0,
            };
            // SAFETY: The process-lifetime actor owns this descriptor. Only this
            // reader dequeues packets; poll observes availability without effects.
            // This administrative retry interval recovers only cached original
            // responses after socket backpressure. It neither advances guest
            // time nor admits HOME or guest execution; the old lane still waits
            // indefinitely. No source callback waits for this reader under BQL.
            let timeout = if self.construction.is_some() { 50 } else { -1 };
            // SAFETY: The retained actor owns the descriptor; poll writes only this one live record.
            let result = unsafe { libc::poll(&mut readiness, 1, timeout) };
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            if result < 0
                || readiness.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            {
                self.fail_administration();
                return;
            }
            if pending_construction.is_some() {
                continue;
            }
            if let Some(construction) = &self.construction {
                match actor.receive_one() {
                    Ok(NativeAdministrativeReceive::Empty) => continue,
                    Ok(NativeAdministrativeReceive::Retained(cursor, _)) => {
                        let frame = actor.original_frame(cursor);
                        let result = if matches!(frame, Ok(NativeFrame::QueryAdministration { .. }))
                        {
                            self.reply_original_administration(actor, custody, cursor)
                        } else {
                            match construction.try_admit(actor, cursor) {
                                Ok(true) => Ok(()),
                                Ok(false) => {
                                    pending_construction = Some(cursor);
                                    continue;
                                }
                                Err(error) => Err(error),
                            }
                        };
                        if result.is_err() {
                            self.fail_administration();
                            return;
                        }
                        if let Some(notify) = self.protocol_notify
                            && notify() != 0
                        {
                            self.fail_administration();
                            return;
                        }
                    }
                    _ => {
                        self.fail_administration();
                        return;
                    }
                }
                continue;
            }
            match actor.receive_one() {
                Ok(NativeAdministrativeReceive::Empty) => continue,
                Ok(NativeAdministrativeReceive::Retained(
                    cursor,
                    NativeAdministrativeClass::ReadOriginal,
                )) => {
                    if self
                        .reply_original_administration(actor, custody, cursor)
                        .is_err()
                    {
                        self.fail_administration();
                        return;
                    }
                }
                _ => {
                    // Every consumed original remains retained. Unsupported work
                    // never passes to native dispatch and cannot clear this fault.
                    self.fail_administration();
                    return;
                }
            }
        }
    }

    fn reply_original_administration(
        &self,
        actor: &NativeAdministrativeInbox,
        custody: &AdministrationCustody,
        cursor: u64,
    ) -> Result<(), NativeCommandError> {
        let original = actor
            .original_frame(cursor)
            .map_err(|_| NativeCommandError::Conflict)?;
        let NativeFrame::QueryAdministration {
            prepared_scope_hash,
            administration_commitment,
        } = original
        else {
            return Err(NativeCommandError::Conflict);
        };
        let credit = actor
            .reserve_reply(cursor)
            .map_err(|_| NativeCommandError::Conflict)?;
        if credit.cursor() != cursor {
            return Err(NativeCommandError::Conflict);
        }
        let facts = custody.query_original()?;
        if facts.prepared_scope_hash != prepared_scope_hash
            || facts.role_commitment != administration_commitment
        {
            return Err(NativeCommandError::Conflict);
        }
        actor
            .retain_reply(credit, &NativeFrame::AdministrationFacts(Box::new(facts)))
            .map_err(|_| NativeCommandError::Conflict)?;
        actor
            .send_reply(cursor)
            .map_err(|_| NativeCommandError::Conflict)?;
        Ok(())
    }

    fn fail_administration(&self) {
        // Fault publication cannot depend on acquiring a journal another owner
        // currently holds. The latch closes dispatch before the best-effort
        // ledger annotation, while all original custody remains available.
        self.administration_faulted
            .store(true, std::sync::atomic::Ordering::Release);
        if let Ok(mut state) = self.state.try_lock() {
            state.quarantined = true;
            state.current = None;
        }
        // Actual original actor, socket, native record and worker handle stay in
        // the registered process-lifetime owner. This is no pause attestation.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // crucible-lint: allow panic-shortcut -- These administration reader tests deliberately panic on invalid fixtures or failed invariants.
    #[allow(clippy::unwrap_used)]
    fn reader_fault_closes_dispatch_while_original_journal_is_busy() {
        let command = super::super::tests::command();
        let owner = NativeNodeControl::new(command.scope.clone(), command.kind.start(), 4).unwrap();
        owner.retain(command.clone()).unwrap();
        let journal = owner.state.lock().unwrap();

        owner.fail_administration();

        assert!(owner.command().is_none());
        assert!(owner.retain(command.clone()).is_err());
        assert_eq!(journal.journal.original(command.sequence), Some(&command));
        assert!(journal.current.is_some());
    }
}
