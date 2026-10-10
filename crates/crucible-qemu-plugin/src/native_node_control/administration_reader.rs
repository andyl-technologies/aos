//! Installed sole reader enrollment and immutable observational reply custody.
//!
//! The reader retains bounded original frames and backed replies. Historical
//! queries and initialization records use their original construction reducer;
//! controller eight additionally retains a validated empty-input compute record
//! for the separate native semantic owner. Receiving a frame never dispatches
//! guest work, releases modeled holds or supplies Ready.

use std::sync::Arc;

use crucible_protocol::node_control::{
    NativeAdministrativePreparation, NativeCommandError, NativeFrame,
};

use super::NativeNodeControl;
use crate::native_node_control::administrative_inbox::{
    NativeAdministrativeInbox, NativeAdministrativeInboxError,
};
use crate::native_node_control::administrative_mailbox::{
    NativeAdministrativeClass, NativeAdministrativeReceive,
};
use crate::native_node_control::{
    administration_abi, administration_custody::AdministrationCustody,
};
use crate::runtime::worker_quiescence::LiveWorkerQuiescence;

/// Treats original mailbox contention as pending without receiving another packet.
fn receive_original_or_pending(
    actor: &NativeAdministrativeInbox,
) -> Result<NativeAdministrativeReceive, NativeAdministrativeInboxError> {
    match actor.receive_one() {
        // A source cut may hold the same actual mailbox while retaining bytes.
        // Busy owns no consumed packet; the sole reader retries its original
        // socket after that hold rather than terminating its registered lifetime.
        Err(NativeAdministrativeInboxError::Busy) => Ok(NativeAdministrativeReceive::Empty),
        result => result,
    }
}

fn original_frame_or_pending(
    actor: &NativeAdministrativeInbox,
    cursor: u64,
) -> Result<Option<NativeFrame>, NativeCommandError> {
    match actor.original_frame(cursor) {
        Ok(frame) => Ok(Some(frame)),
        Err(NativeAdministrativeInboxError::Busy) => Ok(None),
        Err(_) => Err(NativeCommandError::Conflict),
    }
}

fn publish_original_query_or_pending(
    actor: &NativeAdministrativeInbox,
    cursor: u64,
    reply: &NativeFrame,
) -> Result<bool, NativeCommandError> {
    match actor.reply_administration(cursor, reply) {
        Ok(sent) => Ok(sent),
        Err(NativeAdministrativeInboxError::Busy) => Ok(false),
        Err(_) => Err(NativeCommandError::Conflict),
    }
}

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
        let mut endpoint_enrolled = false;
        let mut pending_construction = None;
        loop {
            if !endpoint_enrolled {
                match self.enroll_current_administrative_endpoint() {
                    Ok(enrolled) => {
                        endpoint_enrolled = enrolled;
                        if enrolled
                            && self.effect.is_some()
                            && let Some(notify) = self.protocol_notify
                            && notify() != 0
                        {
                            self.fail_administration();
                            return;
                        }
                    }
                    Err(_) => {
                        self.fail_administration();
                        return;
                    }
                }
            }
            if self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.recover_original_result().is_err())
            {
                self.fail_administration();
                return;
            }
            if self
                .construction
                .as_ref()
                .is_some_and(|construction| construction.recover().is_err())
            {
                self.fail_administration();
                return;
            }
            if let Some(cursor) = pending_construction {
                match self.try_admit_original_administration(actor, custody, cursor) {
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
            // Contention retains the same original ACK/command and credits.
            // This coalesced event permits the parked native owner to recheck
            // them; it never calls a guest dispatcher or takes a later packet.
            if self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.original_progress_pending())
                && let Some(notify) = self.protocol_notify
                && notify() != 0
            {
                self.fail_administration();
                return;
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
            let timeout = if self.construction.is_some() || pending_construction.is_some() {
                50
            } else {
                -1
            };
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
            if self.construction.is_some() {
                match receive_original_or_pending(actor) {
                    Ok(NativeAdministrativeReceive::Empty) => continue,
                    Ok(NativeAdministrativeReceive::Retained(cursor, _)) => {
                        match self.try_admit_original_administration(actor, custody, cursor) {
                            Ok(true) => {}
                            Ok(false) => {
                                pending_construction = Some(cursor);
                                continue;
                            }
                            Err(_) => {
                                self.fail_administration();
                                return;
                            }
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
            match receive_original_or_pending(actor) {
                Ok(NativeAdministrativeReceive::Empty) => continue,
                Ok(NativeAdministrativeReceive::Retained(
                    cursor,
                    NativeAdministrativeClass::ReadOriginal,
                )) => match self.reply_original_administration(actor, custody, cursor) {
                    Ok(true) => {}
                    Ok(false) => pending_construction = Some(cursor),
                    Err(_) => {
                        self.fail_administration();
                        return;
                    }
                },
                _ => {
                    // Every consumed original remains retained. Unsupported work
                    // never passes to native dispatch and cannot clear this fault.
                    self.fail_administration();
                    return;
                }
            }
        }
    }

    fn try_admit_original_administration(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        custody: &AdministrationCustody,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        let Some(frame) = original_frame_or_pending(actor, cursor)? else {
            return Ok(false);
        };
        match frame {
            NativeFrame::EffectCompute(_) => self
                .effect
                .as_ref()
                .ok_or(NativeCommandError::Conflict)?
                .try_admit(actor, cursor),
            NativeFrame::QueryAdministration { .. } => {
                self.reply_original_administration(actor, custody, cursor)
            }
            _ => self
                .construction
                .as_ref()
                .ok_or(NativeCommandError::Conflict)?
                .try_admit(actor, cursor),
        }
    }

    fn reply_original_administration(
        &self,
        actor: &NativeAdministrativeInbox,
        custody: &AdministrationCustody,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        // Startup authenticated this immutable historical record against the
        // actual source registration. Copying it cannot attest current life or
        // grant effects; the mailbox checks the original query and exact reply.
        let facts = custody
            .retained_original()
            .ok_or(NativeCommandError::Conflict)?;
        publish_original_query_or_pending(
            actor,
            cursor,
            &NativeFrame::AdministrationFacts(Box::new(facts)),
        )
    }

    pub(super) fn fail_administration(&self) {
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
    // crucible-lint: allow rust-allow -- This actual socket/mutex test deliberately panics on lost packets or changed custody.
    // crucible-lint: allow panic-shortcut -- This actual socket/mutex test deliberately panics on lost packets or changed custody.
    #[allow(clippy::unwrap_used)]
    fn source_mailbox_contention_preserves_unread_packet_and_original_reader() {
        use crucible_protocol::node_control::{NativeChannel, NativeControlEdition};

        let (host, native) =
            NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration)
                .unwrap();
        let mut endpoint = Some(native);
        let actor = NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            [1; 32],
            false,
            8,
            65536,
        )
        .unwrap();
        let query = NativeFrame::QueryAdministration {
            prepared_scope_hash: [1; 32],
            administration_commitment: [2; 32],
        };
        assert!(host.send(&query).unwrap());
        let held = actor.test_hold_mailbox();

        assert_eq!(
            receive_original_or_pending(&actor).unwrap(),
            NativeAdministrativeReceive::Empty
        );
        drop(held);

        assert!(matches!(
            receive_original_or_pending(&actor).unwrap(),
            NativeAdministrativeReceive::Retained(1, _)
        ));
        assert_eq!(actor.original_frame(1).unwrap(), query);
        assert_eq!(
            receive_original_or_pending(&actor).unwrap(),
            NativeAdministrativeReceive::Empty
        );
    }

    #[test]
    // crucible-lint: allow rust-allow -- This actual retained packet/mutex control panics on changed original custody.
    // crucible-lint: allow panic-shortcut -- This actual retained packet/mutex control panics on changed original custody.
    #[allow(clippy::unwrap_used)]
    fn retained_packet_classification_stays_pending_while_source_holds_ledger() {
        use crucible_protocol::node_control::{NativeChannel, NativeControlEdition};

        let (host, native) =
            NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration)
                .unwrap();
        let mut endpoint = Some(native);
        let actor = NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            [1; 32],
            false,
            8,
            65536,
        )
        .unwrap();
        let frame = NativeFrame::QueryAdministration {
            prepared_scope_hash: [1; 32],
            administration_commitment: [2; 32],
        };
        assert!(host.send(&frame).unwrap());
        assert!(matches!(
            actor.receive_one().unwrap(),
            NativeAdministrativeReceive::Retained(1, _)
        ));
        let original_bytes = actor.original(1).unwrap();
        let held = actor.test_hold_mailbox();

        assert_eq!(original_frame_or_pending(&actor, 1).unwrap(), None);
        drop(held);

        assert_eq!(original_frame_or_pending(&actor, 1).unwrap(), Some(frame));
        assert_eq!(actor.original(1).unwrap(), original_bytes);
        assert_eq!(
            actor.receive_one().unwrap(),
            NativeAdministrativeReceive::Empty
        );
        assert!(original_frame_or_pending(&actor, 2).is_err());
    }

    fn query_reply() -> NativeFrame {
        use crucible_node_contract::U64;
        NativeFrame::AdministrationFacts(Box::new(
            crucible_protocol::node_control::NativeAdministrativeFacts {
                registration_id: U64::new(1),
                thread_id: U64::new(2),
                socket_device: U64::new(3),
                socket_inode: U64::new(4),
                process_id: U64::new(5),
                descriptor_slot: 6,
                prepared_scope_hash: [1; 32],
                role_commitment: [2; 32],
                realize_request_digest: [3; 32],
                policy_digest: [4; 32],
            },
        ))
    }

    #[test]
    // crucible-lint: allow rust-allow -- Actual retained datagram/lock assertions deliberately panic on lost original custody.
    // crucible-lint: allow panic-shortcut -- Actual mailbox contention is the failure signal; modeled facts confer no authority.
    #[allow(clippy::unwrap_used)]
    fn query_admission_after_classification_keeps_same_original_while_held() {
        use crucible_protocol::node_control::{NativeChannel, NativeControlEdition};
        let (host, native) =
            NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration)
                .unwrap();
        let mut endpoint = Some(native);
        let actor = NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            [1; 32],
            false,
            8,
            65536,
        )
        .unwrap();
        let frame = NativeFrame::QueryAdministration {
            prepared_scope_hash: [1; 32],
            administration_commitment: [2; 32],
        };
        assert!(host.send(&frame).unwrap());
        assert!(matches!(
            actor.receive_one().unwrap(),
            NativeAdministrativeReceive::Retained(1, _)
        ));
        let original = actor.original(1).unwrap();
        assert_eq!(original_frame_or_pending(&actor, 1).unwrap(), Some(frame));

        let held = actor.test_hold_mailbox();
        assert!(!publish_original_query_or_pending(&actor, 1, &query_reply()).unwrap());
        assert!(host.receive().unwrap().is_none());
        drop(held);

        assert!(actor.reply_administration(1, &query_reply()).unwrap());
        assert_eq!(host.receive().unwrap(), Some(query_reply()));
        assert_eq!(actor.original(1).unwrap(), original);
        assert_eq!(
            actor.receive_one().unwrap(),
            NativeAdministrativeReceive::Empty
        );
        assert!(actor.reply_administration(1, &query_reply()).unwrap());
        assert_eq!(host.receive().unwrap(), Some(query_reply()));
    }

    #[test]
    // crucible-lint: allow rust-allow -- Finite actual socket-backpressure assertions deliberately panic on lost cached bytes.
    // crucible-lint: allow panic-shortcut -- Backpressure remains original reply custody; modeled facts supply no source authority.
    #[allow(clippy::unwrap_used)]
    fn query_backpressure_recovers_exact_cached_reply_without_new_reservation() {
        use crucible_protocol::node_control::{NativeChannel, NativeControlEdition};
        let (host, native) =
            NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration)
                .unwrap();
        let mut endpoint = Some(native);
        let actor = NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            [1; 32],
            false,
            8,
            65536,
        )
        .unwrap();
        let frame = NativeFrame::QueryAdministration {
            prepared_scope_hash: [1; 32],
            administration_commitment: [2; 32],
        };
        assert!(host.send(&frame).unwrap());
        assert!(matches!(
            actor.receive_one().unwrap(),
            NativeAdministrativeReceive::Retained(1, _)
        ));
        let original = actor.original(1).unwrap();
        let mut sent = 0;
        for _ in 0..4096 {
            if !actor.reply_administration(1, &query_reply()).unwrap() {
                break;
            }
            sent += 1;
        }
        assert!(sent > 0 && sent < 4096);
        assert!(!actor.reply_administration(1, &query_reply()).unwrap());
        for _ in 0..sent {
            assert_eq!(host.receive().unwrap(), Some(query_reply()));
        }
        assert!(host.receive().unwrap().is_none());

        assert!(actor.reply_administration(1, &query_reply()).unwrap());
        assert_eq!(host.receive().unwrap(), Some(query_reply()));
        assert_eq!(actor.original(1).unwrap(), original);
        let mut changed = query_reply();
        if let NativeFrame::AdministrationFacts(facts) = &mut changed {
            facts.thread_id = crucible_node_contract::U64::new(99);
        }
        assert!(actor.reply_administration(1, &changed).is_err());
        assert!(host.receive().unwrap().is_none());
        assert_eq!(actor.original(1).unwrap(), original);
    }

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
