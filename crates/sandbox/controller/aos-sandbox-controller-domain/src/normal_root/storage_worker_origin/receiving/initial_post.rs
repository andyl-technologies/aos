//! Prepays the initial interval's independently owed original observation.
//!
//! This is a second instance of the same observer engine on the SAME actual
//! receiving ledger. The primary interval may itself perform normal currentness
//! RPCs, so its pending post cannot occupy that primary observer slot. No new
//! account, authority constructor, free RPC or health reset is introduced.

use super::*;

impl StoragePrepareReceivingLoanV1<'_> {
    /// Arms one independent initial post before its actual acquisition interval.
    ///
    /// The finite resident/operation capacity remains permanently charged on
    /// the original ledger. A preceding successful sample must have actually
    /// closed all native/Joined/Ended posts before the shared engine disposes
    /// it and lends another noncopy flight. An unsuccessful interval never
    /// admits another entry, even if its final observation itself succeeds.
    ///
    /// # Errors
    /// Refuses an unpaid fixed Session, closed original, pending/failed post,
    /// changed containment prerequisites or same-ledger capacity refusal.
    pub fn arm_initial_observation_post_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if !self.receiving()?.session_fixed {
            self.receiving()?.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.arm_service_acquisition_observation_post_v1()
    }

    /// Arms the original post before the selected initial Mode file is read.
    ///
    /// # Errors
    /// Refuses absent actual Mode prepayment, entered Runtime configuration,
    /// pending/failed posts or refusal on this SAME original's ledger.
    pub fn arm_initial_mode_observation_post_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !matches!(receiving.initial_mode_payment, Some(Ok(())))
            || !receiving.startup.before_runtime_configuration_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.arm_service_acquisition_observation_post_v1()
    }

    /// Arms the independently paid post for genuine configured Output startup.
    ///
    /// # Errors
    /// Refuses absent measured Output payment, entered State, pending/negative
    /// posts or a capacity/currentness failure on the SAME original ledger.
    pub fn arm_output_startup_observation_post_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if !self.receiving()?.startup.output_post_ready_v1() {
            self.receiving()?.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.arm_service_acquisition_observation_post_v1()
    }

    /// Arms a fresh Output post on the same permanently paid currentness peak.
    ///
    /// # Errors
    /// Refuses another writer/source, absent actual Output startup completion,
    /// failed predecessors or any same-original currentness/capacity refusal.
    pub fn arm_output_currentness_observation_post_v1(
        &mut self,
        journal: &crate::Journal,
        source: &std::path::Path,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_retained_output_journal_v1(journal, source)?;
        self.arm_service_acquisition_observation_post_v1()?;
        self.receiving()?.startup.arm_output_names_post_v1();
        Ok(())
    }

    /// Samples the same Output names into its prepaid once-only post slots.
    ///
    /// This observes actual native DATA after health refusal too. It cannot
    /// authorize work, change Journal health or clear the first service cause.
    ///
    /// # Errors
    /// Refuses an absent pending paid flight, another writer, repeat entry or
    /// actual retained health/name failure. The earlier health Result is parked
    /// before physical names; callers preserve that exact failure chronology.
    pub fn observe_output_currentness_names_once_v1(
        &mut self,
        journal: &crate::Journal,
        originals: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), crate::JournalError>>,
    ) -> Result<(), crate::JournalError> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            return Err(crate::JournalError::ProtectedBoundary);
        };
        if !receiving.initial_post_pending || health.is_some()
            || !receiving.startup.enter_output_names_post_v1(journal)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(crate::JournalError::ProtectedBoundary);
        }
        *health = Some(journal.ensure_healthy());
        let result = journal.observe_held_names_post_retaining_v1(originals);
        if matches!(health, Some(Err(_))) {
            return Err(crate::JournalError::Poisoned);
        }
        result
    }

    /// Permanently closes this original after a retained Output failure.
    ///
    /// This negative-only transition observes no native state, grants no work
    /// and cannot reset payment. The upper actual Output owner retains its
    /// first source/credential/name cause through the already completed post.
    pub fn close_output_currentness_v1(&mut self) {
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        {
            receiving.first.get_or_insert(Failure::Closed);
        }
        self.original.open = false;
    }

    pub(super) fn arm_service_acquisition_observation_post_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if receiving.initial_post_pending
            || matches!(receiving.initial_post_result, Some(Err(_)))
            || !receiving.initial_transports_disposed
            || !receiving.containment.named_verifications_settled_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        if receiving.initial_post_local_reservation.is_none() {
            // The primary may retain its negative control-name sample and
            // unresolved worker. The owed sample therefore cannot reuse the
            // main and aggregate readers' already occupied32-name/task peak. These are
            // complete existing per-bookend bounds on the SAME ledger.
            receiving.initial_post_local_demand = Some(super::observer_operation::independent_local_post_demand_v1());
            let Some(Ok(local)) = receiving.initial_post_local_demand.as_ref().copied() else {
                receiving.first.get_or_insert(Failure::InitialPost);
                return Err(StorageReceivingClosedV1);
            };
            receiving.initial_post_local_reservation = Some(receiving.reserve(local));
            if !matches!(receiving.initial_post_local_reservation, Some(Ok(()))) {
                return Err(StorageReceivingClosedV1);
            }
        }
        let result = receiving.initial_post.prepare_once_v1(
            &mut receiving.ledger, &receiving.lifetime,
        );
        if result.is_err() {
            let failure = if receiving.ledger.failure().is_some() {
                Failure::Accounting
            } else {
                Failure::InitialPost
            };
            receiving.first.get_or_insert(failure);
            return Err(StorageReceivingClosedV1);
        }
        // The shared engine has already disposed any preceding positive
        // native sample before this status slot can be replaced.
        receiving.initial_post_result = None;
        receiving.initial_post_pending = true;
        Ok(())
    }

    /// Rechecks only the actual initial HELLO purpose and socket binding.
    ///
    /// The separately armed original post must still run if this refuses.
    /// This lends no request/work authority and performs no PID1 RPC.
    ///
    /// # Errors
    /// Refuses closed ordinary admission, changed wire purpose or socket.
    pub fn require_initial_session_socket_current_v1(
        &mut self,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        if !receiving.session_wire.is_current(super::session_wire::WirePurpose::InitialHello) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let result = receiving.session_wire.require_socket(socket);
        if result.is_err() {
            receiving.first.get_or_insert(Failure::SessionWire);
        }
        result
    }

    /// Performs only the already paid independent initial observation.
    ///
    /// The SAME continuously borrowed loan keeps the actual original, custody,
    /// component and sample resident even when ordinary admission is closed.
    /// This cannot pay work, reopen the original or clear an earlier failure.
    ///
    /// # Errors
    /// Refuses an unarmed/repeated post or any native, containment, PID1,
    /// transport, binding or genuine-lifetime refusal. Full causes stay on the
    /// actual original; earlier primary failure retains priority.
    pub fn finish_initial_observation_post_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        self.finish_initial_observation_native_post_v1()
            .map_err(|_| StorageReceivingClosedV1)
    }

    pub(super) fn finish_initial_observation_native_post_v1(&mut self) -> NativeResult {
        let Some(StorageResourceRecipientCustodyV1::Receiving { component, receiving }) =
            self.original.recipient.as_mut()
        else {
            return Err(StorageWorkerOriginCauseV3::Closed);
        };
        if !receiving.initial_post_pending {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageWorkerOriginCauseV3::Closed);
        }
        // Consume the once-only obligation before native work. Do not consult
        // ordinary receiving health or reopen the original observation latch:
        // either may already be closed by the primary interval's real failure.
        receiving.initial_post_pending = false;
        let Some(initial) = receiving.before.as_ref().and_then(|result| result.as_ref().ok()) else {
            receiving.first.get_or_insert(Failure::InitialPost);
            self.original.open = false;
            receiving.initial_post_result = Some(Err(StorageReceivingClosedV1));
            return Err(StorageWorkerOriginCauseV3::Binding);
        };
        let result = receiving.initial_post.observe_prepared_once_v1(
            &receiving.lifetime, &self.original.custody, component, initial,
            &receiving.containment,
        );
        if result.is_err() {
            receiving.first.get_or_insert(Failure::InitialPost);
            receiving.initial_post_result = Some(Err(StorageReceivingClosedV1));
            self.original.open = false;
            Err(StorageWorkerOriginCauseV3::Binding)
        } else {
            receiving.initial_post_result = Some(Ok(()));
            // In particular, a successful post cannot restore a primary
            // recheck's closed observation latch or erase accounting poison.
            Ok(())
        }
    }
}
