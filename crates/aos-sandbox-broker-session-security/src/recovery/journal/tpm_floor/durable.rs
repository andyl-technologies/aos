//! Protected preparation and reconciliation under two retained journal writers.
//!
//! The existing traffic writer is acquired first, this same-owner sidecar
//! second, and the sealed TPM transport last. The composition grants no
//! endpoint, method, readiness, or effect authority by itself.
//!
//! The separate sidecar owns namespace 47 and exactly these canonical keys:
//!
//! ```text
//! checkpoint = AOSBTF01 (156 bytes)
//! intent     = AOSBTI01 (324 bytes), present only with transaction
//! transaction = AOSJPT01, exact existing ordered JournalTransaction
//! ```

mod physical_slot;
use physical_slot::AttachmentPhysicalV1;

mod controller_initial;
mod storage_initial;
mod storage_forwarding;
use storage_forwarding::BorrowedFinalSuffixV2;
pub(super) mod controller_pair;
mod store;
pub(in crate::recovery::journal) use store::NAME as FLOOR_SIDECAR_NAME;
pub(crate) use store::BrokerSidecarCustodyV1;
mod traffic;
pub(super) use traffic::commit_traffic_transaction_retaining_v3;

use aos_sandbox::{JournalTransaction, ProtectedJournalLockCustodyV1};

use super::backend::{
    AuthenticatedTpmNvIoV1, FloorAdvanceV1, PhysicalTpmNvIoV1, TpmNvExtendFloorBackendV1,
};
use super::{FloorErrorV1, FloorIntentV1, FloorProfileV1, FloorRecoveryV1, reconcile_floor_v1};
use store::{
    BrokerSidecarOpenErrorV1, BrokerSidecarOpenV1, FinalSuffixPreflightV1, FloorStoreV1,
    StoredFloorV1,
};
use traffic::HeldTrafficWriterV1;
use crate::tpm_nv_custody::{FloorIntentDataV1, FloorProfileDataV1, StoredFloorDataV1, reconcile_floor_data_v1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BrokerAttachmentPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Failed,
}

enum BrokerAttachmentFailureV1 {
    Floor(FloorErrorV1),
    Sidecar(BrokerSidecarOpenErrorV1),
    ControllerSidecar,
    StorageSidecar,
    ControllerPayment,
    StoragePayment,
    Native(aos_sandbox::JournalError),
    Endpoint(crate::BrokerSessionSecurityError),
    Unfinished,
    Deadline(crate::DormantBrokerSessionHandshakeErrorV1),
}

/// Keeps genuine partial attachment owners resident before each later gate.
pub(super) struct BrokerAttachmentAttemptV1 {
    // Capture and backend promotion own the SAME physical original in exclusive
    // phases. Preserve that owner before sidecar destruction; traffic remains
    // on the whole original Journal owner, never borrowed into a sibling field.
    physical: AttachmentPhysicalV1,
    controller_payment: Option<crate::tpm_nv_custody::physical::BrokerPhysicalPaymentOriginalV2>,
    storage_payment: Option<crate::tpm_nv_custody::physical::BrokerPhysicalPaymentOriginalV2>,
    pub(super) controller_selected: bool,
    pub(super) storage_selected: bool,
    pub(super) controller_owed_consumed: bool,
    pub(super) controller_primary: Option<Result<(), FloorErrorV1>>,
    pub(super) controller_posts: Option<[Result<(), FloorErrorV1>; 5]>,
    store: Option<FloorStoreV1>,
    opening: Option<BrokerSidecarOpenV1>,
    controller_fixed: Option<Result<(), aos_sandbox::ControllerInitialBrokerSessionClosedV1>>,
    controller_opening: Option<Box<store::ControllerSidecarOpenOriginalV1>>,
    storage_opening: Option<Box<store::StorageSidecarOpenOriginalV2>>,
    storage_fixed: Option<(Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>, Result<(), aos_sandbox::StorageReceivingClosedV1>)>,
    main_lock: Option<ProtectedJournalLockCustodyV1>,
    sidecar_lock: Option<ProtectedJournalLockCustodyV1>,
    phase: BrokerAttachmentPhaseV1,
    first_failure: Option<BrokerAttachmentFailureV1>,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    cold_failure: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
    native_failure: Option<aos_sandbox::JournalError>,
    #[cfg(feature = "online-nix")]
    online_admission_result: Option<Result<(), FloorErrorV1>>,
    #[cfg(feature = "online-nix")]
    postflights: [Option<(Result<(), aos_sandbox::JournalError>, Result<(), FloorErrorV1>)>;
        crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1],
}

impl BrokerAttachmentAttemptV1 {
    pub(super) fn install_currentness_archive_v1(
        &mut self,
        archive: super::super::floor_revalidation::FloorCurrentnessSharedV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Ready || self.first_failure.is_some()
            || self.cold_failure.is_some() || self.native_failure.is_some()
            || self.opening.is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .install_currentness_archive_v1(archive)
    }

    #[cfg(feature = "online-nix")]
    pub(super) fn bind_online_request_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        let operation = self.begin(BrokerAttachmentPhaseV1::Ready)?;
        let result = (|| {
            if operation.attempt.cold_deadline.is_some_and(|original| original != deadline) {
                return Err(FloorErrorV1::Unavailable);
            }
            operation.attempt.cold_deadline = Some(deadline);
            operation.attempt.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?
                .bind_online_request_deadline(deadline)?;
            operation.attempt.check_cold_deadline()
        })();
        operation.finish(result)
    }

    pub(super) fn bind_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Fresh || self.cold_deadline.is_some() {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        self.cold_deadline = Some(deadline);
        self.check_cold_deadline()
    }

    pub(super) fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        if let Some(deadline) = self.cold_deadline {
            if let Err(cause) = deadline.check() {
                self.record(BrokerAttachmentFailureV1::Deadline(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        }
        Ok(())
    }

    pub(super) fn retire_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Ready
            || self.first_failure.is_some()
            || self.cold_failure.is_some()
            || self.cold_deadline != Some(deadline)
        {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        let result = self.physical
            .backend_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .require_cold_retirement(deadline);
        if let Err(cause) = result {
            self.record(BrokerAttachmentFailureV1::Floor(cause));
            return Err(cause);
        }
        self.check_cold_deadline()?;
        // No fallible work follows the final original-D observation.
        if let Some(backend) = self.physical.backend_mut() {
            backend.clear_cold_deadline();
        }
        self.cold_deadline = None;
        Ok(())
    }

    pub(super) const fn fresh() -> Self {
        Self {
            physical: AttachmentPhysicalV1::Empty,
            controller_payment: None,
            storage_payment: None,
            controller_selected: false,
            storage_selected: false,
            controller_owed_consumed: false,
            controller_primary: None,
            controller_posts: None,
            store: None,
            opening: None,
            controller_fixed: None,
            controller_opening: None,
            storage_opening: None,
            storage_fixed: None,
            main_lock: None,
            sidecar_lock: None,
            phase: BrokerAttachmentPhaseV1::Fresh,
            first_failure: None,
            cold_deadline: None,
            cold_failure: None,
            native_failure: None,
            #[cfg(feature = "online-nix")]
            online_admission_result: None,
            #[cfg(feature = "online-nix")]
            postflights: [const { None }; crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1],
        }
    }

    /// Inspects the SAME partial attachment without entering its Ready gate.
    #[cfg(feature = "online-nix")]
    pub(super) fn observe_online_postflight(&mut self) -> Result<(), FloorErrorV1> {
        let slot = self.postflights.iter_mut().find(|slot| slot.is_none())
            .ok_or(FloorErrorV1::Unavailable)?;
        *slot = Some((Err(aos_sandbox::JournalError::ProtectedBoundary), Err(FloorErrorV1::Unavailable)));
        let Some((sidecar, physical)) = slot.as_mut() else {
            return Err(FloorErrorV1::Unavailable);
        };
        *sidecar = match self.store.as_ref() {
            Some(store) => store.validate_held_native(),
            None => Err(aos_sandbox::JournalError::ProtectedBoundary),
        };
        *physical = if let Some(backend) = self.physical.backend_mut() {
            backend.observe_online_postflight()
        } else if let Some(physical) = self.physical.captured_mut() {
            physical.observe_online_postflight()
        } else {
            Err(FloorErrorV1::Unavailable)
        };
        if sidecar.is_err() || physical.is_err() || self.phase != BrokerAttachmentPhaseV1::Ready
            || self.first_failure.is_some() || self.native_failure.is_some()
            || self.cold_failure.is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(super) fn is_fresh_for_controller_v1(&self) -> bool {
        self.phase == BrokerAttachmentPhaseV1::Fresh && self.first_failure.is_none()
            && self.store.is_none() && self.opening.is_none()
            && self.controller_opening.is_none() && self.controller_payment.is_none()
            && self.physical.is_empty()
    }

    pub(super) fn arm_controller_initial_v1(
        &mut self, owner: &super::super::ProtectedBrokerSessionJournalV1,
        receiving: &aos_sandbox::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Fresh || self.controller_selected
            || receiving.role_v1() != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Storage
        { return Err(FloorErrorV1::Unavailable); }
        receiving.require_opened_journal_v1(owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        self.controller_selected = true;
        Ok(())
    }

    pub(super) fn controller_physical_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        match self.first_failure.as_ref()? {
            BrokerAttachmentFailureV1::ControllerPayment => self.controller_payment.as_ref()?.failure(),
            BrokerAttachmentFailureV1::Floor(FloorErrorV1::RetainedControllerPhysical) => {
                self.physical.backend_ref().and_then(|backend| backend.controller_physical_failure_v1())
                    .or_else(|| self.physical.captured_ref()?.controller_physical_failure_v1())
            }
            _ => None,
        }
    }

    pub(super) fn controller_property_failure_view_v1(&self)
        -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>>
    {
        if !matches!(self.first_failure,
            Some(BrokerAttachmentFailureV1::Floor(FloorErrorV1::RetainedControllerPhysical)))
        { return None; }
        self.physical.backend_ref().and_then(|backend| backend.controller_property_failure_view_v1())
            .or_else(|| self.physical.captured_ref()?.controller_property_failure_view_v1())
    }

    pub(super) fn has_controller_owed_v1(&self) -> bool {
        (self.controller_selected || self.storage_selected) && !self.controller_owed_consumed && self.is_failed()
    }

    pub(super) fn observe_controller_attachment_post_v1(
        &mut self, owner: &super::super::ProtectedBrokerSessionJournalV1,
    ) -> (Result<(), FloorErrorV1>, Result<(), FloorErrorV1>, Result<(), FloorErrorV1>) {
        // The real journals remain owned by this same main/attachment. This
        // path never opens names independently or rewrites the healthy phase.
        let main = match owner.journal.as_ref() {
            Some(journal) => super::super::floor_revalidation::validate_rooted(
                owner.floor_currentness.as_ref(), owner.owner, journal,
                &owner.directory, &owner.name,
            ),
            None => Err(FloorErrorV1::Unavailable),
        };
        let sidecar = match self.store.as_ref() {
            Some(store) => store.validate_held(),
            None => Err(FloorErrorV1::Unavailable),
        };
        let physical = if let Some(backend) = self.physical.backend_mut() {
            backend.observe_controller_floor_post_v1()
        } else if let Some(physical) = self.physical.captured_mut() {
            physical.observe_controller_floor_post_v1()
        } else {
            // No helper/service primitive is entered before its actual fixed
            // debit. Existing partial payment/sidecar owners stay resident.
            Err(FloorErrorV1::Unavailable)
        };
        (main, sidecar, physical)
    }

    pub(super) fn finish_storage_initial_program_v2(&mut self,
        main: &aos_sandbox::Journal, receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        let sidecar = self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?.original_controller_pair_journal_v1();
        self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?
            .finish_storage_initial_program_v2(receiving, main, sidecar)
    }

    pub(super) fn storage_physical_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first_failure, Some(BrokerAttachmentFailureV1::StoragePayment)) {
            return self.storage_payment.as_ref()?.failure();
        }
        self.physical.backend_ref().and_then(|backend| backend.controller_physical_failure_v1())
            .or_else(|| self.physical.captured_ref()?.controller_physical_failure_v1())
    }

    pub(super) fn finish_controller_initial_once_v1(&mut self) -> Result<(), FloorErrorV1> {
        self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?
            .finish_controller_initial_once_v1()
    }

    pub(super) fn is_failed(&self) -> bool {
        matches!(
            self.phase,
            BrokerAttachmentPhaseV1::Checking | BrokerAttachmentPhaseV1::Failed
        )
    }

    pub(super) fn is_ready(&self) -> bool {
        self.phase == BrokerAttachmentPhaseV1::Ready
    }

    pub(super) fn fence(&mut self) {
        self.phase = BrokerAttachmentPhaseV1::Failed;
        if self.first_failure.is_none() {
            self.first_failure = Some(BrokerAttachmentFailureV1::Unfinished);
        }
    }

    pub(super) fn record_native_failure(&mut self, cause: aos_sandbox::JournalError) {
        self.record(BrokerAttachmentFailureV1::Native(cause));
    }

    pub(super) fn record_endpoint_failure(&mut self, cause: crate::BrokerSessionSecurityError) {
        self.record(BrokerAttachmentFailureV1::Endpoint(cause));
    }

    pub(super) fn failure_projection(&self) -> FloorErrorV1 {
        match &self.first_failure {
            Some(BrokerAttachmentFailureV1::Floor(error)) => *error,
            Some(BrokerAttachmentFailureV1::ControllerPayment) => FloorErrorV1::RetainedControllerPhysical,
            Some(BrokerAttachmentFailureV1::Sidecar(error)) => error.projection(),
            // Endpoint and unfinished failures keep their actual cause here;
            // the original Broker facade has always projected Unavailable.
            _ => FloorErrorV1::Unavailable,
        }
    }

    fn record(&mut self, failure: BrokerAttachmentFailureV1) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
        }
        self.phase = BrokerAttachmentPhaseV1::Failed;
    }

    pub(super) fn begin(
        &mut self,
        expected: BrokerAttachmentPhaseV1,
    ) -> Result<BrokerAttachmentOperationV1<'_>, FloorErrorV1> {
        if self.phase != expected || self.first_failure.is_some() {
            let cause = self.failure_projection();
            self.fence();
            return Err(cause);
        }
        self.phase = BrokerAttachmentPhaseV1::Checking;
        Ok(BrokerAttachmentOperationV1 {
            attempt: self,
            complete: false,
        })
    }

    pub(super) fn admit(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), FloorErrorV1> {
        self.admit_with_controller_v1(owner, profile, salt_name, auth, launch_image, None, None)
    }

    pub(super) fn admit_controller_initial_v1(
        &mut self, owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1, salt_name: [u8; 34], auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
        receiving: &mut aos_sandbox::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        self.admit_with_controller_v1(owner, profile, salt_name, auth, launch_image, Some(receiving), None)
    }

    pub(super) fn admit_storage_initial_v2(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        self.admit_with_controller_v1(owner, profile, salt_name, auth, launch_image, None, Some(receiving))
    }

    fn admit_with_controller_v1(
        &mut self, owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1, salt_name: [u8; 34], auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
        receiving: Option<&mut aos_sandbox::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        storage: Option<&mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        let selected = storage.is_some();
        if selected { owner.begin_storage_floor_main_programme_v3()?; }
        let result = self.admit_engine_with_controller_v3(owner, profile, salt_name, auth,
            launch_image, receiving, storage);
        if selected { owner.finish_storage_floor_main_programme_v3(result) }
        else { result }
    }

    fn admit_engine_with_controller_v3(
        &mut self, owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1, salt_name: [u8; 34], auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
        mut receiving: Option<&mut aos_sandbox::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        mut storage: Option<&mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        self.check_cold_deadline()?;
        match storage.as_deref_mut() {
            Some(source) => traffic::BrokerTrafficWriterV1::borrow(owner)
                .cuts_storage_receiving_v3(profile, None, source)?,
            None => traffic::BrokerTrafficWriterV1::borrow(owner).cuts(profile, None)?,
        };
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;
        if let Some(receiving) = receiving.as_deref_mut() {
            self.capture_controller_sidecar_once_v1(owner, receiving)?;
        } else if let Some(receiving) = storage.as_deref_mut() {
            self.capture_storage_sidecar_once_v2(owner, receiving)?;
            self.storage_payment = Some(crate::tpm_nv_custody::physical::BrokerPhysicalPaymentOriginalV2::new());
            let result = self.storage_payment.as_mut().ok_or(FloorErrorV1::Unavailable)?
                .prepare_storage_once_v2(receiving,
                    owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                    self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?.original_controller_pair_journal_v1(),
                    launch_image);
            if let Err(cause) = result {
                self.record(BrokerAttachmentFailureV1::StoragePayment);
                return Err(cause);
            }
        } else {
            self.opening = Some(BrokerSidecarOpenV1::prepare(
                owner.owner,
                &owner.directory,
                owner.limits,
            )?);
            if let Some(currentness) = owner.floor_currentness.as_ref() {
                self.opening.as_mut().ok_or(FloorErrorV1::Unavailable)?
                    .inherit_currentness_archive_v1(currentness)?;
            }
            self.check_cold_deadline()?;
            let result = self.opening.as_mut()
                .ok_or(FloorErrorV1::Unavailable)?
                .open();
            if let Err(cause) = result {
                let projection = cause.projection();
                self.record(BrokerAttachmentFailureV1::Sidecar(cause));
                return Err(projection);
            }
            self.opening.as_mut()
                .ok_or(FloorErrorV1::Unavailable)?
                .finish_into(&mut self.store)?;
            // Only the empty opening shell moves away; the actual sidecar is now
            // resident BEFORE traffic's original endpoint postcheck.
            self.opening = None;
        }
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;

        if let Some(receiving) = receiving.as_deref_mut() {
            // Park the entire same-C handoff and all arithmetic before lock
            // duplication, physical-owner construction, helper or PID1 work.
            self.controller_payment = Some(
                crate::tpm_nv_custody::physical::BrokerPhysicalPaymentOriginalV2::new(),
            );
            let result = self.controller_payment.as_mut().ok_or(FloorErrorV1::Unavailable)?
                .prepare_once(receiving,
                    owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                    self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?
                        .original_controller_pair_journal_v1(), launch_image);
            if let Err(cause) = result {
                self.record(BrokerAttachmentFailureV1::ControllerPayment);
                return Err(FloorErrorV1::RetainedControllerPhysical);
            }
        }

        self.main_lock = Some(
            traffic::BrokerTrafficWriterV1::borrow(owner).loan_lock_custody()?,
        );
        self.sidecar_lock = Some(
            self.store.as_ref()
                .ok_or(FloorErrorV1::Unavailable)?
                .loan_lock_custody()?,
        );
        let (main, sidecar) = (self.main_lock.take(), self.sidecar_lock.take());
        match (main, sidecar) {
            (Some(main), Some(sidecar)) => {
                // Retain is infallible on the restricted actual inputs. No gate
                // or callback can run between the OFD move and its owning slot.
                let payment = self.controller_payment.take()
                    .or_else(|| self.storage_payment.take());
                self.physical = AttachmentPhysicalV1::Captured(match payment {
                    Some(payment) => PhysicalTpmNvIoV1::retain_funded_v2(
                        profile, salt_name, auth, [main, sidecar], launch_image, payment,
                    ),
                    None => PhysicalTpmNvIoV1::retain(
                        profile, salt_name, auth, [main, sidecar], launch_image,
                    ),
                });
            }
            (main, sidecar) => {
                self.main_lock = main;
                self.sidecar_lock = sidecar;
                return Err(FloorErrorV1::Unavailable);
            }
        }
        if let Some(deadline) = self.cold_deadline {
            self.physical.captured_mut().ok_or(FloorErrorV1::Unavailable)?
                .bind_cold_deadline(deadline)?;
        }
        self.check_cold_deadline()?;
        if receiving.is_some() || storage.is_some() {
            self.physical.captured_mut().ok_or(FloorErrorV1::Unavailable)?
                .admit_funded_v2(
                    owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                    self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?
                        .original_controller_pair_journal_v1(),
                )?;
        } else {
            self.physical.captured_mut()
                .ok_or(FloorErrorV1::Unavailable)?
                .admit()?;
        }
        self.check_cold_deadline()?;
        if let Some(physical) = self.physical.take_captured() {
            self.physical = AttachmentPhysicalV1::Backend(
                TpmNvExtendFloorBackendV1::retain(profile, physical),
            );
        } else {
            return Err(FloorErrorV1::Unavailable);
        }
        // Keep both original READs: physical admission's READ precedes this
        // backend READ; both execute only after their actual owners are parked.
        if receiving.is_some() || storage.is_some() {
            let pair = controller_pair::HeldControllerFloorPairV1::from_actual_attachment_v1(
                owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?,
            );
            self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?
                .read_with_pair_v1(Some(&pair))?;
        } else {
            self.physical.backend_mut()
                .ok_or(FloorErrorV1::Unavailable)?
                .read()?;
        }
        let selected = storage.is_some();
        if let Some(source) = storage.as_deref_mut() {
            let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
            self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
                .begin_storage_read_programme_v2(main, source)?;
        }
        let result = (|| {
            let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
            let mut floor = self.borrow(&mut traffic, profile)?;
            // The initial Cold suffix uses the same F as capture and physical
            // admission. Source None must never select ordinary sidecar IO.
            floor.storage_receiving = storage.map(|source| {
                source as &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2
            });
            floor.classify()?;
            if floor.recover()? != FloorProgressV1::Current {
                return Err(FloorErrorV1::Diverged);
            }
            Ok(())
        })();
        if selected {
            self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
                .finish_storage_read_programme_v2(result)
        } else { result }
    }

    #[cfg(feature = "online-nix")]
    pub(super) fn admit_online(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        provision: &mut crate::nix_service::floor::OnlineProvisionV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        let profile = provision.profile()?;
        self.check_cold_deadline()?;
        traffic::OnlineTrafficWriterV1::borrow(owner, &mut self.native_failure)
            .purpose_cuts(FloorProfileDataV1::Online(profile), None)?;
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;
        self.opening = Some(BrokerSidecarOpenV1::prepare_online(
            owner.owner, &owner.directory, profile,
        )?);
        self.check_cold_deadline()?;
        let result = self.opening.as_mut().ok_or(FloorErrorV1::Unavailable)?.open();
        if let Err(cause) = result {
            let projected = cause.projection();
            self.record(BrokerAttachmentFailureV1::Sidecar(cause));
            return Err(projected);
        }
        self.opening.as_mut().ok_or(FloorErrorV1::Unavailable)?.finish_into(&mut self.store)?;
        self.opening = None;
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;
        self.main_lock = Some(traffic::OnlineTrafficWriterV1::borrow(owner, &mut self.native_failure)
            .loan_lock_custody()?);
        self.sidecar_lock = Some(self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?
            .loan_lock_custody()?);
        let deadline = self.cold_deadline.ok_or(FloorErrorV1::Unavailable)?;
        let mut preparation = provision.prepare_original_physical_input(profile)?;
        // The origin stays on provision until both genuine locks are ready.
        // The closed physical constructor then parks all three without gates.
        match (
            self.main_lock.take(),
            self.sidecar_lock.take(),
            preparation.take_original_origin(),
        ) {
            (Some(main), Some(sidecar), Some(origin)) => {
                self.physical = AttachmentPhysicalV1::Captured(PhysicalTpmNvIoV1::retain_online(
                    &preparation, [main, sidecar], origin, deadline,
                ));
                preparation.finish_original_transfer();
            }
            (main, sidecar, origin) => {
                self.main_lock = main;
                self.sidecar_lock = sidecar;
                preparation.restore_original_origin(origin);
                return Err(FloorErrorV1::Unavailable);
            }
        }
        self.check_cold_deadline()?;

        if self.online_admission_result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        let result = self.physical.captured_mut().ok_or(FloorErrorV1::Unavailable)?.admit_online();
        self.online_admission_result = Some(result);
        if let Some(Err(cause)) = self.online_admission_result {
            return Err(cause);
        }

        self.check_cold_deadline()?;
        if let Some(physical) = self.physical.take_captured() {
            self.physical = AttachmentPhysicalV1::Backend(
                TpmNvExtendFloorBackendV1::retain_online(profile, physical),
            );
        } else {
            return Err(FloorErrorV1::Unavailable);
        }
        // Physical admission's READ and this backend READ remain distinct.
        self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?.read()?;
        let mut traffic = traffic::OnlineTrafficWriterV1::borrow(owner, &mut self.native_failure);
        let mut floor = BorrowedDurableFloorV1 {
            storage_receiving: None,
            backend: self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?,
            store: self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?,
            traffic: &mut traffic,
            profile: FloorProfileDataV1::Online(profile),
            cold_deadline: self.cold_deadline,
            cold_failure: Some(&mut self.cold_failure),
        };
        floor.classify()?;
        if floor.recover()? != FloorProgressV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    #[cfg(feature = "online-nix")]
    pub(super) fn use_online(
        &mut self, owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: crate::tpm_nv_custody::OnlineFloorProfileV1,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking || self.native_failure.is_some() {
            return Err(self.failure_projection());
        }
        let mut traffic = traffic::OnlineTrafficWriterV1::borrow(owner, &mut self.native_failure);
        let mut floor = BorrowedDurableFloorV1 {
            storage_receiving: None,
            backend: self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?,
            store: self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?,
            traffic: &mut traffic,
            profile: FloorProfileDataV1::Online(profile),
            cold_deadline: self.cold_deadline,
            cold_failure: Some(&mut self.cold_failure),
        };
        floor.require_current()?;
        if let Some(transaction) = transaction {
            floor.prepare(transaction)?;
            if floor.recover()? != FloorProgressV1::Current {
                return Err(FloorErrorV1::Diverged);
            }
        }
        Ok(())
    }

    /// Keeps the same physical attachment checking through both bookends.
    #[cfg(feature = "online-nix")]
    pub(super) fn check_online_existing_output_suffix(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: crate::tpm_nv_custody::OnlineFloorProfileV1,
        prepared_widths: [usize; 3],
    ) -> Result<(), FloorErrorV1> {
        self.use_online(owner, profile, None)?;
        self.check_cold_deadline()?;
        let result = self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .check_online_suffix_capacity(profile, prepared_widths, &mut self.native_failure);
        if let Err(cause) = result {
            if let Some(native) = self.native_failure.take() {
                // An infallible transfer into the first-cause tag happens
                // immediately; no observation runs with the error unowned.
                self.record_native_failure(native);
            }
            return Err(cause);
        }
        self.check_cold_deadline()?;
        self.use_online(owner, profile, None)
    }

    fn require_endpoint(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        if let Err(cause) = owner.endpoint.revalidate() {
            self.record(BrokerAttachmentFailureV1::Endpoint(cause));
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(super) fn check(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        self.check_with_storage_receiving_v2(owner, profile, None)
    }

    pub(super) fn reserve_storage_availability_receiving_v3(&self,
        owner: &super::super::ProtectedBrokerSessionJournalV1,
        receiving: &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2,
        complete: aos_sandbox_core::ResourceVector,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Ready || self.first_failure.is_some() {
            return Err(self.failure_projection());
        }
        let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let sidecar = self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?
            .original_controller_pair_journal_v1();
        receiving.reserve_availability_v3(main, sidecar, complete).map_err(|_| FloorErrorV1::Unavailable)
    }

    pub(super) fn check_with_storage_receiving_v2<'operation>(&'operation mut self,
        owner: &'operation mut super::super::ProtectedBrokerSessionJournalV1, profile: FloorProfileV1,
        receiving: Option<&'operation mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), FloorErrorV1> {
        self.current_checkpoint_with_storage_receiving_v3(owner, profile, receiving).map(|_| ())
    }

    pub(super) fn current_checkpoint_with_storage_receiving_v3<'operation>(&'operation mut self,
        owner: &'operation mut super::super::ProtectedBrokerSessionJournalV1, profile: FloorProfileV1,
        receiving: Option<&'operation mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<crate::tpm_nv_custody::FloorCheckpointDataV1, FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        let mut receiving = receiving;
        let selected = receiving.is_some();
        if selected { owner.begin_storage_floor_main_programme_v3()?; }
        let result = (|| {
            if let Some(source) = receiving.as_mut() {
                let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
                self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
                    .begin_storage_read_programme_v2(main, &mut **source)?;
            }
            let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
            let mut floor = self.borrow(&mut traffic, profile)?;
            floor.storage_receiving = receiving;
            floor.current_checkpoint_v3()
        })();
        let result = if selected {
            match self.store.as_mut() {
                Some(store) => store.finish_storage_read_programme_v2(result),
                None => Err(FloorErrorV1::Unavailable),
            }
        } else { result };
        if selected { owner.finish_storage_floor_main_programme_v3(result) }
        else { result }
    }

    pub(super) fn commit(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.commit_with_storage_receiving_v2(owner, profile, transaction, None)
    }

    pub(super) fn commit_with_storage_receiving_v2<'operation>(&'operation mut self,
        owner: &'operation mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1, transaction: &JournalTransaction,
        receiving: Option<&'operation mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        let mut receiving = receiving;
        let selected = receiving.is_some();
        if selected { owner.begin_storage_floor_main_programme_v3()?; }
        let result = (|| {
            if let Some(source) = receiving.as_mut() {
                let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
                self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?
                    .begin_storage_read_programme_v2(main, &mut **source)?;
            }
            let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
            let mut floor = self.borrow(&mut traffic, profile)?;
            floor.storage_receiving = receiving;
            floor.prepare(transaction)?;
            if floor.recover()? != FloorProgressV1::Current {
                return Err(FloorErrorV1::Diverged);
            }
            Ok(())
        })();
        let result = if selected {
            match self.store.as_mut() {
                Some(store) => store.finish_storage_read_programme_v2(result),
                None => Err(FloorErrorV1::Unavailable),
            }
        } else { result };
        if selected { owner.finish_storage_floor_main_programme_v3(result) }
        else { result }
    }

    fn borrow<'operation, 'receiving, Traffic: HeldTrafficWriterV1>(
        &'operation mut self,
        traffic: &'operation mut Traffic,
        profile: FloorProfileV1,
    ) -> Result<BorrowedDurableFloorV1<'operation, 'receiving, Traffic, PhysicalTpmNvIoV1>, FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        Ok(BorrowedDurableFloorV1 {
            storage_receiving: None,
            backend: self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?,
            store: self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?,
            traffic,
            profile: FloorProfileDataV1::Broker(profile),
            cold_deadline: self.cold_deadline,
            cold_failure: Some(&mut self.cold_failure),
        })
    }
}

pub(super) struct BrokerAttachmentOperationV1<'operation> {
    pub(super) attempt: &'operation mut BrokerAttachmentAttemptV1,
    complete: bool,
}

impl BrokerAttachmentOperationV1<'_> {
    pub(super) fn finish<T>(mut self, result: Result<T, FloorErrorV1>) -> Result<T, FloorErrorV1> {
        let result = match result {
            Ok(value) => self.attempt.check_cold_deadline().map(|()| value),
            Err(cause) => Err(cause),
        };
        let result = match result {
            Ok(value)
                if self.attempt.phase == BrokerAttachmentPhaseV1::Checking
                    && self.attempt.first_failure.is_none()
                    && self.attempt.cold_failure.is_none() =>
            {
                self.attempt.phase = BrokerAttachmentPhaseV1::Ready;
                Ok(value)
            }
            Ok(_) => {
                self.attempt.fence();
                Err(self.attempt.failure_projection())
            }
            Err(cause) => {
                self.attempt.record(BrokerAttachmentFailureV1::Floor(cause));
                Err(cause)
            }
        };
        self.complete = true;
        result
    }
}

impl Drop for BrokerAttachmentOperationV1<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.attempt.fence();
        }
    }
}

pub(super) fn attach_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    profile: FloorProfileV1,
    make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor = DurableTpmFloorV1::open_with_factory(
        traffic::BrokerTrafficWriterV1::borrow(owner),
        profile,
        make_io,
    )?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn check_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.require_current()?;
    Ok(floor.detach())
}

pub(super) fn commit_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
    transaction: &JournalTransaction,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.prepare(transaction)?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn commit_unfloored_broker_v1(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    traffic::commit_owned_traffic_transaction_v1(owner, transaction, None)?;
    owner
        .validate_schema_only()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)
}

/// Retains the actual traffic writer, sidecar flock, and authenticated NV backend.
pub(super) struct DurableTpmFloorV1<Traffic, Io> {
    // Stop the TPM carrier before releasing either retained writer.
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    traffic: Traffic,
    profile: FloorProfileV1,
}

/// Describes a completed local check, never a public readiness/effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloorProgressV1 {
    Current,
    NvNotAdvanced,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1> DurableTpmFloorV1<Traffic, Io> {
    /// Opens existing names only after the real fixed endpoint writer has revalidated.
    pub(super) fn open(
        traffic: Traffic,
        profile: FloorProfileV1,
        io: Io,
    ) -> Result<Self, FloorErrorV1> {
        Self::open_with_factory(traffic, profile, |_| Ok(io))
    }

    fn open_with_factory(
        mut traffic: Traffic,
        profile: FloorProfileV1,
        make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
    ) -> Result<Self, FloorErrorV1> {
        traffic.cuts(profile, None)?;
        let store = traffic.open_floor_store()?;
        let locks = [traffic.loan_lock_custody()?, store.loan_lock_custody()?];
        let backend = TpmNvExtendFloorBackendV1::open(profile, make_io(locks)?)?;
        let mut owner = Self {
            traffic,
            store,
            backend,
            profile,
        };
        owner.classify()?;
        Ok(owner)
    }

    // Owning compatibility callers and resident production callers execute
    // this same algorithm through references to their exact original fields.
    fn borrow(&mut self) -> BorrowedDurableFloorV1<'_, '_, Traffic, Io> {
        BorrowedDurableFloorV1 {
            storage_receiving: None,
            backend: &mut self.backend,
            store: &mut self.store,
            traffic: &mut self.traffic,
            profile: FloorProfileDataV1::Broker(self.profile),
            cold_deadline: None,
            cold_failure: None,
        }
    }

    pub(super) fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        self.borrow().prepare(transaction)
    }

    pub(super) fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
        self.borrow().recover()
    }

    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        self.borrow().require_current()
    }

    /// Releases only the temporary traffic borrow, retaining sidecar and TPM custody.
    pub(super) fn detach(self) -> AttachedFloorV1<Io> {
        AttachedFloorV1 {
            store: self.store,
            backend: self.backend,
            profile: self.profile,
        }
    }

    pub(super) fn resume(traffic: Traffic, attached: AttachedFloorV1<Io>) -> Self {
        Self {
            traffic,
            store: attached.store,
            backend: attached.backend,
            profile: attached.profile,
        }
    }

    fn classify(&mut self) -> Result<(StoredFloorV1, FloorRecoveryV1), FloorErrorV1> {
        let (stored, phase) = self.borrow().classify()?;
        Ok((stored.into_broker()?, phase))
    }
}

enum BorrowedSidecarModelV2 {
    Ordinary(StoredFloorDataV1),
    Storage(std::sync::Arc<StoredFloorDataV1>),
}

impl std::ops::Deref for BorrowedSidecarModelV2 {
    type Target = StoredFloorDataV1;

    fn deref(&self) -> &Self::Target {
        match self { Self::Ordinary(stored) => stored, Self::Storage(stored) => stored }
    }
}

impl BorrowedSidecarModelV2 {
    fn into_broker(self) -> Result<StoredFloorV1, FloorErrorV1> {
        match self {
            Self::Ordinary(stored) => stored.into_broker(),
            // Owning compatibility callers never borrow the selected F source.
            Self::Storage(_) => Err(FloorErrorV1::Unavailable),
        }
    }
}

// A temporary borrow, never a second owner, cached authority or policy factory.
// The local traffic adapter and the genuine financial source have independent
// borrow durations. A stack-local traffic adapter never extends to the source's
// outer borrow; neither reference nor the original-F receipt escapes this turn.
pub(super) struct BorrowedDurableFloorV1<'operation, 'receiving, Traffic, Io> {
    storage_receiving: Option<&'receiving mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    backend: &'operation mut TpmNvExtendFloorBackendV1<Io>,
    store: &'operation mut FloorStoreV1,
    traffic: &'operation mut Traffic,
    profile: FloorProfileDataV1,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    cold_failure: Option<&'operation mut Option<crate::DormantBrokerSessionHandshakeErrorV1>>,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1>
    BorrowedDurableFloorV1<'_, '_, Traffic, Io>
{
    fn read_sidecar_v2(&mut self) -> Result<BorrowedSidecarModelV2, FloorErrorV1> {
        match self.storage_receiving.as_mut() {
            Some(receiving) => {
                let FloorProfileDataV1::Broker(profile) = self.profile else {
                    return Err(FloorErrorV1::Provisioning);
                };
                let main = self.traffic.original_controller_pair_journal_v1()
                    .ok_or(FloorErrorV1::Unavailable)?;
                self.store.read_storage_receiving_v2(main, &mut **receiving, profile)
                    .map(BorrowedSidecarModelV2::Storage)
            }
            None => self.store.read_data(self.profile).map(BorrowedSidecarModelV2::Ordinary),
        }
    }

    fn require_same_sidecar_v2(&mut self, stored: &StoredFloorDataV1) -> Result<(), FloorErrorV1> {
        if self.storage_receiving.is_none() {
            return self.store.require_same_data(stored, self.profile);
        }
        if self.read_sidecar_v2()?.view() == stored.view() { Ok(()) }
        else { Err(FloorErrorV1::Diverged) }
    }

    fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        check_borrowed_cold_deadline(self.cold_deadline, &mut self.cold_failure)
    }

    /// Persists the full exact transaction before the first possible NV extension.
    ///
    /// A failure after the append grants no vacant preparation or retry. The
    /// consuming compatibility owner must be reopened; Required production
    /// keeps its failed originals resident and refuses reopening that owner.
    pub(super) fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        self.require_storage_programme_originals_v3()?;
        self.check_cold_deadline()?;
        let stored = self.read_sidecar_v2()?;
        self.check_cold_deadline()?;
        if stored.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        let (current, target) = self.main_cuts_v3(Some(transaction))?;
        self.check_cold_deadline()?;
        if current != stored.checkpoint.cut()
            || self.read_backend_with_pair_v1()? != stored.checkpoint.nv_value()
        {
            return Err(FloorErrorV1::Diverged);
        }
        let target = target.ok_or(FloorErrorV1::Successor)?;
        let intent = self.new_sidecar_intent_v2(stored.checkpoint, target, transaction)?;
        self.check_cold_deadline()?;
        self.prepare_sidecar_v2(&stored, intent, transaction)?;
        self.check_cold_deadline()?;

        // A changed traffic name/cut after durable prepare closes recovery. It
        // does not replace the retained target or roll the preparation back.
        let (after, prospective) = self.main_cuts_v3(Some(transaction))?;
        if after != current || prospective != Some(target) {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        let retained = self.read_sidecar_v2()?;
        self.check_cold_deadline()?;
        if retained.checkpoint != stored.checkpoint
            || !retained
                .prepared
                .as_ref()
                .is_some_and(|(retained_intent, retained_transaction)| {
                    *retained_intent == intent && retained_transaction == transaction
                })
        {
            return Err(FloorErrorV1::Diverged);
        }
        self.require_same_sidecar_v2(&retained)?;
        if self.read_backend_with_pair_v1()? != stored.checkpoint.nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    /// Finishes only the exact persisted transaction; no new request/nonce is allocated.
    pub(super) fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
        self.require_storage_programme_originals_v3()?;
        let (stored, phase) = self.classify()?;
        let Some((intent, transaction)) = stored.prepared.as_ref() else {
            return if phase == FloorRecoveryV1::Current {
                Ok(FloorProgressV1::Current)
            } else {
                Err(FloorErrorV1::Diverged)
            };
        };
        self.require_sidecar_transaction_v2(*intent, transaction)?;

        if phase == FloorRecoveryV1::ExtendPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            let advanced = self.advance_backend_with_pair_v1(
                *intent, &suffix, &stored, transaction,
            )?;
            if advanced == FloorAdvanceV1::NotAdvanced {
                self.classify()?;
                return Ok(FloorProgressV1::NvNotAdvanced);
            }
        }
        let (stored, phase) = self.classify()?;
        let (intent, transaction) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if phase == FloorRecoveryV1::CommitPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            if self.read_backend_with_pair_v1()? != intent.target().nv_value() {
                return Err(FloorErrorV1::Diverged);
            }
            self.require_prospective_cut_v2(*intent, transaction)?;
            self.validate_sidecar_preflight_v2(&suffix, &stored)?;
            self.check_cold_deadline()?;
            self.commit_main_v3(*intent, transaction)?;
            self.check_cold_deadline()?;
        }

        let (stored, phase) = self.classify()?;
        if phase != FloorRecoveryV1::FinalizePrepared {
            return Err(FloorErrorV1::Diverged);
        }
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if self.read_backend_with_pair_v1()? != intent.target().nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        self.finalize_sidecar_v2(&stored)?;
        self.check_cold_deadline()?;
        let (_, phase) = self.classify()?;
        if phase != FloorRecoveryV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(FloorProgressV1::Current)
    }

    /// Rejects pending recovery at ordinary read/use boundaries.
    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        self.current_checkpoint_v3().map(|_| ())
    }

    fn current_checkpoint_v3(&mut self) -> Result<crate::tpm_nv_custody::FloorCheckpointDataV1, FloorErrorV1> {
        let (stored, phase) = self.classify()?;
        if phase == FloorRecoveryV1::Current {
            Ok(stored.checkpoint)
        } else {
            Err(FloorErrorV1::Diverged)
        }
    }

    fn classify(&mut self) -> Result<(BorrowedSidecarModelV2, FloorRecoveryV1), FloorErrorV1> {
        self.check_cold_deadline()?;
        let stored = self.read_sidecar_v2()?;
        self.check_cold_deadline()?;
        let (cut, _) = self.main_cuts_v3(None)?;
        self.check_cold_deadline()?;
        let nv = self.read_backend_with_pair_v1()?;
        self.check_cold_deadline()?;
        self.require_same_sidecar_v2(&stored)?;
        self.check_cold_deadline()?;
        let (after, _) = self.main_cuts_v3(None)?;
        self.check_cold_deadline()?;
        if after != cut {
            return Err(FloorErrorV1::Diverged);
        }
        let phase = reconcile_floor_data_v1(
            self.profile,
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, _)| *intent),
            cut,
            nv,
        )?;
        Ok((stored, phase))
    }

    fn require_prospective(
        &mut self,
        stored: &StoredFloorDataV1,
        intent: FloorIntentDataV1,
        transaction: &JournalTransaction,
    ) -> Result<BorrowedFinalSuffixV2, FloorErrorV1> {
        self.require_prospective_cut_v2(intent, transaction)?;
        self.check_cold_deadline()?;
        let suffix = self.preflight_sidecar_final_v2(stored)?;
        self.check_cold_deadline()?;
        self.require_same_sidecar_v2(stored)?;
        self.check_cold_deadline()?;
        Ok(suffix)
    }
}

fn check_borrowed_cold_deadline(
    deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    failure: &mut Option<&mut Option<crate::DormantBrokerSessionHandshakeErrorV1>>,
) -> Result<(), FloorErrorV1> {
    if let Some(deadline) = deadline {
        if let Err(cause) = deadline.check() {
            if let Some(slot) = failure.as_mut() {
                if slot.is_none() {
                    **slot = Some(cause);
                }
            }
            return Err(FloorErrorV1::Unavailable);
        }
    }
    Ok(())
}

fn require_prospective_cut(
    traffic: &mut impl HeldTrafficWriterV1,
    profile: FloorProfileDataV1,
    intent: FloorIntentDataV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    intent.require_transaction(transaction)?;
    require_prospective_cut_after_binding_v2(traffic, profile, intent, transaction)
}

fn require_prospective_cut_after_binding_v2(
    traffic: &mut impl HeldTrafficWriterV1,
    profile: FloorProfileDataV1,
    intent: FloorIntentDataV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    let (current, target) = traffic.purpose_cuts(profile, Some(transaction))?;
    if current != intent.predecessor().cut() || target != Some(intent.target().cut()) {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(())
}

#[cfg(test)]
mod cold_cutoff_data_tests {
    use super::check_borrowed_cold_deadline;

    #[test]
    fn legacy_none_performs_no_clock_check_or_cause_replacement() {
        let mut cause = Some(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        let mut slot = Some(&mut cause);

        assert!(check_borrowed_cold_deadline(None, &mut slot).is_ok());
        assert!(matches!(
            cause,
            Some(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        ));
    }
}

/// Retains the two non-traffic owners between opaque reconciliation borrows.
pub(super) struct AttachedFloorV1<Io> {
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    profile: FloorProfileV1,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod resident_attempt_tests {
    use super::*;

    #[test]
    fn only_the_same_successful_attempt_reopens_ready() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        attempt.begin(BrokerAttachmentPhaseV1::Fresh).unwrap()
            .finish(Ok(())).unwrap();
        assert!(attempt.is_ready());

        let error = attempt.begin(BrokerAttachmentPhaseV1::Ready).unwrap()
            .finish::<()>(Err(FloorErrorV1::Provisioning));
        assert_eq!(error, Err(FloorErrorV1::Provisioning));
        assert!(attempt.is_failed());
        assert!(attempt.begin(BrokerAttachmentPhaseV1::Ready).is_err());
        assert_eq!(attempt.failure_projection(), FloorErrorV1::Provisioning);
    }

    #[test]
    fn dropped_forgotten_and_caught_unwind_attempts_are_failed() {
        let mut dropped = BrokerAttachmentAttemptV1::fresh();
        drop(dropped.begin(BrokerAttachmentPhaseV1::Fresh).unwrap());
        assert!(dropped.is_failed());

        let mut forgotten = BrokerAttachmentAttemptV1::fresh();
        std::mem::forget(forgotten.begin(BrokerAttachmentPhaseV1::Fresh).unwrap());
        assert!(forgotten.is_failed());
        assert!(forgotten.begin(BrokerAttachmentPhaseV1::Fresh).is_err());

        let mut unwound = BrokerAttachmentAttemptV1::fresh();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _operation = unwound.begin(BrokerAttachmentPhaseV1::Fresh).unwrap();
            panic!("pure attempt unwind");
        }));
        assert!(caught.is_err());
        assert!(unwound.is_failed());
    }

    #[test]
    fn a_closed_attempt_cannot_be_restored_by_an_ok_result() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        let operation = attempt.begin(BrokerAttachmentPhaseV1::Fresh).unwrap();
        operation.attempt.record(BrokerAttachmentFailureV1::Floor(FloorErrorV1::Diverged));

        assert_eq!(operation.finish(Ok(())), Err(FloorErrorV1::Diverged));
        assert!(attempt.is_failed());
    }

    #[test]
    fn first_native_cause_is_not_replaced_by_projection_or_unfinished() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        attempt.record_native_failure(aos_sandbox::JournalError::ProtectedBoundary);
        attempt.record(BrokerAttachmentFailureV1::Floor(FloorErrorV1::Successor));
        attempt.fence();

        assert!(matches!(
            &attempt.first_failure,
            Some(BrokerAttachmentFailureV1::Native(aos_sandbox::JournalError::ProtectedBoundary))
        ));
        assert_eq!(attempt.failure_projection(), FloorErrorV1::Unavailable);
    }

    #[test]
    fn refused_empty_physical_phase_preserves_native_cause_and_owed_posts() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        attempt.controller_selected = true;
        attempt.record_native_failure(aos_sandbox::JournalError::ProtectedBoundary);
        let first = attempt.first_failure.as_ref().unwrap() as *const _;

        assert!(attempt.physical.take_captured().is_none());
        assert!(attempt.physical.backend_mut().is_none());
        assert!(attempt.begin(BrokerAttachmentPhaseV1::Fresh).is_err());

        assert!(attempt.physical.is_empty());
        assert_eq!(attempt.first_failure.as_ref().unwrap() as *const _, first);
        assert!(attempt.has_controller_owed_v1());
        assert!(!attempt.controller_owed_consumed);
        assert!(attempt.controller_posts.is_none());
        assert_eq!(attempt.failure_projection(), FloorErrorV1::Unavailable);
    }
}

impl BrokerAttachmentAttemptV1 {
    pub(super) fn retire_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &aos_sandbox::Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.is_ready() || self.first_failure.is_some() || self.cold_failure.is_some()
            || self.native_failure.is_some() || !self.controller_selected
            || !matches!(self.controller_primary, Some(Ok(())))
            || self.controller_posts.is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        let sidecar = self.store.as_ref().ok_or(FloorErrorV1::Unavailable)?
            .original_controller_pair_journal_v1();
        self.physical.backend_mut().ok_or(FloorErrorV1::Unavailable)?
            .retire_completed_initial_native_v1(completed, main, sidecar)
    }
}
