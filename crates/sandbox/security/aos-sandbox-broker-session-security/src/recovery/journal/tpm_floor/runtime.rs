//! Attaches the physical floor to the actual two fixed Storage journal owners.
//!
//! Required mode retains the sidecar and helper between opaque traffic borrows.
//! A private whole-owner guard keeps raw public reads unavailable during each
//! reconciliation and restores that same fenced floor on unwind. Schema-only validation
//! is private and grants no currentness. There is no reentrant boolean bypass.
//! Legacy mode admits unrelated Storage traffic but cannot adopt a sidecar or
//! any retained execution-output (46/47/48) history. Public method 46 remains
//! closed pending installed physical TPM/use-boundary qualification.

mod legacy_cold;

mod presence;
pub(crate) use presence::{ModePresenceOriginalV1, mode_presence_receiving_demand_v1};

mod initial;
pub(in crate::recovery::journal) use initial::InitialFloorConfigurationOriginalV1;

use std::path::Path;

use legacy_cold::LegacyColdIntervalV1;

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_controller_domain::{JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};

use super::FloorErrorV1;
use super::durable::{
    BrokerAttachmentAttemptV1, BrokerAttachmentPhaseV1, commit_unfloored_broker_v1,
};
use super::format::FloorEndpointV1;
use super::provisioning::{ImageFloorModeV1, ModePinV1, ProvisionPinV1};
use crate::recovery::journal::{
    BrokerSessionJournalKeyKind, ProtectedBrokerSessionJournalV1, StoredProtocolHistoryV1,
    classified_broker_session_key,
};

/// Deliberately false until physical producer and both installed hooks qualify.
const METHOD46_INSTALLED_QUALIFIED: bool = false;

/// Keeps image mode and physical custody private to the actual journal owner.
pub(in crate::recovery::journal) struct BrokerFloorV1 {
    state: FloorStateV1,
}

enum FloorStateV1 {
    NotScoped,
    ClientColdNotScoped {
        cold: LegacyColdIntervalV1,
    },
    Unavailable,
    Legacy {
        mode: ModePinV1,
        cold: LegacyColdIntervalV1,
    },
    Required {
        mode: ModePinV1,
        provision: ProvisionPinV1,
        launch_image: crate::production_startup::Pid1LaunchImageV1,
        attached: BrokerAttachmentAttemptV1,
    },
    #[cfg(feature = "online-nix")]
    Online {
        provision: crate::nix_service::floor::OnlineProvisionV1,
        attached: BrokerAttachmentAttemptV1,
        postflights: [Option<(Result<(), FloorErrorV1>, Result<(), FloorErrorV1>)>;
            crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1],
    },
}

impl BrokerFloorV1 {
    pub(in crate::recovery::journal) fn reserve_storage_availability_receiving_v3(&self,
        owner: &ProtectedBrokerSessionJournalV1,
        receiving: &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2,
        complete: aos_sandbox_model::ResourceVector,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Required { provision, attached, .. } = &self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        if provision.profile().endpoint() != FloorEndpointV1::StorageBroker {
            return Err(FloorErrorV1::Provisioning);
        }
        attached.reserve_storage_availability_receiving_v3(owner, receiving, complete)
    }

    pub(in crate::recovery::journal) fn observe_storage_availability_receiving_v3(&mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2,
    ) -> Result<(super::FloorProfileV1, super::FloorCheckpointV1), FloorErrorV1> {
        if matches!(&self.state, FloorStateV1::Required { attached, .. } if attached.has_controller_owed_v1()) {
            // The failed primary still owes its already-paid mode/provision,
            // main, sidecar and physical observations. Reuse that exact shared
            // continuation before refusing a new availability observation.
            self.check_with_storage_receiving_v2(owner, Some(receiving))?;
            return Err(FloorErrorV1::Unavailable);
        }
        let FloorStateV1::Required { mode, provision, attached, .. } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        let profile = provision.profile();
        if profile.endpoint() != FloorEndpointV1::StorageBroker {
            return Err(FloorErrorV1::Provisioning);
        }
        let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
        let result = (|| {
            mode.revalidate()?;
            provision.revalidate()?;
            let checkpoint = operation.attempt.current_checkpoint_with_storage_receiving_v3(
                owner, profile, Some(receiving))?;
            provision.revalidate()?;
            mode.revalidate()?;
            match checkpoint {
                crate::tpm_nv_custody::FloorCheckpointDataV1::Broker(checkpoint) => Ok((profile, checkpoint)),
                _ => Err(FloorErrorV1::Provisioning),
            }
        })();
        operation.finish(result)
    }

    pub(in crate::recovery::journal) fn install_initial_broker_currentness_archive_v2(
        &mut self,
        archive: crate::recovery::journal::floor_revalidation::FloorCurrentnessSharedV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { mode, provision, attached, .. } => {
                // The same B/main association and shape debit precede this
                // private call. No sidecar or physical owner exists yet; its
                // actual later capture inherits the SAME archive from main.
                if !attached.is_fresh_for_controller_v1() { return Err(FloorErrorV1::Unavailable); }
                mode.install_currentness_archive_v1(&archive)?;
                provision.install_currentness_archive_v1(&archive)
            }
            _ => self.install_currentness_archive_v1(archive),
        }
    }

    pub(in crate::recovery::journal) fn install_currentness_archive_v1(
        &mut self,
        archive: crate::recovery::journal::floor_revalidation::FloorCurrentnessSharedV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Legacy { mode, .. } => mode.install_currentness_archive_v1(&archive),
            FloorStateV1::Required { mode, provision, attached, .. } => {
                mode.install_currentness_archive_v1(&archive)?;
                provision.install_currentness_archive_v1(&archive)?;
                attached.install_currentness_archive_v1(archive)
            }
            // Arming is only for the already-held fixed Storage owner; it
            // cannot provision a physical floor or select an online profile.
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal) fn online(provision: crate::nix_service::floor::OnlineProvisionV1) -> Self {
        Self { state: FloorStateV1::Online {
            provision, attached: BrokerAttachmentAttemptV1::fresh(),
            postflights: [const { None }; crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1],
        } }
    }

    /// Compares only available retained custody, never NV or floor currentness.
    ///
    /// The unavailable original credential-File observation stays in its own
    /// slot. It is not projected into a failure of otherwise available custody
    /// or treated as a fresh proof. Healthy eligibility still comes exclusively
    /// from the unchanged positive floor/currentness recipe at the caller.
    ///
    /// # Errors
    /// Returns unavailable when the actual attachment comparison fails, its
    /// original custody is missing or fenced, or the fixed archive is full.
    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal) fn observe_online_postflight(
        &mut self,
        _owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Online { attached, postflights, .. } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        let slot = postflights.iter_mut().find(|slot| slot.is_none())
            .ok_or(FloorErrorV1::Unavailable)?;
        *slot = Some((Err(FloorErrorV1::Unavailable), Err(FloorErrorV1::Unavailable)));
        let Some((provision_result, attachment_result)) = slot.as_mut() else {
            return Err(FloorErrorV1::Unavailable);
        };

        // The old loader retains bytes, not original credential Files. Its
        // positive revalidate would reopen names, so it cannot establish a
        // retained negative observation here. Keep that custody unavailable;
        // the actual retained attachment is observed independently below.
        *provision_result = Err(FloorErrorV1::Unavailable);
        *attachment_result = attached.observe_online_postflight();
        if attachment_result.is_err() {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(in crate::recovery::journal) fn finish_storage_initial_program_v2(&mut self,
        main: &aos_sandbox_controller_domain::Journal, receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.finish_storage_initial_program_v2(main, receiving),
            _ => Ok(()),
        }
    }

    pub(in crate::recovery::journal) fn storage_physical_failure_v2(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        match &self.state {
            FloorStateV1::Required { attached, .. } => attached.storage_physical_failure_v2(),
            _ => None,
        }
    }

    pub(in crate::recovery::journal) fn storage_sidecar_failure_v2(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        match &self.state {
            FloorStateV1::Required { attached, .. } => attached.storage_sidecar_failure_v2(),
            _ => None,
        }
    }

    pub(in crate::recovery::journal) fn controller_physical_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        match &self.state {
            FloorStateV1::Required { attached, .. } => attached.controller_physical_failure_v1(),
            _ => None,
        }
    }

    pub(in crate::recovery::journal) fn controller_property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        match &self.state {
            FloorStateV1::Required { attached, .. } => attached.controller_property_failure_view_v1(),
            _ => None,
        }
    }

    pub(in crate::recovery::journal) fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.check_cold_deadline(),
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { attached, .. } => attached.check_cold_deadline(),
            FloorStateV1::Legacy { cold, .. }
            | FloorStateV1::ClientColdNotScoped { cold } => cold.require_current(),
            _ => Ok(()),
        }
    }

    pub(in crate::recovery::journal) fn bind_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.bind_cold_deadline(deadline),
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { attached, .. } => attached.bind_cold_deadline(deadline),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) fn retire_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.retire_cold_deadline(deadline),
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { attached, .. } => attached.retire_cold_deadline(deadline),
            FloorStateV1::Legacy { cold, .. }
            | FloorStateV1::ClientColdNotScoped { cold } => cold.retire(deadline),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) const fn unavailable() -> Self {
        Self {
            state: FloorStateV1::Unavailable,
        }
    }

    #[cfg(test)]
    pub(in crate::recovery::journal) const fn test_not_scoped() -> Self {
        Self {
            state: FloorStateV1::NotScoped,
        }
    }

    pub(in crate::recovery::journal) fn configure(
        directory: &Path,
        protocol: BrokerSessionProtocolV1,
        role: BrokerSessionDurableEndpointV1,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Result<Self, FloorErrorV1> {
        let mut original = InitialFloorConfigurationOriginalV1::new();
        original.configure_with_custody_once(
            directory, protocol, role, launch_image,
            super::provisioning::CredentialReadCustodyV1::Ordinary,
        )?;
        original.take_floor_once().ok_or(FloorErrorV1::Unavailable)
    }

    pub(in crate::recovery::journal) fn requires_existing(&self) -> bool {
        #[cfg(feature = "online-nix")]
        if matches!(&self.state, FloorStateV1::Online { .. }) {
            return true;
        }
        matches!(
            self.state,
            FloorStateV1::Required { .. } | FloorStateV1::Unavailable
        )
    }

    // Only this actual private state owns the resident attempt that must
    // survive unfinished operations. Other dispositions retain legacy Drop.
    pub(in crate::recovery::journal) fn has_resident_required_attempt(&self) -> bool {
        #[cfg(feature = "online-nix")]
        if matches!(&self.state, FloorStateV1::Online { .. }) {
            return true;
        }
        matches!(&self.state, FloorStateV1::Required { .. })
    }

    /// Binds ordinary cold custody while borrowing the genuine receiving loan.
    ///
    /// The MainOpen caller selects the exact fixed Storage broker role. This
    /// comparison neither spends the loan nor selects physical-floor authority.
    ///
    /// # Errors
    /// Rejects unpaid/stale Native custody, another mode, repeated/expired
    /// custody, or changed mode/sidecars.
    pub(in crate::recovery::journal) fn bind_storage_receiving_cold(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        receiving.require_session_fixed_current_v1()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let FloorStateV1::Legacy { mode, cold } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        cold.bind(deadline)?;
        mode.revalidate()?;
        require_no_floor_names(Path::new("/var/lib/aos/sandbox-storage/broker-session"))?;
        mode.revalidate()?;
        cold.check()
    }

    // The non-Storage Host client has no TPM floor. It still binds and
    // retires the same immutable cold deadline through the existing engine.
    pub(in crate::recovery::journal) fn bind_storage_host_cold_v1(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        self.bind_unscoped_cold_v4(deadline)
    }

    pub(in crate::recovery::journal) fn bind_fixed_service_cold_v4(
        &mut self, deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        self.bind_unscoped_cold_v4(deadline)
    }

    fn bind_unscoped_cold_v4(
        &mut self, deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if matches!(self.state, FloorStateV1::NotScoped) {
            self.state = FloorStateV1::ClientColdNotScoped { cold: LegacyColdIntervalV1::new() };
        }
        let FloorStateV1::ClientColdNotScoped { cold } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        cold.bind(deadline)
    }

    /// Binds the same initial Controller cutoff after actual main take/arming.
    ///
    /// The closed Main caller joins role, node, root and actual Journal before
    /// this call. Required remains unavailable until its distinct sidecar phase.
    pub(in crate::recovery::journal) fn bind_controller_initial_cold_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        use aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1 as Role;

        let role = receiving.role_v1();
        receiving.require_fixed_capture_current_v1(role)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        if matches!(&self.state, FloorStateV1::NotScoped) {
            if role == Role::Storage {
                return Err(FloorErrorV1::Unavailable);
            }
            self.state = FloorStateV1::ClientColdNotScoped {
                cold: LegacyColdIntervalV1::new(),
            };
        }
        match &mut self.state {
            FloorStateV1::ClientColdNotScoped { cold } if role != Role::Storage => {
                cold.bind(deadline)
            }
            FloorStateV1::Required { mode, attached, .. } if role == Role::Storage => {
                if !mode.has_currentness_archive_v1() { return Err(FloorErrorV1::Unavailable); }
                attached.bind_cold_deadline(deadline)
            }
            FloorStateV1::Legacy { mode, cold } if role == Role::Storage => {
                // No consuming comparison is permitted on this selected path.
                // The actual same-B shape/Journal join installed this archive.
                if !mode.has_currentness_archive_v1() {
                    return Err(FloorErrorV1::Unavailable);
                }
                cold.bind(deadline)?;
                mode.revalidate()?;
                mode.require_no_floor_names(Path::new(
                    "/var/lib/aos/sandboxd/broker-session/storage",
                ))?;
                mode.revalidate()?;
                cold.check()
            }
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    /// Reports unfinished cold custody for guard restoration, never admission.
    pub(in crate::recovery::journal) fn has_resident_cold_attempt(&self) -> bool {
        self.has_resident_required_attempt()
            || matches!(&self.state,
                FloorStateV1::Legacy { cold, .. } | FloorStateV1::ClientColdNotScoped { cold }
                    if cold.requires_retention())
    }

    /// Fences the original retained cold owner without changing its image mode.
    pub(in crate::recovery::journal) fn fence_retained_cold(&mut self) {
        self.fence_required();
        if let FloorStateV1::Legacy { cold, .. }
            | FloorStateV1::ClientColdNotScoped { cold } = &mut self.state
        {
            if cold.requires_retention() {
                cold.fence();
            }
        }
    }

    /// Borrows the original ordinary cold refusal without consuming its owner.
    pub(in crate::recovery::journal) fn ordinary_cold_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.state {
            FloorStateV1::Legacy { cold, .. }
            | FloorStateV1::ClientColdNotScoped { cold } => cold.failure(),
            _ => None,
        }
    }

    pub(in crate::recovery::journal) fn revalidate_endpoint_for_reopen(
        &mut self,
        endpoint: &mut crate::recovery::journal::ProtectedEndpointV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        match &mut self.state {
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { attached, .. } => {
                attached.fence();
                Err(crate::BrokerSessionSecurityError::Currentness)
            }
            FloorStateV1::Required { attached, .. } => {
                // This borrows disjoint actual owner fields before extraction.
                // A caught unwind fences the original attempt in place.
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)
                    .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
                match endpoint.revalidate() {
                    Ok(()) => operation.finish(Ok(()))
                        .map_err(|_| crate::BrokerSessionSecurityError::Currentness),
                    Err(cause) => {
                        // This public facade error contains static labels only;
                        // the actual cause remains on the resident attempt.
                        let projected = cause.clone();
                        operation.attempt.record_endpoint_failure(cause);
                        let _ = operation.finish::<()>(Err(FloorErrorV1::Unavailable));
                        Err(projected)
                    }
                }
            }
            _ => endpoint.revalidate(),
        }
    }

    pub(in crate::recovery::journal) fn attach_controller_initial_v1(
        &mut self, owner: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Required { mode, provision, launch_image, attached } = &mut self.state
            else { return self.attach(owner); };
        attached.arm_controller_initial_v1(owner, receiving)?;
        let operation = attached.begin(BrokerAttachmentPhaseV1::Fresh)?;
        let result = (|| {
            mode.revalidate()?;
            let profile = provision.profile();
            if owner.endpoint.protected_protocol_and_node().1 != profile.node() {
                return Err(FloorErrorV1::Provisioning);
            }
            let auth = provision.current_auth()?;
            let salt_name = provision.salt_name();
            operation.attempt.admit_controller_initial_v1(
                owner, profile, salt_name, &auth, launch_image, receiving,
            )?;
            provision.revalidate()?;
            mode.revalidate()?;
            operation.attempt.finish_controller_initial_once_v1()
        })();
        operation.attempt.controller_primary = Some(result);
        operation.finish(result)
    }

    pub(in crate::recovery::journal) fn attach_storage_initial_v2(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Required { mode, provision, launch_image, attached } = &mut self.state else {
            return self.attach(owner);
        };
        attached.storage_selected = true;
        let operation = attached.begin(BrokerAttachmentPhaseV1::Fresh)?;
        let result = (|| {
            operation.attempt.check_cold_deadline()?;
            mode.revalidate()?;
            let profile = provision.profile();
            if owner.endpoint.protected_protocol_and_node().1 != profile.node() {
                return Err(FloorErrorV1::Provisioning);
            }
            let auth = provision.current_auth()?;
            let salt_name = provision.salt_name();
            operation.attempt.admit_storage_initial_v2(
                owner, profile, salt_name, &auth, launch_image, receiving,
            )?;
            provision.revalidate()?;
            mode.revalidate()?;
            operation.attempt.check_cold_deadline()
        })();
        operation.finish(result)
    }

    pub(in crate::recovery::journal) fn attach(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { provision, attached, .. } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Fresh)?;
                let result = (|| {
                    provision.revalidate()?;
                    let profile = provision.profile()?;
                    if owner.endpoint.protected_protocol_and_node().1 != profile.node() {
                        return Err(FloorErrorV1::Provisioning);
                    }
                    operation.attempt.admit_online(owner, provision)?;
                    provision.revalidate()
                })();
                operation.finish(result)
            }
            FloorStateV1::Required {
                mode,
                provision,
                launch_image,
                attached,
            } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Fresh)?;
                // Main writer is already retained. Open sidecar next, then
                // TPM; this call recovers only its exact persisted transaction.
                let result = (|| {
                    mode.revalidate()?;
                    let profile = provision.profile();
                    if owner.endpoint.protected_protocol_and_node().1 != profile.node() {
                        return Err(FloorErrorV1::Provisioning);
                    }
                    let auth = provision.current_auth()?;
                    let salt_name = provision.salt_name();
                    operation.attempt.admit(
                        owner,
                        profile,
                        salt_name,
                        &auth,
                        launch_image,
                    )?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
            _ => self.check(owner),
        }
    }

    pub(in crate::recovery::journal) fn suspend_for_reopen(&mut self) {
        if let FloorStateV1::Required { attached, .. } = &mut self.state {
            // Release TPM/sidecar before replacing the main writer, then acquire
            // main → sidecar → TPM again. Mode/provisioning pins stay retained.
            let old = std::mem::replace(attached, BrokerAttachmentAttemptV1::fresh());
            drop(old);
        }
    }

    pub(in crate::recovery::journal) fn storage_initial_failure_post_is_owed_v2(&self) -> bool {
        matches!(&self.state, FloorStateV1::Required { attached, .. }
            if attached.storage_selected && !attached.controller_owed_consumed)
    }

    pub(in crate::recovery::journal) fn observe_storage_initial_failure_post_v2(
        &mut self, owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Required { attached, .. } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        if !attached.storage_selected || attached.controller_owed_consumed {
            return Err(FloorErrorV1::Unavailable);
        }
        attached.fence();
        self.check(owner)
    }

    pub(in crate::recovery::journal) fn observe_controller_initial_failure_post_v1(
        &mut self, owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Required { attached, .. } = &mut self.state
            else { return Err(FloorErrorV1::Unavailable); };
        if !attached.controller_selected || attached.controller_owed_consumed {
            return Err(FloorErrorV1::Unavailable);
        }
        // The actual initial Cold owner already parked its primary error.
        // Fencing here cannot turn an outer semantic refusal into a healthy
        // TPM command, reset Checking or mint a fresh role/operation loan.
        attached.fence();
        self.check(owner)
    }

    pub(in crate::recovery::journal) fn check(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        self.check_with_storage_receiving_v2(owner, None)
    }

    pub(in crate::recovery::journal) fn check_with_storage_receiving_v2(&mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        mut receiving: Option<&mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::NotScoped => Ok(()),
            FloorStateV1::ClientColdNotScoped { cold } => cold.require_current(),
            FloorStateV1::Unavailable => Err(FloorErrorV1::Unavailable),
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { provision, attached, .. } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    provision.revalidate()?;
                    operation.attempt.use_online(owner, provision.profile()?, None)?;
                    provision.revalidate()
                })();
                operation.finish(result)
            }
            FloorStateV1::Legacy { mode, cold } => {
                cold.require_current()?;
                mode.revalidate()?;
                mode.require_no_floor_names(&owner.directory)?;
                require_no_output_history(owner)?;
                mode.revalidate()?;
                cold.require_current()
            }
            FloorStateV1::Required {
                mode,
                provision,
                attached,
                ..
            } => {
                if attached.has_controller_owed_v1() {
                    // This is the one genuinely prearmed continuation after a
                    // failed primary. Every available native post runs despite
                    // an earlier refusal; the healthy begin gate stays closed.
                    attached.controller_owed_consumed = true;
                    let mode_post = mode.revalidate();
                    let provision_post = provision.revalidate();
                    let (main, sidecar, physical) = attached.observe_controller_attachment_post_v1(owner);
                    attached.controller_posts = Some([mode_post, provision_post, main, sidecar, physical]);
                    // Comparison success never discharges an ambiguous TPM
                    // command or restores the original attachment's readiness.
                    return Err(attached.failure_projection());
                }
                // A selected Storage owner has exactly one original F. Every
                // real caller must lend it; an absent financial borrower cannot
                // silently select the ordinary floor reader or writer. The
                // independently owed continuation above remains available.
                if attached.storage_selected && receiving.is_none() {
                    return Err(FloorErrorV1::Unavailable);
                }
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    mode.revalidate()?;
                    provision.revalidate()?;
                    operation.attempt.check_with_storage_receiving_v2(owner, provision.profile(),
                        receiving.as_mut().map(|source| &mut **source as &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2))?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
        }
    }

    pub(in crate::recovery::journal) fn commit(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        self.commit_with_storage_receiving_v2(owner, transaction, None)
    }

    pub(in crate::recovery::journal) fn commit_with_storage_receiving_v2(&mut self,
        owner: &mut ProtectedBrokerSessionJournalV1, transaction: &JournalTransaction,
        mut receiving: Option<&mut dyn super::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), FloorErrorV1> {
        self.check_with_storage_receiving_v2(owner, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2))?;
        let legacy = matches!(&self.state, FloorStateV1::Legacy { .. });

        match &mut self.state {
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { provision, attached, .. } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    operation.attempt.use_online(owner, provision.profile()?, Some(transaction))?;
                    provision.revalidate()
                })();
                operation.finish(result)
            }
            FloorStateV1::Required {
                mode,
                provision,
                attached,
                ..
            } => {
                let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
                let result = (|| {
                    operation.attempt.commit_with_storage_receiving_v2(owner, provision.profile(), transaction,
                        receiving.as_mut().map(|source| &mut **source as &mut dyn super::storage_receiving::StorageFloorFinancialSourceV2))?;
                    provision.revalidate()?;
                    mode.revalidate()
                })();
                operation.finish(result)
            }
            FloorStateV1::NotScoped | FloorStateV1::Legacy { .. }
            | FloorStateV1::ClientColdNotScoped { .. } => {
                // Prospective legacy history cannot introduce a hidden 46 row.
                if legacy {
                    require_no_output_transaction(transaction)?;
                }
                commit_unfloored_broker_v1(owner, transaction)?;
                self.check(owner)
            }
            FloorStateV1::Unavailable => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(in crate::recovery::journal) fn require_method(
        &self,
        method: BrokerMethod,
    ) -> Result<(), FloorErrorV1> {
        if method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
            && !matches!(&self.state, FloorStateV1::Required { attached, .. } if attached.is_ready())
        {
            return Err(FloorErrorV1::Unavailable);
        }
        #[cfg(feature = "online-nix")]
        if let FloorStateV1::Online { attached, .. } = &self.state {
            if crate::recovery::journal::online_nix_verb(method).is_none() || !attached.is_ready()
            {
                return Err(FloorErrorV1::Unavailable);
            }
        }
        if method == BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT {
            if !METHOD46_INSTALLED_QUALIFIED
                || !matches!(
                    &self.state,
                    FloorStateV1::Required {
                        attached,
                        ..
                    } if attached.is_ready()
                )
            {
                return Err(FloorErrorV1::Unavailable);
            }
        }
        if let FloorStateV1::ClientColdNotScoped { cold } = &self.state {
            cold.require_healthy()?;
        }
        if let FloorStateV1::Legacy { cold, .. } = &self.state {
            cold.require_healthy()?;
            if is_output_method(method) {
                return Err(FloorErrorV1::Unavailable);
            }
        }
        Ok(())
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal) fn bind_online_request_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Online { attached, .. } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        if !attached.is_ready() {
            attached.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        attached.bind_online_request_deadline(deadline)
    }

    /// Borrows the actual online floor after main-journal widths are known.
    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal) fn check_online_existing_output_suffix(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        prepared_widths: [usize; 3],
    ) -> Result<(), FloorErrorV1> {
        let FloorStateV1::Online { provision, attached, .. } = &mut self.state else {
            return Err(FloorErrorV1::Unavailable);
        };
        let operation = attached.begin(BrokerAttachmentPhaseV1::Ready)?;
        let result = (|| {
            provision.revalidate()?;
            operation.attempt.check_online_existing_output_suffix(
                owner, provision.profile()?, prepared_widths,
            )?;
            provision.revalidate()
        })();
        operation.finish(result)
    }

    // A failed (or abandoned in-progress) Required owner cannot touch current
    // names, release sidecar/TPM custody or replace its main writer on reopen.
    pub(in crate::recovery::journal) fn require_reopen_allowed(&self) -> Result<(), FloorErrorV1> {
        #[cfg(feature = "online-nix")]
        if matches!(&self.state, FloorStateV1::Online { .. }) {
            return Err(FloorErrorV1::Unavailable);
        }
        if matches!(&self.state, FloorStateV1::Required { attached, .. } if attached.is_failed()) {
            return Err(FloorErrorV1::Unavailable);
        }
        if let FloorStateV1::Legacy { cold, .. }
            | FloorStateV1::ClientColdNotScoped { cold } = &self.state
        {
            cold.require_reopen_allowed()?;
        }
        Ok(())
    }

    pub(in crate::recovery::journal) fn fence_required(&mut self) {
        if let FloorStateV1::Required { attached, .. } = &mut self.state {
            attached.fence();
        }
        #[cfg(feature = "online-nix")]
        if let FloorStateV1::Online { attached, .. } = &mut self.state {
            attached.fence();
        }
    }

    pub(in crate::recovery::journal) fn record_native_failure(
        &mut self,
        cause: aos_sandbox_controller_domain::JournalError,
    ) {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } => attached.record_native_failure(cause),
            #[cfg(feature = "online-nix")]
            FloorStateV1::Online { attached, .. } => attached.record_native_failure(cause),
            _ => {}
        }
        // Unrelated/legacy owners retain their original redacted consuming
        // error contract; no missing lower cause is synthesized for them.
    }
}

fn is_output_method(method: BrokerMethod) -> bool {
    matches!(
        method,
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
    )
}

pub(in crate::recovery::journal) fn require_launch_image_presence(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    supplied: bool,
) -> Result<(), FloorErrorV1> {
    let endpoint = match endpoint {
        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient => {
            FloorEndpointV1::ControllerStorageClient
        }
        crate::ProtectedBrokerSessionFixedEndpointV1::StorageBroker => {
            FloorEndpointV1::StorageBroker
        }
        _ => return Err(FloorErrorV1::Provisioning),
    };
    let mode = ModePinV1::open(endpoint)?;
    require_launch_image_presence_with_mode(endpoint, &mode, supplied)
}

// Selected Storage keeps its actual pin resident instead of reopening the name.
pub(super) fn require_storage_worker_launch_image_presence(
    mode: &ModePinV1,
    supplied: bool,
) -> Result<(), FloorErrorV1> {
    require_launch_image_presence_with_mode(FloorEndpointV1::StorageBroker, mode, supplied)
}

fn require_launch_image_presence_with_mode(
    endpoint: FloorEndpointV1,
    mode: &ModePinV1,
    supplied: bool,
) -> Result<(), FloorErrorV1> {
    ModePresenceOriginalV1::new().capture_once(
        endpoint, mode, supplied, super::provisioning::CredentialReadCustodyV1::Ordinary,
    )
}

pub(super) fn require_storage_worker_launch_image_presence_retaining(
    mode: &ModePinV1,
    supplied: bool,
    original: &mut ModePresenceOriginalV1,
) -> Result<(), FloorErrorV1> {
    original.capture_once(
        FloorEndpointV1::StorageBroker,
        mode,
        supplied,
        super::provisioning::CredentialReadCustodyV1::Retained,
    )
}

fn require_mode_image_presence(mode: ImageFloorModeV1, supplied: bool) -> Result<(), FloorErrorV1> {
    if supplied != matches!(mode, ImageFloorModeV1::Required) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn require_no_floor_names(directory: &Path) -> Result<(), FloorErrorV1> {
    super::super::floor_revalidation::validate_absent(None, directory)
}

fn require_no_output_history(
    owner: &mut ProtectedBrokerSessionJournalV1,
) -> Result<(), FloorErrorV1> {
    let authority = owner
        .journal_mut()
        .map_err(|_| FloorErrorV1::Unavailable)?
        .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
        .map_err(|_| FloorErrorV1::Unavailable)?;
    for (key, value) in authority.records().map_err(|_| FloorErrorV1::Unavailable)? {
        require_no_output_record(key, value)?;
    }
    Ok(())
}

fn require_no_output_transaction(transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::BrokerSessionTraffic {
            return Err(FloorErrorV1::Encoding);
        }
        if let Some(value) = record.value() {
            require_no_output_record(record.key(), value)?;
        }
    }
    Ok(())
}

fn require_no_output_record(key: &[u8], value: &[u8]) -> Result<(), FloorErrorV1> {
    let kind = classified_broker_session_key(key)
        .map_err(|_| FloorErrorV1::Encoding)?
        .0;
    if kind == BrokerSessionJournalKeyKind::Traffic {
        let history =
            StoredProtocolHistoryV1::decode(key, value).map_err(|_| FloorErrorV1::Encoding)?;
        if history
            .history_model()
            .map_err(|_| FloorErrorV1::Encoding)?
            .records()
            .iter()
            .any(|record| is_output_method(record.method()))
        {
            return Err(FloorErrorV1::Diverged);
        }
    }
    // Other typed archives are separately schema-checked before owner use;
    // their strict formats retain only snapshot/inventory/Host37/39 methods.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_dispositions_do_not_select_required_unwind_restoration() {
        assert!(!BrokerFloorV1::test_not_scoped().has_resident_required_attempt());
        assert!(!BrokerFloorV1::unavailable().has_resident_required_attempt());
    }

    #[test]
    fn tpm_floor_method46_is_closed_without_installed_qualification() {
        for gate in [
            BrokerFloorV1::test_not_scoped(),
            BrokerFloorV1::unavailable(),
        ] {
            assert!(
                gate.require_method(BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT)
                    .is_err()
            );
        }
        assert!(
            BrokerFloorV1::test_not_scoped()
                .require_method(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
                .is_ok()
        );
    }

    #[test]
    fn tpm_floor_fixed_storage_root_cannot_be_reclassified_as_host() {
        for directory in [
            "/var/lib/aos/sandboxd/broker-session/storage",
            "/var/lib/aos/sandbox-storage/broker-session",
        ] {
            assert!(
                BrokerFloorV1::configure(
                    Path::new(directory),
                    BrokerSessionProtocolV1::Host,
                    BrokerSessionDurableEndpointV1::Client,
                    None,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn tpm_floor_legacy_rejects_any_sidecar_name_without_deleting_it() {
        let directory = tempfile::tempdir().unwrap();
        assert!(require_no_floor_names(directory.path()).is_ok());
        for name in [
            "session-floor.journal",
            "session-floor.journal.lock",
            "session-floor.journal.compact.tmp",
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, b"retained").unwrap();
            assert!(require_no_floor_names(directory.path()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"retained");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn tpm_floor_startup_image_presence_cannot_downgrade_required_mode() {
        assert!(require_mode_image_presence(ImageFloorModeV1::LegacyClosed, false).is_ok());
        assert!(require_mode_image_presence(ImageFloorModeV1::Required, true).is_ok());
        assert!(require_mode_image_presence(ImageFloorModeV1::Required, false).is_err());
        assert!(require_mode_image_presence(ImageFloorModeV1::LegacyClosed, true).is_err());
    }
}

impl BrokerFloorV1 {
    pub(in crate::recovery::journal) fn retire_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        match &mut self.state {
            FloorStateV1::Required { attached, .. } =>
                attached.retire_completed_initial_native_v1(completed, main),
            FloorStateV1::NotScoped | FloorStateV1::ClientColdNotScoped { .. }
            | FloorStateV1::Legacy { .. } => Ok(()),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }
}
