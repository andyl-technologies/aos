//! Enrolls initial Source independently of RAM controller registration.
//!
//! The actual Source0 loan and immutable family produce its subject. Its host
//! controls retain the same authenticated Main payer and node supervisor; neither
//! a RAM Target, copied limits nor a caller-supplied subject constructs admission.
//! The original storage loan stays outside the shared value until its allocation
//! is freed; destroying that value alone cannot return its storage charge.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use crucible_host_resources::host_services::process_birth::{
    AuthenticatedSourceHostPurpose, ServiceBirthError,
};
use crucible_host_resources::host_supervision::{
    FundedSourcePublisher, HostDeferredCleanupIssuer, HostSupervisionError,
};
use crucible_host_resources::ram_policy::HostResourceVector;

use super::*;
use crate::linux_attempt_host::original_node::retained_error::controller_peak_bytes;

/// Names an actual retained Source reservation and execution incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InstalledSourceSubject {
    pub(crate) containing_cap: [u8; 32],
    pub(crate) reservation: [u8; 32],
    pub(crate) account_generation: u64,
    pub(crate) process_generation: u64,
}

/// Retains actual initial Source enrollment and its already funded host controls.
#[derive(Clone, Debug)]
pub(crate) struct InstalledSourceAdmission {
    held: FundedSourcePublisher<InstalledSourceState>,
}

#[derive(Debug)]
struct InstalledSourceState {
    subject: InstalledSourceSubject,
    resources: HostResourceVector,
    original_metadata_bytes: u64,
    artifact_digest: [u8; 32],
    receiver: crate::artifact_identity::NativeReceiverArtifact,
    supervisor: HostOperationSupervisor,
    cleanup_issuer: Mutex<Option<HostDeferredCleanupIssuer>>,
    host: AuthenticatedSourceHostPurpose,
}

impl OriginalNativeNodeBinding {
    /// Prepays the actual artifact verifier before entering its fixed read frame.
    ///
    /// The same nominal owner is retained in this binding and reused by later
    /// Source admission. Target and repeated reservations refuse before effects.
    ///
    /// # Errors
    /// Refuses foreign original/contract, absent genuine Main/family, repeated
    /// Source funding or exhausted containing control capacity.
    pub(crate) fn prepare_source_artifact_controls(
        &mut self,
        contract: &QemuChildProcessContract,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        InstalledProcessPurposeError,
    > {
        if self.source_host.is_some() || self.installed_process.is_some() {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.launch_in_flight
                    && !slot.launch_abandoned
                    && slot.launch_refusal.is_none()
                    && slot.unsettled.is_none()
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        credit.verify_preparation(original)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.ready
                    && purpose.sound
                    && purpose.matches_launch_contract(contract)
                    && purpose.journal.loans == 0
                    && purpose.journal.incarnations.iter().all(Option::is_none)
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        purpose
            .family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .verify_envelope(0, &purpose.envelope)?;
        let normal = credit
            .original
            .as_ref()
            .and_then(|retained| retained.normal.as_ref())
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let host = slot
            .source_controller
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .retained_source_host()?
            .clone();
        if !host.belongs_to(normal) || slot.source_control_payer.is_none() {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let control = host
            .reserve_controls(3, crate::artifact_identity::installer_verifier_extent())
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        control
            .verify_original(original)
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        self.source_host = Some(host);
        Ok(control)
    }

    /// Enrolls this already issued Source0 before startup or descriptor birth.
    ///
    /// # Errors
    /// Refuses Target, changed contract/generation/Main, an absent authentic
    /// normal credit, or exhausted actual Source host control capacity.
    pub(crate) fn prepare_source_admission(
        &self,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        process_generation: u64,
        budgets: crucible_host_resources::host_supervision::HostOperationBudgets,
    ) -> Result<InstalledSourceAdmission, InstalledProcessPurposeError> {
        self.installed_process
            .as_ref()
            .filter(|loan| {
                loan.subdivision_index == 0 && loan.process_generation == process_generation
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        credit.verify_capture_supervisor(supervisor)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.matches_launch_contract(contract)
                    && purpose.incarnation_subdivision(process_generation) == Some(0)
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let family = purpose
            .family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        family.verify_envelope(0, &purpose.envelope)?;
        let (containing_cap, reservation, account_generation) = family.source_identity();
        let normal = credit
            .original
            .as_ref()
            .and_then(|retained| retained.normal.as_ref())
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let (source_extent, _, _) = source_host_peak()?;
        let host = self
            .source_host
            .as_ref()
            .filter(|host| host.belongs_to(normal))
            .ok_or(InstalledProcessPurposeError::Identity)?
            .clone();
        host.verify_supervisor(supervisor)
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        // The actual Source payer exists before the new node roster or its Arc.
        let control = host
            .reserve_controls(0, source_extent)
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        let node_supervisor = supervisor
            .new_budget_owner(budgets)
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        let controls = purpose
            .controls
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let receiver = controls
            .native_receiver_artifact()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let held = FundedSourcePublisher::new(
            InstalledSourceState {
                subject: InstalledSourceSubject {
                    containing_cap,
                    reservation,
                    account_generation,
                    process_generation,
                },
                resources: normal.bounds(),
                original_metadata_bytes: credit.total_metadata_bytes(),
                artifact_digest: *controls.plugin_sha256(),
                receiver,
                supervisor: node_supervisor,
                cleanup_issuer: Mutex::new(None),
                host,
            },
            control,
        )
        .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        Ok(InstalledSourceAdmission { held })
    }

    /// Corroborates the installed Source loan and its actual containing payer.
    ///
    /// # Errors
    /// Refuses Target, foreign nominal custody, changed contract, artifact,
    /// subject or supervisor before publishing any Source carrier.
    pub(crate) fn verify_source_admission(
        &self,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        admission: &InstalledSourceAdmission,
        process_generation: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        admission
            .held
            .host
            .verify_supervisor(supervisor)
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        if admission.held.supervisor != *supervisor {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let loan = self
            .installed_process
            .as_ref()
            .filter(|loan| {
                loan.subdivision_index == 0 && loan.process_generation == process_generation
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let roster = loan
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(loan.index)
            .filter(|slot| slot.active == Some(loan.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        credit.verify_capture_supervisor(supervisor)?;
        let normal = credit
            .original
            .as_ref()
            .and_then(|retained| retained.normal.as_ref())
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.ready
                    && purpose.sound
                    && purpose.journal.loans != 0
                    && purpose.matches_launch_contract(contract)
                    && purpose.incarnation_subdivision(process_generation) == Some(0)
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let family = purpose
            .family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let (cap, reservation, account_generation) = family.source_identity();
        let controls = purpose
            .controls
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if !admission.held.host.belongs_to(normal)
            || !self
                .source_host
                .as_ref()
                .is_some_and(|host| host.same_owner(&admission.held.host))
            || admission.held.subject
                != (InstalledSourceSubject {
                    containing_cap: cap,
                    reservation,
                    account_generation,
                    process_generation,
                })
            || admission.held.artifact_digest != *controls.plugin_sha256()
            || !controls
                .native_receiver_artifact()
                .is_some_and(|receiver| receiver.same_artifact(&admission.held.receiver))
            || admission.held.original_metadata_bytes != credit.total_metadata_bytes()
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        family.verify_envelope(0, &purpose.envelope)
    }
}

/// Describes the one Main-paid peak shared across verification and process birth.
pub(in crate::linux_attempt_host) fn source_host_peak()
-> Result<(u64, u64, u64), InstalledProcessPurposeError> {
    // Both concrete shared allocations and the funding constructor are admitted
    // before either allocation; the Source value and holder coexist here too.
    let storage = FundedSourcePublisher::<InstalledSourceState>::allocation_bytes()
        .map_err(|_| InstalledProcessPurposeError::Capacity)?;
    let supervisor_extent =
        crucible_host_resources::host_supervision::HostSupervisionBootstrap::structure_bytes()
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
    let source_extent = u64::try_from(storage)
        .ok()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<InstalledSourceState>() as u64))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<InstalledSourceAdmission>() as u64))
        .and_then(|bytes| bytes.checked_add(supervisor_extent))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::QemuNodeChild>() as u64))
        .and_then(|bytes| bytes.checked_add(crate::node::child_shutdown_control_extent()?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::QemuSpawnError>() as u64))
        .ok_or(InstalledProcessPurposeError::Capacity)?;
    let qmp_extent = crate::QemuQmpExactSnapshotControlChannel::<
        std::os::unix::net::UnixStream,
    >::host_allocation_extent()
    .ok_or(InstalledProcessPurposeError::Capacity)?;

    let peak = crate::spawn::OriginalPluginStartup::host_allocation_extent()
        .map_err(|_| InstalledProcessPurposeError::Capacity)?
        .checked_add(
            crate::spawn::preexec_setup::PreparedPreexecSetup::host_allocation_extent()
                .ok_or(InstalledProcessPurposeError::Capacity)?,
        )
        .and_then(|bytes| {
            bytes.checked_add(crate::launch_cleanup::LaunchCleanup::retained_control_bytes()?)
        })
        .and_then(|bytes| bytes.checked_add(qmp_extent))
        .and_then(|bytes| {
            bytes.checked_add(controller_peak_bytes().ok()?)
        })
        .and_then(|bytes| bytes.checked_add(crate::spawn::helper_first::control_peak_bytes()?))
        .and_then(|bytes| bytes.checked_add(source_extent))
        .and_then(|bytes| bytes.checked_add(crate::spawn::helper_receiver::retained_control_bytes()?))
        .and_then(|bytes| {
            bytes.checked_add(
                crate::spawn::source_supervision::OriginalSourceSupervision::host_allocation_extent()?,
            )
        })
        .and_then(|bytes| bytes.checked_add(crate::artifact_identity::installer_verifier_extent()))
        .ok_or(InstalledProcessPurposeError::Capacity)?;
    Ok((
        source_extent,
        peak,
        22 + crate::spawn::source_supervision::PUBLISHER_DESCRIPTOR_PEAK
            + crate::spawn::preexec_setup::PreparedPreexecSetup::descriptor_peak()
            + crate::spawn::helper_receiver::DESCRIPTOR_PEAK,
    ))
}

impl InstalledSourceAdmission {
    /// Retains the exact node owner's future Cleanup issuer during real Setup.
    ///
    /// The inline slot is part of the Source admission's prepaid body. It stays
    /// with that actual admission after Setup returns, including a negative
    /// delegation post. This creates no native resource child or wire grant.
    ///
    /// # Errors
    /// Refuses another supervisor, unavailable Source custody, an occupied or
    /// uncertain slot, or the original delegation and its independent post.
    pub(crate) fn delegate_cleanup_issuer(
        &self,
        setup: &HostOperationGuard,
    ) -> Result<(), HostSupervisionError> {
        if !setup.belongs_to_supervisor(&self.held.supervisor) {
            return Err(HostSupervisionError::Unavailable);
        }
        self.check()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let mut issuer = self
            .held
            .cleanup_issuer
            .try_lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        setup.delegate_deferred_cleanup_issuer(&mut issuer)
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.held.same_owner(&other.held)
    }

    pub(crate) fn subject(&self) -> InstalledSourceSubject {
        self.held.subject
    }

    pub(crate) fn original_metadata_bytes(&self) -> u64 {
        self.held.original_metadata_bytes
    }

    pub(crate) fn artifact_digest(&self) -> [u8; 32] {
        self.held.artifact_digest
    }

    pub(crate) fn resources(&self) -> HostResourceVector {
        self.held.resources
    }

    pub(crate) fn receiver_artifact(&self) -> &crate::artifact_identity::NativeReceiverArtifact {
        &self.held.receiver
    }

    pub(crate) fn supervisor(&self) -> &HostOperationSupervisor {
        &self.held.supervisor
    }

    pub(crate) fn host_purpose(&self) -> &AuthenticatedSourceHostPurpose {
        &self.held.host
    }

    /// Checks the same actual Source enrollment and independently retained Main.
    ///
    /// # Errors
    /// Refuses changed/expired physical custody or an unrelated node supervisor.
    pub(crate) fn check(&self) -> Result<(), ServiceBirthError> {
        self.held.host.verify_supervisor(&self.held.supervisor)
    }
}
