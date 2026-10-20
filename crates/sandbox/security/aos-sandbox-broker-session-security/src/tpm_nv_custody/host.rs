//! Genuine fixed Host inputs and original full-state journal comparisons.
//!
//! The input owner borrows Core's actual comparison Origins and retains fixed
//! mode, auth commitment and helper/loader inputs. A separate private disk
//! owner admits two original existing Journals and exact native funding DATA.
//! The closed physical read consumer parks that same whole owner and derives
//! its one-shot invocation from the same Origins. It alone admits the fixed
//! helper, original lock loans and fresh055 classification, never an effect.
//! A durable coordinator, independent bootstrap publisher and installed
//! terminal-population/next-activation producer remain separate prerequisites.

use aos_sandbox_controller_domain::{
    RuntimeDeploymentComparisonErrorV1, RuntimeDeploymentComparisonOriginsV1,
};
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::FixedRoleCredentialErrorV1;
use crate::recovery::{FloorErrorV1, MeasuredHelperImageV1};

mod provisioning;
mod inputs;
use inputs::HostTpmInputAdmissionOriginalV1;
mod journal;
mod store;
mod coordinator;
mod native_original;
pub(in crate::tpm_nv_custody) use native_original::PublisherNativeOriginalRefV3;
pub use coordinator::{
    RuntimeDeploymentCanaryRunErrorV2, run_runtime_deployment_canary_once_v2,
    run_runtime_boot_preparation_once_v1,
};
pub(super) mod physical;

pub(super) use journal::HostSidecarCustodyV1;
pub(in crate::tpm_nv_custody) use journal::{BootHostMainDataV1, CanaryHostMainDataV2, CanaryHostNativeStepV2};
pub(in crate::tpm_nv_custody) use coordinator::{CanaryAuthenticatedRequestV3, CanaryClockCauseV2};

// These are the existing fixed Core roles, not configurable opener inputs.
// The genuine held-pair comparison independently enforces those same names.
const JOURNAL_DIRECTORY: &str = "/var/lib/aos/sandbox/runtime-deployment";
const MAIN_JOURNAL_NAME: &str = "preparation.journal";
const SIDECAR_JOURNAL_NAME: &str = "tpm-floor.journal";

use provisioning::HostProvisioningPinV1;

/// Retains typed original-owner failures without granting a retry or floor.
#[derive(Debug, thiserror::Error)]
pub(super) enum HostOwnedJournalErrorV1 {
    #[error("Host original journal inputs were rejected")]
    Inputs(#[from] HostTpmAdmissionErrorV1),
    #[error("Host original journal origins were rejected")]
    Origins(#[from] RuntimeDeploymentComparisonErrorV1),
    #[error("Host original native journal was rejected")]
    Journal(#[from] aos_sandbox_controller_domain::JournalError),
    #[error("Host original canonical sidecar was rejected")]
    Canonical(#[from] FloorErrorV1),
    #[error("Host selected original clock failed")]
    CanaryClock(#[from] CanaryClockCauseV2),
    #[error(transparent)]
    CanaryNative(#[from] journal::CanaryNativeErrorV2),
    #[error("Host original retained disk comparison changed")]
    Changed,
    #[error("Host original journal owner is unusable")]
    Unusable,
}

/// Reports a retained cause without formatting credentials or commitments.
#[derive(Debug, thiserror::Error)]
pub(super) enum HostTpmAdmissionErrorV1 {
    #[error("Host TPM input origins were rejected")]
    Origins(#[source] RuntimeDeploymentComparisonErrorV1),
    #[error("Host TPM input mode was rejected")]
    Mode(#[source] FloorErrorV1),
    #[error("Host TPM helper image was rejected")]
    Image(#[source] FloorErrorV1),
    #[error("Host TPM auth credential was rejected")]
    Credential(#[source] FixedRoleCredentialErrorV1),
    #[error("Host TPM auth credential is absent")]
    MissingAuth,
    #[error("Host TPM auth credential is malformed")]
    InvalidAuth,
    #[error("Host TPM auth credential changed")]
    ChangedAuth,
    #[error("Host TPM legacy mode is closed")]
    LegacyClosed,
    #[error("Host TPM admitted purpose inputs changed")]
    ChangedPurpose,
    #[error("Host TPM input admission is unusable")]
    Unusable,
}

/// Retains only genuine fixed Host inputs, never a physical-floor capability.
///
/// Fields are private and construction accepts only the existing genuine
/// Origins owner. No path, FD, role selector, injected transport or credential
/// bytes can be supplied by a caller. A failed or unwound recheck remains closed.
#[must_use = "the genuine Origins and input pins must remain retained"]
pub(super) struct AdmittedHostTpmInputsV1<'origin, 'startup> {
    provisioning: HostProvisioningPinV1<'origin, 'startup>,
    image: MeasuredHelperImageV1,
    usable: bool,
    boot_currentness: Option<inputs::HostInputArchiveV1>,
}

impl<'origin, 'startup> AdmittedHostTpmInputsV1<'origin, 'startup> {
    /// Admits fixed mode, auth, signed purpose and compiled helper inputs.
    ///
    /// # Errors
    /// Rejects origin drift, missing or unsafe fixed credentials, legacy mode,
    /// a purpose mismatch, unavailable image pins or failed final rechecks.
    pub(super) fn admit(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, HostTpmAdmissionErrorV1> {
        origins.recheck().map_err(HostTpmAdmissionErrorV1::Origins)?;
        let provisioning = HostProvisioningPinV1::open(origins)?;
        let image = MeasuredHelperImageV1::open_runtime_deployment()
            .map_err(HostTpmAdmissionErrorV1::Image)?;

        let mut admitted = Self {
            provisioning,
            image,
            usable: true,
            boot_currentness: None,
        };
        admitted.recheck()?;
        Ok(admitted)
    }

    /// Rechecks the same auth commitment, immutable pins and genuine Origins.
    ///
    /// # Errors
    /// Rejects previous failure or any credential, mode, image or origin drift.
    /// The latch is closed before fallible checks, including during unwinding.
    pub(super) fn recheck(&mut self) -> Result<(), HostTpmAdmissionErrorV1> {
        begin_recheck(&mut self.usable)?;
        if let Some(archive) = self.boot_currentness.as_mut() {
            archive.run_once(&self.provisioning, &self.image, inputs::HostInputOperationV1::Recheck)?;
            self.usable = true;
            return Ok(());
        }
        self.recheck_inner()?;
        self.usable = true;
        Ok(())
    }

    /// Rereads exact private auth between complete retained-input rechecks.
    ///
    /// Only a later purpose-closed AUTH transfer may consume these zeroizing
    /// bytes. This internal return value authenticates neither a child nor NV.
    ///
    /// # Errors
    /// Rejects previous failure, missing, unsafe or changed auth, or any input
    /// drift. A failed postcheck wipes the just-read auth and stays closed.
    pub(super) fn current_auth(
        &mut self,
    ) -> Result<Zeroizing<[u8; 32]>, HostTpmAdmissionErrorV1> {
        if let Some(archive) = self.boot_currentness.as_mut() {
            begin_recheck(&mut self.usable)?;
            let auth = archive.run_once(&self.provisioning, &self.image, inputs::HostInputOperationV1::Auth)?
                .ok_or(HostTpmAdmissionErrorV1::Unusable)?;
            self.usable = true;
            return Ok(auth);
        }
        self.recheck()?;
        begin_recheck(&mut self.usable)?;
        let auth = self.provisioning.current_auth()?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(auth)
    }

    pub(super) fn helper_path(&self) -> &std::path::Path {
        self.image.path()
    }

    /// Parks the normal input post before the enclosing physical operation.
    ///
    /// # Errors
    /// Refuses unhealthy input custody, duplicate pending debt or Source
    /// exhaustion before any physical effect may enter. Canary is unchanged.
    pub(super) fn prepare_boot_owed_recheck_v1(&mut self) -> Result<(), HostTpmAdmissionErrorV1> {
        let Some(archive) = self.boot_currentness.as_mut() else {
            return Ok(());
        };
        if !self.usable {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        self.usable = false;
        if let Err(cause) = archive.prepare_owed_once(&self.provisioning, &self.image) {
            return Err(cause);
        }
        self.usable = true;
        Ok(())
    }

    /// Consumes the exact prepared normal native post without a new debit.
    ///
    /// Earlier failure does not suppress its independent auth, mode and held
    /// image observations. Success cannot restore a previously closed owner.
    ///
    /// # Errors
    /// Retains missing debt, prior failure or any original/native post refusal.
    pub(super) fn observe_boot_owed_recheck_once_v1(&mut self) -> Result<(), HostTpmAdmissionErrorV1> {
        let Some(archive) = self.boot_currentness.as_mut() else {
            return Ok(());
        };
        let was_usable = self.usable;
        self.usable = false;
        archive.observe_owed_once(&self.provisioning, &self.image)?;
        if !was_usable {
            return Err(HostTpmAdmissionErrorV1::Unusable);
        }
        self.usable = true;
        Ok(())
    }

    /// Drains remaining prepaid normal post lanes after the caught body unwind.
    ///
    /// The terminal one-shot never restores input health. Already entered
    /// native originals stay retained; only still-unused owed lanes may enter.
    ///
    /// # Errors
    /// Refuses repeat drain or retains any outstanding original post failure.
    pub(super) fn drain_boot_owed_recheck_after_unwind_once_v1(
        &mut self,
    ) -> Result<(), HostTpmAdmissionErrorV1> {
        let Some(archive) = self.boot_currentness.as_mut() else {
            return Ok(());
        };
        self.usable = false;
        archive.drain_after_unwind_once(&self.provisioning, &self.image)
    }

    pub(super) fn require_executed_helper(&mut self, pid: u32) -> Result<(), HostTpmAdmissionErrorV1> {
        if let Some(archive) = self.boot_currentness.as_mut() {
            begin_recheck(&mut self.usable)?;
            archive.run_once(&self.provisioning, &self.image, inputs::HostInputOperationV1::Executed(pid))?;
            self.usable = true;
            return Ok(());
        }
        self.recheck()?;
        begin_recheck(&mut self.usable)?;
        self.image.require_executed(pid)
            .map_err(HostTpmAdmissionErrorV1::Image)?;
        self.image.revalidate()
            .map_err(HostTpmAdmissionErrorV1::Image)?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<(), HostTpmAdmissionErrorV1> {
        drop(self.provisioning.current_auth()?);
        self.provisioning.recheck_mode()?;
        self.image.revalidate().map_err(HostTpmAdmissionErrorV1::Image)?;
        self.provisioning.recheck_origins()
    }
}

/// Closes health before work; only the actual owner restores it after success.
fn begin_recheck(usable: &mut bool) -> Result<(), HostTpmAdmissionErrorV1> {
    if !*usable {
        return Err(HostTpmAdmissionErrorV1::Unusable);
    }
    *usable = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrun_input_latch_closes_before_checks_and_never_recovers_a_failure() {
        let mut usable = true;

        begin_recheck(&mut usable).unwrap();

        assert!(!usable);
        assert!(matches!(
            begin_recheck(&mut usable),
            Err(HostTpmAdmissionErrorV1::Unusable),
        ));
        assert!(!usable);
    }

    #[test]
    fn unrun_input_latch_starts_closed_without_a_genuine_owner() {
        let mut usable = false;

        let result = begin_recheck(&mut usable);

        assert!(matches!(result, Err(HostTpmAdmissionErrorV1::Unusable)));
        assert!(!usable);
    }
}
