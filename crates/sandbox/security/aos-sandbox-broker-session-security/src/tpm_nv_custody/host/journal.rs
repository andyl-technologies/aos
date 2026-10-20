//! Genuine admitted Host inputs and two original existing journal owners.
//!
//! Journals are opened only at fixed root-owned roles, main first and sidecar
//! second, with no create, repair, seed or recovery fallback. Transient Core
//! guards reborrow these same owned fields; no self-borrowed guard is stored.
//! The whole owner and exact TX remain borrowed through native funding DATA.
//! The private physical borrow can lend only these same original locks and
//! compare this complete disk pair. No journal effect or activation is exposed.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_controller_domain::journal::{
    CapturedJournalOpenModeV1, RuntimeDeploymentFloorCapturedJournalOpenV1,
    RuntimeDeploymentMainCapturedJournalOpenV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use aos_sandbox_controller_domain::{
    HostPhysicalInvocationErrorV1, HostPhysicalInvocationLeaseV1,
    Journal, JournalLimits, JournalTransaction, ProtectedJournalPreflight,
    ProtectedJournalSnapshot, ProtectedJournalLockCustodyV1,
    RecordNamespace, RuntimeDeploymentComparisonOriginsV1,
};

use super::{
    AdmittedHostTpmInputsV1, HostOwnedJournalErrorV1, JOURNAL_DIRECTORY,
    MAIN_JOURNAL_NAME, SIDECAR_JOURNAL_NAME,
};
use super::store::{HostDiskAssociationV1, StoredHostFloorV1, compare_original_state};
use crate::tpm_nv_custody::{
    FloorCutV1, HostFloorIntentDataV1, HostSidecarStoreV1, HostSuffixPreflightV1,
    sidecar_limits,
};

mod boot_receiving;
use boot_receiving::BootNamePostsV1;

/// Parks every returned admission prefix before the next fallible observation.
///
/// Only the actual publisher coordinator creates this reservoir. Failed opens,
/// complete replay reports and the already assembled owner stay resident; the
/// old temporary-returning admission remains a separate, unchanged API.
pub(super) struct HostCanaryJournalAdmissionV2<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    inputs: Option<Result<AdmittedHostTpmInputsV1<'origin, 'startup>, super::HostTpmAdmissionErrorV1>>,
    boot_inputs: super::HostTpmInputAdmissionOriginalV1<'origin, 'startup>,
    boot_main: RuntimeDeploymentMainCapturedJournalOpenV1,
    boot_sidecar: RuntimeDeploymentFloorCapturedJournalOpenV1,
    main: Option<Result<(Journal, aos_sandbox_controller_domain::RecoveryReport), aos_sandbox_controller_domain::JournalError>>,
    sidecar: Option<Result<(Journal, aos_sandbox_controller_domain::RecoveryReport), aos_sandbox_controller_domain::JournalError>>,
    reports: [Option<aos_sandbox_controller_domain::RecoveryReport>; 2],
    owner: Option<HostOwnedJournalInputsV1<'origin, 'startup>>,
    attempted: bool,
    first_failure: Arc<Option<HostOwnedJournalErrorV1>>,
    first_stage: Option<CanaryJournalAdmissionStageV2>,
    post_debt: [Option<HostOwnedJournalErrorV1>; 6],
    boot_name_posts: Option<Box<BootNamePostsV1>>,
}

#[derive(Clone, Copy, Debug)]
enum CanaryJournalAdmissionStageV2 { Input, Main, Sidecar, Other }

/// Shares the populated native cause and its irreversible failed-stage tag.
#[derive(Clone, Debug)]
pub(super) struct CanaryJournalAdmissionDiagnosticV2 {
    cause: Arc<Option<HostOwnedJournalErrorV1>>,
    stage: CanaryJournalAdmissionStageV2,
}

impl std::fmt::Display for CanaryJournalAdmissionDiagnosticV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "selected Host native admission refused at {:?}", self.stage)
    }
}

impl std::error::Error for CanaryJournalAdmissionDiagnosticV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

impl<'origin, 'startup> HostCanaryJournalAdmissionV2<'origin, 'startup> {
    pub(super) fn new(origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>) -> Self {
        Self {
            origins, inputs: None, main: None, sidecar: None, reports: [None, None], owner: None,
            boot_inputs: super::HostTpmInputAdmissionOriginalV1::new(),
            boot_main: RuntimeDeploymentMainCapturedJournalOpenV1::new(),
            boot_sidecar: RuntimeDeploymentFloorCapturedJournalOpenV1::new(),
            attempted: false, first_failure: Arc::new(None), first_stage: None,
            post_debt: std::array::from_fn(|_| None),
            boot_name_posts: None,
        }
    }

    pub(super) fn admit_once(&mut self) -> Result<(), CanaryJournalAdmissionDiagnosticV2> {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }
        if self.attempted {
            // An interrupted admission has no returned native cause to clone.
            // The coordinator's caught-unwind route never calls this again;
            // an internal reentry must fence before releasing original fields.
            std::process::abort();
        } else {
            if Arc::get_mut(&mut self.first_failure).is_none()
                || self.post_debt.iter().any(Option::is_some)
            {
                std::process::abort();
            }
            self.attempted = true;
            self.first_stage = Some(CanaryJournalAdmissionStageV2::Other);
            let result = self.admit_inner();
            if let Err(cause) = result {
                self.park_first(cause);
            }
            // Each available original is observed independently. A poisoned
            // input is never readmitted merely to manufacture a positive cut.
            if self.boot_name_posts.is_none() {
                let origins = self
                    .origins
                    .recheck()
                    .map_err(HostOwnedJournalErrorV1::from);
                self.retain_post(0, origins);
            }
            if let Some(Ok((journal, _))) = self.main.as_ref() {
                let main = if let Some(posts) = self.boot_name_posts.as_mut() {
                    posts.observe_once(0, journal)
                } else { journal.validate_held_root_owned_at(
                    Path::new(JOURNAL_DIRECTORY), MAIN_JOURNAL_NAME,
                ).map_err(HostOwnedJournalErrorV1::from) };
                self.retain_post(1, main);
            }
            if let Some(Ok((journal, _))) = self.sidecar.as_ref() {
                let sidecar = if let Some(posts) = self.boot_name_posts.as_mut() {
                    posts.observe_once(1, journal)
                } else { journal.validate_held_root_owned_at(
                    Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME,
                ).map_err(HostOwnedJournalErrorV1::from) };
                self.retain_post(2, sidecar);
            }
            if self.boot_name_posts.is_none() {
                if let Some(owner) = self.owner.as_mut() {
                    let whole = owner.recheck();
                    self.retain_post(3, whole);
                }
            }
        }
        if self.first_failure.is_some() { Err(self.diagnostic()) } else { Ok(()) }
    }

    pub(super) fn admit_boot_once_v1(
        &mut self,
        native: &aos_sandbox_controller_domain::RuntimeBootPreparationNativeOriginalV1<'_, '_>,
    ) -> Result<(), CanaryJournalAdmissionDiagnosticV2> {
        if !std::ptr::eq(self.origins, native.origins_v1()) || self.boot_name_posts.is_some() {
            self.park_first(HostOwnedJournalErrorV1::Changed);
            return Err(self.diagnostic());
        }
        if let Err(cause) = native.begin_outer_startup_after_v1() {
            self.park_first(cause.into());
            return Err(self.diagnostic());
        }
        match BootNamePostsV1::prepare(self.origins) {
            Ok(posts) => self.boot_name_posts = Some(Box::new(posts)),
            Err(cause) => {
                self.park_first(cause);
                let after = native
                    .finish_outer_startup_after_owed_once_v1()
                    .map_err(HostOwnedJournalErrorV1::from);
                self.retain_post(4, after);
                return Err(self.diagnostic());
            }
        }
        let _body = self.admit_once();
        let native_posts = self.drain_boot_after_unwind_once_v1();
        self.retain_post(5, native_posts);
        let after = native
            .finish_outer_startup_after_owed_once_v1()
            .map_err(HostOwnedJournalErrorV1::from);
        self.retain_post(4, after);
        if self.first_failure.is_some() {
            Err(self.diagnostic())
        } else {
            Ok(())
        }
    }

    pub(super) fn drain_boot_after_unwind_once_v1(
        &mut self,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        let input = match self.owner.as_mut() {
            Some(owner) => owner.inputs.drain_boot_owed_recheck_after_unwind_once_v1(),
            None => match self.inputs.as_mut().and_then(|result| result.as_mut().ok()) {
                Some(inputs) => inputs.drain_boot_owed_recheck_after_unwind_once_v1(),
                None => Ok(()),
            },
        };
        let history = match self.owner.as_ref() {
            Some(owner) => owner
                .origins
                .drain_boot_journal_after_unwind_once_v1(&owner.main, owner.store.original_ref())
                .map_err(HostOwnedJournalErrorV1::from),
            None => {
                let main = self
                    .main
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|(journal, _)| {
                        self.origins
                            .drain_boot_journal_member_after_unwind_once_v1(journal)
                    });
                let sidecar = self
                    .sidecar
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|(journal, _)| {
                        self.origins
                            .drain_boot_journal_member_after_unwind_once_v1(journal)
                    });
                main.transpose()
                    .and_then(|_| sidecar.transpose())
                    .map(|_| ())
                    .map_err(HostOwnedJournalErrorV1::from)
            }
        };
        let main = if let Some(posts) = self.boot_name_posts.as_mut() {
            let journal = self.owner.as_ref().map(|owner| &owner.main).or_else(|| {
                self.main
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .map(|(journal, _)| journal)
            });
            match journal {
                Some(journal) => posts.observe_once(0, journal),
                None => Ok(()),
            }
        } else {
            Ok(())
        };
        let sidecar = if let Some(posts) = self.boot_name_posts.as_mut() {
            let journal = self
                .owner
                .as_ref()
                .map(|owner| owner.store.original_ref())
                .or_else(|| {
                    self.sidecar
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .map(|(journal, _)| journal)
                });
            match journal {
                Some(journal) => posts.observe_once(1, journal),
                None => Ok(()),
            }
        } else {
            Ok(())
        };
        // Both name diagnostics are backed by permanent native originals.
        input?;
        main?;
        sidecar?;
        history?;
        Ok(())
    }

    fn admit_inner(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        self.origins.recheck()?;
        if self.origins.canary_purpose_v2().is_none() && self.origins.boot_purpose_v1().is_none() {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.inputs = Some(if self.origins.boot_purpose_v1().is_some() {
            AdmittedHostTpmInputsV1::admit_boot_retaining_once(self.origins, &mut self.boot_inputs)
        } else {
            AdmittedHostTpmInputsV1::admit(self.origins)
        });
        if matches!(self.inputs.as_ref(), Some(Err(_))) {
            self.first_stage = Some(CanaryJournalAdmissionStageV2::Input);
            return match self.inputs.take() {
                Some(Err(cause)) => Err(HostOwnedJournalErrorV1::Inputs(cause)),
                _ => std::process::abort(),
            };
        }
        if self.origins.boot_purpose_v1().is_some() {
            self.inputs
                .as_mut()
                .and_then(|result| result.as_mut().ok())
                .ok_or(HostOwnedJournalErrorV1::Unusable)?
                .prepare_boot_owed_recheck_v1()?;
        }
        let main_limits = self.origins.compared_main_limits()?;
        self.main = Some(if self.origins.boot_purpose_v1().is_some() {
            self.origins.admit_boot_publisher_representation_v1(Some(
                RuntimeDeploymentMainCapturedJournalOpenV1::fixed_preparation_demand()
                    .map_err(aos_sandbox_controller_domain::JournalError::from)?,
            ))?;
            self.boot_main.prepare_once(main_limits, CapturedJournalOpenModeV1::ExistingOnly);
            if let Some(extent) = self.boot_main.captured_extent() {
                let demand = boot_replay_demand_v1(extent)?;
                self.origins.admit_boot_publisher_representation_v1(demand)?;
                self.boot_main.replay_once();
            }
            self.boot_main.take_opened().ok_or(aos_sandbox_controller_domain::JournalError::ProtectedBoundary)
        } else {
            Journal::open_existing_protected_at(
                Path::new(JOURNAL_DIRECTORY), MAIN_JOURNAL_NAME, main_limits,
            )
        });
        if matches!(self.main.as_ref(), Some(Err(_))) {
            self.first_stage = Some(CanaryJournalAdmissionStageV2::Main);
            return match self.main.take() {
                Some(Err(cause)) => Err(HostOwnedJournalErrorV1::Journal(cause)),
                _ => std::process::abort(),
            };
        }
        let (main, report) = self.main.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(HostOwnedJournalErrorV1::Unusable)?;
        if report.truncated_bytes != 0 {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        drop(self.origins.hold_main(main)?);
        let limits = sidecar_limits(main_limits)?;
        self.sidecar = Some(if self.origins.boot_purpose_v1().is_some() {
            self.origins.admit_boot_publisher_representation_v1(Some(
                RuntimeDeploymentFloorCapturedJournalOpenV1::fixed_preparation_demand()
                    .map_err(aos_sandbox_controller_domain::JournalError::from)?,
            ))?;
            self.boot_sidecar.prepare_once(limits, CapturedJournalOpenModeV1::ExistingOnly);
            if let Some(extent) = self.boot_sidecar.captured_extent() {
                let demand = boot_replay_demand_v1(extent)?;
                self.origins.admit_boot_publisher_representation_v1(demand)?;
                self.boot_sidecar.replay_once();
            }
            self.boot_sidecar.take_opened().ok_or(aos_sandbox_controller_domain::JournalError::ProtectedBoundary)
        } else {
            Journal::open_existing_protected_at(
                Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME, limits,
            )
        });
        if matches!(self.sidecar.as_ref(), Some(Err(_))) {
            self.first_stage = Some(CanaryJournalAdmissionStageV2::Sidecar);
            return match self.sidecar.take() {
                Some(Err(cause)) => Err(HostOwnedJournalErrorV1::Journal(cause)),
                _ => std::process::abort(),
            };
        }
        let (_, report) = self.sidecar.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostOwnedJournalErrorV1::Unusable)?;
        if report.truncated_bytes != 0 || self.owner.is_some()
            || !matches!(self.inputs.as_ref(), Some(Ok(_)))
            || !matches!(self.main.as_ref(), Some(Ok(_)))
            || !matches!(self.sidecar.as_ref(), Some(Ok(_)))
        {
            return Err(HostOwnedJournalErrorV1::Changed);
        }

        // All slot/destination checks precede ANY move. This final match has
        // no fallible work between removal and parking the same whole owner.
        if let (Some(Ok(inputs)), Some(Ok((main, main_report))), Some(Ok((journal, sidecar_report)))) = (
            self.inputs.take(), self.main.take(), self.sidecar.take(),
        ) {
            self.reports = [Some(main_report), Some(sidecar_report)];
            self.owner = Some(HostOwnedJournalInputsV1 {
                origins: self.origins, inputs, main,
                store: HostSidecarStoreV1::from_host(HostSidecarCustodyV1 {
                    journal, main_limits, origins: self.origins,
                }),
                usable: true,
            });
        }
        self.owner.as_mut().ok_or(HostOwnedJournalErrorV1::Unusable)?.recheck()
    }

    pub(super) fn owner_mut(&mut self) -> Result<&mut HostOwnedJournalInputsV1<'origin, 'startup>, HostOwnedJournalErrorV1> {
        if !self.attempted || self.first_failure.is_some() {
            return Err(HostOwnedJournalErrorV1::Unusable);
        }
        self.owner.as_mut().ok_or(HostOwnedJournalErrorV1::Unusable)
    }

    /// Borrows the original lower cause while every reached admission remains held.
    pub(super) fn first_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_stage {
            Some(CanaryJournalAdmissionStageV2::Input) => self.boot_inputs.failure(),
            Some(CanaryJournalAdmissionStageV2::Main) => self.boot_main.failure(),
            Some(CanaryJournalAdmissionStageV2::Sidecar) => self.boot_sidecar.failure(),
            _ => None,
        }.or_else(|| self.first_failure.as_ref().as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    fn retain_post(&mut self, index: usize, result: Result<(), HostOwnedJournalErrorV1>) {
        if let Err(cause) = result {
            if self.first_failure.is_none() {
                self.first_stage = Some(CanaryJournalAdmissionStageV2::Other);
                self.park_first(cause);
            } else {
                self.post_debt[index] = Some(cause);
            }
        }
    }

    fn park_first(&mut self, cause: HostOwnedJournalErrorV1) {
        if self.first_failure.is_some() {
            return;
        }
        // Normal pre-admission failures occur before admit_once selects a
        // native stage. Preserve any already selected lower stage and cause.
        self.first_stage.get_or_insert(CanaryJournalAdmissionStageV2::Other);
        let slot = Arc::get_mut(&mut self.first_failure).unwrap_or_else(|| std::process::abort());
        *slot = Some(cause);
    }

    fn diagnostic(&self) -> CanaryJournalAdmissionDiagnosticV2 {
        if self.first_failure.is_none() { std::process::abort(); }
        CanaryJournalAdmissionDiagnosticV2 {
            cause: Arc::clone(&self.first_failure),
            stage: self.first_stage.unwrap_or_else(|| std::process::abort()),
        }
    }
}

// The captured same-File extent is DATA. Only its genuine normal Origins pays
// before this shared native parser, semantic replay and terminal EOF probe.
fn boot_replay_demand_v1(
    extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
) -> Result<Option<ResourceVector>, aos_sandbox_controller_domain::JournalError> {
    let native = extent.dominant_native_receiving_demand_v1()?;
    let semantic = extent.dominant_semantic_receiving_demand_v1()?;
    Ok(native.checked_add(semantic).ok().and_then(|demand| {
        Some(demand.with(D::OutputBytes, extent.native_bytes.checked_add(1)?))
    }))
}

/// Carries only the genuine Host constructor's same original fixed sidecar.
///
/// Private construction/fields exclude raw Journal, DATA, default or callback
/// factories. This capsule owns no TPM, signer, secret or physical comparison.
pub(in crate::tpm_nv_custody) struct HostSidecarCustodyV1<'origin, 'startup> {
    journal: Journal,
    main_limits: JournalLimits,
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
}

impl HostSidecarCustodyV1<'_, '_> {
    pub(in crate::tpm_nv_custody) fn validate_held(&self) -> Result<(), HostOwnedJournalErrorV1> {
        self.origins.recheck()?;
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_journal_currentness_representation_v1(&self.journal)?;
        }
        self.journal.validate_held_root_owned_at(
            Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME,
        )?;
        self.origins.recheck()?;
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    pub(in crate::tpm_nv_custody) fn journal_ref(&self) -> &Journal {
        &self.journal
    }

    pub(in crate::tpm_nv_custody) fn is_boot_v1(&self) -> bool {
        self.origins.boot_purpose_v1().is_some()
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_models_v1(
        &self,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_journal_model_representation_v1(&self.journal)?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_lock_loan_v1(
        &self,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_journal_lock_loan_representation_v1(&self.journal)?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_append_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_journal_append_representation_v1(&self.journal, transaction)?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_prepared_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_transaction_model_representation_v1(transaction)?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_shapes_v1<I, T>(
        &self,
        transactions: I,
    ) -> Result<(), HostOwnedJournalErrorV1>
    where
        I: IntoIterator<Item = Result<T, aos_sandbox_controller_domain::JournalError>>,
        T: ExactSizeIterator<Item = aos_sandbox_journal::geometry::RecordShape>,
    {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins
                .admit_boot_journal_sequence_representation_v1(&self.journal, transactions)?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) fn admit_boot_digest_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins.admit_boot_publisher_representation_v1(
                crate::tpm_nv_custody::FloorHeadTransactionOriginalV3::receiving_demand_v3(
                    transaction,
                ),
            )?;
        }
        Ok(())
    }

    pub(in crate::tpm_nv_custody) const fn main_limits(&self) -> JournalLimits {
        self.main_limits
    }
}

/// Owns genuine admitted inputs and the actual existing full-state disk pair.
///
/// No raw writer, field, detach, clone, signer, secret or effect API escapes.
/// Failed/unwound work closes this same owner's usable latch before checks.
/// Ordinary drop releases files/borrows only; it is not a physical debt drain.
#[must_use = "genuine inputs and both original writers must stay retained"]
pub(super) struct HostOwnedJournalInputsV1<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    inputs: AdmittedHostTpmInputsV1<'origin, 'startup>,
    main: Journal,
    store: HostSidecarStoreV1<'origin, 'startup>,
    usable: bool,
}

impl<'origin, 'startup> HostOwnedJournalInputsV1<'origin, 'startup> {
    pub(super) fn require_boot_native_original_v1(
        &self,
        original: &aos_sandbox_controller_domain::RuntimeBootPreparationNativeOriginalV1<'_, '_>,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_none()
            || !std::ptr::eq(self.origins, original.origins_v1())
        {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok(())
    }
    /// Admits only independently existing originals under genuine Origins.
    ///
    /// # Errors
    /// Rejects input/origin drift, unsafe or absent originals, wrong limits,
    /// native/signed/canonical history disagreement or missing pending capacity.
    pub(super) fn admit(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, HostOwnedJournalErrorV1> {
        origins.recheck()?;
        let inputs = AdmittedHostTpmInputsV1::admit(origins)?;
        let main_limits = origins.compared_main_limits()?;
        let (mut main, main_report) = Journal::open_existing_protected_at(
            Path::new(JOURNAL_DIRECTORY), MAIN_JOURNAL_NAME, main_limits,
        )?;
        if main_report.truncated_bytes != 0 {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        drop(origins.hold_main(&mut main)?);
        let limits = sidecar_limits(main_limits)?;
        let (journal, sidecar_report) = Journal::open_existing_protected_at(
            Path::new(JOURNAL_DIRECTORY), SIDECAR_JOURNAL_NAME, limits,
        )?;
        if sidecar_report.truncated_bytes != 0 {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let custody = HostSidecarCustodyV1 { journal, main_limits, origins };
        let mut owner = Self {
            origins, inputs, main,
            store: HostSidecarStoreV1::from_host(custody),
            usable: true,
        };
        owner.recheck()?;
        Ok(owner)
    }

    /// Rechecks the same genuine inputs, full native pair and typed disk chain.
    ///
    /// # Errors
    /// Rejects previous failure, any original drift or unavailable cold suffix.
    pub(super) fn recheck(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(())
    }

    /// Returns rechecked disk-only associations, never fresh NV recovery rights.
    ///
    /// # Errors
    /// Rejects owner/input/pair/history drift, pending capacity or prior failure.
    pub(super) fn compare_cold_disk_state(
        &mut self,
    ) -> Result<StoredHostFloorV1, HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        let stored = self.recheck_inner()?;
        self.usable = true;
        Ok(stored)
    }

    /// Funds one exact signed TX and ordered suffix while borrowing this owner.
    ///
    /// # Errors
    /// Rejects a substituted/past TX, signed/native/schema mismatch, stale
    /// originals or any of the actual eight main/sidecar native limit failures.
    pub(super) fn fund_exact_transition<'owner, 'tx>(
        &'owner mut self,
        transaction: &'tx JournalTransaction,
    ) -> Result<HostFundingCutV1<'owner, 'origin, 'startup, 'tx>, HostOwnedJournalErrorV1> {
        self.begin_operation()?;
        let stored = self.recheck_inner()?;
        let CanaryHostFundingV2 { intent, main_token, main_snapshot, suffix } =
            self.fund_same_original_inner_v2(transaction, &stored)?;
        self.usable = true;
        let mut funded = HostFundingCutV1 {
            owner: self, transaction, stored, intent, main_token, main_snapshot, suffix,
        };
        funded.recheck()?;
        Ok(funded)
    }

    // This is the SAME ordered all-eight/snapshot/suffix engine. The selected
    // physical borrower does not reset the parked outer owner's usable latch.
    fn fund_same_original_inner_v2(
        &mut self,
        transaction: &JournalTransaction,
        stored: &StoredHostFloorV1,
    ) -> Result<CanaryHostFundingV2, HostOwnedJournalErrorV1> {
        let intent = match &stored.prepared {
            Some((intent, original)) => {
                if transaction != original {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
                *intent
            }
            None => {
                let target = self.compare_prospective(transaction, stored.current)?;
                self.admit_boot_digest_v1(transaction)?;
                HostFloorIntentDataV1::compare_successor(
                    self.origins_scope()?, stored.checkpoint, target, transaction,
                )?
            }
        };
        let main_token = if stored.association == HostDiskAssociationV1::PendingMainTarget {
            // The same original TX was authenticated at its historical native
            // predecessor/target above. It must never be preflighted again.
            None
        } else {
            if self.origins.boot_purpose_v1().is_some() {
                self.origins
                    .admit_boot_journal_append_representation_v1(&self.main, transaction)?;
            }
            let authority = self.main
                .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
            let token = authority.preflight_transactions(std::slice::from_ref(transaction))?;
            authority.validate_preflight_for_effect(&token, std::slice::from_ref(transaction))?;
            Some(token)
        };
        let main_snapshot = self.main
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?.snapshot()?;
        let suffix = self.store.fund_suffix(intent, transaction, stored.prepared.is_some())?;
        if &self.recheck_inner()? != stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok(CanaryHostFundingV2 { intent, main_token, main_snapshot, suffix })
    }

    fn begin_operation(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        close_owner_health(&mut self.usable)
    }

    fn admit_boot_digest_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.origins.boot_purpose_v1().is_some() {
            self.origins.admit_boot_publisher_representation_v1(
                crate::tpm_nv_custody::FloorHeadTransactionOriginalV3::receiving_demand_v3(
                    transaction,
                ),
            )?;
        }
        Ok(())
    }

    fn origins_scope(&mut self) -> Result<[u8; 32], HostOwnedJournalErrorV1> {
        Ok(self.origins.hold_main(&mut self.main)?.compared_scope()?)
    }

    fn compare_prospective(
        &mut self,
        transaction: &JournalTransaction,
        current: FloorCutV1,
    ) -> Result<FloorCutV1, HostOwnedJournalErrorV1> {
        let mut held = self.origins.hold_main(&mut self.main)?.compare_append(transaction)?;
        let before = held.compared_current()?;
        if FloorCutV1::new(before.0, before.1)? != current {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let target = held.compared_target()?;
        Ok(FloorCutV1::new(target.0, target.1)?)
    }

    fn recheck_inner(&mut self) -> Result<StoredHostFloorV1, HostOwnedJournalErrorV1> {
        self.origins.recheck()?;
        self.inputs.recheck()?;
        self.store.validate_held()?;
        let main_limits = self.origins.compared_main_limits()?;
        let expected_limits = sidecar_limits(main_limits)?;
        let stored = {
            let mut pair = self.origins.hold_pair(&mut self.main, self.store.original_mut())?;
            if pair.compared_sidecar_limits()? != expected_limits {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            let stored = compare_original_state(&mut pair, main_limits)?;
            if pair.compared_sidecar_sequence()? != stored.sidecar_sequence {
                return Err(HostOwnedJournalErrorV1::Changed);
            }
            stored
        };
        if let Some((intent, transaction)) = &stored.prepared {
            if stored.association == HostDiskAssociationV1::PendingMainOld {
                if self.compare_prospective(transaction, stored.current)? != intent.target().cut() {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
            }
            // Cold admission checks actual remaining final capacity without
            // retaining a fake future permit. The funding guard reacquires it.
            let suffix = self.store.fund_suffix(*intent, transaction, true)?;
            self.store.validate_suffix(&suffix)?;
        }
        self.store.require_projection(
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, transaction)| (*intent, transaction)),
        )?;
        self.inputs.recheck()?;
        self.store.validate_held()?;
        self.origins.recheck()?;
        Ok(stored)
    }
}

/// Parks the SAME whole owner before any fallible physical invocation work.
///
/// No raw writer or configurable input escapes. The physical owner retains
/// this borrow; it alone may use these named original comparison/loan seams.
pub(in crate::tpm_nv_custody) struct HeldHostPhysicalJournalV1<'owner, 'origin, 'startup> {
    owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>,
    admitted_usable: bool,
    canary_funding: Option<CanaryHostFundingV2>,
    canary_commits: [Option<Arc<CanaryNativeResultV2>>; 3],
    boot_name_posts: [Option<Box<BootNamePostsV1>>; 32],
    boot_name_next: usize,
    boot_name_pending: Option<usize>,
}

impl<'owner, 'origin, 'startup> HeldHostPhysicalJournalV1<'owner, 'origin, 'startup> {
    pub(super) fn park(owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>) -> Self {
        let admitted_usable = owner.usable;
        owner.usable = false;
        Self {
            owner, admitted_usable, canary_funding: None,
            canary_commits: std::array::from_fn(|_| None),
            boot_name_posts: std::array::from_fn(|_| None),
            boot_name_next: 0,
            boot_name_pending: None,
        }
    }

    pub(super) fn claim_invocation(
        &self,
    ) -> Result<HostPhysicalInvocationLeaseV1<'origin, 'startup>, HostPhysicalInvocationErrorV1> {
        self.owner.origins.claim_host_physical_invocation()
    }

    pub(super) fn close(&mut self) {
        self.admitted_usable = false;
        self.owner.usable = false;
    }

    pub(super) fn compare_state(
        &mut self,
    ) -> Result<(StoredHostFloorV1, [u8; 32]), HostOwnedJournalErrorV1> {
        if !self.admitted_usable {
            return Err(HostOwnedJournalErrorV1::Unusable);
        }
        let stored = self.owner.recheck_inner()?;
        let scope = self.owner.origins_scope()?;
        if self.owner.recheck_inner()? != stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok((stored, scope))
    }

    pub(super) fn helper_path(&self) -> &Path {
        self.owner.inputs.helper_path()
    }

    // Only new primary observations use this same-owner debit. Independently
    // owed drains consume their earlier reserve and never call this forwarder.
    pub(super) fn admit_boot_representation_v1(
        &self,
        demand: Option<ResourceVector>,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_none() {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.owner.origins.admit_boot_publisher_representation_v1(demand)?;
        Ok(())
    }

    pub(super) fn require_executed_helper(
        &mut self,
        pid: u32,
    ) -> Result<(), super::HostTpmAdmissionErrorV1> {
        self.owner.inputs.require_executed_helper(pid)
    }

    pub(super) fn current_auth(
        &mut self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, super::HostTpmAdmissionErrorV1> {
        self.owner.inputs.current_auth()
    }

    pub(super) fn names(&self) -> ([u8; 34], [u8; 34]) {
        let claims = self.owner.origins.genesis_claims();
        (claims.nv_name, claims.salt_name)
    }

    pub(super) fn loan_main(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, HostOwnedJournalErrorV1> {
        self.compare_state()?;
        let loan = self.owner.origins.hold_main(&mut self.owner.main)?.loan_main_lock()?;
        self.compare_state()?;
        Ok(loan)
    }

    pub(super) fn loan_sidecar(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, HostOwnedJournalErrorV1> {
        self.compare_state()?;
        let loan = self.owner.store.loan_host_lock()?;
        self.compare_state()?;
        Ok(loan)
    }

    pub(super) fn canary_main_data_v2(&mut self) -> Result<CanaryHostMainDataV2, HostOwnedJournalErrorV1> {
        let (stored, scope) = self.compare_state()?;
        if self.owner.origins.canary_purpose_v2().is_none() {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.owner.origins.genesis_claims().signer)
            .map_err(|_| HostOwnedJournalErrorV1::Changed)?;
        let mut last = None;
        for (name, bytes) in self.owner.main.records(RecordNamespace::HostCatalogReconciliation) {
            if name == aos_sandbox_protocol::runtime_deployment::canary::GENESIS_KEY_V2 {
                continue;
            }
            // The genuine same-main guard already checked the complete row
            // grammar, canonical order, signature and original native COMMIT.
            let association = aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationV2::decode(bytes, &key)
                .map_err(|_| HostOwnedJournalErrorV1::Changed)?;
            last = Some(association);
        }
        let data = CanaryHostMainDataV2 { stored, scope, last };
        let after = self.compare_state()?;
        if after.0 != data.stored || after.1 != data.scope {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok(data)
    }

    pub(super) fn fund_canary_same_v2(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<HostFloorIntentDataV1, HostOwnedJournalErrorV1> {
        if self.canary_funding.is_some() || (self.owner.origins.canary_purpose_v2().is_none()
            && self.owner.origins.boot_purpose_v1().is_none()) {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        let (stored, _) = self.compare_state()?;
        self.canary_funding = Some(self.owner.fund_same_original_inner_v2(transaction, &stored)?);
        let funding = self.canary_funding.as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        Ok(funding.intent)
    }

    pub(super) fn prepare_canary_destinations_v2(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if !self.admitted_usable || (self.owner.origins.canary_purpose_v2().is_none()
            && self.owner.origins.boot_purpose_v1().is_none())
            || self.canary_commits.iter().any(Option::is_some)
        {
            return Err(HostOwnedJournalErrorV1::Unusable);
        }
        // Only the selected borrower allocates these three empty DATA result
        // destinations before helper/effect crossings. Ordinary park is inert.
        for slot in &mut self.canary_commits {
            *slot = Some(Arc::new(None));
        }
        Ok(())
    }

    /// Compares only this saved, funded pending transition before physical EXTEND.
    pub(super) fn canary_extend_input_v2(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<[u8; 32], HostOwnedJournalErrorV1> {
        self.owner.admit_boot_digest_v1(transaction)?;
        let funding = self.canary_funding.as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        funding.intent.require_transaction(transaction)?;
        let intent = funding.intent;
        let (stored, _) = self.compare_state()?;
        if stored.association != HostDiskAssociationV1::PendingMainOld
            || stored.prepared.as_ref().is_none_or(|(saved, bytes)| *saved != intent || bytes != transaction)
        {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        // Both main and final-only sidecar capacity must be current before
        // EXTEND, not obtained by signing or dispatching a prospective result.
        let suffix = self.owner.store.fund_suffix(intent, transaction, true)?;
        let funding = self.canary_funding.as_mut().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        funding.suffix = suffix;
        self.owner.store.validate_suffix(&funding.suffix)?;
        let authority = self.owner.main.claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        authority.validate_snapshot_for_effect(&funding.main_snapshot)?;
        authority.validate_preflight_for_effect(
            funding.main_token.as_ref().ok_or(HostOwnedJournalErrorV1::Changed)?,
            std::slice::from_ref(transaction),
        )?;
        Ok(intent.target().extend_input())
    }

    // Available original input and fixed-file observations remain separate on
    // a failed selected action. They do not reopen, repair or readmit owners.
    pub(super) fn observe_canary_inputs_v2(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_some() {
            self.owner.inputs.observe_boot_owed_recheck_once_v1()?;
            // The enclosing physical operation independently finishes its
            // prepaid genuine credential/startup post. This input-only branch
            // cannot substitute a fresh after-effect Source debit for it.
            return Ok(());
        } else {
            self.owner.inputs.recheck()?;
        }
        self.owner.origins.recheck()?;
        Ok(())
    }

    pub(super) fn prepare_boot_input_after_v1(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_some() {
            self.owner.inputs.prepare_boot_owed_recheck_v1()?;
            let index = self.boot_name_next;
            if self.boot_name_pending.is_some() || index >= self.boot_name_posts.len() {
                return Err(HostOwnedJournalErrorV1::Unusable);
            }
            let posts = BootNamePostsV1::prepare(self.owner.origins)?;
            self.boot_name_posts[index] = Some(Box::new(posts));
            self.boot_name_next += 1;
            self.boot_name_pending = Some(index);
        }
        Ok(())
    }

    pub(super) fn drain_boot_input_after_unwind_once_v1(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_some() {
            let input = self
                .owner
                .inputs
                .drain_boot_owed_recheck_after_unwind_once_v1();
            let history = self.owner.origins.drain_boot_journal_after_unwind_once_v1(
                &self.owner.main,
                self.owner.store.original_ref(),
            );
            let main = self.observe_boot_name_post_v1(0);
            let sidecar = self.observe_boot_name_post_v1(1);
            input?;
            main?;
            sidecar?;
            history?;
        }
        Ok(())
    }

    pub(super) fn observe_canary_main_name_v2(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_some() { return self.observe_boot_name_post_v1(0); }
        self.owner.main.validate_held_root_owned_at(Path::new(JOURNAL_DIRECTORY), MAIN_JOURNAL_NAME)?;
        Ok(())
    }

    pub(super) fn observe_canary_sidecar_name_v2(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        if self.owner.origins.boot_purpose_v1().is_some() {
            return self.observe_boot_name_post_v1(1);
        }
        self.owner.store.validate_held()
    }

    fn observe_boot_name_post_v1(&mut self, lane: usize) -> Result<(), HostOwnedJournalErrorV1> {
        let Some(index) = self.boot_name_pending else {
            return Ok(());
        };
        let posts = self.boot_name_posts[index]
            .as_mut()
            .ok_or(HostOwnedJournalErrorV1::Unusable)?;
        let journal = match lane {
            0 => &self.owner.main,
            1 => self.owner.store.original_ref(),
            _ => return Err(HostOwnedJournalErrorV1::Changed),
        };
        let result = posts.observe_once(lane, journal);
        if posts.complete() {
            self.boot_name_pending = None;
        }
        result
    }

    /// Performs exactly one already-funded selected native step on these writers.
    ///
    /// The original CommitResult/JournalError enters a vacant resident slot
    /// BEFORE its coarse projection or any physical/name/history postcheck.
    pub(super) fn commit_canary_step_v2(
        &mut self,
        step: CanaryHostNativeStepV2,
        transaction: &JournalTransaction,
        original: &super::PublisherNativeOriginalRefV3<'_, '_, '_>,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        self.require_native_original_v3(original)?;
        self.owner.admit_boot_digest_v1(transaction)?;
        let index = step.index();
        if self.canary_commits[index].as_ref().is_none_or(|slot| slot.as_ref().is_some())
            || !self.admitted_usable
            || (self.owner.origins.canary_purpose_v2().is_none()
                && self.owner.origins.boot_purpose_v1().is_none())
        {
            return Err(HostOwnedJournalErrorV1::Unusable);
        }
        let (stored, _) = self.compare_state()?;
        let funding = self.canary_funding.as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        funding.intent.require_transaction(transaction)?;
        let intent = funding.intent;
        match step {
            CanaryHostNativeStepV2::Prepare => {
                if stored.prepared.is_some() || stored.association != HostDiskAssociationV1::Complete {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
                self.owner.store.validate_suffix(&funding.suffix)?;
                let destination = self.canary_commits[index].as_mut().and_then(Arc::get_mut)
                    .filter(|slot| slot.is_none()).ok_or(HostOwnedJournalErrorV1::Unusable)?;
                *destination = Some(self.owner.store.commit_first_canary_v2(&funding.suffix, original));
            }
            CanaryHostNativeStepV2::Main => {
                if stored.prepared.as_ref().is_none_or(|(saved, bytes)| *saved != intent || bytes != transaction)
                    || stored.association != HostDiskAssociationV1::PendingMainOld
                {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
                // Prepare invalidates the old two-step sidecar token. Use the
                // same engine at its ACTUAL new sequence for final-only funding.
                let suffix = self.owner.store.fund_suffix(intent, transaction, true)?;
                self.canary_funding.as_mut().ok_or(HostOwnedJournalErrorV1::Unusable)?.suffix = suffix;
                let funding = self.canary_funding.as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
                let authority = self.owner.main.claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
                authority.validate_snapshot_for_effect(&funding.main_snapshot)?;
                authority.validate_preflight_for_effect(
                    funding.main_token.as_ref().ok_or(HostOwnedJournalErrorV1::Changed)?,
                    std::slice::from_ref(transaction),
                )?;
                drop(authority);
                self.owner.store.validate_suffix(&funding.suffix)?;
                if self.owner.origins.boot_purpose_v1().is_some() {
                    self.owner
                        .origins
                        .admit_boot_journal_append_representation_v1(
                            &self.owner.main,
                            transaction,
                        )?;
                }
                let mut authority = self.owner.main.claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
                let destination = self.canary_commits[index].as_mut().and_then(Arc::get_mut)
                    .filter(|slot| slot.is_none()).ok_or(HostOwnedJournalErrorV1::Unusable)?;
                original.require_clock()?;
                *destination = Some(authority.commit(transaction).map_err(HostOwnedJournalErrorV1::from));
            }
            CanaryHostNativeStepV2::Finalize => {
                if stored.prepared.as_ref().is_none_or(|(saved, bytes)| *saved != intent || bytes != transaction)
                    || stored.association != HostDiskAssociationV1::PendingMainTarget
                {
                    return Err(HostOwnedJournalErrorV1::Changed);
                }
                self.owner.store.validate_suffix(&funding.suffix)?;
                let destination = self.canary_commits[index].as_mut().and_then(Arc::get_mut)
                    .filter(|slot| slot.is_none()).ok_or(HostOwnedJournalErrorV1::Unusable)?;
                *destination = Some(self.owner.store.commit_first_canary_v2(&funding.suffix, original));
            }
        }
        let result = self.canary_commits[index].as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        if matches!(result.as_ref(), Some(Err(_))) {
            return Err(HostOwnedJournalErrorV1::CanaryNative(CanaryNativeErrorV2 {
                result: Arc::clone(result),
            }));
        }
        let returned = match result.as_ref() {
            Some(Ok(returned)) => returned,
            _ => return Err(HostOwnedJournalErrorV1::Unusable),
        };
        let funding = self.canary_funding.as_ref().ok_or(HostOwnedJournalErrorV1::Unusable)?;
        let mut pair = self.owner.origins.hold_pair(
            &mut self.owner.main, self.owner.store.original_mut(),
        )?;
        match step {
            CanaryHostNativeStepV2::Main => {
                pair.compare_canary_main_commit_v2(transaction, returned)?;
            }
            CanaryHostNativeStepV2::Prepare | CanaryHostNativeStepV2::Finalize => {
                pair.compare_canary_sidecar_commit_v2(
                    funding.suffix.first_canary_transaction_v2()?, returned,
                )?;
            }
        }
        drop(pair);
        let (after, _) = self.compare_state()?;
        let expected = match step {
            CanaryHostNativeStepV2::Prepare => HostDiskAssociationV1::PendingMainOld,
            CanaryHostNativeStepV2::Main => HostDiskAssociationV1::PendingMainTarget,
            CanaryHostNativeStepV2::Finalize => HostDiskAssociationV1::Complete,
        };
        if after.association != expected || match step {
            CanaryHostNativeStepV2::Finalize => after.checkpoint != intent.target(),
            _ => after.prepared.as_ref().is_none_or(|(saved, bytes)| *saved != intent || bytes != transaction),
        } {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok(())
    }

    pub(super) fn require_native_original_v3(
        &self,
        original: &super::PublisherNativeOriginalRefV3<'_, '_, '_>,
    ) -> Result<(), HostOwnedJournalErrorV1> {
        match original {
            super::PublisherNativeOriginalRefV3::Canary(_)
                if self.owner.origins.canary_purpose_v2().is_some() => Ok(()),
            super::PublisherNativeOriginalRefV3::Boot(original)
                if self.owner.origins.boot_purpose_v1().is_some()
                    && std::ptr::eq(self.owner.origins, original.origins_v1()) => Ok(()),
            _ => Err(HostOwnedJournalErrorV1::Changed),
        }
    }

    pub(super) fn boot_main_data_v1(&mut self) -> Result<BootHostMainDataV1, HostOwnedJournalErrorV1> {
        let (stored, scope) = self.compare_state()?;
        let purpose = self.owner.origins.boot_purpose_v1().ok_or(HostOwnedJournalErrorV1::Changed)?;
        let mut last = None;
        for (name, bytes) in self.owner.main.records(RecordNamespace::HostCatalogReconciliation) {
            if name == aos_sandbox_protocol::runtime_deployment::boot_preparation::BOOT_PREPARATION_GENESIS_KEY_V1 {
                continue;
            }
            // The same original full native fold has already admitted every
            // row. This projects the final signed DATA without another parser
            // or Journal read; it grants no new physical floor or append.
            last = Some(aos_sandbox_protocol::runtime_deployment::boot_preparation::SignedBootPreparationRecordDataV1::verify_v1(
                bytes, purpose,
            ).map_err(|_| HostOwnedJournalErrorV1::Changed)?);
        }
        let after = self.compare_state()?;
        if after.0 != stored || after.1 != scope {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        Ok(BootHostMainDataV1 { stored, scope, last })
    }
}

pub(in crate::tpm_nv_custody) struct BootHostMainDataV1 {
    pub(in crate::tpm_nv_custody) stored: StoredHostFloorV1,
    pub(in crate::tpm_nv_custody) scope: [u8; 32],
    pub(in crate::tpm_nv_custody) last: Option<aos_sandbox_protocol::runtime_deployment::boot_preparation::SignedBootPreparationRecordDataV1>,
}

pub(in crate::tpm_nv_custody) struct CanaryHostMainDataV2 {
    pub(in crate::tpm_nv_custody) stored: StoredHostFloorV1,
    pub(in crate::tpm_nv_custody) scope: [u8; 32],
    pub(in crate::tpm_nv_custody) last: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationV2>,
}

struct CanaryHostFundingV2 {
    intent: HostFloorIntentDataV1,
    main_token: Option<ProtectedJournalPreflight>,
    main_snapshot: ProtectedJournalSnapshot,
    suffix: HostSuffixPreflightV1,
}

type CanaryNativeResultV2 = Option<Result<aos_sandbox_controller_domain::CommitResult, HostOwnedJournalErrorV1>>;

/// Shares only the authentic parked native cause, never its original writer.
#[derive(Clone, Debug)]
pub(super) struct CanaryNativeErrorV2 {
    result: Arc<CanaryNativeResultV2>,
}

impl std::fmt::Display for CanaryNativeErrorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected Host native step failed with retained custody")
    }
}

impl std::error::Error for CanaryNativeErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.result.as_ref() {
            Some(Err(cause)) => Some(cause),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::tpm_nv_custody) enum CanaryHostNativeStepV2 {
    Prepare,
    Main,
    Finalize,
}

impl CanaryHostNativeStepV2 {
    const fn index(self) -> usize {
        match self { Self::Prepare => 0, Self::Main => 1, Self::Finalize => 2 }
    }
}

/// Retains exact funding DATA plus the whole original owner and original TX.
///
/// No fields, raw tokens/writers, mutation or physical capability are exported.
/// Any future prepare invalidates a two-TX suffix: a later granted coordinator
/// must read actual pending state and reacquire its fresh final-only suffix.
#[must_use = "exact funding DATA must keep both actual originals borrowed"]
pub(super) struct HostFundingCutV1<'owner, 'origin, 'startup, 'tx> {
    owner: &'owner mut HostOwnedJournalInputsV1<'origin, 'startup>,
    transaction: &'tx JournalTransaction,
    stored: StoredHostFloorV1,
    intent: HostFloorIntentDataV1,
    main_token: Option<ProtectedJournalPreflight>,
    main_snapshot: ProtectedJournalSnapshot,
    suffix: HostSuffixPreflightV1,
}

impl HostFundingCutV1<'_, '_, '_, '_> {
    /// Rechecks full original state and exact instance/sequence/ordered funding.
    ///
    /// # Errors
    /// Rejects any input/history drift, substituted token/TX or previous failure.
    pub(super) fn recheck(&mut self) -> Result<(), HostOwnedJournalErrorV1> {
        self.owner.begin_operation()?;
        if self.owner.recheck_inner()? != self.stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.owner.admit_boot_digest_v1(self.transaction)?;
        self.intent.require_transaction(self.transaction)?;
        let authority = self.owner.main
            .claim_protected_authority(RecordNamespace::HostCatalogReconciliation)?;
        authority.validate_snapshot_for_effect(&self.main_snapshot)?;
        if let Some(token) = &self.main_token {
            authority.validate_preflight_for_effect(token, std::slice::from_ref(self.transaction))?;
        }
        drop(authority);
        self.owner.store.validate_suffix(&self.suffix)?;
        if self.owner.recheck_inner()? != self.stored {
            return Err(HostOwnedJournalErrorV1::Changed);
        }
        self.owner.usable = true;
        Ok(())
    }

    /// Returns only rechecked complete predecessor/target cut DATA.
    ///
    /// # Errors
    /// Rejects drift or an unusable owner/funding guard; grants no effect.
    pub(super) fn compared_cuts(&mut self) -> Result<(FloorCutV1, FloorCutV1), HostOwnedJournalErrorV1> {
        self.recheck()?;
        Ok((self.intent.predecessor().cut(), self.intent.target().cut()))
    }
}

fn close_owner_health(usable: &mut bool) -> Result<(), HostOwnedJournalErrorV1> {
    if !*usable {
        return Err(HostOwnedJournalErrorV1::Unusable);
    }
    *usable = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrun_whole_owner_health_refuses_closed_data_without_constructing_origins() {
        let mut usable = true;

        close_owner_health(&mut usable).unwrap();

        assert!(!usable);
        assert!(matches!(close_owner_health(&mut usable), Err(HostOwnedJournalErrorV1::Unusable)));
    }

    #[test]
    fn unrun_private_health_closes_before_unwind_without_fabricating_an_owner() {
        let mut usable = true;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            close_owner_health(&mut usable).unwrap();
            panic!("inert private latch vector");
        }));

        assert!(result.is_err());
        assert!(!usable);
    }
}
