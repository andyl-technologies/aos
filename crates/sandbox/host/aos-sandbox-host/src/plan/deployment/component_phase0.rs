//! Captures installed component phase-0 DATA inside its original paid interval.
//!
//! The owner retains every reached native prefix and its independent Control
//! post. Only complete positive disposal exposes the partial deployment claim;
//! the claim still cannot construct backend readiness or authorize a workload.

use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Weak};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;
use aos_systemd_client::{ServicePropertiesReadOriginalV2, SystemdClient};

use crate::phase0_probe::{Phase0DeploymentFactsDataV2, Phase0DeploymentFactsOriginalV2};
use crate::plan::readiness::boot_preparation_original::{
    BootPreparationClosedV1, HostBootPreparationOriginalV1,
};
use crate::plan::readiness::component_original::{
    PackagedRuntimeOriginalV2, ReadinessLoadOriginalV2,
};
use crate::{HostError, Result};

use super::component_target::HostShiftedTargetOriginalV2;
use super::control::{HostComponentControlStartupV2, HostControlPreparationReceivingV5};
use super::{HOST_SERVICE, VerifiedPhase0ClaimV1};

const HARDENING: &[&str] = &[
    "NoNewPrivileges",
    "PrivateDevices",
    "MemoryDenyWriteExecute",
    "ProtectSystem",
];

const HOST_DEPENDENCIES: &[&str] = &["Requires", "After"];

#[derive(Clone, Copy)]
enum First {
    Entry,
    Before,
    Body,
    BootAfter,
    After,
    Disposal,
    Reentry,
    Quote,
    Aliases,
}

// Large fixed native destinations are constructed only after the same Control
// ledger has admitted their complete source-owned representation.
struct Phase0CaptureV2 {
    facts: [Phase0DeploymentFactsOriginalV2; 2],
    load: [ReadinessLoadOriginalV2; 2],
    package: [PackagedRuntimeOriginalV2; 4],
    policy: [RetainedLiveSelinuxPolicyReadbackV1; 3],
    target: HostShiftedTargetOriginalV2,
    hardening: ServicePropertiesReadOriginalV2,
    boot_preparation: HostBootPreparationOriginalV1,
    boot_entered: bool,
    boot_body_failure_selected: bool,
    boot_after: Option<std::result::Result<(), BootPreparationClosedV1>>,
    programs: Vec<u8>,
    program_allocation: Option<std::result::Result<(), std::collections::TryReserveError>>,
    manager: Option<Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>>,
    before: Option<Result<()>>,
    preparation: Option<Result<()>>,
    before_original_selected: bool,
    body: Option<Result<()>>,
    after: Option<Result<()>>,
    after_original_selected: bool,
    disposal: Option<Result<()>>,
    aliases: Option<Result<()>>,
    draft_claim: Option<VerifiedPhase0ClaimV1>,
}

impl Phase0CaptureV2 {
    fn new() -> Self {
        Self {
            facts: std::array::from_fn(|_| Phase0DeploymentFactsOriginalV2::new()),
            load: std::array::from_fn(|_| ReadinessLoadOriginalV2::new()),
            package: std::array::from_fn(|_| PackagedRuntimeOriginalV2::new()),
            policy: std::array::from_fn(|_| RetainedLiveSelinuxPolicyReadbackV1::new()),
            target: HostShiftedTargetOriginalV2::new(),
            hardening: ServicePropertiesReadOriginalV2::new(),
            boot_preparation: HostBootPreparationOriginalV1::new(),
            boot_entered: false,
            boot_body_failure_selected: false,
            boot_after: None,
            programs: Vec::new(),
            program_allocation: None,
            manager: None,
            before: None,
            preparation: None,
            before_original_selected: false,
            body: None,
            after: None,
            after_original_selected: false,
            disposal: None,
            aliases: None,
            draft_claim: None,
        }
    }

    async fn observe_body(
        &mut self,
        loan: &HostControlPreparationReceivingV5<'_>,
        systemd: &Arc<SystemdClient>,
        credentials: &Path,
        state: &Path,
        nspawn: &str,
        policy: &str,
    ) -> Result<()> {
        let programs = loan.component_programs_v2()?;
        self.program_allocation = Some(self.programs.try_reserve_exact(programs.len()));
        if !matches!(self.program_allocation, Some(Ok(()))) {
            return Err(closed());
        }
        self.programs.extend_from_slice(programs);
        let host_pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
        self.hardening
            .observe_startup_once_v2(
                systemd,
                HOST_SERVICE,
                host_pid,
                HARDENING,
                HOST_DEPENDENCIES,
            )
            .await
            .map_err(|_| closed())?;
        crate::plan::readiness::verify_host_service_hardening(
            self.hardening.service_values_v2().ok_or_else(closed)?,
        )?;

        // Publication success is independently observed before either load can
        // advance the rollback watermark. Its final observation remains owed
        // even if facts, package validation or a later JSON load refuses.
        let hostd = loan.component_host_executable_path_v2()?;
        self.boot_entered = true;
        self.boot_preparation
            .observe_before_once_v1(systemd, credentials, &self.hardening, nspawn, hostd, policy)
            .await
            .map_err(|_| closed())?;
        self.facts[0]
            .observe_once_v2(
                credentials,
                nspawn,
                loan.component_host_executable_path_v2()?,
                policy,
            )
            .map_err(|_| closed())?;
        let facts = self.facts[0].facts_v2().copied();
        self.load[0]
            .load_with_boot_preparation_once_v1(credentials, state, nspawn, &self.boot_preparation)
            .map_err(|_| closed())?;
        let Some(readiness) = self.load[0].evidence_v2()? else {
            // An optional report remains independently checked even before a
            // readiness publisher exists. Absence never opens the backend.
            if let Some(facts) = facts {
                self.target
                    .observe_once_v2(systemd, facts.observation)
                    .await
                    .map_err(|_| closed())?;
                self.facts[1]
                    .observe_once_v2(
                        credentials,
                        nspawn,
                        loan.component_host_executable_path_v2()?,
                        policy,
                    )
                    .map_err(|_| closed())?;
                if self.facts[1].facts_v2() != Some(&facts) {
                    return Err(HostError::State(
                        "phase-0 probe changed during Host readback".to_owned(),
                    ));
                }
            }
            return Ok(());
        };

        self.package[0]
            .capture_component_once_v2(readiness, loan.component_pid1_original_v2()?)
            .map_err(|_| closed())?;
        self.policy[0].verify_once(policy).map_err(|_| closed())?;
        // The existing service verifier ends with a fresh package comparison.
        self.package[1]
            .capture_component_once_v2(readiness, loan.component_pid1_original_v2()?)
            .map_err(|_| closed())?;
        self.package[0]
            .proof_v2()?
            .require_same_observed_v2(self.package[1].proof_v2()?)?;
        compare_policy(&mut self.policy, 1, policy)?;
        let (probe_digest, observation) = match_probe(readiness, facts)?;

        self.target
            .observe_once_v2(systemd, observation)
            .await
            .map_err(|_| closed())?;
        self.package[2]
            .capture_component_once_v2(readiness, loan.component_pid1_original_v2()?)
            .map_err(|_| closed())?;
        self.package[0]
            .proof_v2()?
            .require_same_observed_v2(self.package[2].proof_v2()?)?;
        compare_policy(&mut self.policy, 2, policy)?;
        let policy_digest = self.policy[0].verified().ok_or_else(closed)?.digest();

        let publisher_generation = readiness.publisher_generation();
        self.load[1]
            .load_with_boot_preparation_once_v1(credentials, state, nspawn, &self.boot_preparation)
            .map_err(|_| closed())?;
        let final_readiness = self.load[1].evidence_v2()?.ok_or_else(closed)?;
        self.package[3]
            .capture_component_once_v2(final_readiness, loan.component_pid1_original_v2()?)
            .map_err(|_| closed())?;
        self.package[0]
            .proof_v2()?
            .require_same_observed_v2(self.package[3].proof_v2()?)?;
        self.facts[1]
            .observe_once_v2(
                credentials,
                nspawn,
                loan.component_host_executable_path_v2()?,
                policy,
            )
            .map_err(|_| closed())?;
        let (final_probe, final_observation) =
            match_probe(final_readiness, self.facts[1].facts_v2().copied())?;
        if final_readiness.publisher_generation() != publisher_generation
            || final_probe != probe_digest
            || final_observation != observation
        {
            return Err(HostError::State(
                "phase-0 claim changed during live readback".to_owned(),
            ));
        }
        self.draft_claim = Some(VerifiedPhase0ClaimV1 {
            readiness: self.load[0].take_evidence_v2()?.ok_or_else(closed)?,
            packaged: self.package[0].take_proof_v2()?,
            probe_digest,
            observation,
            policy_digest,
        });
        Ok(())
    }

    fn body_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.preparation
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(|e| e as _)
            .or_else(|| {
                self.program_allocation
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .map(|e| e as _)
            })
            .or_else(|| self.hardening.failure().map(|error| error as _))
            .or_else(|| {
                self.boot_body_failure_selected
                    .then(|| self.boot_preparation.failure())
                    .flatten()
            })
            .or_else(|| self.facts[0].failure_v2())
            .or_else(|| self.load[0].failure())
            .or_else(|| self.package[0].failure())
            .or_else(|| self.policy[0].failure())
            .or_else(|| self.package[1].failure())
            .or_else(|| self.policy[1].failure())
            .or_else(|| self.target.failure())
            .or_else(|| self.package[2].failure())
            .or_else(|| self.policy[2].failure())
            .or_else(|| self.load[1].failure())
            .or_else(|| self.package[3].failure())
            .or_else(|| self.facts[1].failure_v2())
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|e| e as _))
    }
}

/// Retains one paid, boot-local installed component deployment verification.
///
/// A complete claim establishes only phase-0 deployment DATA. Actual payload,
/// supervisor, Agent and Guardian verification remain with the Launch owner.
#[must_use = "retain the whole phase-0 original through its consuming launch"]
pub struct HostComponentPhase0OriginalV2 {
    capture: Option<Box<Phase0CaptureV2>>,
    entry: Option<Result<()>>,
    quote: Option<Result<ResourceVector>>,
    manager_origin: Option<Weak<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>>,
    entry_original_selected: bool,
    first: Option<First>,
    entered: bool,
    complete: bool,
}

impl HostComponentPhase0OriginalV2 {
    /// Creates empty destinations without allocation, native IO or admission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capture: None,
            entry: None,
            quote: None,
            manager_origin: None,
            entry_original_selected: false,
            first: None,
            entered: false,
            complete: false,
        }
    }

    pub(in crate::plan::deployment) fn receiving_demand_v2(
        credentials: &Path,
        state: &Path,
        nspawn: &str,
        hostd: &Path,
        policy: &str,
        program_bytes: usize,
    ) -> Option<ResourceVector> {
        let path_bytes = credentials
            .as_os_str()
            .len()
            .checked_add(state.as_os_str().len())?
            .checked_add(nspawn.len())?;
        let facts = Phase0DeploymentFactsOriginalV2::receiving_demand_v2(
            credentials,
            nspawn,
            hostd,
            policy,
        )?;
        let load = ReadinessLoadOriginalV2::receiving_demand_v2(path_bytes)?;
        let package = PackagedRuntimeOriginalV2::receiving_demand_v2(path_bytes)?;
        let target = HostShiftedTargetOriginalV2::receiving_demand_v2()?;
        let mac = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let memory = std::mem::size_of::<Phase0CaptureV2>()
            .checked_mul(3)?
            .checked_add(program_bytes.checked_mul(3)?)?
            .checked_add(ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(
                HARDENING.len(),
                HOST_DEPENDENCIES.len(),
            )?)?
            .checked_add(3_usize.checked_mul(mac.memory_bytes)?)?;
        let boot =
            HostBootPreparationOriginalV1::receiving_demand_v1(credentials, nspawn, hostd, policy)?;
        let mut result = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(
                D::OpenFiles,
                u64::try_from(3_usize.checked_mul(mac.open_files)?).ok()?,
            )
            .with(D::MetadataEntries, mac.metadata_entries.checked_mul(3)?)
            .with(D::OutputBytes, mac.input_bytes.checked_mul(3)?)
            .checked_add(boot)
            .ok()?;
        for demand in [
            facts, facts, load, load, package, package, package, package, target,
        ] {
            result = result.checked_add(demand).ok()?;
        }
        Some(result)
    }

    /// Observes deployment once using the same admitted Control and manager.
    ///
    /// # Errors
    /// Retains insufficient funding, changed startup, failed native or package
    /// verification, and independently owed post failures. Reentry is refused.
    pub async fn observe_once_v2(
        &mut self,
        startup: &mut HostComponentControlStartupV2,
        systemd: &Arc<SystemdClient>,
        credentials: &Path,
        state: &Path,
        nspawn: &str,
        policy: &str,
    ) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(closed());
        }
        self.entered = true;
        self.quote = Some((|| {
            self.manager_origin = Some(Arc::downgrade(
                startup.component_phase0_manager_original_v2()?,
            ));
            Self::receiving_demand_v2(
                credentials,
                state,
                nspawn,
                startup.component_host_executable_path_v2()?,
                policy,
                startup.component_programs_v2()?.len(),
            )
            .ok_or(HostError::ResourceExhausted)
        })());
        let demand = match self.quote.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => {
                self.first = Some(First::Quote);
                return Err(closed());
            }
        };
        let mut loan = match startup.begin_component_phase0_once_v2(
            systemd,
            demand,
            &mut self.entry_original_selected,
        ) {
            Ok(loan) => {
                self.entry = Some(Ok(()));
                loan
            }
            Err(error) => {
                self.entry = Some(Err(error));
                self.first = Some(First::Entry);
                return Err(closed());
            }
        };
        self.capture = Some(Box::new(Phase0CaptureV2::new()));
        let Some(capture) = self.capture.as_mut() else {
            std::process::abort();
        };
        capture.preparation = Some((|| {
            capture.manager = Some(Arc::clone(loan.component_manager_original_v2()?));
            Ok(())
        })());
        if !matches!(capture.preparation, Some(Ok(()))) {
            self.first = Some(First::Body);
        }
        capture.before = Some(loan.observe_before_once_v5().await);
        if !matches!(capture.before, Some(Ok(()))) {
            capture.before_original_selected = loan.component_phase0_control_failure_selected_v2();
            self.first.get_or_insert(First::Before);
        } else if self.first.is_none() {
            capture.body = Some(
                capture
                    .observe_body(&loan, systemd, credentials, state, nspawn, policy)
                    .await,
            );
            if !matches!(capture.body, Some(Ok(()))) {
                // Snapshot selection before the independent Boot post can
                // acquire a later cause on the same retained owner.
                capture.boot_body_failure_selected = capture.boot_preparation.failure().is_some();
                self.first.get_or_insert(First::Body);
            }
        }
        if capture.boot_entered {
            capture.boot_after = Some(
                capture
                    .boot_preparation
                    .observe_after_once_v1(systemd)
                    .await,
            );
            if !matches!(capture.boot_after, Some(Ok(()))) {
                self.first.get_or_insert(First::BootAfter);
            }
        }
        // The independent destination was prepaid and prearmed by this same
        // loan. A body refusal cannot suppress its native/source/clock posts.
        capture.after = Some(loan.observe_after_once_v5().await);
        if !matches!(capture.after, Some(Ok(()))) {
            capture.after_original_selected = loan.component_phase0_control_failure_selected_v2();
            self.first.get_or_insert(First::After);
        }
        if self.first.is_none() {
            let target_retired = capture.facts[0].facts_v2().is_none()
                || capture.target.retire_completed_native_aliases_v2();
            let hardening_retired = capture.hardening.retire_completed_native_aliases_v2();
            let boot_retired = !capture.boot_entered
                || capture
                    .boot_preparation
                    .retire_completed_native_aliases_v1();
            capture.aliases = Some(if target_retired && hardening_retired && boot_retired {
                Ok(())
            } else {
                Err(closed())
            });
            if !matches!(capture.aliases, Some(Ok(()))) {
                self.first = Some(First::Aliases);
            }
        }
        if self.first.is_none() {
            capture.disposal = Some(loan.dispose_positive_once_v5());
            if !matches!(capture.disposal, Some(Ok(()))) {
                self.first = Some(First::Disposal);
            }
        }
        self.complete = self.first.is_none();
        if self.complete { Ok(()) } else { Err(closed()) }
    }

    /// Borrows the fully completed partial deployment claim.
    ///
    /// # Errors
    /// Rejects incomplete capture or an absent optional readiness credential.
    pub fn phase0_v2(&self) -> Result<&VerifiedPhase0ClaimV1> {
        if !self.complete || self.first.is_some() {
            return Err(closed());
        }
        self.capture
            .as_ref()
            .and_then(|c| c.draft_claim.as_ref())
            .ok_or_else(closed)
    }

    /// Reports a fully observed optional claim without promoting its absence.
    ///
    /// # Errors
    /// Rejects an incomplete or failed retained interval.
    pub fn has_claim_v2(&self) -> Result<bool> {
        if !self.complete || self.first.is_some() {
            return Err(closed());
        }
        Ok(self
            .capture
            .as_ref()
            .is_some_and(|c| c.draft_claim.is_some()))
    }

    /// Requires the exact original admitted startup and readonly manager.
    ///
    /// # Errors
    /// Rejects an incomplete owner or a different or closed startup original.
    pub(crate) fn require_same_startup_v2(
        &self,
        startup: &HostComponentControlStartupV2,
    ) -> Result<()> {
        self.phase0_v2()?;
        let manager = self
            .capture
            .as_ref()
            .and_then(|c| c.manager.as_ref())
            .ok_or_else(closed)?;
        startup.require_component_phase0_origin_v2(manager)
    }

    /// Borrows the actual verified program artifact after complete capture.
    ///
    /// # Errors
    /// Rejects absent claims, incomplete capture or an empty program artifact.
    pub(crate) fn programs_v2(&self) -> Result<&[u8]> {
        self.phase0_v2()?;
        self.capture
            .as_ref()
            .map(|c| c.programs.as_slice())
            .filter(|p| !p.is_empty())
            .ok_or_else(closed)
    }

    /// Borrows a local cause or the enclosing Control refusal marker.
    ///
    /// [`Self::failure_with_startup_v2`] also resolves selected Control native
    /// and financial causes while borrowing that same startup original.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|e| e as _),
            First::Before => self
                .capture
                .as_ref()?
                .before
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            First::Body => self.capture.as_ref()?.body_failure(),
            First::BootAfter => self.capture.as_ref()?.boot_preparation.failure(),
            First::After => self
                .capture
                .as_ref()?
                .after
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            First::Disposal => self
                .capture
                .as_ref()?
                .disposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            First::Reentry => Some(&CLOSED),
            First::Quote => self.quote.as_ref()?.as_ref().err().map(|e| e as _),
            First::Aliases => self
                .capture
                .as_ref()?
                .aliases
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
        }
    }

    /// Borrows the exact selected Control cause from the same startup original.
    ///
    /// Selection is latched at the failed entry or native boundary, before
    /// later posts can introduce another cause. The weak association preserves
    /// the actual manager identity without constructing another source owner.
    #[must_use]
    pub fn failure_with_startup_v2<'cause>(
        &'cause self,
        startup: &'cause HostComponentControlStartupV2,
    ) -> Option<&'cause (dyn Error + 'cause)> {
        let selected = match self.first? {
            First::Entry => self.entry_original_selected,
            First::Before => self.capture.as_ref()?.before_original_selected,
            First::After => self.capture.as_ref()?.after_original_selected,
            _ => false,
        };
        if selected {
            if let Some(origin) = self.manager_origin.as_ref().and_then(Weak::upgrade) {
                if let Some(cause) = startup.component_phase0_failure_for_origin_v2(&origin) {
                    return Some(cause);
                }
            }
        }
        self.failure().map(|cause| cause as _)
    }
}

impl Default for HostComponentPhase0OriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn match_probe(
    readiness: &crate::plan::ProtectedBackendReadinessEvidence,
    facts: Option<Phase0DeploymentFactsDataV2>,
) -> Result<([u8; 32], crate::phase0_probe::Phase0ProbeObservationV2)> {
    super::matching_signed_probe(
        readiness.phase0_probe_claim(),
        facts.map(|f| (f.probe_digest, f.observation)),
    )
}

fn compare_policy(
    policies: &mut [RetainedLiveSelinuxPolicyReadbackV1; 3],
    index: usize,
    path: &str,
) -> Result<()> {
    policies[index].verify_once(path).map_err(|_| closed())?;
    policies[0]
        .verified()
        .ok_or_else(closed)?
        .require_same_observed_v1(policies[index].verified().ok_or_else(closed)?)
        .map_err(|error| HostError::State(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
#[error("component phase-0 original is incomplete or closed")]
struct Closed;
static CLOSED: Closed = Closed;

fn closed() -> HostError {
    HostError::Fence("component phase-0 original is incomplete or closed")
}
