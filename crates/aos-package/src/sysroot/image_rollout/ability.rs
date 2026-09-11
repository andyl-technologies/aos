//! Native provider backend for checked single-host A/B rollout operations.
//!
//! The ordinary ability runtime owns intent, completion, cancellation, and
//! recovery. This backend owns only the physical sysroot effects. It always
//! reauthenticates the exact image pair against `ImageGenerationState`, then
//! uses the existing transition-intent and rollout record for selection.

use std::collections::BTreeSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_plan::{AbRolloutRequest, MAX_RETENTION_MILLIS, RolloutImageIdentity};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::types::{ImageGeneration, ImageGenerationState, ImageRolloutStatus};

use super::{qualified_rollout_record, validate_active_rollout_selection};
use crate::sysroot::{
    load_image_generation_state_pub, prepare_image_selection, remove_file_durable, sync_directory,
    write_atomic_durable,
};

const EXECUTION_SCHEMA: &str = "aos.ability.native-ab-image-rollout-state/v1";
const EXECUTION_DIRECTORY: &str = "ability-rollouts";
const UKI_RETENTION_DIRECTORY: &str = "EFI/.aos-rollout-retention";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UkiRetentionManifest {
    schema: String,
    candidate: String,
    candidate_entry: String,
    candidate_sha256: String,
    predecessor: String,
    predecessor_entry: String,
    predecessor_sha256: String,
}

/// Describes durable progress through the native A/B provider backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AbilityRolloutPhase {
    /// Both exact images have durable store and ESP retention roots.
    Retained,
    /// The candidate is authenticated in the inactive slot.
    Prepared,
    /// Current workloads have completed the configured drain.
    Drained,
    /// The candidate is the durable next-boot selection.
    Selected,
    /// The authenticated candidate booted and awaits terminal health.
    CandidateBooted,
    /// Candidate health succeeded while both images remain retained.
    HealthyRetained,
    /// The predecessor regained authority while both images remain retained.
    FallbackRetained,
    /// Retirement was admitted and is durably removing rollout-specific roots.
    Retiring,
    /// The later transition removed the inactive image's expired lease.
    Retired,
}

/// Preserves the authenticated terminal branch after its lease is retired.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AbilityRolloutOutcome {
    /// The candidate remains active after successful health evaluation.
    CandidateHealthy,
    /// The candidate failed health and must return authority to the predecessor.
    CandidateUnhealthy,
    /// The predecessor remains active after candidate health failure.
    PredecessorFallback,
}

/// Records the provider-owned projection of an ordinary checked transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbilityRolloutState {
    /// Identifies the durable provider-state schema.
    pub(crate) schema: String,
    /// Retains the exact checked rollout request.
    pub(crate) request: AbRolloutRequest,
    /// Identifies the retained predecessor generation.
    pub(crate) predecessor_generation: u32,
    /// Identifies the prepared candidate generation.
    pub(crate) candidate_generation: u32,
    /// Records the last durably completed physical phase.
    pub(crate) phase: AbilityRolloutPhase,
    /// Preserves the terminal active image and health branch through retirement.
    pub(crate) outcome: Option<AbilityRolloutOutcome>,
}

/// Reports the physical A/B outcome used during reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalRolloutObservation {
    /// Selection is durable but no member of the pair has booted from it yet.
    AwaitingBoot,
    /// The candidate booted and awaits terminal health assessment.
    CandidateBooted,
    /// Candidate health succeeded and the physical rollout finalized.
    Healthy,
    /// The predecessor booted after failure, before boot commit finalized it.
    FallbackPendingCommit,
    /// The retained predecessor regained authority after candidate failure.
    Fallback,
}

/// Applies checked rollout effects to the existing A/B image backend.
#[derive(Clone, Debug)]
pub(crate) struct NativeAbRolloutBackend {
    image_profile: PathBuf,
    boot_root: PathBuf,
}

impl NativeAbRolloutBackend {
    /// Constructs a backend over one image profile and mounted ESP.
    pub(crate) fn new(image_profile: impl Into<PathBuf>, boot_root: impl Into<PathBuf>) -> Self {
        Self {
            image_profile: image_profile.into(),
            boot_root: boot_root.into(),
        }
    }

    /// Reauthenticates the physical rollout prerequisite before runtime intent.
    ///
    /// # Errors
    ///
    /// Returns an error when the request, image pair, active image, durable
    /// provider state, or retention deadline differs from current authority.
    pub(crate) fn preflight_operation(
        &self,
        request: &AbRolloutRequest,
        method: &str,
        now_millis: u64,
    ) -> Result<()> {
        let images = self.authenticate_pair(request)?;
        let predecessor = unique_image(&images, &request.predecessor, "predecessor")?;
        let candidate = unique_image(&images, &request.candidate, "candidate")?;
        ensure!(
            predecessor.slot != candidate.slot,
            "rollout images do not occupy opposite A/B slots"
        );

        let state_path = self.execution_directory(request)?.join("state.json");
        let has_state = state_path.is_file();
        if method == "retain" && !has_state {
            ensure!(
                predecessor.number == images.running && images.active_rollout.is_none(),
                "rollout predecessor is stale or another rollout is active"
            );
            ensure!(
                matches!(
                    request.retention_expires_at_millis.checked_sub(now_millis),
                    Some(1..=MAX_RETENTION_MILLIS)
                ),
                "rollout retention window is invalid"
            );
            return Ok(());
        }

        let state = self.require_state(request)?;
        ensure!(
            state.predecessor_generation == predecessor.number
                && state.candidate_generation == candidate.number,
            "durable rollout generations differ from authenticated images"
        );
        ensure!(
            images.running == predecessor.number || images.running == candidate.number,
            "current active image is outside the retained rollout pair"
        );
        if method == "retire" {
            ensure!(
                now_millis >= request.retention_expires_at_millis,
                "rollout retention lease has not expired"
            );
            self.authenticate_terminal_outcome(request, &state)?;
        }
        Ok(())
    }

    /// Installs both store roots and a durable provider record before mutation.
    ///
    /// # Errors
    ///
    /// Returns an error when image identity is stale or retention roots, UKI
    /// copies, their manifest, or provider state cannot be written durably.
    pub(crate) fn retain(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let images = self.authenticate_pair(request)?;
        let predecessor = unique_image(&images, &request.predecessor, "predecessor")?;
        let candidate = unique_image(&images, &request.candidate, "candidate")?;
        ensure!(
            predecessor.number == images.running && predecessor.slot != candidate.slot,
            "rollout pair is stale or does not occupy opposite A/B slots"
        );

        let directory = self.execution_directory(request)?;
        ensure_private_directory(&self.image_profile.join(EXECUTION_DIRECTORY))?;
        ensure_private_directory(&directory)?;
        cleanup_stale_temporaries(&directory, is_execution_temporary)?;
        // `/var/lib/profiles` is bind-mounted beneath Nix's real gcroots
        // directory, so these exact closure links are recursively collected as
        // durable roots rather than ordinary application symlinks.
        install_exact_root(
            &directory.join("predecessor-toplevel"),
            &request.predecessor.toplevel,
        )?;
        install_exact_root(
            &directory.join("predecessor-executor"),
            &request.predecessor.executor,
        )?;
        install_exact_root(
            &directory.join("candidate-toplevel"),
            &request.candidate.toplevel,
        )?;
        install_exact_root(
            &directory.join("candidate-executor"),
            &request.candidate.executor,
        )?;
        let uki_directory = self.retained_uki_directory(request)?;
        ensure_private_directory(&self.boot_root.join(UKI_RETENTION_DIRECTORY))?;
        ensure_private_directory(&uki_directory)?;
        cleanup_stale_temporaries(&uki_directory, is_retention_temporary)?;
        let (predecessor_entry, predecessor_sha256) =
            self.retain_uki(&uki_directory, "predecessor", predecessor)?;
        let (candidate_entry, candidate_sha256) =
            self.retain_uki(&uki_directory, "candidate", candidate)?;
        let manifest = UkiRetentionManifest {
            schema: EXECUTION_SCHEMA.to_string(),
            candidate: candidate.uki_path.clone(),
            candidate_entry,
            candidate_sha256,
            predecessor: predecessor.uki_path.clone(),
            predecessor_entry,
            predecessor_sha256,
        };
        publish_manifest(&uki_directory.join("manifest.json"), &manifest)?;

        let state = AbilityRolloutState {
            schema: EXECUTION_SCHEMA.to_string(),
            request: request.clone(),
            predecessor_generation: predecessor.number,
            candidate_generation: candidate.number,
            phase: AbilityRolloutPhase::Retained,
            outcome: None,
        };
        self.write_state(&state)?;
        Ok(state)
    }

    /// Authenticates the inactive candidate as physically prepared.
    ///
    /// # Errors
    ///
    /// Returns an error when retention has not completed, another image is
    /// pending, identity changed, or the prepared phase cannot be persisted.
    pub(crate) fn prepare(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let mut state = self.require_state(request)?;
        ensure!(
            matches!(
                state.phase,
                AbilityRolloutPhase::Retained | AbilityRolloutPhase::Prepared
            ),
            "candidate preparation is out of order"
        );
        let images = self.authenticate_pair(request)?;
        ensure!(
            images.pending.is_none() || images.pending == Some(state.candidate_generation),
            "another image is already pending"
        );
        state.phase = AbilityRolloutPhase::Prepared;
        self.write_state(&state)?;
        Ok(state)
    }

    /// Runs the supplied production drain and records success durably.
    ///
    /// # Errors
    ///
    /// Returns an error when preparation has not completed, identity changed,
    /// the drain fails, or the drained phase cannot be persisted.
    pub(crate) fn drain(
        &self,
        request: &AbRolloutRequest,
        drain: impl FnOnce() -> Result<()>,
    ) -> Result<AbilityRolloutState> {
        let mut state = self.require_state(request)?;
        if state.phase == AbilityRolloutPhase::Drained {
            return Ok(state);
        }
        ensure!(
            state.phase == AbilityRolloutPhase::Prepared,
            "drain is out of order"
        );
        self.authenticate_pair(request)?;
        drain().context("draining workloads for A/B rollout")?;
        state.phase = AbilityRolloutPhase::Drained;
        self.write_state(&state)?;
        Ok(state)
    }

    /// Uses the existing durable image-transition intent to select the candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when drain has not completed, physical identity or
    /// rollout state changed, boot selection fails, or state cannot persist.
    pub(crate) fn select(
        &self,
        request: &AbRolloutRequest,
        entry_id: &str,
        select: impl FnOnce(&str) -> Result<()>,
    ) -> Result<AbilityRolloutState> {
        let mut execution = self.require_state(request)?;
        if execution.phase == AbilityRolloutPhase::Selected {
            return Ok(execution);
        }
        ensure!(
            execution.phase == AbilityRolloutPhase::Drained,
            "selection is out of order"
        );

        let mut images = self.authenticate_pair(request)?;
        let rollout = qualified_rollout_record(
            &images,
            execution.candidate_generation,
            &request.candidate.state_format,
        )?;
        prepare_image_selection(
            &self.image_profile,
            &mut images,
            execution.candidate_generation,
            entry_id,
            Some(rollout),
        )?;
        let stable_entry_id = crate::sysroot::stable_uki_entry_id(entry_id)?;
        select(&stable_entry_id).context("selecting the counted A/B candidate")?;

        execution.phase = AbilityRolloutPhase::Selected;
        self.write_state(&execution)?;
        Ok(execution)
    }

    /// Reauthenticates durable sysroot state after a crash or reboot.
    ///
    /// # Errors
    ///
    /// Returns an error when provider state, image identity, or the physical
    /// active or terminal rollout record differs from the checked request.
    pub(crate) fn observe(&self, request: &AbRolloutRequest) -> Result<PhysicalRolloutObservation> {
        let execution = self.require_state(request)?;
        let images = self.authenticate_pair(request)?;
        let matching = |rollout: &crate::types::ImageRollout| {
            rollout.candidate == execution.candidate_generation
                && rollout.prior == execution.predecessor_generation
                && rollout.state_version == request.candidate.state_format
        };

        if let Some(active) = &images.active_rollout {
            ensure!(
                matching(active),
                "active rollout differs from checked identity"
            );
            if active.status == ImageRolloutStatus::Staged {
                validate_active_rollout_selection(&images, active, execution.candidate_generation)?;
            }
            return Ok(match active.status {
                ImageRolloutStatus::Staged => PhysicalRolloutObservation::AwaitingBoot,
                ImageRolloutStatus::CandidateBooted => {
                    ensure!(
                        images.running == execution.candidate_generation,
                        "active candidate status differs from the running image"
                    );
                    PhysicalRolloutObservation::CandidateBooted
                }
                ImageRolloutStatus::HealthFailed => {
                    if images.running == execution.candidate_generation {
                        PhysicalRolloutObservation::CandidateBooted
                    } else {
                        ensure!(
                            images.running == execution.predecessor_generation,
                            "failed rollout status differs from the retained image pair"
                        );
                        PhysicalRolloutObservation::FallbackPendingCommit
                    }
                }
                ImageRolloutStatus::Succeeded => {
                    bail!("a successful rollout cannot remain active")
                }
            });
        }
        let terminal = images
            .last_rollout
            .as_ref()
            .filter(|rollout| matching(rollout))
            .context("physical image state has no matching active or terminal rollout")?;
        Ok(match terminal.status {
            ImageRolloutStatus::Succeeded => {
                ensure!(
                    images.running == execution.candidate_generation,
                    "successful rollout does not name the running candidate"
                );
                PhysicalRolloutObservation::Healthy
            }
            ImageRolloutStatus::HealthFailed => {
                ensure!(
                    images.running == execution.predecessor_generation,
                    "failed rollout does not name the running predecessor"
                );
                PhysicalRolloutObservation::Fallback
            }
            _ => bail!("terminal rollout carries a nonterminal status"),
        })
    }

    /// Requires a physically finalized rollout outcome.
    ///
    /// # Errors
    ///
    /// Returns an error while candidate success or predecessor fallback remains
    /// represented by an active rollout awaiting boot commit.
    pub(crate) fn observe_terminal_outcome(
        &self,
        request: &AbRolloutRequest,
    ) -> Result<PhysicalRolloutObservation> {
        let observation = self.observe(request)?;
        ensure!(
            matches!(
                observation,
                PhysicalRolloutObservation::Healthy | PhysicalRolloutObservation::Fallback
            ),
            "rollout has not reached a physically finalized outcome"
        );
        Ok(observation)
    }

    /// Resolves the candidate's exact installed systemd-boot entry.
    ///
    /// # Errors
    ///
    /// Returns an error when candidate identity or its installed UKI is absent
    /// or ambiguous.
    pub(crate) fn candidate_entry_id(&self, request: &AbRolloutRequest) -> Result<String> {
        let images = self.authenticate_pair(request)?;
        let candidate = unique_image(&images, &request.candidate, "candidate")?;
        crate::sysroot::resolve_installed_uki_entry(&self.boot_root, &candidate.uki_path)
    }

    /// Verifies provider evidence required before physical boot finalization.
    ///
    /// # Errors
    ///
    /// Returns an error unless the running member of the exact image pair has
    /// the corresponding retained, provider-owned terminal branch.
    pub(crate) fn verify_boot_commit(
        &self,
        request: &AbRolloutRequest,
        running: u32,
    ) -> Result<()> {
        let state = self.require_state(request)?;
        let physical = self.observe(request)?;
        let expected = if running == state.candidate_generation {
            (
                AbilityRolloutPhase::HealthyRetained,
                AbilityRolloutOutcome::CandidateHealthy,
                PhysicalRolloutObservation::CandidateBooted,
            )
        } else if running == state.predecessor_generation {
            (
                AbilityRolloutPhase::FallbackRetained,
                AbilityRolloutOutcome::PredecessorFallback,
                PhysicalRolloutObservation::FallbackPendingCommit,
            )
        } else {
            bail!("running image is outside the checked rollout pair")
        };
        ensure!(
            (state.phase, state.outcome, physical) == (expected.0, Some(expected.1), expected.2),
            "provider health evidence does not authorize boot finalization"
        );
        self.authenticate_retention(request)?;
        Ok(())
    }

    /// Authenticates one method's durable postcondition without replaying it.
    ///
    /// This path is used for both reconciliation and cancellation. It may read
    /// physical image, lease, and provider state, but never writes provider
    /// state, changes boot selection, drains workloads, or requests a reboot.
    ///
    /// # Errors
    ///
    /// Returns an error when durable or physical state does not prove the
    /// method's postcondition under the exact checked image identity.
    pub(crate) fn observe_operation(
        &self,
        request: &AbRolloutRequest,
        method: &str,
    ) -> Result<AbilityRolloutState> {
        let state = self.require_state(request)?;
        let images = self.authenticate_pair(request)?;
        self.authenticate_state_generations(&state, &images)?;

        match method {
            "retain" => {
                ensure!(
                    !matches!(
                        state.phase,
                        AbilityRolloutPhase::Retiring | AbilityRolloutPhase::Retired
                    ),
                    "retention postcondition is no longer present"
                );
                self.authenticate_retention(request)?;
                Ok(state)
            }
            "prepare" => {
                ensure!(
                    !matches!(
                        state.phase,
                        AbilityRolloutPhase::Retained
                            | AbilityRolloutPhase::Retiring
                            | AbilityRolloutPhase::Retired
                    ),
                    "candidate preparation postcondition is not durable"
                );
                self.authenticate_retention(request)?;
                Ok(state)
            }
            "drain" => {
                ensure!(
                    matches!(
                        state.phase,
                        AbilityRolloutPhase::Drained
                            | AbilityRolloutPhase::Selected
                            | AbilityRolloutPhase::CandidateBooted
                            | AbilityRolloutPhase::HealthyRetained
                            | AbilityRolloutPhase::FallbackRetained
                    ),
                    "drain postcondition is not durable"
                );
                self.authenticate_retention(request)?;
                Ok(state)
            }
            "select" | "observe-boot" => {
                let state = self.project_physical_observation(request, state)?;
                self.authenticate_retention(request)?;
                Ok(state)
            }
            "observe-health" => self.health_assessment(request),
            "withdraw" => self.observe_withdrawal(request),
            "hold" => self.observe_hold(request),
            "retire" => {
                ensure!(
                    state.phase == AbilityRolloutPhase::Retired,
                    "retirement postcondition is not durable"
                );
                self.authenticate_terminal_outcome(request, &state)?;
                self.authenticate_retirement(request, &images)?;
                Ok(state)
            }
            _ => bail!("unsupported rollout method"),
        }
    }

    /// Records the reconciled boot or terminal outcome in provider state.
    ///
    /// # Errors
    ///
    /// Returns an error when physical observation fails or the reconciled
    /// provider state cannot be written durably.
    pub(crate) fn reconcile(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let state = self.require_state(request)?;
        let state = self.project_physical_observation(request, state)?;
        self.write_state(&state)?;
        Ok(state)
    }

    /// Records the health hook's checked result after candidate activation resumes.
    ///
    /// Final firmware blessing remains in `aos-image-boot-commit`, after
    /// activation publishes its complete transaction evidence. The provider
    /// record makes recovery independent of later changes to the health hook.
    ///
    /// # Errors
    ///
    /// Returns an error while the candidate has not booted, when physical image
    /// state differs from the request, or when the result conflicts with an
    /// already recorded assessment.
    pub(crate) fn record_health(
        &self,
        request: &AbRolloutRequest,
        healthy: bool,
    ) -> Result<AbilityRolloutState> {
        let mut state = self.require_state(request)?;
        let outcome = if healthy {
            AbilityRolloutOutcome::CandidateHealthy
        } else {
            AbilityRolloutOutcome::CandidateUnhealthy
        };
        if let Some(recorded) = state.outcome {
            ensure!(
                recorded == outcome,
                "health hook result changed after publication"
            );
            return self.health_assessment(request);
        }
        ensure!(
            state.phase == AbilityRolloutPhase::CandidateBooted
                && self.observe(request)? == PhysicalRolloutObservation::CandidateBooted,
            "rollout candidate is not ready for health assessment"
        );
        let images = self.authenticate_pair(request)?;
        ensure!(
            images
                .active_rollout
                .as_ref()
                .is_some_and(|rollout| rollout.status == ImageRolloutStatus::CandidateBooted),
            "rollout candidate is already withdrawing"
        );
        self.authenticate_retention(request)?;
        state.outcome = Some(outcome);
        self.write_state(&state)?;
        Ok(state)
    }

    /// Reauthenticates a previously published health-hook result.
    ///
    /// # Errors
    ///
    /// Returns an error when no provisional result exists or physical state no
    /// longer agrees with the checked rollout branch.
    pub(crate) fn health_assessment(
        &self,
        request: &AbRolloutRequest,
    ) -> Result<AbilityRolloutState> {
        let state = self.require_state(request)?;
        let physical = self.observe(request)?;
        let valid = matches!(
            (state.phase, state.outcome, physical),
            (
                AbilityRolloutPhase::CandidateBooted,
                Some(
                    AbilityRolloutOutcome::CandidateHealthy
                        | AbilityRolloutOutcome::CandidateUnhealthy
                ),
                PhysicalRolloutObservation::CandidateBooted,
            ) | (
                AbilityRolloutPhase::CandidateBooted,
                Some(AbilityRolloutOutcome::CandidateUnhealthy),
                PhysicalRolloutObservation::FallbackPendingCommit,
            ) | (
                AbilityRolloutPhase::HealthyRetained,
                Some(AbilityRolloutOutcome::CandidateHealthy),
                PhysicalRolloutObservation::CandidateBooted | PhysicalRolloutObservation::Healthy,
            ) | (
                AbilityRolloutPhase::FallbackRetained,
                Some(AbilityRolloutOutcome::PredecessorFallback),
                PhysicalRolloutObservation::FallbackPendingCommit
                    | PhysicalRolloutObservation::Fallback,
            )
        );
        ensure!(valid, "rollout health assessment is not durable");
        self.authenticate_retention(request)?;
        Ok(state)
    }

    /// Returns a published health assessment without inventing missing evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when provider state is malformed or a published result
    /// disagrees with the physical rollout.
    pub(crate) fn health_assessment_if_recorded(
        &self,
        request: &AbRolloutRequest,
    ) -> Result<Option<AbilityRolloutState>> {
        let state = self.require_state(request)?;
        if state.outcome.is_none() {
            return Ok(None);
        }
        self.health_assessment(request).map(Some)
    }

    /// Completes the transaction after a terminal outcome has a durable lease.
    ///
    /// # Errors
    ///
    /// Returns an error until authenticated health or fallback is terminal, or
    /// when reconciliation fails.
    pub(crate) fn hold(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let mut state = self.health_assessment(request)?;
        match state.outcome {
            Some(AbilityRolloutOutcome::CandidateHealthy) => {
                state.phase = AbilityRolloutPhase::HealthyRetained;
            }
            Some(AbilityRolloutOutcome::PredecessorFallback) => {
                ensure!(
                    state.phase == AbilityRolloutPhase::FallbackRetained,
                    "fallback hold precedes durable withdrawal"
                );
            }
            Some(AbilityRolloutOutcome::CandidateUnhealthy) | None => {
                bail!("unhealthy candidate has not completed withdrawal")
            }
        }
        self.authenticate_retention(request)?;
        self.write_state(&state)?;
        Ok(state)
    }

    /// Completes fallback withdrawal only after the predecessor is authoritative.
    ///
    /// # Errors
    ///
    /// Returns an error until authenticated fallback is terminal, or when
    /// reconciliation fails.
    pub(crate) fn withdraw(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let mut state = self.health_assessment(request)?;
        match self.observe(request)? {
            PhysicalRolloutObservation::CandidateBooted => {
                ensure!(
                    state.phase == AbilityRolloutPhase::CandidateBooted
                        && state.outcome == Some(AbilityRolloutOutcome::CandidateUnhealthy),
                    "candidate withdrawal lacks failed health evidence"
                );
                self.mark_candidate_health_failed(request, &state)?;
            }
            PhysicalRolloutObservation::FallbackPendingCommit
            | PhysicalRolloutObservation::Fallback => {
                ensure!(
                    matches!(
                        state.outcome,
                        Some(AbilityRolloutOutcome::CandidateUnhealthy)
                            | Some(AbilityRolloutOutcome::PredecessorFallback)
                    ),
                    "fallback lacks failed candidate health evidence"
                );
                state.phase = AbilityRolloutPhase::FallbackRetained;
                state.outcome = Some(AbilityRolloutOutcome::PredecessorFallback);
                self.write_state(&state)?;
            }
            PhysicalRolloutObservation::AwaitingBoot | PhysicalRolloutObservation::Healthy => {
                bail!("candidate traffic remains admitted or fallback is unproven")
            }
        }
        self.authenticate_retention(request)?;
        Ok(state)
    }

    fn observe_withdrawal(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let state = self.health_assessment(request)?;
        ensure!(
            state.phase == AbilityRolloutPhase::FallbackRetained
                && state.outcome == Some(AbilityRolloutOutcome::PredecessorFallback),
            "rollout withdrawal postcondition is not durable"
        );
        Ok(state)
    }

    fn observe_hold(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let state = self.health_assessment(request)?;
        ensure!(
            matches!(
                (state.phase, state.outcome),
                (
                    AbilityRolloutPhase::HealthyRetained,
                    Some(AbilityRolloutOutcome::CandidateHealthy)
                ) | (
                    AbilityRolloutPhase::FallbackRetained,
                    Some(AbilityRolloutOutcome::PredecessorFallback)
                )
            ),
            "rollout hold postcondition is not durable"
        );
        Ok(state)
    }

    fn mark_candidate_health_failed(
        &self,
        request: &AbRolloutRequest,
        state: &AbilityRolloutState,
    ) -> Result<()> {
        let mut images = self.authenticate_pair(request)?;
        let rollout = images
            .active_rollout
            .as_mut()
            .context("candidate withdrawal has no active rollout")?;
        ensure!(
            rollout.candidate == state.candidate_generation
                && rollout.prior == state.predecessor_generation
                && rollout.state_version == request.candidate.state_format
                && matches!(
                    rollout.status,
                    ImageRolloutStatus::CandidateBooted | ImageRolloutStatus::HealthFailed
                ),
            "candidate withdrawal differs from checked rollout state"
        );
        rollout.status = ImageRolloutStatus::HealthFailed;
        let bytes = serde_json::to_vec_pretty(&images)?;
        write_atomic_durable(
            &self.image_profile.join(crate::sysroot::IMAGE_STATE_FILE),
            &bytes,
        )?;
        Ok(())
    }

    /// Removes an expired lease during a separately admitted current transition.
    ///
    /// # Errors
    ///
    /// Returns an error before expiry, for nonterminal or stale state, or when
    /// inactive roots and the physical UKI lease cannot be removed durably.
    pub(crate) fn retire(
        &self,
        request: &AbRolloutRequest,
        now_millis: u64,
    ) -> Result<AbilityRolloutState> {
        ensure!(
            now_millis >= request.retention_expires_at_millis,
            "rollout retention lease has not expired"
        );
        let mut state = self.require_state(request)?;
        ensure!(
            matches!(
                state.phase,
                AbilityRolloutPhase::HealthyRetained
                    | AbilityRolloutPhase::FallbackRetained
                    | AbilityRolloutPhase::Retiring
            ),
            "only a terminal rollout lease can retire"
        );
        let expected_active = match state.outcome {
            Some(AbilityRolloutOutcome::CandidateHealthy)
                if matches!(
                    state.phase,
                    AbilityRolloutPhase::HealthyRetained | AbilityRolloutPhase::Retiring
                ) =>
            {
                "candidate"
            }
            Some(AbilityRolloutOutcome::PredecessorFallback)
                if matches!(
                    state.phase,
                    AbilityRolloutPhase::FallbackRetained | AbilityRolloutPhase::Retiring
                ) =>
            {
                "predecessor"
            }
            _ => bail!("terminal rollout state has no matching authenticated outcome"),
        };
        let images = self.authenticate_pair(request)?;
        self.authenticate_terminal_outcome(request, &state)?;
        let running = images
            .running_generation()
            .context("image state has no running generation")?;
        let running_identity = if image_matches(running, &request.candidate) {
            "candidate"
        } else if image_matches(running, &request.predecessor) {
            "predecessor"
        } else {
            bail!("current active image is outside the retained rollout pair")
        };
        ensure!(
            running_identity == expected_active,
            "terminal rollout outcome differs from the active image"
        );
        self.authenticate_ordinary_image_roots(running)?;

        let directory = self.execution_directory(request)?;
        if state.phase != AbilityRolloutPhase::Retiring {
            self.authenticate_retention(request)?;
            state.phase = AbilityRolloutPhase::Retiring;
            self.write_state(&state)?;
        }
        for identity in ["candidate", "predecessor"] {
            for suffix in ["toplevel", "executor"] {
                remove_file_durable(&directory.join(format!("{identity}-{suffix}")))?;
            }
        }
        let uki_directory = self.retained_uki_directory(request)?;
        for name in ["candidate.efi", "predecessor.efi", "manifest.json"] {
            remove_file_durable(&uki_directory.join(name))?;
        }
        match fs::remove_dir(&uki_directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("removing retired UKI lease {}", uki_directory.display())
                });
            }
        }
        let uki_parent = uki_directory
            .parent()
            .context("UKI retention lease has no parent")?;
        sync_directory(uki_parent)?;
        state.phase = AbilityRolloutPhase::Retired;
        self.write_state(&state)?;
        Ok(state)
    }

    fn project_physical_observation(
        &self,
        request: &AbRolloutRequest,
        mut state: AbilityRolloutState,
    ) -> Result<AbilityRolloutState> {
        let (phase, outcome) = match self.observe(request)? {
            PhysicalRolloutObservation::AwaitingBoot => {
                ensure!(
                    state.outcome.is_none(),
                    "health evidence precedes candidate boot"
                );
                (AbilityRolloutPhase::Selected, None)
            }
            PhysicalRolloutObservation::CandidateBooted => {
                (AbilityRolloutPhase::CandidateBooted, state.outcome)
            }
            PhysicalRolloutObservation::Healthy => (
                AbilityRolloutPhase::HealthyRetained,
                Some(AbilityRolloutOutcome::CandidateHealthy),
            ),
            PhysicalRolloutObservation::FallbackPendingCommit
            | PhysicalRolloutObservation::Fallback => (
                AbilityRolloutPhase::FallbackRetained,
                Some(AbilityRolloutOutcome::PredecessorFallback),
            ),
        };
        state.phase = phase;
        state.outcome = outcome;
        Ok(state)
    }

    fn authenticate_state_generations(
        &self,
        state: &AbilityRolloutState,
        images: &ImageGenerationState,
    ) -> Result<()> {
        let predecessor = unique_image(images, &state.request.predecessor, "predecessor")?;
        let candidate = unique_image(images, &state.request.candidate, "candidate")?;
        ensure!(
            state.predecessor_generation == predecessor.number
                && state.candidate_generation == candidate.number
                && predecessor.slot != candidate.slot,
            "durable rollout generations differ from authenticated images"
        );
        ensure!(
            images.running == predecessor.number || images.running == candidate.number,
            "current active image is outside the retained rollout pair"
        );
        Ok(())
    }

    fn authenticate_retention(&self, request: &AbRolloutRequest) -> Result<()> {
        let directory = self.execution_directory(request)?;
        for (name, target) in [
            (
                "predecessor-toplevel",
                request.predecessor.toplevel.as_str(),
            ),
            (
                "predecessor-executor",
                request.predecessor.executor.as_str(),
            ),
            ("candidate-toplevel", request.candidate.toplevel.as_str()),
            ("candidate-executor", request.candidate.executor.as_str()),
        ] {
            require_exact_root(&directory.join(name), target)?;
        }
        authenticate_uki_retention_directory(&self.retained_uki_directory(request)?)?;
        Ok(())
    }

    fn authenticate_terminal_outcome(
        &self,
        request: &AbRolloutRequest,
        state: &AbilityRolloutState,
    ) -> Result<()> {
        let expected = match self.observe_terminal_outcome(request)? {
            PhysicalRolloutObservation::Healthy => AbilityRolloutOutcome::CandidateHealthy,
            PhysicalRolloutObservation::Fallback => AbilityRolloutOutcome::PredecessorFallback,
            _ => bail!("physical rollout outcome is not terminal"),
        };
        ensure!(
            state.outcome == Some(expected),
            "durable terminal outcome differs from physical image state"
        );
        Ok(())
    }

    fn authenticate_retirement(
        &self,
        request: &AbRolloutRequest,
        images: &ImageGenerationState,
    ) -> Result<()> {
        ensure!(
            fs::symlink_metadata(self.retained_uki_directory(request)?)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "retired UKI lease is still present"
        );
        let running = images
            .running_generation()
            .context("image state has no running generation")?;
        if !image_matches(running, &request.candidate)
            && !image_matches(running, &request.predecessor)
        {
            bail!("current active image is outside the retained rollout pair")
        }
        self.authenticate_ordinary_image_roots(running)?;

        let directory = self.execution_directory(request)?;
        for identity in ["candidate", "predecessor"] {
            for suffix in ["toplevel", "executor"] {
                ensure!(
                    fs::symlink_metadata(directory.join(format!("{identity}-{suffix}")))
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                    "retired rollout-specific root is still present"
                );
            }
        }
        Ok(())
    }

    fn authenticate_ordinary_image_roots(&self, image: &ImageGeneration) -> Result<()> {
        let directory = self
            .image_profile
            .join(format!("image-gen-{}", image.number));
        require_exact_root(&directory.join("toplevel"), &image.toplevel)?;
        let executor = image
            .native_executor_ref
            .as_deref()
            .context("active image has no native executor identity")?;
        require_exact_root(&directory.join("executor"), executor)
    }

    fn authenticate_pair(&self, request: &AbRolloutRequest) -> Result<ImageGenerationState> {
        ensure!(
            request.strategy == "single-host-ab-v1" && request.concurrency == 1,
            "unsupported rollout strategy or concurrency"
        );
        ensure!(
            !request.candidate.state_format.is_empty()
                && request.candidate.state_format == request.predecessor.state_format,
            "rollout images have incompatible state formats"
        );
        let images = load_image_generation_state_pub(&self.image_profile)?;
        unique_image(&images, &request.predecessor, "predecessor")?;
        unique_image(&images, &request.candidate, "candidate")?;
        Ok(images)
    }

    fn execution_directory(&self, request: &AbRolloutRequest) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical(EXECUTION_SCHEMA, request)?;
        Ok(self
            .image_profile
            .join(EXECUTION_DIRECTORY)
            .join(digest.to_string().replace(':', "-")))
    }

    fn retained_uki_directory(&self, request: &AbRolloutRequest) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical(EXECUTION_SCHEMA, request)?;
        Ok(self
            .boot_root
            .join(UKI_RETENTION_DIRECTORY)
            .join(digest.to_string().replace(':', "-")))
    }

    fn require_state(&self, request: &AbRolloutRequest) -> Result<AbilityRolloutState> {
        let path = self.execution_directory(request)?.join("state.json");
        let state: AbilityRolloutState = serde_json::from_slice(
            &read_regular_bounded(&path, 1024 * 1024)
                .with_context(|| format!("reading {}", path.display()))?,
        )?;
        ensure!(
            state.schema == EXECUTION_SCHEMA && state.request == *request,
            "durable rollout state differs from checked request"
        );
        Ok(state)
    }

    fn write_state(&self, state: &AbilityRolloutState) -> Result<()> {
        let directory = self.execution_directory(&state.request)?;
        ensure_private_directory(&self.image_profile.join(EXECUTION_DIRECTORY))?;
        ensure_private_directory(&directory)?;
        cleanup_stale_temporaries(&directory, is_execution_temporary)?;
        write_atomic_regular(
            &directory.join("state.json"),
            &serde_json::to_vec_pretty(state)?,
            true,
        )
    }

    fn retain_uki(
        &self,
        directory: &Path,
        label: &str,
        generation: &ImageGeneration,
    ) -> Result<(String, String)> {
        let entry =
            crate::sysroot::resolve_installed_uki_entry(&self.boot_root, &generation.uki_path)?;
        let source = self.boot_root.join("EFI/Linux").join(&entry);
        let source_digest = file_sha256_regular(&source)?;
        let destination = directory.join(format!("{label}.efi"));
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_file()
                        && file_sha256_regular(&destination)? == source_digest,
                    "retained {label} UKI differs from installed image"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish_regular_copy(&source, &destination, source_digest)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok((entry, Sha256Digest::from_bytes(source_digest).to_string()))
    }
}

/// Returns stable UKI entry identities protected by installed provider leases.
///
/// # Errors
///
/// Returns an error when the retention directory cannot be read or any lease
/// directory or manifest is malformed, missing, or uses an unsupported schema.
pub(crate) fn retained_uki_entry_ids(boot_root: &Path) -> Result<BTreeSet<String>> {
    let root = boot_root.join(UKI_RETENTION_DIRECTORY);
    let mut retained = BTreeSet::new();
    match fs::symlink_metadata(&root) {
        Ok(metadata) => ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o777 == 0o700,
            "invalid UKI retention root"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(retained),
        Err(error) => return Err(error.into()),
    }
    let entries = fs::read_dir(&root)?;
    for entry in entries {
        let entry = entry?;
        let metadata = entry.file_type()?;
        ensure!(
            metadata.is_dir() && !metadata.is_symlink(),
            "invalid UKI retention lease directory"
        );
        retained.extend(authenticate_uki_retention_directory(&entry.path())?);
    }
    Ok(retained)
}

fn authenticate_uki_retention_directory(directory: &Path) -> Result<BTreeSet<String>> {
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o777 == 0o700,
        "UKI retention lease is not a root-private directory"
    );
    let manifest_path = directory.join("manifest.json");
    let manifest: UkiRetentionManifest =
        serde_json::from_slice(&read_regular_bounded(&manifest_path, 16 * 1024)?)?;
    ensure!(
        manifest.schema == EXECUTION_SCHEMA,
        "invalid UKI retention manifest schema"
    );
    let entries = fs::read_dir(directory)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::other("retention entry name is not UTF-8"))
        })
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(
        entries
            == BTreeSet::from([
                "candidate.efi".to_string(),
                "manifest.json".to_string(),
                "predecessor.efi".to_string(),
            ]),
        "UKI retention lease contains unexpected entries"
    );

    let mut retained = BTreeSet::new();
    for (label, identity, entry, expected_digest) in [
        (
            "candidate",
            &manifest.candidate,
            &manifest.candidate_entry,
            &manifest.candidate_sha256,
        ),
        (
            "predecessor",
            &manifest.predecessor,
            &manifest.predecessor_entry,
            &manifest.predecessor_sha256,
        ),
    ] {
        let identity_entry = Path::new(identity)
            .file_name()
            .and_then(|name| name.to_str())
            .context("retained UKI identity has no UTF-8 entry id")?;
        let stable_identity = crate::sysroot::stable_uki_entry_id(identity_entry)?;
        let stable_entry = crate::sysroot::stable_uki_entry_id(entry)?;
        ensure!(
            stable_identity == stable_entry,
            "retained {label} UKI entry differs from its authenticated identity"
        );
        let expected_digest = Sha256Digest::parse(expected_digest)
            .with_context(|| format!("decoding retained {label} UKI digest"))?;
        ensure!(
            Sha256Digest::from_bytes(file_sha256_regular(
                &directory.join(format!("{label}.efi")),
            )?) == expected_digest,
            "retained {label} UKI copy differs from its manifest"
        );
        retained.insert(stable_entry);
    }
    Ok(retained)
}

fn publish_manifest(path: &Path, manifest: &UkiRetentionManifest) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(manifest)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file() && read_regular_bounded(path, 16 * 1024)? == encoded,
                "retention manifest differs from the authenticated lease"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic_regular(path, &encoded, false)
        }
        Err(error) => Err(error.into()),
    }
}

fn publish_regular_copy(source: &Path, destination: &Path, expected: [u8; 32]) -> Result<()> {
    let temporary = destination.with_extension(format!("efi.new-{}", std::process::id()));
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    ensure!(
        source.metadata()?.is_file(),
        "retained UKI source is not regular"
    );
    remove_stale_regular_temporary(&temporary)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let copied = (|| -> Result<()> {
        std::io::copy(&mut source, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        Ok(())
    })();
    if let Err(error) = copied {
        drop(output);
        let _ = remove_file_durable(&temporary);
        return Err(error);
    }
    drop(output);
    let copied_digest = file_sha256_regular(&temporary);
    if !matches!(copied_digest, Ok(actual) if actual == expected) {
        let _ = remove_file_durable(&temporary);
        bail!("retained UKI copy changed during publication");
    }
    let published = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &temporary,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    );
    if let Err(error) = published {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| {
            format!(
                "publishing retained UKI {} without replacement",
                destination.display()
            )
        });
    }
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn write_atomic_regular(path: &Path, contents: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("durable rollout file has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("durable rollout file has no UTF-8 name")?;
    let temporary = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    remove_stale_regular_temporary(&temporary)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let written = (|| -> Result<()> {
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = written {
        drop(file);
        let _ = remove_file_durable(&temporary);
        return Err(error);
    }
    drop(file);

    let flags = if replace {
        rustix::fs::RenameFlags::empty()
    } else {
        rustix::fs::RenameFlags::NOREPLACE
    };
    if let Err(error) =
        rustix::fs::renameat_with(rustix::fs::CWD, &temporary, rustix::fs::CWD, path, flags)
    {
        let _ = remove_file_durable(&temporary);
        return Err(error).with_context(|| format!("publishing rollout file {}", path.display()));
    }
    sync_directory(parent)
}

fn remove_stale_regular_temporary(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "rollout temporary path contains a non-regular entry"
            );
            remove_file_durable(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_stale_temporaries(directory: &Path, recognized: fn(&str) -> bool) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("rollout temporary name is not UTF-8"))?;
        if !recognized(&name) {
            continue;
        }
        ensure!(
            entry.file_type()?.is_file(),
            "rollout temporary path contains a non-regular entry"
        );
        remove_file_durable(&entry.path())?;
    }
    Ok(())
}

fn is_execution_temporary(name: &str) -> bool {
    numeric_suffix(name, ".state.json.tmp.")
}

fn is_retention_temporary(name: &str) -> bool {
    numeric_suffix(name, "candidate.efi.new-")
        || numeric_suffix(name, "predecessor.efi.new-")
        || numeric_suffix(name, ".manifest.json.tmp.")
}

fn numeric_suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn read_regular_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "rollout lease file is not a bounded regular file"
    );
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    file.read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "rollout lease file changed while reading"
    );
    Ok(bytes)
}

fn file_sha256_regular(path: &Path) -> Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "rollout artifact is not a regular file"
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn unique_image<'a>(
    images: &'a ImageGenerationState,
    identity: &RolloutImageIdentity,
    label: &str,
) -> Result<&'a ImageGeneration> {
    let mut matching = images
        .generations
        .iter()
        .filter(|generation| image_matches(generation, identity));
    let image = matching
        .next()
        .with_context(|| format!("{label} image does not match an authenticated generation"))?;
    ensure!(
        matching.next().is_none(),
        "{label} image identity is ambiguous"
    );
    Ok(image)
}

fn image_matches(generation: &ImageGeneration, identity: &RolloutImageIdentity) -> bool {
    generation.toplevel == identity.toplevel
        && generation
            .uki_source_path
            .as_deref()
            .unwrap_or(&generation.uki_path)
            == identity.uki
        && generation.native_executor_ref.as_deref() == Some(identity.executor.as_str())
        && generation.state_version.as_deref() == Some(identity.state_format.as_str())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "rollout state path is not a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    ensure!(
        fs::symlink_metadata(path)?.permissions().mode() & 0o777 == 0o700,
        "rollout state directory is not root-private"
    );
    Ok(())
}

fn require_exact_root(path: &Path, target: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_symlink(),
        "rollout root is not a symlink"
    );
    ensure!(
        fs::read_link(path)? == Path::new(target),
        "rollout root targets another artifact"
    );
    Ok(())
}

fn install_exact_root(path: &Path, target: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_symlink(),
                "rollout root path contains a non-symlink"
            );
            return require_exact_root(path, target);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    ensure!(
        fs::symlink_metadata(&temporary)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "rollout root temporary path is occupied"
    );
    symlink(target, &temporary)?;
    let published = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &temporary,
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    );
    if let Err(error) = published {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| {
            format!(
                "publishing rollout root {} without replacement",
                path.display()
            )
        });
    }
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::types::{ImageRollout, ImageSlot};

    fn image(number: u32, slot: ImageSlot, seed: u8) -> ImageGeneration {
        ImageGeneration {
            number,
            slot,
            uki_path: format!("EFI/Linux/aos-{number}+3.efi"),
            uki_source_path: None,
            toplevel: format!(
                "/nix/store/{}-top",
                char::from(b'a' + seed).to_string().repeat(32)
            ),
            package_name: "aos".into(),
            version: number.to_string(),
            state_version: Some("7".into()),
            native_executor_ref: Some(format!(
                "/nix/store/{}-executor",
                char::from(b'k' + seed).to_string().repeat(32)
            )),
            registry: "test".into(),
            kernel_path: None,
            evaluator_ref: format!(
                "/nix/store/{}-base",
                char::from(b'p' + seed).to_string().repeat(32)
            ),
            module_abi: 1,
            baselib_digest: "sha256:test".into(),
            root_verity_roothash: None,
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-09-10T00:00:00Z".into(),
        }
    }

    struct Fixture {
        _tmp: TempDir,
        backend: NativeAbRolloutBackend,
        request: AbRolloutRequest,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let predecessor = image(1, ImageSlot::A, 0);
            let candidate = image(2, ImageSlot::B, 1);
            let state = ImageGenerationState {
                running: 1,
                default: 1,
                pending: None,
                recovery_known_good: None,
                recovery_pending: None,
                active_rollout: None,
                last_rollout: None,
                generations: vec![predecessor.clone(), candidate.clone()],
            };
            fs::create_dir_all(tmp.path()).unwrap();
            let boot_root = tmp.path().join("boot");
            fs::create_dir_all(boot_root.join("EFI/Linux")).unwrap();
            for generation in [&predecessor, &candidate] {
                fs::write(
                    boot_root.join(&generation.uki_path),
                    format!("uki-{}", generation.number),
                )
                .unwrap();
            }
            fs::write(
                tmp.path().join(crate::sysroot::IMAGE_STATE_FILE),
                serde_json::to_vec_pretty(&state).unwrap(),
            )
            .unwrap();
            for generation in [&predecessor, &candidate] {
                crate::store::create_image_gc_roots(
                    &tmp.path().join(format!("image-gen-{}", generation.number)),
                    generation,
                )
                .unwrap();
            }
            let identity = |generation: &ImageGeneration| RolloutImageIdentity {
                toplevel: generation.toplevel.clone(),
                uki: generation.uki_path.clone(),
                executor: generation.native_executor_ref.clone().unwrap(),
                state_format: generation.state_version.clone().unwrap(),
            };
            let request = AbRolloutRequest {
                strategy: "single-host-ab-v1".into(),
                concurrency: 1,
                predecessor: identity(&predecessor),
                candidate: identity(&candidate),
                retention_expires_at_millis: 2_000,
            };
            let image_profile = tmp.path().to_path_buf();
            Self {
                _tmp: tmp,
                backend: NativeAbRolloutBackend::new(image_profile, boot_root),
                request,
            }
        }

        fn images(&self) -> ImageGenerationState {
            load_image_generation_state_pub(&self.backend.image_profile).unwrap()
        }

        fn write_images(&self, images: &ImageGenerationState) {
            fs::write(
                self.backend
                    .image_profile
                    .join(crate::sysroot::IMAGE_STATE_FILE),
                serde_json::to_vec_pretty(images).unwrap(),
            )
            .unwrap();
        }
    }

    fn complete_terminal_rollout(
        fixture: &Fixture,
        running: u32,
        status: ImageRolloutStatus,
    ) -> AbilityRolloutState {
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        fixture.backend.drain(&fixture.request, || Ok(())).unwrap();
        fixture
            .backend
            .select(&fixture.request, "aos-2+3.efi", |_| Ok(()))
            .unwrap();

        let mut images = fixture.images();
        images.running = 2;
        images.active_rollout.as_mut().unwrap().status = ImageRolloutStatus::CandidateBooted;
        fixture.write_images(&images);
        fixture.backend.reconcile(&fixture.request).unwrap();
        fixture
            .backend
            .record_health(&fixture.request, status == ImageRolloutStatus::Succeeded)
            .unwrap();
        let provider_state = if status == ImageRolloutStatus::Succeeded {
            fixture.backend.hold(&fixture.request).unwrap()
        } else {
            fixture.backend.withdraw(&fixture.request).unwrap();
            images = fixture.images();
            images.running = 1;
            fixture.write_images(&images);
            fixture.backend.withdraw(&fixture.request).unwrap()
        };

        images = fixture.images();
        images.running = running;
        images.pending = None;
        images.active_rollout = None;
        images.last_rollout = Some(ImageRollout {
            schema: super::super::IMAGE_ROLLOUT_SCHEMA.into(),
            candidate: 2,
            prior: 1,
            state_version: "7".into(),
            status,
        });
        fixture.write_images(&images);
        provider_state
    }

    fn publish_retention_prefix(fixture: &Fixture, publications: usize) {
        if publications == 0 {
            return;
        }
        let directory = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap();
        ensure_private_directory(
            directory
                .parent()
                .expect("execution directory has a parent"),
        )
        .unwrap();
        ensure_private_directory(&directory).unwrap();
        let roots = [
            (
                "predecessor-toplevel",
                fixture.request.predecessor.toplevel.as_str(),
            ),
            (
                "predecessor-executor",
                fixture.request.predecessor.executor.as_str(),
            ),
            (
                "candidate-toplevel",
                fixture.request.candidate.toplevel.as_str(),
            ),
            (
                "candidate-executor",
                fixture.request.candidate.executor.as_str(),
            ),
        ];
        for (index, (name, target)) in roots.into_iter().enumerate() {
            if publications > index {
                install_exact_root(&directory.join(name), target).unwrap();
            }
        }
        if publications <= 4 {
            return;
        }

        let images = fixture.images();
        let predecessor =
            unique_image(&images, &fixture.request.predecessor, "predecessor").unwrap();
        let candidate = unique_image(&images, &fixture.request.candidate, "candidate").unwrap();
        let uki_directory = fixture
            .backend
            .retained_uki_directory(&fixture.request)
            .unwrap();
        ensure_private_directory(uki_directory.parent().expect("UKI lease has a parent")).unwrap();
        ensure_private_directory(&uki_directory).unwrap();
        let (predecessor_entry, predecessor_sha256) = fixture
            .backend
            .retain_uki(&uki_directory, "predecessor", predecessor)
            .unwrap();
        if publications == 5 {
            return;
        }
        let (candidate_entry, candidate_sha256) = fixture
            .backend
            .retain_uki(&uki_directory, "candidate", candidate)
            .unwrap();
        if publications == 6 {
            return;
        }
        publish_manifest(
            &uki_directory.join("manifest.json"),
            &UkiRetentionManifest {
                schema: EXECUTION_SCHEMA.to_string(),
                candidate: candidate.uki_path.clone(),
                candidate_entry,
                candidate_sha256,
                predecessor: predecessor.uki_path.clone(),
                predecessor_entry,
                predecessor_sha256,
            },
        )
        .unwrap();
        if publications == 7 {
            return;
        }

        fixture.backend.retain(&fixture.request).unwrap();
    }

    #[test]
    fn retention_precedes_prepare_drain_and_selection() {
        let fixture = Fixture::new();
        assert!(fixture.backend.prepare(&fixture.request).is_err());
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        fixture.backend.drain(&fixture.request, || Ok(())).unwrap();
        fixture
            .backend
            .select(&fixture.request, "aos-2+3.efi", |entry| {
                assert_eq!(entry, "aos-2.efi");
                Ok(())
            })
            .unwrap();

        let images = fixture.images();
        assert_eq!(images.pending, Some(2));
        assert_eq!(images.active_rollout.as_ref().unwrap().candidate, 2);
        assert_eq!(
            fixture.backend.observe(&fixture.request).unwrap(),
            PhysicalRolloutObservation::AwaitingBoot
        );
    }

    #[test]
    fn retention_retry_completes_after_every_durable_publication_prefix() {
        for publications in 0..=8 {
            let fixture = Fixture::new();
            publish_retention_prefix(&fixture, publications);

            let state = fixture.backend.retain(&fixture.request).unwrap();
            assert_eq!(state.phase, AbilityRolloutPhase::Retained);
            fixture
                .backend
                .observe_operation(&fixture.request, "retain")
                .unwrap();
            assert_eq!(
                retained_uki_entry_ids(&fixture.backend.boot_root).unwrap(),
                BTreeSet::from(["aos-1.efi".to_string(), "aos-2.efi".to_string()])
            );
        }
    }

    #[test]
    fn recovery_observes_partial_health_and_terminal_branches() {
        let fixture = Fixture::new();
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        fixture.backend.drain(&fixture.request, || Ok(())).unwrap();
        fixture
            .backend
            .select(&fixture.request, "aos-2+3.efi", |_| Ok(()))
            .unwrap();
        let mut images = fixture.images();
        images.running = 2;
        images.active_rollout.as_mut().unwrap().status = ImageRolloutStatus::CandidateBooted;
        fixture.write_images(&images);
        assert_eq!(
            fixture.backend.reconcile(&fixture.request).unwrap().phase,
            AbilityRolloutPhase::CandidateBooted
        );
        assert_eq!(
            fixture
                .backend
                .record_health(&fixture.request, true)
                .unwrap()
                .phase,
            AbilityRolloutPhase::CandidateBooted
        );
        assert_eq!(
            fixture
                .backend
                .require_state(&fixture.request)
                .unwrap()
                .phase,
            AbilityRolloutPhase::CandidateBooted
        );
        assert_eq!(
            fixture.backend.hold(&fixture.request).unwrap().phase,
            AbilityRolloutPhase::HealthyRetained
        );
        assert_eq!(
            fixture
                .backend
                .observe_operation(&fixture.request, "hold")
                .unwrap()
                .phase,
            AbilityRolloutPhase::HealthyRetained
        );
        fixture
            .backend
            .verify_boot_commit(&fixture.request, 2)
            .unwrap();

        // Boot commit runs after structured activation and turns the checked
        // health decision into the firmware and image-state terminal record.
        images.active_rollout = None;
        images.last_rollout = Some(ImageRollout {
            schema: super::super::IMAGE_ROLLOUT_SCHEMA.into(),
            candidate: 2,
            prior: 1,
            state_version: "7".into(),
            status: ImageRolloutStatus::Succeeded,
        });
        fixture.write_images(&images);
        assert_eq!(
            fixture
                .backend
                .observe_operation(&fixture.request, "hold")
                .unwrap()
                .phase,
            AbilityRolloutPhase::HealthyRetained
        );
    }

    #[test]
    fn unhealthy_assessment_withdraws_before_fallback_can_commit() {
        let fixture = Fixture::new();
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        fixture.backend.drain(&fixture.request, || Ok(())).unwrap();
        fixture
            .backend
            .select(&fixture.request, "aos-2+3.efi", |_| Ok(()))
            .unwrap();

        let mut images = fixture.images();
        images.running = 2;
        images.active_rollout.as_mut().unwrap().status = ImageRolloutStatus::CandidateBooted;
        fixture.write_images(&images);
        fixture.backend.reconcile(&fixture.request).unwrap();
        let assessed = fixture
            .backend
            .record_health(&fixture.request, false)
            .unwrap();
        assert_eq!(assessed.phase, AbilityRolloutPhase::CandidateBooted);
        assert_eq!(
            assessed.outcome,
            Some(AbilityRolloutOutcome::CandidateUnhealthy)
        );
        assert!(fixture.backend.hold(&fixture.request).is_err());
        assert!(
            fixture
                .backend
                .verify_boot_commit(&fixture.request, 2)
                .is_err()
        );

        let withdrawing = fixture.backend.withdraw(&fixture.request).unwrap();
        assert_eq!(withdrawing.phase, AbilityRolloutPhase::CandidateBooted);
        assert_eq!(
            fixture.images().active_rollout.as_ref().unwrap().status,
            ImageRolloutStatus::HealthFailed
        );

        images = fixture.images();
        images.running = 1;
        fixture.write_images(&images);
        assert_eq!(
            fixture.backend.observe(&fixture.request).unwrap(),
            PhysicalRolloutObservation::FallbackPendingCommit
        );
        let withdrawn = fixture.backend.withdraw(&fixture.request).unwrap();
        assert_eq!(withdrawn.phase, AbilityRolloutPhase::FallbackRetained);
        assert_eq!(
            withdrawn.outcome,
            Some(AbilityRolloutOutcome::PredecessorFallback)
        );
        fixture.backend.hold(&fixture.request).unwrap();
        assert!(
            fixture
                .backend
                .observe_terminal_outcome(&fixture.request)
                .is_err(),
            "pending fallback must not authorize a retained no-op"
        );
        assert!(
            fixture.backend.retire(&fixture.request, 2_000).is_err(),
            "pending fallback must not authorize rollout-root retirement"
        );
        assert!(
            fixture
                .backend
                .preflight_operation(&fixture.request, "retire", 2_000)
                .is_err(),
            "pending fallback must reject retirement before effect acquisition"
        );
        assert_eq!(
            fixture
                .backend
                .require_state(&fixture.request)
                .unwrap()
                .phase,
            AbilityRolloutPhase::FallbackRetained
        );
        fixture
            .backend
            .verify_boot_commit(&fixture.request, 1)
            .unwrap();
    }

    #[test]
    fn terminal_status_cannot_complete_before_the_matching_image_is_active() {
        let fixture = Fixture::new();
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        fixture.backend.drain(&fixture.request, || Ok(())).unwrap();
        fixture
            .backend
            .select(&fixture.request, "aos-2+3.efi", |_| Ok(()))
            .unwrap();

        let mut images = fixture.images();
        images.running = 2;
        images.active_rollout.as_mut().unwrap().status = ImageRolloutStatus::HealthFailed;
        fixture.write_images(&images);
        assert_eq!(
            fixture.backend.observe(&fixture.request).unwrap(),
            PhysicalRolloutObservation::CandidateBooted
        );
        assert!(fixture.backend.withdraw(&fixture.request).is_err());
        assert!(
            fixture
                .backend
                .record_health(&fixture.request, true)
                .is_err()
        );

        let terminal = images.active_rollout.take().unwrap();
        images.last_rollout = Some(ImageRollout {
            status: ImageRolloutStatus::Succeeded,
            ..terminal.clone()
        });
        images.running = 1;
        fixture.write_images(&images);
        assert!(fixture.backend.observe(&fixture.request).is_err());

        images.last_rollout = Some(ImageRollout {
            status: ImageRolloutStatus::HealthFailed,
            ..terminal
        });
        images.running = 2;
        fixture.write_images(&images);
        assert!(fixture.backend.observe(&fixture.request).is_err());
    }

    #[test]
    fn stale_identity_and_early_retirement_fail_without_effects() {
        let fixture = Fixture::new();
        let mut stale = fixture.request.clone();
        stale.candidate.executor.push_str("-forged");
        assert!(fixture.backend.retain(&stale).is_err());
        assert!(
            !fixture
                .backend
                .image_profile
                .join(EXECUTION_DIRECTORY)
                .exists()
        );

        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        assert!(fixture.backend.retire(&fixture.request, 1_999).is_err());
    }

    #[test]
    fn preflight_rejects_stale_or_unbounded_fresh_rollouts() {
        let fixture = Fixture::new();
        fixture
            .backend
            .preflight_operation(&fixture.request, "retain", 1_000)
            .unwrap();
        assert!(
            fixture
                .backend
                .preflight_operation(&fixture.request, "retain", 2_000)
                .is_err()
        );
        let mut unbounded = fixture.request.clone();
        unbounded.retention_expires_at_millis = 1_000 + MAX_RETENTION_MILLIS + 1;
        assert!(
            fixture
                .backend
                .preflight_operation(&unbounded, "retain", 1_000)
                .is_err()
        );

        let mut images = fixture.images();
        images.running = 2;
        fixture.write_images(&images);
        assert!(
            fixture
                .backend
                .preflight_operation(&fixture.request, "retain", 1_000)
                .is_err()
        );
    }

    #[test]
    fn retention_directories_are_private_and_roots_reject_regular_occupants() {
        let fixture = Fixture::new();
        let execution = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap();
        ensure_private_directory(
            execution
                .parent()
                .expect("execution directory has a parent"),
        )
        .unwrap();
        ensure_private_directory(&execution).unwrap();
        let occupied = execution.join("predecessor-toplevel");
        fs::write(&occupied, "foreign").unwrap();

        assert!(fixture.backend.retain(&fixture.request).is_err());
        assert!(fs::symlink_metadata(&occupied).unwrap().is_file());
        assert_eq!(fs::read_to_string(&occupied).unwrap(), "foreign");
        assert_eq!(
            fs::symlink_metadata(&execution)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn retained_uki_scan_rejects_missing_tampered_and_symlinked_copies() {
        let missing = Fixture::new();
        missing.backend.retain(&missing.request).unwrap();
        let missing_lease = missing
            .backend
            .retained_uki_directory(&missing.request)
            .unwrap();
        fs::remove_file(missing_lease.join("candidate.efi")).unwrap();
        assert!(retained_uki_entry_ids(&missing.backend.boot_root).is_err());

        let tampered = Fixture::new();
        tampered.backend.retain(&tampered.request).unwrap();
        let tampered_lease = tampered
            .backend
            .retained_uki_directory(&tampered.request)
            .unwrap();
        fs::write(tampered_lease.join("predecessor.efi"), "tampered").unwrap();
        assert!(retained_uki_entry_ids(&tampered.backend.boot_root).is_err());

        let linked = Fixture::new();
        linked.backend.retain(&linked.request).unwrap();
        let linked_lease = linked
            .backend
            .retained_uki_directory(&linked.request)
            .unwrap();
        fs::remove_file(linked_lease.join("candidate.efi")).unwrap();
        symlink(
            linked.backend.boot_root.join("EFI/Linux/aos-2+3.efi"),
            linked_lease.join("candidate.efi"),
        )
        .unwrap();
        assert!(retained_uki_entry_ids(&linked.backend.boot_root).is_err());
    }

    #[test]
    fn retained_uki_publication_rejects_a_preexisting_symlink() {
        let fixture = Fixture::new();
        let lease = fixture
            .backend
            .retained_uki_directory(&fixture.request)
            .unwrap();
        ensure_private_directory(lease.parent().expect("retention directory has a parent"))
            .unwrap();
        ensure_private_directory(&lease).unwrap();
        symlink(
            fixture.backend.boot_root.join("EFI/Linux/aos-2+3.efi"),
            lease.join("candidate.efi"),
        )
        .unwrap();

        assert!(fixture.backend.retain(&fixture.request).is_err());
        assert!(
            fs::symlink_metadata(lease.join("candidate.efi"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn retained_uki_scan_rejects_nonprivate_root_and_lease_directories() {
        let root_fixture = Fixture::new();
        root_fixture.backend.retain(&root_fixture.request).unwrap();
        let root = root_fixture.backend.boot_root.join(UKI_RETENTION_DIRECTORY);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(retained_uki_entry_ids(&root_fixture.backend.boot_root).is_err());

        let lease_fixture = Fixture::new();
        lease_fixture
            .backend
            .retain(&lease_fixture.request)
            .unwrap();
        let lease = lease_fixture
            .backend
            .retained_uki_directory(&lease_fixture.request)
            .unwrap();
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(retained_uki_entry_ids(&lease_fixture.backend.boot_root).is_err());
    }

    #[test]
    fn retention_retry_cleans_regular_temporaries_and_rejects_foreign_entries() {
        let retry = Fixture::new();
        let execution = retry.backend.execution_directory(&retry.request).unwrap();
        ensure_private_directory(
            execution
                .parent()
                .expect("execution directory has a parent"),
        )
        .unwrap();
        ensure_private_directory(&execution).unwrap();
        fs::write(execution.join(".state.json.tmp.999"), "partial").unwrap();
        let lease = retry
            .backend
            .retained_uki_directory(&retry.request)
            .unwrap();
        ensure_private_directory(lease.parent().expect("lease has a parent")).unwrap();
        ensure_private_directory(&lease).unwrap();
        fs::write(lease.join("candidate.efi.new-999"), "partial").unwrap();
        fs::write(lease.join(".manifest.json.tmp.999"), "partial").unwrap();

        retry.backend.retain(&retry.request).unwrap();
        assert!(!execution.join(".state.json.tmp.999").exists());
        assert!(!lease.join("candidate.efi.new-999").exists());
        assert!(!lease.join(".manifest.json.tmp.999").exists());

        fs::write(lease.join("foreign"), "unexpected").unwrap();
        assert!(retained_uki_entry_ids(&retry.backend.boot_root).is_err());

        let linked = Fixture::new();
        let linked_lease = linked
            .backend
            .retained_uki_directory(&linked.request)
            .unwrap();
        ensure_private_directory(linked_lease.parent().expect("lease has a parent")).unwrap();
        ensure_private_directory(&linked_lease).unwrap();
        symlink(
            linked.backend.boot_root.join("EFI/Linux/aos-2+3.efi"),
            linked_lease.join("candidate.efi.new-999"),
        )
        .unwrap();
        assert!(linked.backend.retain(&linked.request).is_err());
        assert!(
            fs::symlink_metadata(linked_lease.join("candidate.efi.new-999"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn terminal_hold_recovery_rejects_missing_or_tampered_retention() {
        let missing = Fixture::new();
        complete_terminal_rollout(&missing, 2, ImageRolloutStatus::Succeeded);
        let missing_copy = missing
            .backend
            .retained_uki_directory(&missing.request)
            .unwrap()
            .join("candidate.efi");
        fs::remove_file(missing_copy).unwrap();
        let restarted = NativeAbRolloutBackend::new(
            missing.backend.image_profile.clone(),
            missing.backend.boot_root.clone(),
        );
        assert!(restarted.hold(&missing.request).is_err());
        assert!(
            restarted
                .observe_operation(&missing.request, "hold")
                .is_err()
        );

        let tampered = Fixture::new();
        complete_terminal_rollout(&tampered, 1, ImageRolloutStatus::HealthFailed);
        let root = tampered
            .backend
            .execution_directory(&tampered.request)
            .unwrap()
            .join("predecessor-toplevel");
        fs::remove_file(&root).unwrap();
        symlink(&tampered.request.candidate.toplevel, &root).unwrap();
        let restarted = NativeAbRolloutBackend::new(
            tampered.backend.image_profile.clone(),
            tampered.backend.boot_root.clone(),
        );
        assert!(restarted.withdraw(&tampered.request).is_err());
        assert!(
            restarted
                .observe_operation(&tampered.request, "withdraw")
                .is_err()
        );
    }

    #[test]
    fn read_only_postcondition_observation_never_updates_provider_state() {
        let fixture = Fixture::new();
        fixture.backend.retain(&fixture.request).unwrap();
        fixture.backend.prepare(&fixture.request).unwrap();
        let state_path = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap()
            .join("state.json");
        let before = fs::read(&state_path).unwrap();

        let observed = fixture
            .backend
            .observe_operation(&fixture.request, "prepare")
            .unwrap();
        assert_eq!(observed.phase, AbilityRolloutPhase::Prepared);
        assert_eq!(fs::read(&state_path).unwrap(), before);
        assert!(
            fixture
                .backend
                .observe_operation(&fixture.request, "drain")
                .is_err()
        );
        assert_eq!(fs::read(&state_path).unwrap(), before);
    }

    #[test]
    fn retirement_removes_the_uki_lease_without_hiding_the_active_entry() {
        let fixture = Fixture::new();
        let terminal = complete_terminal_rollout(&fixture, 2, ImageRolloutStatus::Succeeded);
        assert_eq!(
            terminal.outcome,
            Some(AbilityRolloutOutcome::CandidateHealthy)
        );

        fixture.backend.retire(&fixture.request, 2_000).unwrap();
        fs::remove_file(fixture.backend.boot_root.join("EFI/Linux/aos-1+3.efi")).unwrap();
        fixture
            .backend
            .preflight_operation(&fixture.request, "retire", 2_000)
            .unwrap();

        assert!(
            retained_uki_entry_ids(&fixture.backend.boot_root)
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .backend
                .boot_root
                .join("EFI/Linux/aos-2+3.efi")
                .is_file()
        );
        let execution = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap();
        assert!(
            execution
                .join("predecessor-toplevel")
                .symlink_metadata()
                .is_err()
        );
        for identity in ["candidate", "predecessor"] {
            for suffix in ["toplevel", "executor"] {
                assert!(
                    execution
                        .join(format!("{identity}-{suffix}"))
                        .symlink_metadata()
                        .is_err()
                );
            }
        }
        assert_eq!(
            fs::read_link(fixture.backend.image_profile.join("image-gen-2/toplevel")).unwrap(),
            Path::new(&fixture.request.candidate.toplevel)
        );

        let restarted = NativeAbRolloutBackend::new(
            fixture.backend.image_profile.clone(),
            fixture.backend.boot_root.clone(),
        );
        let recovered = restarted
            .observe_operation(&fixture.request, "retire")
            .unwrap();
        assert_eq!(recovered.phase, AbilityRolloutPhase::Retired);
        assert_eq!(
            recovered.outcome,
            Some(AbilityRolloutOutcome::CandidateHealthy)
        );
    }

    #[test]
    fn retirement_resumes_after_partial_rollout_root_cleanup() {
        let fixture = Fixture::new();
        let mut terminal = complete_terminal_rollout(&fixture, 2, ImageRolloutStatus::Succeeded);
        terminal.phase = AbilityRolloutPhase::Retiring;
        fixture.backend.write_state(&terminal).unwrap();

        let execution = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap();
        remove_file_durable(&execution.join("candidate-toplevel")).unwrap();
        let uki_lease = fixture
            .backend
            .retained_uki_directory(&fixture.request)
            .unwrap();
        remove_file_durable(&uki_lease.join("candidate.efi")).unwrap();

        let retired = fixture.backend.retire(&fixture.request, 2_000).unwrap();
        assert_eq!(retired.phase, AbilityRolloutPhase::Retired);
        fixture
            .backend
            .observe_operation(&fixture.request, "retire")
            .unwrap();
    }

    #[test]
    fn fallback_retirement_preserves_the_predecessor_outcome_after_restart() {
        let fixture = Fixture::new();
        let terminal = complete_terminal_rollout(&fixture, 1, ImageRolloutStatus::HealthFailed);
        assert_eq!(
            terminal.outcome,
            Some(AbilityRolloutOutcome::PredecessorFallback)
        );

        fixture.backend.retire(&fixture.request, 2_000).unwrap();
        let restarted = NativeAbRolloutBackend::new(
            fixture.backend.image_profile.clone(),
            fixture.backend.boot_root.clone(),
        );
        let recovered = restarted
            .observe_operation(&fixture.request, "retire")
            .unwrap();
        assert_eq!(recovered.phase, AbilityRolloutPhase::Retired);
        assert_eq!(
            recovered.outcome,
            Some(AbilityRolloutOutcome::PredecessorFallback)
        );

        let execution = fixture
            .backend
            .execution_directory(&fixture.request)
            .unwrap();
        for identity in ["candidate", "predecessor"] {
            for suffix in ["toplevel", "executor"] {
                assert!(
                    execution
                        .join(format!("{identity}-{suffix}"))
                        .symlink_metadata()
                        .is_err()
                );
            }
        }
        assert_eq!(
            fs::read_link(fixture.backend.image_profile.join("image-gen-1/toplevel")).unwrap(),
            Path::new(&fixture.request.predecessor.toplevel)
        );
    }
}
