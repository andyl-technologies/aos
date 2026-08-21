//! Restart-safe coordinator ownership of one bounded planner component call.
//!
//! The driver reconstructs the current planner state and page cursor from the
//! authenticated campaign head before every call. It never retains a volatile
//! cursor as authority, and it holds no repository mutation guard while the
//! external planner component executes.

use std::sync::Arc;

use super::*;
use crate::{PlannerClient, PlannerClientError, PlannerService};

/// Coordinator-owned driver for one configured planner component.
pub struct CampaignPlannerDriver<S> {
    repository: Arc<CampaignRepository>,
    planner: PlannerClient<S>,
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    initial_state: PlannerState,
    scan_limit: u32,
    budget: PlanningBudget,
}

impl<S> CampaignPlannerDriver<S> {
    /// Builds one exact planner driver without publishing repository content.
    ///
    /// The engine descriptor, reproducible artifact, and initial state must
    /// name one engine. The page limit is bounded independently of the
    /// invocation's object, byte, output, and fuel budget.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignPlannerDriverConfigError`] when the checked client and
    /// repository use different planner authorities, an identity cannot be
    /// derived, the configured basis names different engines, or the page
    /// limit is outside `1..=10,000`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: Arc<CampaignRepository>,
        planner: PlannerClient<S>,
        engine: PlannerEngine,
        artifact: PolicyArtifact,
        initial_state: PlannerState,
        scan_limit: u32,
        budget: PlanningBudget,
    ) -> Result<Self, CampaignPlannerDriverConfigError> {
        if !repository
            .planner_authority
            .as_ref()
            .is_some_and(|authority| authority.has_same_planner_material(planner.authority()))
        {
            return Err(CampaignPlannerDriverConfigError::AuthorityMismatch);
        }
        let engine_id = engine.id()?;
        artifact.id()?;
        initial_state.id()?;
        if artifact.engine() != engine_id || initial_state.engine() != engine_id {
            return Err(CampaignPlannerDriverConfigError::BasisMismatch);
        }
        if scan_limit == 0 || scan_limit > MAX_PLANNER_SCAN_PAGE_ITEMS {
            return Err(CampaignPlannerDriverConfigError::InvalidScanLimit);
        }
        Ok(Self {
            repository,
            planner,
            engine,
            artifact,
            initial_state,
            scan_limit,
            budget,
        })
    }

    /// Advances the planner by at most one bounded component invocation.
    ///
    /// A prior `ContinueScan` resumes at its authenticated cursor after a
    /// process restart. A prior terminal result is returned without calling
    /// the component while its exact planning view remains current. Any
    /// semantic-root change starts a fresh scan from the prior portable state.
    ///
    /// Repository locks are not held across [`PlannerService::plan`]. A head
    /// change during that call therefore fails at ordinary snapshot acceptance
    /// instead of blocking unrelated owner mutations.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignPlannerDriverError::Repository`] when authenticated
    /// resume, invocation preparation, request construction, or acceptance
    /// fails. Returns [`CampaignPlannerDriverError::Planner`] when the checked
    /// component call fails or produces an invalid response.
    pub fn step(
        &mut self,
        campaign: &str,
    ) -> Result<CampaignPlannerStepOutcome, CampaignPlannerDriverError<S::Error>>
    where
        S: PlannerService,
    {
        let resume = self.repository.planner_resume(
            campaign,
            &self.engine,
            &self.artifact,
            &self.initial_state,
        )?;
        let (snapshot, state, after) = match resume {
            PlannerResume::Ready {
                snapshot,
                state,
                after,
            } => (snapshot, state, after),
            PlannerResume::Settled {
                snapshot,
                step,
                disposition,
            } => {
                return Ok(CampaignPlannerStepOutcome::Settled {
                    snapshot,
                    step,
                    disposition,
                });
            }
        };

        let invocation = self.repository.prepare_planner_invocation(
            campaign,
            snapshot,
            &self.engine,
            &self.artifact,
            &state,
            after,
            self.scan_limit,
            self.budget,
        )?;
        let invocation_id = invocation.id().map_err(CampaignRepositoryError::from)?;
        let request = self
            .repository
            .build_planner_request(snapshot, invocation_id)?;
        let response = self
            .planner
            .plan(&request)
            .map_err(CampaignPlannerDriverError::Planner)?;
        let result = self
            .repository
            .accept_planner_response(campaign, &request, &response)?;
        let accepted = self
            .repository
            .load_planner_step_at(result.new_snapshot, result.step)?;
        Ok(CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: accepted.disposition().clone(),
        })
    }

    /// Returns the checked planner client when coordinator ownership ends.
    #[must_use]
    pub fn into_planner(self) -> PlannerClient<S> {
        self.planner
    }
}

impl CampaignRepository {
    fn planner_resume(
        &self,
        campaign: &str,
        engine: &PlannerEngine,
        artifact: &PolicyArtifact,
        initial_state: &PlannerState,
    ) -> Result<PlannerResume, CampaignRepositoryError> {
        let head = self.head(campaign)?;
        let snapshot = head.snapshot_id();
        let input_view = head.snapshot().planning_view().id()?;
        let engine_id = engine.id()?;
        let artifact_id = artifact.id()?;
        let Some(step_content) = self
            .merkle
            .get(head.snapshot().roots().coordination, planner_head_key())?
        else {
            return Ok(PlannerResume::Ready {
                snapshot,
                state: initial_state.clone(),
                after: None,
            });
        };

        let step_id = PlannerStepId::from_content_id(step_content)?;
        let step = self.load_planner_step_at(snapshot, step_id)?;
        if step.engine() != engine_id || step.policy_artifact() != artifact_id {
            return Err(integrity("planner-driver-configured-basis-mismatch"));
        }
        let state_envelope = self.require_record_kind(
            step.next_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let state = crate::codec::decode::<PlannerState>(state_envelope.body())?;
        if state.id()? != step.next_state() || state.engine() != engine_id {
            return Err(integrity("planner-driver-next-state-identity-mismatch"));
        }

        if step.input_view() != input_view {
            return Ok(PlannerResume::Ready {
                snapshot,
                state,
                after: None,
            });
        }
        match step.disposition() {
            PlannerDisposition::ContinueScan { cursor } => Ok(PlannerResume::Ready {
                snapshot,
                state,
                after: cursor.after(),
            }),
            disposition @ (PlannerDisposition::Issue { .. } | PlannerDisposition::NoWork) => {
                Ok(PlannerResume::Settled {
                    snapshot,
                    step: step_id,
                    disposition: disposition.clone(),
                })
            }
        }
    }
}

enum PlannerResume {
    Ready {
        snapshot: CampaignSnapshotId,
        state: PlannerState,
        after: Option<PlanningScanPosition>,
    },
    Settled {
        snapshot: CampaignSnapshotId,
        step: PlannerStepId,
        disposition: PlannerDisposition,
    },
}

/// Result of one bounded coordinator planner step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignPlannerStepOutcome {
    /// One authenticated response advanced the campaign.
    Advanced {
        /// Stable repository acceptance result.
        result: PlannerStepResult,
        /// Coordinator-accepted semantic disposition.
        disposition: PlannerDisposition,
    },
    /// The current semantic view already has a terminal planner result.
    Settled {
        /// Current authenticated snapshot.
        snapshot: CampaignSnapshotId,
        /// Exact accepted step settling that view.
        step: PlannerStepId,
        /// Existing terminal disposition.
        disposition: PlannerDisposition,
    },
}

/// Invalid static configuration for a campaign planner driver.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CampaignPlannerDriverConfigError {
    /// A configured descriptor or record identity could not be derived.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// The checked client does not use the repository's planner authority.
    #[error("campaign planner client and repository authority differ")]
    AuthorityMismatch,
    /// The engine descriptor, artifact, and initial state name different engines.
    #[error("campaign planner driver basis names different engines")]
    BasisMismatch,
    /// The configured scan page is empty or exceeds the fixed coordinator bound.
    #[error("campaign planner scan page limit must be in 1..=10,000")]
    InvalidScanLimit,
}

/// Failure while driving one coordinator planner step.
#[derive(Debug, thiserror::Error)]
pub enum CampaignPlannerDriverError<E> {
    /// Authenticated repository preparation or acceptance failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The checked planner component call failed.
    #[error("planner component call failed: {0}")]
    Planner(PlannerClientError<E>),
}
