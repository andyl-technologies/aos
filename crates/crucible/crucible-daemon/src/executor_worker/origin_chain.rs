//! Selected-continuation origin chains that keep one origin resident at a time.
//!
//! A continuation attempt (`AttemptStart::AfterAttempt`) names its origin
//! attempt and the configuration that origin claims to have reached. Executing
//! it replays every ancestor from the oldest discovery or branch base:
//!
//! ```text
//! base (Discover | Branch) -> origin 1 -> ... -> origin N (terminal) -> attempt
//!                             |<- reloaded per walk ->|  |<- resident ->|
//! ```
//!
//! [`AttemptOriginChain`] retains each intermediate origin only by identity:
//! its attempt record, the reached configuration-artifact ID, and the source
//! observation ID of a controlled continuation. Only the terminal origin is
//! fully loaded, because its reached configuration is the attempt's starting
//! boundary. Consumers visit origins oldest first with
//! [`AttemptOriginChain::try_for_each`], which loads, reauthenticates, lends,
//! and drops one intermediate origin before reading the next. Resident artifact
//! memory is therefore the base, the terminal origin, and the largest single
//! intermediate origin, independent of chain depth. Resolution charges exactly
//! that peak against the attempt's resident-byte ceiling.

use super::*;

use crucible_campaign::{
    BranchPathId, ConfigurationArtifactId, Observation, ScenarioArtifactId, ScenarioDefId,
};

/// Fixed per-record allocation headroom charged beside each canonical payload.
const SELECTED_ORIGIN_STRUCTURAL_BYTES: u64 = 4096;

/// Nonempty oldest-first continuation ancestry with one resident terminal origin.
///
/// Intermediate origins are retained by identity and reloaded on demand. Every
/// reload repeats the authentication performed during resolution, so a value
/// produced by [`resolve_attempt_execution_input`] cannot lend an origin whose
/// lineage, path, reached artifact, or controlled source proof differs from the
/// one admitted at resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptOriginChain {
    binding: OriginBinding,
    intermediates: Vec<OriginChainLink>,
    terminal: ResolvedAttemptOrigin,
    peak_intermediate_encoded_bytes: u64,
}

/// Lineage and path every origin in one chain must share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OriginBinding {
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    path: BranchPathId,
}

/// One origin attempt and the boundary identities its successor names.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OriginChainLink {
    attempt: Attempt,
    reached: ConfigurationArtifactId,
    source_observation: Option<ObservationId>,
}

impl AttemptOriginChain {
    /// Returns the final origin that establishes the semantic start boundary.
    #[must_use]
    pub const fn last(&self) -> &ResolvedAttemptOrigin {
        &self.terminal
    }

    /// Returns the number of origin attempts in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intermediates.len() + 1
    }

    /// Returns false because a selected continuation always has an origin.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Returns the largest encoded footprint of one non-terminal origin.
    ///
    /// The footprint is the reached artifact's canonical payload plus the
    /// retained source-proof charge. It is zero for a single-origin chain.
    #[must_use]
    pub const fn peak_intermediate_encoded_bytes(&self) -> u64 {
        self.peak_intermediate_encoded_bytes
    }

    /// Visits every origin oldest first, holding at most one reloaded origin.
    ///
    /// Each intermediate origin is reloaded from `store`, reauthenticated
    /// against the chain's lineage and path, lent to `visit`, and dropped before
    /// the next is read. The resident terminal origin is visited last without
    /// a reload. Walking the chain again repeats the intermediate reads.
    ///
    /// # Errors
    ///
    /// Returns the first error from `visit`, or a converted
    /// [`CampaignRepositoryError`] when an intermediate origin is unavailable,
    /// corrupt, or no longer authenticates against the chain.
    pub fn try_for_each<E>(
        &self,
        store: &CampaignExecutorStore,
        visit: impl FnMut(&ResolvedAttemptOrigin) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<CampaignRepositoryError>,
    {
        self.try_for_each_from(store, visit)
    }

    fn try_for_each_from<S, E>(
        &self,
        source: &S,
        mut visit: impl FnMut(&ResolvedAttemptOrigin) -> Result<(), E>,
    ) -> Result<(), E>
    where
        S: OriginRecordSource,
        E: From<CampaignRepositoryError>,
    {
        for link in &self.intermediates {
            let origin = resolve_origin_link(source, self.binding, link)?;
            visit(&origin)?;
        }
        visit(&self.terminal)
    }
}

/// Repository reads needed to authenticate one continuation origin.
///
/// The production source is the executor's narrow repository facade; the seam
/// lets chain-walk tests count reads without publishing attempt records.
trait OriginRecordSource {
    fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError>;

    fn load_observation(&self, id: ObservationId) -> Result<Observation, CampaignRepositoryError>;
}

impl OriginRecordSource for CampaignExecutorStore {
    fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        CampaignExecutorStore::load_configuration_artifact(self, id)
    }

    fn load_observation(&self, id: ObservationId) -> Result<Observation, CampaignRepositoryError> {
        CampaignExecutorStore::load_observation(self, id)
    }
}

/// Peak resident-byte accounting for one origin-chain resolution.
///
/// Retained values (base and terminal) stay charged. Transient intermediate
/// origins are charged only as the largest single one, because every consumer
/// drops an intermediate before loading the next.
#[derive(Debug)]
struct OriginResidentBudget {
    limit: u64,
    retained: u64,
    peak_transient: u64,
}

impl OriginResidentBudget {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            retained: 0,
            peak_transient: 0,
        }
    }

    /// Charges a value that stays resident for the rest of the execution.
    fn retain(&mut self, bytes: u64) -> Result<(), CampaignRepositoryError> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .ok_or_else(origin_byte_overflow)?;
        self.check(self.peak_transient)
    }

    /// Admits one origin that is dropped before the next is loaded.
    fn admit_transient(&mut self, bytes: u64) -> Result<(), CampaignRepositoryError> {
        self.check(bytes)?;
        self.peak_transient = self.peak_transient.max(bytes);
        Ok(())
    }

    fn check(&self, transient: u64) -> Result<(), CampaignRepositoryError> {
        let peak = self
            .retained
            .checked_add(transient)
            .ok_or_else(origin_byte_overflow)?;
        if peak > self.limit {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "attempt-origin-artifacts-exceed-resource-limit",
            });
        }
        Ok(())
    }
}

/// Returns the resident charge of one configuration artifact.
///
/// Decoded schedules and replay-plan prefixes are charged by the typed
/// Crucible adapter. This phase retains only canonical envelopes.
fn origin_artifact_bytes(artifact: &ConfigurationArtifact) -> Result<u64, CampaignRepositoryError> {
    charged_bytes(artifact.payload().len())
}

/// Resolves a continuation's base start and origin chain within its ceiling.
///
/// `attempt_chain` runs from the requested attempt back to its oldest
/// discovery or branch base, as returned by the repository. The base and the
/// terminal origin stay resident; intermediate origins are charged only as the
/// largest single one.
pub(super) fn resolve_after_attempt_start(
    store: &CampaignExecutorStore,
    lineage: &CampaignLineage,
    path: BranchPathId,
    mut attempt_chain: Vec<Attempt>,
    maximum_resident_bytes: u64,
) -> Result<ResolvedAttemptStart, CampaignRepositoryError> {
    // The headroom keeps one later bounded artifact load admissible after the
    // base and terminal origin stay resident.
    let maximum_origin_bytes = maximum_resident_bytes
        .min(MAX_SELECTED_ORIGIN_ARTIFACT_BYTES)
        .checked_sub(MAX_CONFIGURATION_ARTIFACT_LOAD_BYTES)
        .ok_or(CampaignRepositoryError::InvalidRequest {
            reason: "selected-origin-resident-limit-cannot-load-one-artifact",
        })?;
    let mut budget = OriginResidentBudget::new(maximum_origin_bytes);

    let base_attempt = attempt_chain
        .pop()
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-is-empty",
        })?;
    let base = match base_attempt.start() {
        AttemptStart::Discover { configuration } => {
            let configuration = store.load_configuration_artifact(configuration)?;
            budget.retain(origin_artifact_bytes(&configuration)?)?;
            ResolvedAttemptStart::Discover { configuration }
        }
        AttemptStart::Branch {
            parent, selection, ..
        } => {
            let parent = store.load_configuration_artifact(parent)?;
            budget.retain(origin_artifact_bytes(&parent)?)?;
            ResolvedAttemptStart::Branch {
                parent,
                selection: Box::new(store.resolve_selection(selection)?),
            }
        }
        AttemptStart::AfterAttempt { .. } => {
            return Err(CampaignRepositoryError::Integrity {
                reason: "attempt-origin-chain-has-no-base",
            });
        }
    };

    attempt_chain.reverse();
    let origins = resolve_origin_chain(
        store,
        lineage,
        path,
        base_attempt,
        attempt_chain,
        &mut budget,
    )?;
    Ok(ResolvedAttemptStart::AfterAttempt {
        base: Box::new(base),
        origins: Box::new(origins),
    })
}

/// Authenticates an `AfterAttempt` ancestry and retains only its terminal origin.
///
/// `base_attempt` is the oldest discovery or branch attempt, and `descendants`
/// runs oldest first through the requested attempt. Each descendant names its
/// predecessor as origin; the predecessor and the descendant's reached
/// boundary form one origin. `budget` must already hold the resident base.
fn resolve_origin_chain<S>(
    source: &S,
    lineage: &CampaignLineage,
    path: BranchPathId,
    base_attempt: Attempt,
    descendants: Vec<Attempt>,
    budget: &mut OriginResidentBudget,
) -> Result<AttemptOriginChain, CampaignRepositoryError>
where
    S: OriginRecordSource,
{
    let binding = OriginBinding {
        scenario: lineage.scenario(),
        scenario_artifact: lineage.scenario_content(),
        path,
    };
    let origin_count = descendants.len();
    let mut intermediates = Vec::with_capacity(origin_count.saturating_sub(1));
    let mut peak_intermediate_encoded_bytes = 0_u64;
    let mut origin_attempt = base_attempt;

    for (index, descendant) in descendants.into_iter().enumerate() {
        let link = origin_chain_link(origin_attempt, &descendant)?;
        let origin = resolve_origin_link(source, binding, &link)?;
        let resident_bytes = origin_artifact_bytes(origin.reached())?
            .checked_add(origin.source_stop_charge()?)
            .ok_or_else(origin_byte_overflow)?;

        if index + 1 == origin_count {
            budget.retain(resident_bytes)?;
            return Ok(AttemptOriginChain {
                binding,
                intermediates,
                terminal: origin,
                peak_intermediate_encoded_bytes,
            });
        }

        // The loaded origin is dropped here; consumers reload it on demand.
        budget.admit_transient(resident_bytes)?;
        peak_intermediate_encoded_bytes =
            peak_intermediate_encoded_bytes.max(origin.encoded_bytes()?);
        intermediates.push(link);
        origin_attempt = descendant;
    }

    Err(CampaignRepositoryError::Integrity {
        reason: "attempt-origin-chain-has-no-boundary",
    })
}

fn origin_chain_link(
    origin_attempt: Attempt,
    descendant: &Attempt,
) -> Result<OriginChainLink, CampaignRepositoryError> {
    let AttemptStart::AfterAttempt { origin, reached } = descendant.start() else {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-has-interior-base",
        });
    };
    if origin_attempt.id()? != origin {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-link-mismatch",
        });
    }

    Ok(OriginChainLink {
        attempt: origin_attempt,
        reached,
        source_observation: descendant
            .continuation_input()
            .map(AttemptContinuationInput::source_observation),
    })
}

fn resolve_origin_link<S>(
    source: &S,
    binding: OriginBinding,
    link: &OriginChainLink,
) -> Result<ResolvedAttemptOrigin, CampaignRepositoryError>
where
    S: OriginRecordSource,
{
    let reached = source.load_configuration_artifact(link.reached)?;
    if reached.scenario() != binding.scenario
        || reached.scenario_artifact() != binding.scenario_artifact
        || link.attempt.path() != binding.path
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-lineage-mismatch",
        });
    }

    let (source_stop, source_stop_bytes) = match link.source_observation {
        Some(observation) => {
            let (stop, bytes) =
                resolve_continuation_source_stop(source, observation, &link.attempt, &reached)?;
            let bytes = u64::try_from(bytes).map_err(|_| origin_byte_overflow())?;
            (Some(stop), bytes)
        }
        None => (None, 0),
    };

    Ok(ResolvedAttemptOrigin {
        attempt: link.attempt.clone(),
        reached,
        source_stop,
        source_stop_bytes,
    })
}

fn resolve_continuation_source_stop<S>(
    source: &S,
    source_observation: ObservationId,
    source_attempt: &Attempt,
    reached: &ConfigurationArtifact,
) -> Result<(StopOutcome, usize), CampaignRepositoryError>
where
    S: OriginRecordSource,
{
    let observation = source.load_observation(source_observation)?;
    if observation.attempt() != source_attempt.id()? {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-origin-mismatch",
        });
    }
    if observation.child_content() != reached.id()?
        || observation.child() != reached.configuration()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-reached-mismatch",
        });
    }
    if !observation.stop().reaches(source_attempt.stop()) {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-stop-mismatch",
        });
    }

    let bytes = observation.canonical_bytes().len();
    Ok((observation.stop().clone(), bytes))
}

impl ResolvedAttemptOrigin {
    /// Returns the resident charge of the retained source proof, if any.
    fn source_stop_charge(&self) -> Result<u64, CampaignRepositoryError> {
        if self.source_stop.is_none() {
            return Ok(0);
        }
        self.source_stop_bytes
            .checked_add(SELECTED_ORIGIN_STRUCTURAL_BYTES)
            .ok_or_else(origin_byte_overflow)
    }

    /// Returns the reached payload plus source-proof bytes charged by decoding.
    fn encoded_bytes(&self) -> Result<u64, CampaignRepositoryError> {
        u64::try_from(self.reached.payload().len())
            .ok()
            .and_then(|bytes| bytes.checked_add(self.source_stop_bytes))
            .ok_or_else(origin_byte_overflow)
    }
}

fn charged_bytes(encoded_bytes: usize) -> Result<u64, CampaignRepositoryError> {
    u64::try_from(encoded_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(SELECTED_ORIGIN_STRUCTURAL_BYTES))
        .ok_or_else(origin_byte_overflow)
}

fn origin_byte_overflow() -> CampaignRepositoryError {
    CampaignRepositoryError::Integrity {
        reason: "attempt-origin-artifact-byte-count-overflow",
    }
}

#[cfg(test)]
mod tests;
