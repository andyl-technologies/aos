//! Lazy typed branching of recorded application-randomness choices.
//!
//! Live app-random requests are recorded as an exact [`Decision::RngDraw`]
//! followed by a campaign [`Decision::Selection`]. Branching consumes one
//! validated [`ChoiceDiscovery`] at that exact parent and emits only typed
//! campaign selections. The legacy raw [`Decision::AppRandom`] schedule form
//! remains readable for replay, but has no branch-generation entry point.

use crucible_campaign::{ChoiceDiscovery, Selection, SelectionOrigin};
use thiserror::Error;

use super::*;
use crate::{AppRandomSelectable, AppRandomSelectableError, SelectionDecision};

/// Maximum deterministic alternatives sampled for one recorded draw.
pub const MAX_APP_RANDOM_SAMPLES_PER_DRAW: u8 = 64;

/// Validated per-draw alternative sampling budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AppRandomSampleBudget(u8);

impl AppRandomSampleBudget {
    /// Validates a per-draw alternative count.
    ///
    /// Returns `None` when `samples` exceeds
    /// [`MAX_APP_RANDOM_SAMPLES_PER_DRAW`].
    #[must_use]
    pub const fn new(samples: u8) -> Option<Self> {
        if samples <= MAX_APP_RANDOM_SAMPLES_PER_DRAW {
            Some(Self(samples))
        } else {
            None
        }
    }

    /// Returns the validated number of alternatives per observed draw.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Configuration for one lazy app-random branch point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomBranchConfig {
    /// Validated number of alternatives sampled for the recorded draw.
    pub samples_per_draw: AppRandomSampleBudget,
    /// Seed for deterministic value sampling.
    pub seed: Seed,
}

/// One recorded typed app-random request site available for branch exploration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppRandomDrawSite {
    /// Node requesting random data.
    pub node: NodeId,
    /// Decision stream serving the request.
    pub stream: RngStreamId,
    /// Per-stream request identifier.
    pub request_id: u64,
    /// Requested bit width, capped at 64.
    pub width: u8,
}

/// Result of one lazy typed app-random branch expansion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomBranchRun {
    /// Exact request site expanded by this call.
    pub observed_site: AppRandomDrawSite,
    /// Typed campaign selections considered for branching.
    pub decisions: Vec<Decision>,
    /// Frontier report for the generated children.
    pub report: FrontierReductionReport,
}

/// Failure while resolving or expanding one typed app-random branch point.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomBranchError {
    /// The exact parent does not end immediately after the request's RNG draw.
    #[error("typed app-random branch parent does not end in an RNG draw")]
    MissingParentDraw,
    /// The schedule draw and selection evidence name different raw draws.
    #[error("typed app-random selection evidence does not match its parent RNG draw")]
    ParentDrawMismatch,
    /// The supplied records do not form the standardized producer contract.
    #[error(transparent)]
    Selectable(#[from] AppRandomSelectableError),
    /// Graph materialization or frontier enumeration failed.
    #[error(transparent)]
    Engine(#[from] EngineError),
}

/// Generates typed campaign alternatives for one exact app-random branch point.
///
/// `parent` must end with the [`Decision::RngDraw`] paired with `observed`.
/// `discovery` supplies the authenticated declaration, domain, and opportunity
/// emitted by the live producer. The returned decisions replace only the
/// observed selection; they retain the draw in the immutable prefix and bind
/// every alternative to the exact parent branch point.
///
/// # Errors
///
/// Returns [`AppRandomBranchError`] when the parent/draw pairing is malformed,
/// the discovery is not the standardized app-random contract, or the observed
/// model sample cannot be reproduced.
pub fn app_random_branch_decisions(
    parent: &Configuration,
    observed: &SelectionDecision,
    discovery: &ChoiceDiscovery,
    config: &AppRandomBranchConfig,
) -> Result<Vec<Decision>, AppRandomBranchError> {
    let (selectable, observed_value) = resolve_app_random_site(parent, observed, discovery)?;
    alternatives_for_site(parent, &selectable, observed_value, config)
}

fn resolve_app_random_site(
    parent: &Configuration,
    observed: &SelectionDecision,
    discovery: &ChoiceDiscovery,
) -> Result<(AppRandomSelectable, u64), AppRandomBranchError> {
    let Some(Decision::RngDraw(draw)) = parent.schedule.decisions().last() else {
        return Err(AppRandomBranchError::MissingParentDraw);
    };
    let selection = observed
        .selection()
        .map_err(AppRandomSelectableError::from)?;
    let SelectionOrigin::ModelSample(evidence) = selection.origin() else {
        return Err(AppRandomSelectableError::NotModelSample.into());
    };
    if evidence.draw() != draw.value {
        return Err(AppRandomBranchError::ParentDrawMismatch);
    }
    let selectable = AppRandomSelectable::from_model_sample_records(
        draw.stream.clone(),
        &selection,
        discovery.declaration(),
        discovery.opportunity(),
        discovery.domain(),
    )?;
    let observed = selectable.apply_selection(&selection, parent)?;
    Ok((selectable, observed.value))
}

impl TemporalGraph {
    /// Lazily branches one validated app-random choice at its exact parent.
    ///
    /// The caller chooses one branch point; this method never scans or eagerly
    /// expands every draw in a retained schedule. A zero-sample budget records
    /// no graph mutation.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomBranchError`] when the parent/draw/discovery basis is
    /// invalid, or graph checkpointing and frontier enumeration fail.
    pub fn branch_app_random(
        &mut self,
        parent: &Configuration,
        observed: &SelectionDecision,
        discovery: &ChoiceDiscovery,
        config: &AppRandomBranchConfig,
    ) -> Result<AppRandomBranchRun, AppRandomBranchError> {
        let (selectable, observed_value) = resolve_app_random_site(parent, observed, discovery)?;
        let decisions = alternatives_for_site(parent, &selectable, observed_value, config)?;
        let observed_site = site_from_selectable(&selectable);
        if decisions.is_empty() {
            return Ok(AppRandomBranchRun {
                observed_site,
                decisions,
                report: FrontierReductionReport::default(),
            });
        }

        self.record_checkpoint_closure(parent)?;
        let report = self.enumerate_frontier_reduced(
            parent,
            decisions.clone(),
            FrontierReductionPolicy::none(),
        )?;
        Ok(AppRandomBranchRun {
            observed_site,
            decisions,
            report,
        })
    }
}

fn site_from_selectable(selectable: &AppRandomSelectable) -> AppRandomDrawSite {
    AppRandomDrawSite {
        node: selectable.node().clone(),
        stream: selectable.stream().clone(),
        request_id: selectable.request_id(),
        width: selectable.width(),
    }
}

fn alternatives_for_site(
    parent: &Configuration,
    selectable: &AppRandomSelectable,
    observed_value: u64,
    config: &AppRandomBranchConfig,
) -> Result<Vec<Decision>, AppRandomBranchError> {
    let mask = width_mask(selectable.width());
    let site = site_from_selectable(selectable);
    let mut sample_prefix = Vec::new();
    sample_prefix.extend_from_slice(&config.seed.bytes());
    append_len_prefixed(&mut sample_prefix, site.node.name.as_bytes());
    append_len_prefixed(&mut sample_prefix, site.stream.domain.as_bytes());
    append_len_prefixed(&mut sample_prefix, site.stream.name.as_bytes());
    sample_prefix.extend_from_slice(&site.request_id.to_be_bytes());
    sample_prefix.push(site.width);

    let mut values = BTreeSet::new();
    let mut alternatives = Vec::new();
    for sample in 0..u64::from(config.samples_per_draw.get()) {
        let mut material = sample_prefix.clone();
        material.extend_from_slice(&sample.to_be_bytes());
        let value = content_hash_low_u64(ContentHash::from_canonical_hex_bytes(
            "crucible.app-random.branch.v3",
            &material,
        )) & mask;
        if value == observed_value || !values.insert(value) {
            continue;
        }
        let selection: Selection = selectable.branch_selection(parent, value)?;
        alternatives.push(Decision::Selection(SelectionDecision::new(&selection)));
    }
    Ok(alternatives)
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

const fn width_mask(width: u8) -> u64 {
    match width {
        0 => 0,
        64.. => u64::MAX,
        _ => (1u64 << width) - 1,
    }
}
