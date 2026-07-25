//! Integrated exploration of recorded application-randomness requests.
//!
//! Draw sites come only from causal [`Decision::AppRandom`] observations already
//! present in a recorded schedule. Branches replace the observed served value at
//! its original prefix, preserving the scenario draw cap instead of appending a
//! second response for the same request.

use super::*;

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

/// Configuration for recorded app-random branch generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomBranchConfig {
    /// Validated number of alternatives sampled for each recorded draw.
    pub samples_per_draw: AppRandomSampleBudget,
    /// Seed for deterministic value sampling.
    pub seed: Seed,
}

/// One recorded app-random request site available for branch exploration.
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

/// Result of app-random branch expansion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomBranchRun {
    /// Sites derived from recorded causal decisions.
    pub observed_sites: Vec<AppRandomDrawSite>,
    /// Alternative decisions considered for branching.
    pub decisions: Vec<Decision>,
    /// Frontier report for the generated children.
    pub report: FrontierReductionReport,
}

/// Derives unique draw sites from recorded app-random decisions.
#[must_use]
pub fn app_random_draw_sites_from_schedule(schedule: &Schedule) -> Vec<AppRandomDrawSite> {
    observed_app_random_draws(schedule).into_keys().collect()
}

/// Generates seeded alternatives for the app-random draws recorded in `schedule`.
#[must_use]
pub fn app_random_branch_decisions(
    schedule: &Schedule,
    config: &AppRandomBranchConfig,
) -> Vec<Decision> {
    observed_app_random_draws(schedule)
        .into_iter()
        .flat_map(|(site, observed_value)| alternatives_for_site(&site, observed_value, config))
        .collect()
}

impl TemporalGraph {
    /// Branches recorded app-random observations over bounded seeded alternatives.
    ///
    /// Each alternative replaces one observed response at its original schedule
    /// prefix. A schedule with no app-random observations produces no graph
    /// mutations or children.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::AppRandomDrawCapExceeded`] if a reconstructed
    /// prefix violates the scenario draw cap, or another [`EngineError`] when a
    /// prefix or child cannot be recorded.
    pub fn branch_app_random(
        &mut self,
        frontier: &Configuration,
        config: &AppRandomBranchConfig,
    ) -> Result<AppRandomBranchRun, EngineError> {
        let observed_sites = app_random_draw_sites_from_schedule(&frontier.schedule);
        let mut decisions = Vec::new();
        let mut report = FrontierReductionReport::default();
        let mut expanded_sites = BTreeSet::new();
        for (index, observed) in frontier.schedule.decisions().iter().enumerate() {
            let Decision::AppRandom(observed) = observed else {
                continue;
            };
            let site = site_from_decision(observed);
            if !expanded_sites.insert(site.clone()) {
                continue;
            }
            let alternatives = alternatives_for_site(&site, observed.value, config);
            if alternatives.is_empty() {
                continue;
            }
            let parent = Configuration {
                def: frontier.def.clone(),
                schedule: Schedule::from_decisions(
                    frontier.schedule.decisions()[..index].iter().cloned(),
                ),
            };
            self.record_checkpoint_closure(&parent)?;
            let branch = self.enumerate_frontier_reduced(
                &parent,
                alternatives.clone(),
                FrontierReductionPolicy::none(),
            )?;
            decisions.extend(alternatives);
            report.explored.extend(branch.explored);
            report.covered.extend(branch.covered);
        }
        Ok(AppRandomBranchRun {
            observed_sites,
            decisions,
            report,
        })
    }
}

fn observed_app_random_draws(schedule: &Schedule) -> BTreeMap<AppRandomDrawSite, u64> {
    let mut observed = BTreeMap::new();
    for decision in schedule.decisions() {
        if let Decision::AppRandom(random) = decision {
            observed
                .entry(site_from_decision(random))
                .or_insert(random.value);
        }
    }
    observed
}

fn site_from_decision(random: &AppRandomDecision) -> AppRandomDrawSite {
    AppRandomDrawSite {
        node: random.node.clone(),
        stream: random.stream.clone(),
        request_id: random.request_id,
        width: random.width.min(64),
    }
}

fn alternatives_for_site(
    site: &AppRandomDrawSite,
    observed_value: u64,
    config: &AppRandomBranchConfig,
) -> Vec<Decision> {
    let mask = width_mask(site.width);
    let mut values = BTreeSet::new();
    let mut alternatives = Vec::new();
    for sample in 0..u64::from(config.samples_per_draw.get()) {
        let material = format!(
            "seed={}\nnode={}\nstream_domain={}\nstream_name={}\nrequest_id={}\nwidth={}\nsample={sample}",
            config.seed.to_hex(),
            site.node.name,
            site.stream.domain,
            site.stream.name,
            site.request_id,
            site.width
        );
        let value = content_hash_low_u64(ContentHash::from_canonical_material(
            "crucible.app-random.branch.v2",
            &material,
        )) & mask;
        if value == observed_value || !values.insert(value) {
            continue;
        }
        alternatives.push(Decision::AppRandom(AppRandomDecision {
            node: site.node.clone(),
            stream: site.stream.clone(),
            request_id: site.request_id,
            width: site.width,
            value,
        }));
    }
    alternatives
}

const fn width_mask(width: u8) -> u64 {
    match width {
        0 => 0,
        64.. => u64::MAX,
        _ => (1u64 << width) - 1,
    }
}
