//! Branch-reseed construction for deterministic decision recorders.

use std::collections::BTreeMap;

use crucible_sim::{DecisionRng, DecisionStream};

use super::DecisionRecorder;
use crate::{Configuration, Decision, DecisionRngState, RngStreamId, Seed};

impl DecisionRecorder {
    /// Builds a recorder from an explicit seed and authoritative stream cursors.
    ///
    /// This constructor is the branch/reseed path: the configuration keeps its
    /// immutable scenario seed and recorded prefix, while only future draws use
    /// `seed` at the positions supplied by the live scheduler.
    #[must_use]
    pub fn from_seed_and_positions(
        configuration: Configuration,
        seed: Seed,
        positions: &DecisionRngState,
    ) -> Self {
        let rng = seed.decision_rng();
        let streams = hydrate_stream_positions(&rng, positions);
        let app_random_draws = count_app_random_draws(configuration.schedule.decisions());
        Self {
            configuration,
            rng,
            streams,
            app_random_draws,
        }
    }
}

pub(super) fn count_app_random_draws(decisions: &[Decision]) -> u64 {
    decisions
        .iter()
        .filter(|decision| matches!(decision, Decision::AppRandom(_)))
        .count() as u64
}

fn hydrate_stream_positions(
    rng: &DecisionRng,
    positions: &DecisionRngState,
) -> BTreeMap<RngStreamId, DecisionStream> {
    positions
        .positions
        .iter()
        .map(|(stream, position)| {
            let mut decision_stream = rng.fork_in_domain(&stream.domain, &stream.name);
            decision_stream.advance_by(position.draws);
            (stream.clone(), decision_stream)
        })
        .collect()
}
