//! Seeded decision recording for the engine schedule.
//!
//! This module is the engine-side bridge between the L0 deterministic decision
//! streams and the L3 [`Schedule`]. Intended randomness enters the engine only
//! by drawing from [`DecisionRng`] forks and appending the resulting
//! [`Decision`] values in scheduler order.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crucible_sim::{DecisionRng, DecisionStream};

use crate::{
    AppRandomDecision, Configuration, Decision, FaultDecision, FaultId, RngDecision, RngStreamId,
    Schedule, VirtualTime, step,
};

/// Records intended nondeterminism into a configuration's [`Schedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecorder {
    configuration: Configuration,
    rng: DecisionRng,
    streams: BTreeMap<RngStreamId, DecisionStream>,
}

impl DecisionRecorder {
    /// Builds a recorder from the current configuration and scenario seed.
    ///
    /// Existing [`Decision::RngDraw`] entries in the schedule advance the
    /// corresponding stream positions so resumed recording does not repeat
    /// prior draws.
    #[must_use]
    pub fn new(configuration: Configuration, seed: u64) -> Self {
        let rng = DecisionRng::new(seed);
        let streams = hydrate_streams(&rng, configuration.schedule.decisions());
        Self {
            configuration,
            rng,
            streams,
        }
    }

    /// Returns the current configuration after all recorded decisions.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the current schedule after all recorded decisions.
    #[must_use]
    pub fn schedule(&self) -> &Schedule {
        &self.configuration.schedule
    }

    /// Consumes the recorder and returns the current configuration.
    #[must_use]
    pub fn into_configuration(self) -> Configuration {
        self.configuration
    }

    /// Draws one `u64` from `stream` and records a [`Decision::RngDraw`].
    pub fn draw_u64(&mut self, stream: RngStreamId) -> u64 {
        let value = self.draw_stream_value(&stream).1;
        self.append_decision(Decision::RngDraw(RngDecision { stream, value }));
        value
    }

    /// Resolves a probabilistic fault through `stream` and records the outcome.
    ///
    /// The fault fires when the raw `u64` draw is strictly below
    /// `fire_below`. The raw draw is recorded before the derived
    /// [`Decision::FaultFires`] outcome.
    pub fn decide_fault(
        &mut self,
        at: VirtualTime,
        fault: FaultId,
        stream: RngStreamId,
        fire_below: u64,
    ) -> bool {
        let value = self.draw_u64(stream);
        let fired = value < fire_below;
        self.append_decision(Decision::FaultFires(FaultDecision { at, fault, fired }));
        fired
    }

    /// Serves an application-requested random value and records it.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError::InvalidAppRandomWidth`] when `width` is
    /// zero or greater than 64 bits.
    pub fn serve_app_random(
        &mut self,
        node: crate::NodeId,
        stream: RngStreamId,
        width: u8,
    ) -> Result<u64, DecisionRecordError> {
        if width == 0 || width > 64 {
            return Err(DecisionRecordError::InvalidAppRandomWidth { width });
        }

        let (request_id, raw_value) = self.draw_stream_value(&stream);
        self.append_decision(Decision::RngDraw(RngDecision {
            stream: stream.clone(),
            value: raw_value,
        }));
        let value = mask_to_width(raw_value, width);
        self.append_decision(Decision::AppRandom(AppRandomDecision {
            node,
            stream,
            request_id,
            width,
            value,
        }));
        Ok(value)
    }

    fn draw_stream_value(&mut self, stream: &RngStreamId) -> (u64, u64) {
        let decision_stream = self
            .streams
            .entry(stream.clone())
            .or_insert_with(|| self.rng.fork(&stream.name));
        let request_id = decision_stream.draws();
        let value = decision_stream.next_u64();
        (request_id, value)
    }

    fn append_decision(&mut self, decision: Decision) {
        self.configuration = step(&self.configuration, decision);
    }
}

/// An error produced while recording an intended-randomness decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionRecordError {
    /// The requested app-random bit width is outside `1..=64`.
    InvalidAppRandomWidth {
        /// The invalid requested bit width.
        width: u8,
    },
}

impl fmt::Display for DecisionRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAppRandomWidth { width } => {
                write!(f, "app-random width {width} is outside 1..=64")
            }
        }
    }
}

impl Error for DecisionRecordError {}

fn mask_to_width(value: u64, width: u8) -> u64 {
    if width == 64 {
        value
    } else {
        value & ((1_u64 << width) - 1)
    }
}

fn hydrate_streams(
    rng: &DecisionRng,
    decisions: &[Decision],
) -> BTreeMap<RngStreamId, DecisionStream> {
    let mut streams = BTreeMap::new();

    for decision in decisions {
        if let Decision::RngDraw(RngDecision { stream, .. }) = decision {
            let decision_stream = streams
                .entry(stream.clone())
                .or_insert_with(|| rng.fork(&stream.name));
            let _ = decision_stream.next_u64();
        }
    }

    streams
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentHash, NodeId, ScenarioDef};

    #[test]
    fn decision_recorder_records_rng_draws_and_fault_outcomes() {
        assert_decision_rng_branch_coverage();
    }

    #[test]
    fn decision_recorder_keeps_per_entity_streams_stable() {
        assert_per_entity_rng_forking_coverage();
    }

    #[test]
    fn decision_recorder_does_not_perturb_streams_for_unrelated_world_edits() {
        let baseline_config = Configuration::genesis(scenario_from_world_material(
            "world.nodes=node-a\nworld.links=\nseed=7",
        ));
        let edited_config = Configuration::genesis(scenario_from_world_material(
            "world.nodes=node-a,node-z\nworld.links=\nseed=7",
        ));
        let seed = 0x0010_c001;
        let stable_stream = rng_stream("node-a/faults");
        let unrelated_stream = rng_stream("node-z/faults");

        assert_ne!(baseline_config.def, edited_config.def);

        let mut baseline = DecisionRecorder::new(baseline_config, seed);
        let mut edited = DecisionRecorder::new(edited_config, seed);

        let baseline_draw = baseline.draw_u64(stable_stream.clone());
        let _unrelated_draw = edited.draw_u64(unrelated_stream.clone());
        let edited_draw = edited.draw_u64(stable_stream.clone());

        assert_eq!(baseline_draw, edited_draw);
        assert!(matches!(
            baseline.schedule().decisions().first(),
            Some(Decision::RngDraw(RngDecision { stream, value }))
                if stream == &stable_stream && *value == baseline_draw
        ));
        assert!(matches!(
            edited.schedule().decisions().first(),
            Some(Decision::RngDraw(RngDecision { stream, .. })) if stream == &unrelated_stream
        ));
        assert!(matches!(
            edited.schedule().decisions().get(1),
            Some(Decision::RngDraw(RngDecision { stream, value }))
                if stream == &stable_stream && *value == edited_draw
        ));
    }

    #[test]
    fn decision_recorder_records_app_random_after_rng_draw() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let stream = rng_stream("node-a/app");
        let mut recorder = DecisionRecorder::new(config, 7);

        let value = match recorder.serve_app_random(node("node-a"), stream.clone(), 12) {
            Ok(value) => value,
            Err(error) => panic!("valid width should record app random: {error}"),
        };

        assert!(value < (1 << 12));
        assert_eq!(recorder.schedule().len(), 2);
        assert!(matches!(
            &recorder.schedule().decisions()[0],
            Decision::RngDraw(RngDecision { stream: recorded, .. }) if recorded == &stream
        ));
        assert!(matches!(
            &recorder.schedule().decisions()[1],
            Decision::AppRandom(AppRandomDecision {
                node: recorded_node,
                stream: recorded_stream,
                request_id: 0,
                width: 12,
                value: recorded_value,
            }) if recorded_node == &node("node-a")
                && recorded_stream == &stream
                && *recorded_value == value
        ));
    }

    #[test]
    fn decision_recorder_rejects_invalid_app_random_widths() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let mut recorder = DecisionRecorder::new(config, 7);

        assert_eq!(
            recorder.serve_app_random(node("node-a"), rng_stream("node-a/app"), 0),
            Err(DecisionRecordError::InvalidAppRandomWidth { width: 0 })
        );
        assert_eq!(
            recorder.serve_app_random(node("node-a"), rng_stream("node-a/app"), 65),
            Err(DecisionRecordError::InvalidAppRandomWidth { width: 65 })
        );
        assert!(recorder.schedule().is_empty());
    }

    #[test]
    fn decision_recorder_resumes_stream_positions_from_existing_schedule() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let seed = 0x0010_c001;
        let stream = rng_stream("node-a/app");
        let mut recorder = DecisionRecorder::new(config, seed);

        let first = recorder.draw_u64(stream.clone());
        let served = match recorder.serve_app_random(node("node-a"), stream.clone(), 8) {
            Ok(value) => value,
            Err(error) => panic!("valid app-random width should record: {error}"),
        };
        let mut resumed = DecisionRecorder::new(recorder.into_configuration(), seed);
        let resumed_draw = resumed.draw_u64(stream.clone());

        let mut expected_stream = crucible_sim::DecisionRng::new(seed).fork(&stream.name);
        let expected_first = expected_stream.next_u64();
        let expected_served_raw = expected_stream.next_u64();
        let expected_resumed = expected_stream.next_u64();

        assert_eq!(first, expected_first);
        assert_eq!(served, expected_served_raw & 0xff);
        assert_eq!(resumed_draw, expected_resumed);
        assert_eq!(resumed.schedule().len(), 4);
        assert!(matches!(
            resumed.schedule().decisions().last(),
            Some(Decision::RngDraw(RngDecision { stream: recorded, value }))
                if recorded == &stream && *value == expected_resumed
        ));
    }

    fn assert_decision_rng_branch_coverage() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let stream = rng_stream("node-a/faults");
        let fault = FaultId {
            name: String::from("loss"),
        };
        let mut recorder = DecisionRecorder::new(config, 0x0010_c001);

        let raw = recorder.draw_u64(stream.clone());
        let fired = recorder.decide_fault(
            VirtualTime { ticks: 4 },
            fault.clone(),
            stream.clone(),
            u64::MAX,
        );

        assert_eq!(recorder.schedule().len(), 3);
        assert!(fired);
        assert!(matches!(
            &recorder.schedule().decisions()[0],
            Decision::RngDraw(RngDecision { stream: recorded, value }) if recorded == &stream && *value == raw
        ));
        assert!(matches!(
            &recorder.schedule().decisions()[1],
            Decision::RngDraw(RngDecision { stream: recorded, value }) if recorded == &stream && *value != raw
        ));
        assert!(matches!(
            &recorder.schedule().decisions()[2],
            Decision::FaultFires(FaultDecision { at, fault: recorded, fired: true })
                if *at == (VirtualTime { ticks: 4 }) && recorded == &fault
        ));
    }

    fn assert_per_entity_rng_forking_coverage() {
        let first_config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let second_config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let mut before = DecisionRecorder::new(first_config, 0x0010_c001);
        let mut after = DecisionRecorder::new(second_config, 0x0010_c001);

        let node_a_before = before.draw_u64(rng_stream("node-a/faults"));
        let _node_b_before = before.draw_u64(rng_stream("node-b/faults"));
        let _node_b_after = after.draw_u64(rng_stream("node-b/faults"));
        let node_a_after = after.draw_u64(rng_stream("node-a/faults"));

        assert_eq!(node_a_before, node_a_after);
        assert_ne!(before.schedule(), after.schedule());
    }

    fn rng_stream(name: &str) -> RngStreamId {
        RngStreamId {
            name: name.to_owned(),
        }
    }

    fn scenario_from_world_material(material: &str) -> ScenarioDef {
        ScenarioDef::from_canonical_material("crucible.test.world", material)
    }

    fn node(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }
}
