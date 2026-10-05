//! Seeded decision recording for the engine schedule.
//!
//! This module is the engine-side bridge between the L0 deterministic decision
//! streams and the L3 [`Schedule`]. Intended randomness enters the engine only
//! by drawing from [`DecisionRng`] forks and appending the resulting
//! [`Decision`] values in scheduler order.

mod app_random_selectable;
mod network_fault_selectable;
mod reseed;
mod signal_fault_selectable;

#[cfg(test)]
macro_rules! accepted_step {
    ($configuration:expr, $decision:expr $(,)?) => {
        crate::try_step($configuration, $decision)
            .unwrap_or_else(|error| panic!("test configuration step should be accepted: {error}"))
    };
}

pub use app_random_selectable::{
    AppRandomSelectable, AppRandomSelectableError, app_random_stream_belongs_to_node,
    validate_app_random_model_selection,
};
pub(crate) use app_random_selectable::{
    is_app_random_model_selection, is_app_random_schedule_decision,
};
pub use network_fault_selectable::{
    NETWORK_FAULT_CAMPAIGN_ADAPTER, NetworkFaultCampaignBranch, NetworkFaultCampaignReplayPlan,
    NetworkFaultPhase, NetworkFaultSelectable, NetworkFaultSelectableError,
};
pub use signal_fault_selectable::{
    MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES, MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES,
    SIGNAL_FAULT_CAMPAIGN_ADAPTER, SignalFaultCampaignBranch, SignalFaultCampaignReplayPlan,
    SignalFaultSelectable, SignalFaultSelectableError,
};

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crucible_sim::{DecisionRng, DecisionStream};

use crate::{
    BackendRngEvidence, Configuration, Decision, EngineError, Icount, PreemptionDecision,
    PreemptionKind, RngDecision, RngStreamId, Schedule, SelectionDecision, TimeConversionError,
    VcpuId, try_step,
};

/// Records intended nondeterminism into a configuration's [`Schedule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecorder {
    configuration: Configuration,
    rng: DecisionRng,
    streams: BTreeMap<RngStreamId, DecisionStream>,
    app_random_draws: u64,
}

impl DecisionRecorder {
    /// Builds a recorder from the current configuration's scenario seed.
    ///
    /// Existing [`Decision::RngDraw`] entries in the schedule advance the
    /// corresponding stream positions so resumed recording does not repeat
    /// prior draws.
    #[must_use]
    pub fn new(configuration: Configuration) -> Self {
        let rng = configuration.def.seed().decision_rng();
        let streams = hydrate_streams(&rng, configuration.schedule.decisions());
        let app_random_draws = reseed::count_app_random_draws(configuration.schedule.decisions());
        Self {
            configuration,
            rng,
            streams,
            app_random_draws,
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
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError`] when the resulting schedule violates the
    /// scenario's app-random draw limit.
    pub fn draw_u64(&mut self, stream: RngStreamId) -> Result<u64, DecisionRecordError> {
        let value = self.draw_stream_value(&stream).1;
        self.append_decision(Decision::RngDraw(RngDecision { stream, value }))?;
        Ok(value)
    }

    /// Admits one backend RNG observation as a typed campaign selection.
    ///
    /// The recorder derives the raw model draw from the exact named stream,
    /// requires it to reproduce the guest-served value, then appends one
    /// [`Decision::RngDraw`] followed by one [`Decision::Selection`]. The
    /// returned discovery contains the exact declaration, domain, and
    /// opportunity needed by the observation-candidate handoff.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError`] when the request is malformed, exceeds
    /// the scenario cap, or differs from the scenario-seeded model sample. No
    /// recorder state changes on error.
    pub fn admit_backend_rng_evidence(
        &mut self,
        decision: BackendRngEvidence,
    ) -> Result<crucible_campaign::ChoiceDiscovery, DecisionRecordError> {
        let selectable = AppRandomSelectable::from_decision(&self.configuration.def, &decision)?;
        self.ensure_app_random_draw_available()?;

        let mut advanced_stream =
            self.streams
                .get(&decision.stream)
                .cloned()
                .unwrap_or_else(|| {
                    self.rng
                        .fork_in_domain(&decision.stream.domain, &decision.stream.name)
                });
        let raw_value = advanced_stream.next_u64();
        let selection = selectable.normalize_sample(&decision, raw_value)?;
        let discovery = selectable.into_discovery()?;

        self.app_random_draws += 1;
        self.streams
            .insert(decision.stream.clone(), advanced_stream);
        self.append_decision(Decision::RngDraw(RngDecision {
            stream: decision.stream,
            value: raw_value,
        }))?;
        self.append_decision(Decision::Selection(SelectionDecision::new(&selection)))?;
        Ok(discovery)
    }

    /// Applies one authenticated campaign selection to an observed live request.
    ///
    /// The recorder advances the same named RNG stream and retains its full raw
    /// draw, constructs the exact branch parent after that draw, validates the
    /// supplied selection against the reconstructed opportunity and parent, and
    /// requires the plugin-served value to equal the selected value. No state
    /// changes if any check fails.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError`] when the request is malformed, the draw
    /// cap is exhausted, the selection does not bind the live opportunity and
    /// exact parent, or the plugin served another value.
    pub fn apply_app_random_selection(
        &mut self,
        decision: BackendRngEvidence,
        selection: &crucible_campaign::Selection,
    ) -> Result<crucible_campaign::ChoiceDiscovery, DecisionRecordError> {
        let selectable = AppRandomSelectable::from_decision(&self.configuration.def, &decision)?;
        self.ensure_app_random_draw_available()?;

        let mut advanced_stream =
            self.streams
                .get(&decision.stream)
                .cloned()
                .unwrap_or_else(|| {
                    self.rng
                        .fork_in_domain(&decision.stream.domain, &decision.stream.name)
                });
        let raw_value = advanced_stream.next_u64();
        let parent = try_step(
            &self.configuration,
            Decision::RngDraw(RngDecision {
                stream: decision.stream.clone(),
                value: raw_value,
            }),
        )?;
        let selected = selectable.apply_selection(selection, &parent)?;
        if selected != decision {
            return Err(AppRandomSelectableError::AppliedDecisionMismatch.into());
        }
        let discovery = selectable.into_discovery()?;

        self.app_random_draws += 1;
        self.streams
            .insert(decision.stream.clone(), advanced_stream);
        self.configuration = parent;
        self.append_decision(Decision::Selection(SelectionDecision::new(selection)))?;
        Ok(discovery)
    }

    /// Computes the exact branch parent for one observed live random request.
    ///
    /// The returned identity includes the full seeded raw draw that must precede
    /// a campaign selection. This operation does not mutate the recorder, so a
    /// scheduler can locate an installed selection before committing either the
    /// draw or the selection.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError`] when the request is malformed or the
    /// scenario app-random draw cap has already been reached.
    pub fn app_random_selection_parent(
        &self,
        decision: &BackendRngEvidence,
    ) -> Result<crate::ContentHash, DecisionRecordError> {
        AppRandomSelectable::from_decision(&self.configuration.def, decision)?;
        self.ensure_app_random_draw_available()?;

        let mut advanced_stream =
            self.streams
                .get(&decision.stream)
                .cloned()
                .unwrap_or_else(|| {
                    self.rng
                        .fork_in_domain(&decision.stream.domain, &decision.stream.name)
                });
        let raw_value = advanced_stream.next_u64();
        Ok(try_step(
            &self.configuration,
            Decision::RngDraw(RngDecision {
                stream: decision.stream.clone(),
                value: raw_value,
            }),
        )?
        .id())
    }

    /// Derives the default round-robin vCPU switch without recording it.
    ///
    /// Default preemptions are audit-only: they are deterministic from the node
    /// identity, current instruction count, fixed RR quantum, and vCPU count,
    /// so they do not consume a schedule entry.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionRecordError::InvalidRoundRobinQuantum`] when
    /// `rr_switch_quantum` is zero, [`DecisionRecordError::InvalidVcpuCount`]
    /// when `vcpu_count` is zero, or
    /// [`DecisionRecordError::InvalidRoundRobinBoundary`] when `at` is not a
    /// nonzero RR switch boundary.
    pub fn default_rr_preemption(
        &self,
        node: crate::NodeId,
        at: Icount,
        rr_switch_quantum: u64,
        vcpu_count: u32,
    ) -> Result<PreemptionDecision, DecisionRecordError> {
        if rr_switch_quantum == 0 {
            return Err(DecisionRecordError::InvalidRoundRobinQuantum);
        }
        if vcpu_count == 0 {
            return Err(DecisionRecordError::InvalidVcpuCount);
        }
        if at.retired == 0 || !at.retired.is_multiple_of(rr_switch_quantum) {
            return Err(DecisionRecordError::InvalidRoundRobinBoundary {
                at,
                rr_switch_quantum,
            });
        }

        let switch_index = at.retired / rr_switch_quantum;
        let to_vcpu = (switch_index % u64::from(vcpu_count)) as u32;
        let from_vcpu = if to_vcpu == 0 {
            vcpu_count - 1
        } else {
            to_vcpu - 1
        };

        let at = at
            .initial_virtual_time()
            .map_err(|source| DecisionRecordError::PreemptionTimeOverflow { source })?;
        Ok(PreemptionDecision {
            node,
            at,
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: from_vcpu },
                to_vcpu: VcpuId { index: to_vcpu },
            },
        })
    }

    fn draw_stream_value(&mut self, stream: &RngStreamId) -> (u64, u64) {
        let decision_stream = self
            .streams
            .entry(stream.clone())
            .or_insert_with(|| self.rng.fork_in_domain(&stream.domain, &stream.name));
        let request_id = decision_stream.draws();
        let value = decision_stream.next_u64();
        (request_id, value)
    }

    fn append_decision(&mut self, decision: Decision) -> Result<(), DecisionRecordError> {
        self.configuration = try_step(&self.configuration, decision)?;
        Ok(())
    }

    fn ensure_app_random_draw_available(&self) -> Result<(), DecisionRecordError> {
        let cap = self.configuration.def.app_random_draw_cap();
        if self.app_random_draws >= cap {
            return Err(DecisionRecordError::AppRandomDrawCapExceeded {
                cap,
                attempted: self.app_random_draws.saturating_add(1),
            });
        }
        Ok(())
    }
}

/// An error produced while recording an intended-randomness decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionRecordError {
    /// The resulting configuration violated a model invariant.
    Engine {
        /// Exact model validation failure.
        source: EngineError,
    },
    /// Typed app-random choice construction or validation failed.
    InvalidAppRandomSelection {
        /// Exact producer-contract failure.
        source: AppRandomSelectableError,
    },
    /// The scenario app-random draw cap has been reached.
    AppRandomDrawCapExceeded {
        /// The configured per-scenario draw cap.
        cap: u64,
        /// The one-based draw ordinal that would exceed `cap`.
        attempted: u64,
    },
    /// The configured round-robin switch quantum is zero.
    InvalidRoundRobinQuantum,
    /// The configured vCPU count is zero.
    InvalidVcpuCount,
    /// The requested instruction count is not a nonzero RR switch boundary.
    InvalidRoundRobinBoundary {
        /// The requested preemption instruction count.
        at: Icount,
        /// The configured round-robin switch quantum.
        rr_switch_quantum: u64,
    },
    /// The authored raw RR boundary cannot fit the exact tick timeline.
    PreemptionTimeOverflow {
        /// Checked retirement-to-time conversion failure.
        source: TimeConversionError,
    },
}

impl fmt::Display for DecisionRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine { source } => write!(f, "configuration step rejected: {source}"),
            Self::InvalidAppRandomSelection { source } => {
                write!(f, "invalid typed app-random selection: {source}")
            }
            Self::AppRandomDrawCapExceeded { cap, attempted } => {
                write!(f, "app-random draw {attempted} exceeds scenario cap {cap}")
            }
            Self::InvalidRoundRobinQuantum => {
                write!(f, "round-robin switch quantum must be nonzero")
            }
            Self::InvalidVcpuCount => write!(f, "vCPU count must be nonzero"),
            Self::InvalidRoundRobinBoundary {
                at,
                rr_switch_quantum,
            } => write!(
                f,
                "instruction count {} is not a nonzero round-robin switch boundary for quantum {}",
                at.retired, rr_switch_quantum
            ),
            Self::PreemptionTimeOverflow { source } => {
                write!(f, "preemption time conversion failed: {source}")
            }
        }
    }
}

impl Error for DecisionRecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine { source } => Some(source),
            Self::InvalidAppRandomSelection { source } => Some(source),
            Self::PreemptionTimeOverflow { source } => Some(source),
            _ => None,
        }
    }
}

impl From<EngineError> for DecisionRecordError {
    fn from(source: EngineError) -> Self {
        match source {
            EngineError::AppRandomDrawCapExceeded { cap, actual, .. } => {
                Self::AppRandomDrawCapExceeded {
                    cap,
                    attempted: actual,
                }
            }
            source => Self::Engine { source },
        }
    }
}

impl From<AppRandomSelectableError> for DecisionRecordError {
    fn from(source: AppRandomSelectableError) -> Self {
        Self::InvalidAppRandomSelection { source }
    }
}

#[cfg(test)]
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
                .or_insert_with(|| rng.fork_in_domain(&stream.domain, &stream.name));
            let _ = decision_stream.next_u64();
        }
    }

    streams
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    trait DecisionRecorderTestExt {
        fn draw_u64_accepted(&mut self, stream: RngStreamId) -> u64;
    }

    impl DecisionRecorderTestExt for DecisionRecorder {
        fn draw_u64_accepted(&mut self, stream: RngStreamId) -> u64 {
            self.draw_u64(stream)
                .unwrap_or_else(|error| panic!("test RNG draw should be accepted: {error}"))
        }
    }

    use crate::{
        EngineError, NodeId, Plan, Properties, ScenarioDef, ScenarioDefForm, Schedule, Seed, World,
        reduce, try_step,
    };

    #[test]
    fn decision_recorder_records_rng_draws() {
        assert_decision_rng_branch_coverage();
    }

    fn assert_decision_rng_branch_coverage() {
        let config = Configuration::genesis(scenario_from_seed(Seed::from_u64(0xdec1_5100)));
        let stream = rng_stream("node-a/fault-signal");
        let mut recorder = DecisionRecorder::new(config);
        let raw = recorder.draw_u64_accepted(stream.clone());
        assert!(matches!(
            recorder.schedule().decisions(),
            [Decision::RngDraw(RngDecision { stream: recorded, value })]
                if recorded == &stream && *value == raw
        ));
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
        let stable_stream = rng_stream("node-a/faults");
        let unrelated_stream = rng_stream("node-z/faults");

        assert_ne!(baseline_config.def, edited_config.def);

        let mut baseline = DecisionRecorder::new(baseline_config);
        let mut edited = DecisionRecorder::new(edited_config);

        let baseline_draw = baseline.draw_u64_accepted(stable_stream.clone());
        let _unrelated_draw = edited.draw_u64_accepted(unrelated_stream.clone());
        let edited_draw = edited.draw_u64_accepted(stable_stream.clone());

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
    fn decision_recorder_domain_separates_same_name_node_and_link_streams() {
        let config = Configuration::genesis(scenario_from_world_material(
            "world.nodes=shared\nworld.links=shared\nseed=domain",
        ));
        let node_stream = RngStreamId::for_node("shared");
        let link_stream = RngStreamId::for_link("shared");
        let mut recorder = DecisionRecorder::new(config);

        let node_draw = recorder.draw_u64_accepted(node_stream.clone());
        let link_draw = recorder.draw_u64_accepted(link_stream.clone());

        assert_ne!(node_stream.domain, link_stream.domain);
        assert_ne!(node_draw, link_draw);
        assert_eq!(recorder.schedule().len(), 2);
        assert!(matches!(
            &recorder.schedule().decisions()[0],
            Decision::RngDraw(RngDecision { stream, value })
                if stream == &node_stream && *value == node_draw
        ));
        assert!(matches!(
            &recorder.schedule().decisions()[1],
            Decision::RngDraw(RngDecision { stream, value })
                if stream == &link_stream && *value == link_draw
        ));
    }

    #[test]
    fn decision_recorder_admits_backend_rng_evidence_as_a_typed_selection() {
        let config = Configuration::genesis(default_scenario());
        let stream = rng_stream("node-a/typed-app-random");
        let mut expected_stream = config
            .def
            .seed()
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let raw_draw = expected_stream.next_u64();
        let expected_value = mask_to_width(raw_draw, 16);
        let observed = BackendRngEvidence {
            node: node("node-a"),
            stream: stream.clone(),
            request_id: 0xfeed,
            width: 16,
            value: expected_value,
        };
        let mut recorder = DecisionRecorder::new(config);
        let before = recorder.clone();
        let mismatch = BackendRngEvidence {
            value: expected_value ^ 1,
            ..observed.clone()
        };
        assert!(matches!(
            recorder.admit_backend_rng_evidence(mismatch),
            Err(DecisionRecordError::InvalidAppRandomSelection {
                source: AppRandomSelectableError::SampleMismatch { .. }
            })
        ));
        assert_eq!(recorder, before);

        let discovery = recorder
            .admit_backend_rng_evidence(observed)
            .expect("seeded live request should normalize");
        assert_eq!(recorder.schedule().len(), 2);
        assert!(matches!(
            &recorder.schedule().decisions()[0],
            Decision::RngDraw(RngDecision { stream: recorded, value })
                if recorded == &stream && *value == raw_draw
        ));
        let Decision::Selection(decision) = &recorder.schedule().decisions()[1] else {
            panic!("live app randomness should record a typed selection")
        };
        assert!(decision.is_app_random_model_sample());
        let selection = decision.selection().expect("canonical selection");
        assert_eq!(
            selection.opportunity(),
            discovery
                .opportunity()
                .id()
                .expect("discovered opportunity id")
        );
        validate_app_random_model_selection(
            &selection,
            discovery.declaration(),
            discovery.opportunity(),
            discovery.domain(),
        )
        .expect("normalized choice should verify independently");

        let round_tripped = Schedule::from_compact_binary(&recorder.schedule().to_compact_binary())
            .expect("typed app-random schedule should round trip");
        assert!(matches!(
            &round_tripped.decisions()[1],
            Decision::Selection(selection) if selection.is_app_random_model_sample()
        ));
    }

    #[test]
    fn decision_recorder_applies_campaign_branch_only_at_the_exact_live_parent() {
        let config = Configuration::genesis(default_scenario());
        let stream = rng_stream("app-random/node:6:node-a/stream:6:branch");
        let mut expected_stream = config
            .def
            .seed()
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let raw_draw = expected_stream.next_u64();
        let selected_value = mask_to_width(raw_draw, 16) ^ 1;
        let observed = BackendRngEvidence {
            node: node("node-a"),
            stream: stream.clone(),
            request_id: 17,
            width: 16,
            value: selected_value,
        };
        let parent = accepted_step!(
            &config,
            Decision::RngDraw(RngDecision {
                stream: stream.clone(),
                value: raw_draw,
            }),
        );
        let selectable = AppRandomSelectable::from_decision(&config.def, &observed)
            .expect("live request should reconstruct");
        let selection = selectable
            .branch_selection(&parent, selected_value)
            .expect("exact parent should admit a branch");

        let mut recorder = DecisionRecorder::new(config.clone());
        assert_eq!(
            recorder
                .app_random_selection_parent(&observed)
                .expect("live parent should derive"),
            parent.id()
        );
        recorder
            .apply_app_random_selection(observed.clone(), &selection)
            .expect("plugin-served branch value should validate");
        assert_eq!(
            recorder.configuration().id(),
            accepted_step!(
                &parent,
                Decision::Selection(SelectionDecision::new(&selection))
            )
            .id()
        );

        let mut wrong_parent_recorder = DecisionRecorder::new(accepted_step!(
            &config,
            Decision::RngDraw(RngDecision {
                stream: rng_stream("unrelated"),
                value: 9,
            }),
        ));
        let before = wrong_parent_recorder.clone();
        assert!(
            wrong_parent_recorder
                .apply_app_random_selection(observed, &selection)
                .is_err()
        );
        assert_eq!(wrong_parent_recorder, before);
    }

    #[test]
    fn typed_app_random_selection_counts_against_cap_after_resume() {
        let seed = Seed::from_u64(0x0010_c020);
        let config = Configuration::genesis(scenario_from_seed_and_app_random_draw_cap(seed, 1));
        let stream = rng_stream("node-a/typed-app-random-cap");
        let mut expected_stream = seed
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let raw_draw = expected_stream.next_u64();
        let observed = BackendRngEvidence {
            node: node("node-a"),
            stream: stream.clone(),
            request_id: 1,
            width: 8,
            value: mask_to_width(raw_draw, 8),
        };
        let mut recorder = DecisionRecorder::new(config.clone());
        recorder
            .admit_backend_rng_evidence(observed.clone())
            .expect("first typed app-random selection should fit the cap");
        let recorded = recorder.into_configuration();
        let typed_selection = recorded.schedule.decisions()[1].clone();

        assert!(reduce(&recorded.def, &recorded.schedule).is_ok());
        assert_eq!(
            try_step(&recorded, typed_selection),
            Err(EngineError::AppRandomDrawCapExceeded {
                scenario: config.def.id(),
                cap: 1,
                actual: 2,
            })
        );

        let mut resumed = DecisionRecorder::new(recorded);
        assert_eq!(
            resumed.admit_backend_rng_evidence(BackendRngEvidence {
                request_id: 2,
                ..observed
            }),
            Err(DecisionRecordError::AppRandomDrawCapExceeded {
                cap: 1,
                attempted: 2,
            })
        );
        assert_eq!(resumed.schedule().len(), 2);
    }

    #[test]
    fn app_random_draw_cap_is_scenario_hash_material() {
        let seed = Seed::from_u64(0x0010_c01a);
        let loose = scenario_from_seed_and_app_random_draw_cap(seed, 2);
        let tight = scenario_from_seed_and_app_random_draw_cap(seed, 1);
        let default = scenario_from_seed(seed);

        assert_ne!(loose.id(), tight.id());
        assert_ne!(default.id(), tight.id());
        assert_eq!(loose.app_random_draw_cap(), 2);
        assert_eq!(tight.app_random_draw_cap(), 1);
        assert_eq!(
            default.app_random_draw_cap(),
            crate::DEFAULT_APP_RANDOM_DRAW_CAP
        );
    }

    #[test]
    fn app_random_draw_cap_round_trips_through_scenario_form_serialization() {
        let world = World::from_nodes(Vec::new()).expect("empty world should build");
        let form = ScenarioDefForm::from_components_with_app_random_draw_cap(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(0x0010_c01b),
            3,
        )
        .expect("scenario form with app-random cap should build");
        let toml = form
            .to_canonical_toml()
            .expect("scenario form TOML should serialize");
        let from_toml =
            ScenarioDefForm::from_canonical_toml(&toml).expect("scenario form TOML should parse");
        let from_binary = ScenarioDefForm::from_compact_binary(&form.to_compact_binary())
            .expect("scenario form binary should parse");

        assert!(toml.contains("app_random_draw_cap = 3"));
        assert_eq!(from_toml.id(), form.id());
        assert_eq!(from_toml.app_random_draw_cap(), 3);
        assert_eq!(from_binary.id(), form.id());
        assert_eq!(from_binary.app_random_draw_cap(), 3);

        let unbounded = ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(0x0010_c01d),
        )
        .expect("default app-random cap scenario form should build");
        let unbounded_toml = unbounded
            .to_canonical_toml()
            .expect("default app-random cap scenario form TOML should serialize");
        let unbounded_from_toml = ScenarioDefForm::from_canonical_toml(&unbounded_toml)
            .expect("default app-random cap scenario form TOML should parse");
        assert!(unbounded_toml.contains(&format!(
            "app_random_draw_cap = \"u64:{}\"",
            crate::DEFAULT_APP_RANDOM_DRAW_CAP
        )));
        assert_eq!(unbounded_from_toml.id(), unbounded.id());
        assert_eq!(
            unbounded_from_toml.app_random_draw_cap(),
            crate::DEFAULT_APP_RANDOM_DRAW_CAP
        );
    }

    #[test]
    fn decision_recorder_resumes_stream_positions_from_existing_schedule() {
        let seed = Seed::from_u64(0x0010_c001);
        let config = Configuration::genesis(scenario_from_seed(seed));
        let stream = rng_stream("node-a/app");
        let mut recorder = DecisionRecorder::new(config);

        let first = recorder.draw_u64_accepted(stream.clone());
        let second = recorder.draw_u64_accepted(stream.clone());
        let mut resumed = DecisionRecorder::new(recorder.into_configuration());
        let resumed_draw = resumed.draw_u64_accepted(stream.clone());

        let mut expected_stream = seed
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);
        let expected_first = expected_stream.next_u64();
        let expected_second = expected_stream.next_u64();
        let expected_resumed = expected_stream.next_u64();

        assert_eq!(first, expected_first);
        assert_eq!(second, expected_second);
        assert_eq!(resumed_draw, expected_resumed);
        assert_eq!(resumed.schedule().len(), 3);
        assert!(matches!(
            resumed.schedule().decisions().last(),
            Some(Decision::RngDraw(RngDecision { stream: recorded, value }))
                if recorded == &stream && *value == expected_resumed
        ));
    }

    #[test]
    fn decision_recorder_derives_default_rr_preemption_without_recording_schedule() {
        let config = Configuration::genesis(scenario_from_world_material(
            "world.nodes=node-a\nseed=preemption",
        ));
        let first = DecisionRecorder::new(config.clone());
        let second = DecisionRecorder::new(config);

        let first_switch =
            match first.default_rr_preemption(node("node-a"), Icount { retired: 4096 }, 4096, 4) {
                Ok(decision) => decision,
                Err(error) => panic!("valid default RR switch should be derived: {error}"),
            };
        let second_switch =
            match second.default_rr_preemption(node("node-a"), Icount { retired: 4096 }, 4096, 4) {
                Ok(decision) => decision,
                Err(error) => panic!("valid default RR switch should be derived: {error}"),
            };

        assert_eq!(first_switch, second_switch);
        assert_eq!(first.schedule().len(), 0);
        assert_eq!(second.schedule().len(), 0);
        assert!(matches!(
            first_switch,
            PreemptionDecision {
                at: crate::SimInstant { ticks: 204_800 },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
                ..
            }
        ));
    }

    #[test]
    fn decision_recorder_rejects_invalid_default_preemption_shape() {
        let config = Configuration::genesis(default_scenario());
        let recorder = DecisionRecorder::new(config);

        assert_eq!(
            recorder.default_rr_preemption(node("node-a"), Icount { retired: 1 }, 0, 1),
            Err(DecisionRecordError::InvalidRoundRobinQuantum)
        );
        assert_eq!(
            recorder.default_rr_preemption(node("node-a"), Icount { retired: 1 }, 4096, 0),
            Err(DecisionRecordError::InvalidVcpuCount)
        );
        assert_eq!(
            recorder.default_rr_preemption(node("node-a"), Icount { retired: 0 }, 4096, 4),
            Err(DecisionRecordError::InvalidRoundRobinBoundary {
                at: Icount { retired: 0 },
                rr_switch_quantum: 4096,
            })
        );
        assert_eq!(
            recorder.default_rr_preemption(node("node-a"), Icount { retired: 4095 }, 4096, 4),
            Err(DecisionRecordError::InvalidRoundRobinBoundary {
                at: Icount { retired: 4095 },
                rr_switch_quantum: 4096,
            })
        );
        assert!(recorder.schedule().is_empty());
    }

    #[test]
    fn decision_recorder_rejects_default_rr_preemption_time_overflow() {
        let config = Configuration::genesis(default_scenario());
        let recorder = DecisionRecorder::new(config);

        assert!(matches!(
            recorder.default_rr_preemption(node("node-a"), Icount { retired: u64::MAX }, 1, 4),
            Err(DecisionRecordError::PreemptionTimeOverflow { .. })
        ));
        assert!(recorder.schedule().is_empty());
    }

    fn assert_per_entity_rng_forking_coverage() {
        let first_config = Configuration::genesis(default_scenario());
        let second_config = Configuration::genesis(default_scenario());
        let mut before = DecisionRecorder::new(first_config);
        let mut after = DecisionRecorder::new(second_config);

        let node_a_before = before.draw_u64_accepted(rng_stream("node-a/faults"));
        let _node_b_before = before.draw_u64_accepted(rng_stream("node-b/faults"));
        let _node_b_after = after.draw_u64_accepted(rng_stream("node-b/faults"));
        let node_a_after = after.draw_u64_accepted(rng_stream("node-a/faults"));

        assert_eq!(node_a_before, node_a_after);
        assert_ne!(before.schedule(), after.schedule());
    }

    fn rng_stream(name: &str) -> RngStreamId {
        RngStreamId::for_node(name)
    }

    fn scenario_from_world_material(material: &str) -> ScenarioDef {
        ScenarioDef::from_canonical_material("crucible.test.world", material)
    }

    fn default_scenario() -> ScenarioDef {
        scenario_from_seed(Seed::default())
    }

    fn scenario_from_seed(seed: Seed) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.decision",
            "scenario=stub",
            seed,
        )
    }

    fn scenario_from_seed_and_app_random_draw_cap(seed: Seed, cap: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed_and_app_random_draw_cap(
            "crucible.test.decision",
            "scenario=stub",
            seed,
            cap,
        )
    }

    fn node(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }
}
