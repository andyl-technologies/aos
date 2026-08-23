//! Application-randomness normalization through the typed choice model.
//!
//! One guest random request is represented by an unsigned integer domain, a
//! reusable declaration, a stable runtime opportunity, and a selection. The
//! seeded RNG's full `u64` draw remains the model-sample evidence; the selected
//! value is its low `width` bits. Campaign branches may replace that value at
//! the same exact opportunity without advancing the underlying RNG stream.

use std::collections::BTreeSet;

use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceRngStreamId, ChoiceSource, ChoiceValue, ConfigurationId, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, ModelSampleEvidence, ModelSampleVerifier,
    ProbabilityModelId, ScenarioDefId, SelectableDeclaration, Selection, SelectionOrigin,
};
use crucible_protocol::WHITEBOX_DOORBELL_PROTOCOL_VERSION;
use thiserror::Error;

use crate::{AppRandomDecision, Configuration, NodeId, RngStreamId, ScenarioDef};

const APP_RANDOM_DOMAIN_SEMANTIC_VERSION: u32 = 1;
const MAX_APP_RANDOM_COMPONENT_BYTES: usize = 512;

/// One fully reconstructed application-random selectable occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomSelectable {
    node: NodeId,
    stream: RngStreamId,
    request_id: u64,
    width: u8,
    model: AppRandomUniformModel,
    declaration: SelectableDeclaration,
    domain: ChoiceDomain,
    opportunity: crucible_campaign::ChoiceOpportunity,
}

impl AppRandomSelectable {
    /// Builds the typed selectable for one exact guest random request.
    ///
    /// The identity depends only on stable semantic coordinates. Inserting an
    /// unrelated choice or drawing another named RNG stream does not renumber
    /// this request or perturb its model-sampling stream.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomSelectableError`] when the width or string components
    /// are outside the campaign profile, or canonical choice construction
    /// fails.
    pub fn new(
        scenario: &ScenarioDef,
        node: NodeId,
        stream: RngStreamId,
        request_id: u64,
        width: u8,
    ) -> Result<Self, AppRandomSelectableError> {
        validate_width(width)?;
        validate_component("node", &node.name)?;
        validate_component("stream domain", &stream.domain)?;
        validate_component("stream name", &stream.name)?;

        let scenario = campaign_scenario_id(scenario);
        let model = AppRandomUniformModel::new(&stream, width);
        let domain = app_random_domain(width)?;
        let declaration = app_random_declaration(&node, width, model.stream())?;
        let opportunity = app_random_opportunity(
            scenario,
            &node,
            request_id,
            width,
            &declaration,
            &domain,
            model,
        )?;

        Ok(Self {
            node,
            stream,
            request_id,
            width,
            model,
            declaration,
            domain,
            opportunity,
        })
    }

    /// Reconstructs the selectable named by an existing app-random decision.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomSelectableError`] when the decision has an invalid
    /// width/value pair or its producer components exceed campaign bounds.
    pub fn from_decision(
        scenario: &ScenarioDef,
        decision: &AppRandomDecision,
    ) -> Result<Self, AppRandomSelectableError> {
        validate_width(decision.width)?;
        if mask_to_width(decision.value, decision.width) != decision.value {
            return Err(AppRandomSelectableError::ValueOutsideWidth {
                width: decision.width,
                value: decision.value,
            });
        }
        Self::new(
            scenario,
            decision.node.clone(),
            decision.stream.clone(),
            decision.request_id,
            decision.width,
        )
    }

    /// Returns the reusable selectable declaration.
    #[must_use]
    pub const fn declaration(&self) -> &SelectableDeclaration {
        &self.declaration
    }

    /// Returns the exact unsigned integer domain.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    /// Returns the stable runtime opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &crucible_campaign::ChoiceOpportunity {
        &self.opportunity
    }

    /// Returns the uniform probability-model identity.
    #[must_use]
    pub const fn model_id(&self) -> ProbabilityModelId {
        self.model.id()
    }

    /// Returns the keyed choice-RNG stream identity.
    #[must_use]
    pub const fn choice_stream_id(&self) -> ChoiceRngStreamId {
        self.model.stream()
    }

    /// Converts one seeded raw draw into a model-sampled selection.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomSelectableError`] if canonical selection construction
    /// fails.
    pub fn sampled_selection(&self, raw_draw: u64) -> Result<Selection, AppRandomSelectableError> {
        let evidence = ModelSampleEvidence::new(self.model.id(), self.model.stream(), raw_draw);
        let value =
            ChoiceValue::Integer(IntegerValue::Unsigned(mask_to_width(raw_draw, self.width)));
        Ok(Selection::new_model_sample(
            &self.opportunity,
            &self.domain,
            value,
            evidence,
            &self.model,
        )?)
    }

    /// Normalizes an observed seeded decision and proves its exact draw.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomSelectableError::DecisionSiteMismatch`] when the
    /// decision names another request, or
    /// [`AppRandomSelectableError::SampleMismatch`] when `raw_draw` does not
    /// reproduce its served value.
    pub fn normalize_sample(
        &self,
        decision: &AppRandomDecision,
        raw_draw: u64,
    ) -> Result<Selection, AppRandomSelectableError> {
        if decision.node != self.node
            || decision.stream != self.stream
            || decision.request_id != self.request_id
            || decision.width != self.width
        {
            return Err(AppRandomSelectableError::DecisionSiteMismatch);
        }
        let expected = mask_to_width(raw_draw, self.width);
        if decision.value != expected {
            return Err(AppRandomSelectableError::SampleMismatch {
                expected,
                actual: decision.value,
            });
        }
        self.sampled_selection(raw_draw)
    }

    /// Validates and applies a selection at its exact parent configuration.
    ///
    /// Model samples reproduce the low-bit mapping. Campaign branches must bind
    /// the exact semantic branch point beneath `parent`. Default and locked
    /// replay origins undergo their corresponding base replay checks.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomSelectableError`] when the selection, parent scenario,
    /// provenance, domain, or selected value disagrees with this request.
    pub fn apply_selection(
        &self,
        selection: &Selection,
        parent: &Configuration,
    ) -> Result<AppRandomDecision, AppRandomSelectableError> {
        if campaign_scenario_id(&parent.def) != self.opportunity.scenario() {
            return Err(AppRandomSelectableError::ParentScenarioMismatch);
        }
        match selection.origin() {
            SelectionOrigin::ModelSample(_) => {
                selection.validate_model_replay(&self.opportunity, &self.domain, &self.model)?
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent =
                    ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
                selection.validate_branch_replay(
                    &self.opportunity,
                    &self.domain,
                    self.opportunity.branch_point_id(parent),
                )?;
            }
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(&self.opportunity, &self.domain)?;
            }
        }
        let ChoiceValue::Integer(IntegerValue::Unsigned(value)) = selection.value() else {
            return Err(AppRandomSelectableError::NonUnsignedValue);
        };
        Ok(AppRandomDecision {
            node: self.node.clone(),
            stream: self.stream.clone(),
            request_id: self.request_id,
            width: self.width,
            value: *value,
        })
    }
}

/// Validates one resolved model-sampled selection as app randomness.
///
/// This is the pre-execution verifier used when a configuration artifact
/// contains a model-sampled selection. It reconstructs the complete standardized
/// declaration and opportunity contract from authenticated record fields before
/// accepting the draw-to-value mapping.
///
/// # Errors
///
/// Returns [`AppRandomSelectableError`] when the origin is not a model sample,
/// the records do not form the standard app-random contract, or the draw does
/// not reproduce the selected value.
pub fn validate_app_random_model_selection(
    selection: &Selection,
    declaration: &SelectableDeclaration,
    opportunity: &crucible_campaign::ChoiceOpportunity,
    domain: &ChoiceDomain,
) -> Result<(), AppRandomSelectableError> {
    let SelectionOrigin::ModelSample(evidence) = selection.origin() else {
        return Err(AppRandomSelectableError::NotModelSample);
    };
    let width = app_random_width(domain)?;
    let ChoiceSource::Guest {
        node,
        protocol_version,
    } = opportunity.source()
    else {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    };
    if *protocol_version != u32::from(WHITEBOX_DOORBELL_PROTOCOL_VERSION) {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    let request_id = parse_request_instance(opportunity.instance())?;
    let model = AppRandomUniformModel::from_ids(evidence.model(), evidence.stream(), width);
    if model.id() != expected_model_id(width) {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    let node = NodeId { name: node.clone() };
    let expected_declaration = app_random_declaration(&node, width, model.stream())?;
    if declaration != &expected_declaration {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    let expected_opportunity = app_random_opportunity(
        opportunity.scenario(),
        &node,
        request_id,
        width,
        declaration,
        domain,
        model,
    )?;
    if opportunity != &expected_opportunity {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    selection.validate_model_replay(opportunity, domain, &model)?;
    Ok(())
}

/// Failure while constructing, validating, or applying app randomness.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomSelectableError {
    /// The requested bit width is outside `1..=64`.
    #[error("app-random selectable width {width} is outside 1..=64")]
    InvalidWidth {
        /// Invalid bit width.
        width: u8,
    },
    /// A stable producer component is empty or exceeds the campaign bound.
    #[error("app-random selectable {component} is empty or exceeds 512 bytes")]
    InvalidComponent {
        /// Stable component class.
        component: &'static str,
    },
    /// A recorded value does not fit its declared bit width.
    #[error("app-random value {value} does not fit width {width}")]
    ValueOutsideWidth {
        /// Declared bit width.
        width: u8,
        /// Invalid value.
        value: u64,
    },
    /// The observed decision names another dynamic request.
    #[error("app-random decision does not name this selectable occurrence")]
    DecisionSiteMismatch,
    /// The seeded draw does not reproduce the observed served value.
    #[error("app-random seeded draw produced {expected}, not recorded value {actual}")]
    SampleMismatch {
        /// Value derived from the exact draw.
        expected: u64,
        /// Recorded served value.
        actual: u64,
    },
    /// The selection is not model-sampled.
    #[error("app-random model validation requires a model-sampled selection")]
    NotModelSample,
    /// The declaration/opportunity is not the standardized app-random contract.
    #[error("choice records do not form the standardized app-random producer contract")]
    ProducerContractMismatch,
    /// The opportunity instance is not a canonical request identifier.
    #[error("app-random opportunity instance is not a canonical request identifier")]
    InvalidRequestInstance,
    /// The selected value is not an unsigned integer.
    #[error("app-random selection value is not an unsigned integer")]
    NonUnsignedValue,
    /// The supplied parent belongs to another scenario.
    #[error("app-random selection parent belongs to another scenario")]
    ParentScenarioMismatch,
    /// Canonical campaign choice construction or validation failed.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AppRandomUniformModel {
    id: ProbabilityModelId,
    stream: ChoiceRngStreamId,
    width: u8,
}

impl AppRandomUniformModel {
    fn new(stream: &RngStreamId, width: u8) -> Self {
        Self::from_ids(expected_model_id(width), choice_stream_id(stream), width)
    }

    const fn from_ids(id: ProbabilityModelId, stream: ChoiceRngStreamId, width: u8) -> Self {
        Self { id, stream, width }
    }

    const fn id(self) -> ProbabilityModelId {
        self.id
    }

    const fn stream(self) -> ChoiceRngStreamId {
        self.stream
    }
}

impl ModelSampleVerifier for AppRandomUniformModel {
    fn verifies(&self, evidence: ModelSampleEvidence, value: &ChoiceValue) -> bool {
        evidence.model() == self.id
            && evidence.stream() == self.stream
            && matches!(
                value,
                ChoiceValue::Integer(IntegerValue::Unsigned(selected))
                    if *selected == mask_to_width(evidence.draw(), self.width)
            )
    }
}

fn app_random_domain(width: u8) -> Result<ChoiceDomain, CampaignCodecError> {
    let maximum = mask_to_width(u64::MAX, width);
    Ok(ChoiceDomain::Integer(IntegerDomain::new(
        APP_RANDOM_DOMAIN_SEMANTIC_VERSION,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(maximum),
        1,
        None,
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?))
}

fn app_random_width(domain: &ChoiceDomain) -> Result<u8, AppRandomSelectableError> {
    let ChoiceDomain::Integer(integer) = domain else {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    };
    let IntegerValue::Unsigned(maximum) = integer.maximum() else {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    };
    let width = if maximum == u64::MAX {
        64
    } else {
        let cardinality = maximum.saturating_add(1);
        if !cardinality.is_power_of_two() {
            return Err(AppRandomSelectableError::ProducerContractMismatch);
        }
        cardinality.trailing_zeros() as u8
    };
    if width == 0 {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    if domain != &app_random_domain(width)? {
        return Err(AppRandomSelectableError::ProducerContractMismatch);
    }
    Ok(width)
}

fn app_random_declaration(
    node: &NodeId,
    width: u8,
    stream: ChoiceRngStreamId,
) -> Result<SelectableDeclaration, CampaignCodecError> {
    let stream_tag = format!("stream-{}", stream.to_hex());
    let class_context =
        ChoiceClassContext::new(BTreeSet::from([String::from("app-random"), stream_tag]))?;
    SelectableDeclaration::new(
        format!("app-random-u{width}"),
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(WHITEBOX_DOORBELL_PROTOCOL_VERSION),
        },
        app_random_domain(width)?,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        class_context,
        BTreeSet::from([
            String::from("app-random"),
            String::from("uniform-unsigned"),
            format!("width-{width}"),
        ]),
        false,
    )
}

fn app_random_opportunity(
    scenario: ScenarioDefId,
    node: &NodeId,
    request_id: u64,
    width: u8,
    declaration: &SelectableDeclaration,
    domain: &ChoiceDomain,
    model: AppRandomUniformModel,
) -> Result<crucible_campaign::ChoiceOpportunity, CampaignCodecError> {
    let scheduler = derive_node_coordinate(scenario, &node.name);
    let producer = derive_producer_coordinate(model.stream(), width);
    crucible_campaign::ChoiceOpportunity::new(
        scenario,
        declaration,
        domain,
        ChoiceCoordinate {
            scheduler,
            producer,
        },
        format!("request-{request_id:016x}"),
        Some(model.id()),
    )
}

fn choice_stream_id(stream: &RngStreamId) -> ChoiceRngStreamId {
    let mut material = Vec::with_capacity(16 + stream.domain.len() + stream.name.len());
    append_string(&mut material, &stream.domain);
    append_string(&mut material, &stream.name);
    ChoiceRngStreamId::from_hash(CampaignHash::derive(
        "crucible.app-random.choice-rng-stream.v1",
        &material,
    ))
}

fn expected_model_id(width: u8) -> ProbabilityModelId {
    ProbabilityModelId::from_hash(CampaignHash::derive(
        "crucible.app-random.uniform-model.v1",
        &[width],
    ))
}

fn derive_node_coordinate(scenario: ScenarioDefId, node: &str) -> CampaignHash {
    let mut material = Vec::with_capacity(40 + node.len());
    material.extend_from_slice(&scenario.as_hash().as_bytes());
    append_string(&mut material, node);
    CampaignHash::derive("crucible.app-random.scheduler-coordinate.v1", &material)
}

fn derive_producer_coordinate(stream: ChoiceRngStreamId, width: u8) -> CampaignHash {
    let mut material = Vec::with_capacity(33);
    material.extend_from_slice(&stream.as_hash().as_bytes());
    material.push(width);
    CampaignHash::derive("crucible.app-random.producer-coordinate.v1", &material)
}

fn append_string(material: &mut Vec<u8>, value: &str) {
    material.extend_from_slice(&(value.len() as u64).to_be_bytes());
    material.extend_from_slice(value.as_bytes());
}

fn campaign_scenario_id(scenario: &ScenarioDef) -> ScenarioDefId {
    ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes))
}

fn parse_request_instance(instance: &str) -> Result<u64, AppRandomSelectableError> {
    let Some(value) = instance.strip_prefix("request-") else {
        return Err(AppRandomSelectableError::InvalidRequestInstance);
    };
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppRandomSelectableError::InvalidRequestInstance);
    }
    let request_id = u64::from_str_radix(value, 16)
        .map_err(|_| AppRandomSelectableError::InvalidRequestInstance)?;
    if format!("{request_id:016x}") != value {
        return Err(AppRandomSelectableError::InvalidRequestInstance);
    }
    Ok(request_id)
}

fn validate_width(width: u8) -> Result<(), AppRandomSelectableError> {
    if (1..=64).contains(&width) {
        Ok(())
    } else {
        Err(AppRandomSelectableError::InvalidWidth { width })
    }
}

fn validate_component(
    component: &'static str,
    value: &str,
) -> Result<(), AppRandomSelectableError> {
    if value.is_empty() || value.len() > MAX_APP_RANDOM_COMPONENT_BYTES {
        Err(AppRandomSelectableError::InvalidComponent { component })
    } else {
        Ok(())
    }
}

const fn mask_to_width(value: u64, width: u8) -> u64 {
    if width == 64 {
        value
    } else {
        value & ((1_u64 << width) - 1)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn scenario(name: &str) -> ScenarioDef {
        ScenarioDef::from_canonical_material("crucible.test.app-random-selectable", name)
    }

    fn selectable_fixture(stream_name: &str) -> AppRandomSelectable {
        AppRandomSelectable::new(
            &scenario("scenario"),
            NodeId {
                name: String::from("node-a"),
            },
            RngStreamId::for_node(stream_name),
            7,
            16,
        )
        .expect("app-random selectable should build")
    }

    #[test]
    fn seeded_sample_round_trips_through_typed_selection() {
        let subject = selectable_fixture("guest/backoff");
        let raw_draw = 0xfedc_ba98_7654_3210;
        let observed = AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::for_node("guest/backoff"),
            request_id: 7,
            width: 16,
            value: 0x3210,
        };
        let selection = subject
            .normalize_sample(&observed, raw_draw)
            .expect("matching seeded observation should normalize");
        assert_eq!(
            subject.model_id().to_hex(),
            "8b567a53b3111d422a1cecd8779ea87d3c204d910e35a45d4d8db9be68c75ed3"
        );
        assert_eq!(
            subject.choice_stream_id().to_hex(),
            "97e52d8203353f0457e09988abc3e1df70328e74eab2262a89d08e2a75e0f9bd"
        );
        assert_eq!(
            subject.declaration().semantic_id().to_hex(),
            "ca8667efe6b0485cab013a87d3e926c6d86db9f8b5165c4df504d1f59af1d7ec"
        );
        assert_eq!(
            subject.opportunity().semantic_id().to_hex(),
            "4005afdd76b2c6be0e82216b5b6d6e76950d2df015f254ed0f31e2d8fa17e79e"
        );

        validate_app_random_model_selection(
            &selection,
            subject.declaration(),
            subject.opportunity(),
            subject.domain(),
        )
        .expect("resolved app-random model sample should validate");
        let parent = Configuration::genesis(scenario("scenario"));
        assert_eq!(
            subject
                .apply_selection(&selection, &parent)
                .expect("model selection should apply"),
            observed
        );
    }

    #[test]
    fn campaign_branch_applies_at_exact_parent_only() {
        let subject = selectable_fixture("guest/backoff");
        let parent = Configuration::genesis(scenario("scenario"));
        let branch_point = subject
            .opportunity()
            .branch_point_id(ConfigurationId::from_hash(CampaignHash::from_bytes(
                parent.id().bytes,
            )));
        let selection = Selection::new_campaign_branch(
            subject.opportunity(),
            subject.domain(),
            ChoiceValue::Integer(IntegerValue::Unsigned(9)),
            branch_point,
        )
        .expect("branch selection should build");

        assert_eq!(
            subject
                .apply_selection(&selection, &parent)
                .expect("exact branch point should apply")
                .value,
            9
        );
        let foreign = Configuration::genesis(scenario("foreign"));
        assert!(matches!(
            subject.apply_selection(&selection, &foreign),
            Err(AppRandomSelectableError::ParentScenarioMismatch)
        ));
    }

    #[test]
    fn stable_stream_identity_is_insertion_independent() {
        let first = selectable_fixture("guest/backoff");
        let unrelated = selectable_fixture("guest/unrelated");
        let rebuilt = selectable_fixture("guest/backoff");

        assert_eq!(first, rebuilt);
        assert_ne!(first.choice_stream_id(), unrelated.choice_stream_id());
        assert_ne!(first.opportunity(), unrelated.opportunity());
    }

    #[test]
    fn invalid_or_forged_samples_fail_closed() {
        assert!(matches!(
            AppRandomSelectable::new(
                &scenario("scenario"),
                NodeId {
                    name: String::from("node-a"),
                },
                RngStreamId::for_node("guest/backoff"),
                0,
                0,
            ),
            Err(AppRandomSelectableError::InvalidWidth { width: 0 })
        ));

        let subject = selectable_fixture("guest/backoff");
        let mismatched = AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::for_node("guest/backoff"),
            request_id: 7,
            width: 16,
            value: 1,
        };
        assert!(matches!(
            subject.normalize_sample(&mismatched, 2),
            Err(AppRandomSelectableError::SampleMismatch {
                expected: 2,
                actual: 1
            })
        ));

        let other = selectable_fixture("guest/other");
        let selection = other
            .sampled_selection(3)
            .expect("other stream sample should build");
        assert!(
            validate_app_random_model_selection(
                &selection,
                subject.declaration(),
                subject.opportunity(),
                subject.domain(),
            )
            .is_err()
        );

        let zero_width_domain = ChoiceDomain::Integer(
            IntegerDomain::new(
                APP_RANDOM_DOMAIN_SEMANTIC_VERSION,
                IntegerRepresentation::Unsigned64,
                IntegerValue::Unsigned(0),
                IntegerValue::Unsigned(0),
                1,
                None,
                ExactRational::new(1, 1).expect("unit scale"),
                Vec::new(),
            )
            .expect("singleton integer domain is generally valid"),
        );
        assert!(matches!(
            app_random_width(&zero_width_domain),
            Err(AppRandomSelectableError::ProducerContractMismatch)
        ));
    }
}
