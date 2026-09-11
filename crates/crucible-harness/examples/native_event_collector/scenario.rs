//! Scenario declaration extraction without executing the scenario model.

use serde::Serialize;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub(super) struct PrerequisiteReport {
    pub(super) status: &'static str,
    pub(super) source: Option<String>,
    pub(super) source_binding: &'static str,
    pub(super) evaluation: &'static str,
    pub(super) pass_events: Vec<PassPrerequisite>,
    pub(super) guest_marker_assertions: Vec<GuestMarkerAssertion>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct PassPrerequisite {
    pub(super) event: String,
    pub(super) trigger: toml::Value,
    pub(super) assertion_state_requirements: Vec<AssertionStateRequirement>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct AssertionStateRequirement {
    pub(super) assertion: String,
    pub(super) required_state: String,
    pub(super) canonical_material_matches: u64,
    #[serde(skip)]
    query: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct GuestMarkerAssertion {
    pub(super) assertion: String,
    pub(super) marker: String,
    pub(super) property: toml::Value,
    pub(super) canonical_material_matches: u64,
    #[serde(skip)]
    query: usize,
}

#[derive(Clone, Debug)]
pub(super) struct EvidenceQuery {
    event_kind: &'static str,
    lines: Vec<String>,
}

impl EvidenceQuery {
    pub(super) fn matches(&self, event_kind: &str, material: &str) -> bool {
        if event_kind != self.event_kind {
            return false;
        }
        self.lines
            .iter()
            .all(|expected| material.lines().any(|line| line == expected))
    }
}

#[derive(Clone, Debug)]
pub(super) struct ScenarioDeclarations {
    source: String,
    pass_events: Vec<PassPrerequisite>,
    guest_marker_assertions: Vec<GuestMarkerAssertion>,
    queries: Vec<EvidenceQuery>,
}

impl ScenarioDeclarations {
    pub(super) fn load(path: &Path, maximum_bytes: u64) -> Result<Self, String> {
        let bytes = super::read_bounded_file(path, maximum_bytes, "scenario source")?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("scenario source {} is not UTF-8", path.display()))?;
        let document = text
            .parse::<toml::Value>()
            .map_err(|error| format!("decode scenario source {}: {error}", path.display()))?;
        let pass_values = document
            .get("plan")
            .and_then(|plan| plan.get("event"))
            .and_then(toml::Value::as_array)
            .ok_or_else(|| String::from("scenario source has no plan.event array"))?;

        let mut queries = Vec::new();
        let mut pass_events = Vec::new();
        for event in pass_values {
            let action_kind = event
                .get("action")
                .and_then(|action| action.get("kind"))
                .and_then(toml::Value::as_str);
            if action_kind != Some("pass") {
                continue;
            }
            let id = required_string(event, "id", "pass event")?;
            let trigger = event
                .get("trigger")
                .cloned()
                .ok_or_else(|| format!("pass event `{id}` has no trigger"))?;
            let mut assertion_state_requirements = Vec::new();
            collect_assertion_states(&trigger, &mut assertion_state_requirements, &mut queries)?;
            pass_events.push(PassPrerequisite {
                event: id,
                trigger,
                assertion_state_requirements,
            });
        }

        let assertions = document
            .get("properties")
            .and_then(|properties| properties.get("assertion"))
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut guest_marker_assertions = Vec::new();
        for assertion in assertions {
            let id = required_string(assertion, "id", "assertion")?;
            let Some(property) = assertion.get("property") else {
                return Err(format!("assertion `{id}` has no property"));
            };
            collect_guest_markers(
                property,
                &id,
                property,
                &mut guest_marker_assertions,
                &mut queries,
            );
        }

        Ok(Self {
            source: path.display().to_string(),
            pass_events,
            guest_marker_assertions,
            queries,
        })
    }

    pub(super) fn evidence_queries(&self) -> &[EvidenceQuery] {
        &self.queries
    }

    pub(super) fn finish(mut self, evidence: &[u64]) -> Result<PrerequisiteReport, String> {
        for event in &mut self.pass_events {
            for requirement in &mut event.assertion_state_requirements {
                requirement.canonical_material_matches =
                    evidence
                        .get(requirement.query)
                        .copied()
                        .ok_or_else(|| String::from("missing assertion-state evidence counter"))?;
            }
        }
        for assertion in &mut self.guest_marker_assertions {
            assertion.canonical_material_matches = evidence
                .get(assertion.query)
                .copied()
                .ok_or_else(|| String::from("missing guest-marker evidence counter"))?;
        }
        Ok(PrerequisiteReport {
            status: "declarations_decoded",
            source: Some(self.source),
            source_binding: "unverified",
            evaluation: "not_semantically_evaluated",
            pass_events: self.pass_events,
            guest_marker_assertions: self.guest_marker_assertions,
        })
    }
}

pub(super) fn unavailable() -> PrerequisiteReport {
    PrerequisiteReport {
        status: "scenario_source_not_supplied",
        source: None,
        source_binding: "unavailable",
        evaluation: "not_evaluated",
        pass_events: Vec::new(),
        guest_marker_assertions: Vec::new(),
    }
}

fn collect_assertion_states(
    value: &toml::Value,
    output: &mut Vec<AssertionStateRequirement>,
    queries: &mut Vec<EvidenceQuery>,
) -> Result<(), String> {
    if value.get("kind").and_then(toml::Value::as_str) == Some("assertion_state") {
        let assertion = required_string(value, "name", "assertion-state trigger")?;
        let required_state = required_string(value, "state", "assertion-state trigger")?;
        let query = queries.len();
        queries.push(EvidenceQuery {
            event_kind: "assertion_state_changed",
            lines: vec![
                format!("event_payload.attribute.id.value.value={assertion}"),
                format!(
                    "event_payload.attribute.new_state.value.value={}",
                    debug_variant(&required_state)
                ),
            ],
        });
        output.push(AssertionStateRequirement {
            assertion,
            required_state,
            canonical_material_matches: 0,
            query,
        });
    }
    match value {
        toml::Value::Array(values) => {
            for value in values {
                collect_assertion_states(value, output, queries)?;
            }
        }
        toml::Value::Table(values) => {
            for value in values.values() {
                collect_assertion_states(value, output, queries)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_guest_markers(
    value: &toml::Value,
    assertion: &str,
    property: &toml::Value,
    output: &mut Vec<GuestMarkerAssertion>,
    queries: &mut Vec<EvidenceQuery>,
) {
    if value.get("kind").and_then(toml::Value::as_str) == Some("guest_marker")
        && let Some(marker) = value.get("marker").and_then(toml::Value::as_str)
    {
        let query = queries.len();
        queries.push(EvidenceQuery {
            event_kind: "guest_marker",
            lines: vec![
                String::from("event_payload.attribute.marker_kind.value.value=event"),
                format!("event_payload.attribute.marker.value.value={marker}"),
            ],
        });
        output.push(GuestMarkerAssertion {
            assertion: assertion.to_owned(),
            marker: marker.to_owned(),
            property: property.clone(),
            canonical_material_matches: 0,
            query,
        });
    }
    match value {
        toml::Value::Array(values) => {
            for value in values {
                collect_guest_markers(value, assertion, property, output, queries);
            }
        }
        toml::Value::Table(values) => {
            for value in values.values() {
                collect_guest_markers(value, assertion, property, output, queries);
            }
        }
        _ => {}
    }
}

fn required_string(value: &toml::Value, key: &str, role: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{role} has no string `{key}`"))
}

fn debug_variant(value: &str) -> String {
    value
        .split(['_', '-'])
        .filter(|component| !component.is_empty())
        .map(|component| {
            let mut characters = component.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(characters).collect()
            })
        })
        .collect()
}
