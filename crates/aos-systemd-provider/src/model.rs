//! Typed systemd packaged-unit realization and observation values.

use std::collections::BTreeMap;

use aos_ability_model::{ArtifactReference, ResourceReference};
use serde::{Deserialize, Serialize};

pub(crate) const INTERFACE_NAME: &str = "aos.systemd.packaged-unit";
pub(crate) const OBSERVATION_SCHEMA: &str = "aos.ability.systemd-packaged-unit-observation/v1";
pub(crate) const REALIZATION_SCHEMA: &str = "aos.systemd.packaged-unit-realization/v1";
pub(crate) const PROVIDER_CONTEXT_SCHEMA: &str = "aos.systemd.packaged-unit-context/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Activation {
    Enabled,
    Reference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnitSource {
    pub(crate) artifact: ArtifactReference,
    pub(crate) unit_file: String,
    pub(crate) unit_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealizedUnitSource {
    pub(crate) artifact: ArtifactReference,
    pub(crate) unit_file: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependencies {
    pub(crate) after: Vec<ResourceReference>,
    pub(crate) before: Vec<ResourceReference>,
    pub(crate) requires: Vec<ResourceReference>,
    pub(crate) wants: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DropIn {
    pub(crate) accepted_exit_statuses: Vec<i64>,
    pub(crate) reload_triggers: Vec<String>,
    pub(crate) search_path: Vec<ArtifactReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackagedUnitRequest {
    pub(crate) source: UnitSource,
    pub(crate) activation: Activation,
    pub(crate) dependencies: Dependencies,
    pub(crate) drop_in: DropIn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackagedUnitRealization {
    pub(crate) schema: String,
    pub(crate) source: RealizedUnitSource,
    pub(crate) systemd_unit: SystemdUnitIdentity,
    pub(crate) activation: Activation,
    pub(crate) drop_in_text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdUnitIdentity {
    pub(crate) unit_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnitState {
    Absent,
    Active,
    Failed,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackagedUnitObservation {
    pub(crate) schema: String,
    pub(crate) expected: PackagedUnitRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<PackagedUnitRequest>,
    pub(crate) unit_name: String,
    pub(crate) state: UnitState,
    pub(crate) discrepancies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderContext {
    pub(crate) schema: String,
    pub(crate) manager_bus_id: String,
    pub(crate) manager_owner: String,
    pub(crate) unit_identity: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevisionReceipt<'a> {
    pub(crate) schema: &'static str,
    pub(crate) resource: &'a aos_ability_model::ResourceId,
    pub(crate) unit_name: &'a str,
    pub(crate) revision: aos_ability_model::RevisionId,
}

pub(crate) fn empty_outputs()
-> BTreeMap<aos_ability_model::LocalKey, aos_ability_model::AbilityValue> {
    BTreeMap::new()
}
