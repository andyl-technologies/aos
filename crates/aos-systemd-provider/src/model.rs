//! Typed systemd realization, observation, and pinned-context values.

use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, ArtifactReference, InterfaceKey, LocalKey, ResourceReference,
};
use serde::{Deserialize, Serialize};

pub(crate) const PACKAGED_UNIT_EFFECTS_INTERFACE_NAME: &str = "aos.systemd.packaged-unit-effects";
pub(crate) const OBSERVATION_SCHEMA: &str = "aos.ability.systemd-packaged-unit-observation/v1";
pub(crate) const REALIZATION_SCHEMA: &str = "aos.systemd.packaged-unit-realization/v1";
pub(crate) const PROVIDER_CONTEXT_SCHEMA: &str = "aos.systemd.packaged-unit-context/v1";
pub(crate) const SERVICE_REALIZATION_SCHEMA: &str = "aos.systemd.service-realization/v1";
pub(crate) const SERVICE_EFFECTS_INTERFACE_NAME: &str = "aos.systemd.service-effects";
pub(crate) const MANAGER_WATCHDOG_EFFECTS_INTERFACE_NAME: &str =
    "aos.systemd.manager-watchdog-effects";
pub(crate) const MANAGER_WATCHDOG_REALIZATION_SCHEMA: &str =
    "aos.systemd.manager-watchdog-realization/v1";
pub(crate) const MANAGER_WATCHDOG_OBSERVATION_SCHEMA: &str =
    "aos.ability.systemd-manager-watchdog-observation/v1";
pub(crate) const MANAGER_WATCHDOG_CONTEXT_SCHEMA: &str = "aos.systemd.manager-watchdog-context/v1";
pub(crate) const STATIC_MANIFEST_SCHEMA: &str = "aos.systemd.static-unit-manifest/v1";

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
    pub(crate) prerequisites: Vec<ResourceReference>,
    pub(crate) dependencies: Dependencies,
    pub(crate) drop_in: DropIn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PackagedUnitEffectsRequest {
    PackagedUnit { desired: PackagedUnitRequest },
}

impl PackagedUnitEffectsRequest {
    pub(crate) const fn desired(&self) -> &PackagedUnitRequest {
        match self {
            Self::PackagedUnit { desired } => desired,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackagedUnitRealization {
    pub(crate) schema: String,
    pub(crate) source: RealizedUnitSource,
    pub(crate) systemd_unit: SystemdUnitIdentity,
    pub(crate) activation: Activation,
    pub(crate) drop_in: Vec<SystemdSection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdUnitIdentity {
    pub(crate) unit_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SemanticUnitText {
    pub(crate) template: String,
    pub(crate) substitutions: BTreeMap<LocalKey, SemanticSubstitution>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SemanticSubstitution {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) encoding: SemanticSubstitutionEncoding,
    pub(crate) source: SemanticSubstitutionSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SemanticSubstitutionEncoding {
    Escaped,
    Quoted,
    Raw,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SemanticSubstitutionSource {
    ArtifactPath {
        artifact: ArtifactReference,
        relative_path: String,
    },
    ExecutionPath {
        value: String,
    },
    GroupName {
        value: String,
    },
    PrincipalName {
        value: String,
    },
    RuntimeString {
        value: String,
    },
    SystemdUnitName {
        identity: ServiceUnitIdentity,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdDirective {
    pub(crate) name: String,
    pub(crate) value: SemanticUnitText,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) enum SystemdSectionName {
    Install,
    Service,
    Socket,
    Unit,
}

impl SystemdSectionName {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Install => "Install",
            Self::Service => "Service",
            Self::Socket => "Socket",
            Self::Unit => "Unit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdSection {
    pub(crate) name: SystemdSectionName,
    pub(crate) directives: Vec<SystemdDirective>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdUnitDocument {
    pub(crate) systemd_unit: SystemdUnitIdentity,
    pub(crate) sections: Vec<SystemdSection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceFacetIdentity {
    pub(crate) interface: InterfaceKey,
    pub(crate) facet: LocalKey,
    pub(crate) observation_schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ServiceUnitIdentity {
    Unit {
        unit_name: String,
    },
    TemplateInstance {
        template_unit_name: String,
        instance: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServiceLinkRelationship {
    Requires,
    Wants,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealizedServiceLink {
    pub(crate) parent: ServiceUnitIdentity,
    pub(crate) child: ServiceUnitIdentity,
    pub(crate) relationship: ServiceLinkRelationship,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealizedServiceAlias {
    pub(crate) alias: ServiceUnitIdentity,
    pub(crate) target: ServiceUnitIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceRealization {
    pub(crate) schema: String,
    pub(crate) systemd_unit: ServiceUnitIdentity,
    pub(crate) units: Vec<SystemdUnitDocument>,
    pub(crate) facets: Vec<ServiceFacetIdentity>,
    pub(crate) links: Vec<RealizedServiceLink>,
    pub(crate) prerequisites: Vec<ResourceReference>,
    pub(crate) aliases: Vec<RealizedServiceAlias>,
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ServiceEffectsRequest {
    Service { desired: AbilityValue },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagerWatchdogRequest {
    pub(crate) enabled: bool,
    pub(crate) runtime_timeout_millis: u64,
    pub(crate) reboot_timeout_millis: u64,
    pub(crate) kexec_timeout_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagerWatchdogRealization {
    pub(crate) schema: String,
    pub(crate) enabled: bool,
    pub(crate) runtime_timeout_millis: u64,
    pub(crate) reboot_timeout_millis: u64,
    pub(crate) kexec_timeout_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ManagerWatchdogEffectsRequest {
    ManagerWatchdog { desired: ManagerWatchdogRequest },
}

impl ManagerWatchdogEffectsRequest {
    pub(crate) const fn desired(&self) -> &ManagerWatchdogRequest {
        match self {
            Self::ManagerWatchdog { desired } => desired,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ManagerWatchdogState {
    Absent,
    Configured,
    Divergent,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagerWatchdogObservation {
    pub(crate) schema: String,
    pub(crate) expected: ManagerWatchdogRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<ManagerWatchdogRequest>,
    pub(crate) state: ManagerWatchdogState,
    pub(crate) manager_incarnation_changed: bool,
    pub(crate) discrepancies: Vec<LocalKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagerWatchdogContext {
    pub(crate) schema: String,
    pub(crate) manager_bus_id: String,
    pub(crate) manager_owner: String,
    pub(crate) materialization_owned: bool,
}

impl ServiceEffectsRequest {
    pub(crate) const fn desired(&self) -> &AbilityValue {
        match self {
            Self::Service { desired } => desired,
        }
    }
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
    pub(crate) unit_owned: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevisionReceipt<'a> {
    pub(crate) schema: &'static str,
    pub(crate) resource: &'a aos_ability_model::ResourceId,
    pub(crate) unit_name: &'a str,
    pub(crate) revision: aos_ability_model::RevisionId,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceRevisionReceipt<'a> {
    pub(crate) schema: &'static str,
    pub(crate) resource: &'a aos_ability_model::ResourceId,
    pub(crate) units: Vec<&'a str>,
    pub(crate) links: Vec<ServiceReceiptLink<'a>>,
    pub(crate) revision: aos_ability_model::RevisionId,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceReceiptLink<'a> {
    pub(crate) path: &'a str,
    pub(crate) target: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticUnitManifest {
    pub(crate) schema: String,
    pub(crate) primary: StaticPrimaryUnit,
    pub(crate) entries: Vec<StaticUnitManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticPrimaryUnit {
    pub(crate) unit_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) logical_instance: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum StaticUnitManifestEntry {
    File {
        path: String,
        content: aos_contract::Sha256Digest,
    },
    Symlink {
        path: String,
        target: String,
    },
}

pub(crate) fn empty_outputs()
-> BTreeMap<aos_ability_model::LocalKey, aos_ability_model::AbilityValue> {
    BTreeMap::new()
}
