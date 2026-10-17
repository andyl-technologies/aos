//! Defines the source-installed closed Clock metadata interpretation and codec.
//!
//! The fixed label adds no timers, ports, state, callbacks or execution methods.
//! Its declaration, handler manifest and preservation policy are regenerated
//! locally. The handler manifest binds the measured host executable as a build
//! identity; that executable remains an independently authenticated immutable
//! graph input, rather than a provider-issued qualification label.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crucible::node_admission::*;
use crucible::node_state::{NativeExtensionPreservationPolicy, StateError};
use crucible_node_contract::*;

use super::{fail, state_error};

const IDENTIFIER: &str = "crucible.installed-clock/metadata-label";
const SPECIFICATION: &[u8] = b"crucible Clock metadata label v1: exactly one owned host integer Clock; label is fixed immutable display metadata. No ports, alarms, ingress, callbacks, pending events, new state domains or altered execution/timing/error semantics. Exact native state remains the existing host/native-continuation-v1 envelope and integer cursor. Durable preservation retains complete original world/application/handler/contracts and bound executable identity. Unknown bodies, parameters, handlers, topology or state effects refuse before native allocation. Original scopes never rebase to fresh activation identities.";
const PARAMETERS: &str = "owned integer clock";

pub(in crate::node_observed_executor::factory) struct ClockLabelPolicy {
    pub(super) selection: ExtensionSelection,
    pub(super) declaration: ExtensionDeclaration,
    pub(super) semantics: ExtensionSemanticContract,
    pub(super) handler: ContentRef,
    pub(super) preservation: ContentRef,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(in crate::node_observed_executor::factory) base: crate::node_scenario::NodeScenario,
    pub(in crate::node_observed_executor::factory) labeled: crate::node_scenario::NodeScenario,
    host: ContentRef,
}

impl ClockLabelPolicy {
    pub(super) fn new(
        mut scenario: crate::node_scenario::NodeScenario,
        host: &ContentRef,
    ) -> Result<Rc<Self>, super::NodeObservedError> {
        if scenario.descriptors.len() != 1
            || scenario.compatibility.len() != 1
            || !scenario.world.connections.is_empty()
            || !scenario.world.extensions.is_empty()
            || scenario.compatibility[0]
                .implementation
                .implementation_id
                .as_str()
                != "crucible-host-clock"
            || !scenario.descriptors[0].ports.is_empty()
        {
            return Err(super::observed_refusal(
                "label requires one installed closed host Clock",
            ));
        }
        let base = scenario.clone();
        let mut objects = BTreeMap::new();
        let semantic = put(&mut objects, SPECIFICATION.to_vec(), "text/plain")?;
        let schema_definition = put(&mut objects, br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"label":{"const":"owned integer clock"}},"required":["label"],"additionalProperties":false}"#.to_vec(), "application/json")?;
        let handler = put_json(
            &mut objects,
            &serde_json::json!({
                "schema_version":1,"implementation":"crucible.installed-clock.metadata-handler.v1",
                "host_build":host.hash,"behavior":"fixed checked metadata; no native effects",
            }),
        )?;
        let preservation = put_json(
            &mut objects,
            &serde_json::json!({
                "schema_version":1,"implementation":"crucible.installed-clock.metadata-preservation.v1",
                "host_build":host.hash,"native_codec":"host/native-continuation-v1",
                "native_profile":"host/exact-v1","original_scope":"immutable durable world",
                "state_effects":"none","time_effects":"none","unknown_dependencies":"refuse",
            }),
        )?;
        let declaration = ExtensionDeclaration {
            schema_version: 1,
            identifier: Id::new(IDENTIFIER)?,
            owner: ExtensionNamespaceOwner {
                authority: Id::new("crucible/source-installed-clock")?,
                publication_origin: semantic.clone(),
            },
            semantic_version: SemanticVersion {
                major: 1.into(),
                minor: 0.into(),
                patch: 0.into(),
                prerelease: None,
                build: None,
            },
            schema: SchemaRef {
                id: Id::new("crucible.installed-clock/label-parameters")?,
                version: 1,
                definition: schema_definition.clone(),
                extensions: Default::default(),
            },
            schema_digest: schema_definition.hash,
            specification: semantic.clone(),
            dependencies: vec![],
            required_features: vec![],
            applicability: vec![ExtensionApplicability {
                location: ExtensionLocation::WorldBinding,
                operation_kinds: vec![],
                direction: None,
                roles: vec![],
                modes: vec![],
                facets: vec![],
                ports: vec![],
                lanes: vec![],
            }],
            timing_effects: semantic.clone(),
            state_effects: semantic.clone(),
            error_behavior: semantic.clone(),
            limits: ExtensionLimits {
                maximum_message_bytes: 4096.into(),
                maximum_objects: 1.into(),
                maximum_allocation_bytes: 4096.into(),
                maximum_pending_events: 0.into(),
                maximum_operations: 0.into(),
            },
            conformance: semantic.clone(),
        };
        let selection = ExtensionSelection {
            declaration: put_json(&mut objects, &declaration)?,
            identifier: declaration.identifier.clone(),
            semantic_version: declaration.semantic_version.clone(),
            schema_digest: declaration.schema_digest.clone(),
        };
        let semantics = ExtensionSemanticContract {
            class_contract: semantic.clone(),
            facet_contract: semantic.clone(),
            mode_contract: semantic.clone(),
            port_contract: semantic.clone(),
            timing_contract: semantic.clone(),
            state_contract: semantic.clone(),
            error_contract: semantic.clone(),
            qualification_contract: semantic,
            locations: BTreeSet::from([ExtensionRecordKind::WorldBinding]),
            roles: BTreeSet::new(),
            facets: BTreeSet::new(),
            modes: vec![],
            interfaces: BTreeSet::new(),
            impact: ExtensionImpact::Metadata,
        };
        scenario.world.extensions.insert(
            IDENTIFIER.into(),
            serde_json::to_value(ExtensionUse {
                selection: selection.clone(),
                parameters: serde_json::json!({"label":PARAMETERS}),
            })?,
        );
        scenario.world.scenario_ref = put_json(
            &mut objects,
            &serde_json::json!({
                "format":"crucible.installed-clock-label-world","version":1,
                "base_scenario":base.world.scenario_ref,"extension":selection,
            }),
        )?;
        for (reference, bytes) in &objects {
            scenario
                .content
                .push(crate::node_scenario::ScenarioContent {
                    reference: reference.clone(),
                    bytes: bytes.clone(),
                });
        }
        scenario.content.sort_by(|a, b| {
            (&a.reference.hash.domain, &a.reference.hash.digest)
                .cmp(&(&b.reference.hash.domain, &b.reference.hash.digest))
        });
        Ok(Rc::new(Self {
            selection,
            declaration,
            semantics,
            handler,
            preservation,
            objects,
            base,
            labeled: scenario,
            host: host.clone(),
        }))
    }

    pub(in crate::node_observed_executor::factory) fn registry(
        self: &Rc<Self>,
    ) -> Result<InstalledExtensionRegistry, super::NodeObservedError> {
        InstalledExtensionRegistry::install(
            vec![ExtensionRegistration {
                selection: self.selection.clone(),
                handler: self.clone(),
                qualification: self.clone(),
            }],
            self.as_ref(),
            ExtensionRegistryLimits::default(),
        )
        .map_err(super::observed_refusal)
    }

    pub(super) fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        if graph.world() != &self.labeled.world
            || graph.node_ids().count() != 1
            || graph.selected_extensions().applications().len() != 1
            || graph.selected_extensions().definitions().len() != 1
            || !graph.coordinator_policy().external_inputs.is_empty()
            || !graph.coordinator_policy().same_time_closure.is_empty()
            || !graph.ownership_policy().internal_dependencies.is_empty()
        {
            return Err(state_error("installed labeled Clock graph differs"));
        }
        let expected = &self.labeled.descriptors[0];
        if graph.descriptor(&expected.id) != Some(expected)
            || graph
                .binding(&expected.id)
                .is_none_or(|binding| binding.compatibility != self.labeled.compatibility[0])
        {
            return Err(state_error(
                "installed labeled Clock native identity differs",
            ));
        }
        let application = graph
            .selected_extensions()
            .applications()
            .next()
            .ok_or_else(|| state_error("Clock label application absent"))?;
        if application.scope().record_kind() != ExtensionRecordKind::WorldBinding
            || application.scope().record_path() != &ExtensionRecordPath::World
            || application.scope().world_hash() != graph.world_binding_hash()
            || application.handler_identity() != &self.handler
            || application.semantic_contract() != &self.semantics
            || application.selected()
                != &(ExtensionUse {
                    selection: self.selection.clone(),
                    parameters: serde_json::json!({"label":PARAMETERS}),
                })
            || application.scope().record_hash()
                != &canonical::json_hash("cnp.extension-application-record.v1", graph.world())
                    .map_err(state_error)?
        {
            return Err(state_error(
                "Clock label original scope or frozen semantics differs",
            ));
        }
        Ok(())
    }

    fn check_application(
        &self,
        application: &ExtensionApplication<'_>,
        selected: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        if application.world() != &self.labeled.world
            || application.descriptors() != self.labeled.descriptors
            || application.bindings().len() != 1
            || application.bindings()[0].compatibility != self.labeled.compatibility[0]
            || application.scope().record_kind() != ExtensionRecordKind::WorldBinding
            || application.scope().record_path() != &ExtensionRecordPath::World
            || selected.selection != self.selection
            || selected.parameters != serde_json::json!({"label":PARAMETERS})
        {
            return Err(fail(
                "label is outside its source-installed native Clock context",
            ));
        }
        super::measure_current_host(&self.host).map_err(|error| fail(error.to_string()))
    }

    pub(super) fn selected_dependencies(
        &self,
        graph: &AdmittedGraph,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<Vec<ContentRef>, StateError> {
        self.check_graph(graph)?;
        if let Some(original) = self.objects.get(reference) {
            if original != bytes {
                return Err(state_error("installed label body changed"));
            }
            if reference == &self.selection.declaration {
                let d = &self.declaration;
                return Ok(sorted(vec![
                    d.owner.publication_origin.clone(),
                    d.schema.definition.clone(),
                    d.specification.clone(),
                    d.timing_effects.clone(),
                    d.state_effects.clone(),
                    d.error_behavior.clone(),
                    d.conformance.clone(),
                ]));
            }
            if reference == &self.labeled.world.scenario_ref {
                return Err(state_error("scenario body is not a selected codec leaf"));
            }
            return Ok(vec![]);
        }
        for application in graph.selected_extensions().applications() {
            let raw =
                canonical::canonical_json(&serde_json::to_value(application).map_err(state_error)?)
                    .map_err(state_error)?;
            if reference
                == &canonical::content_ref(&raw, "application/json").map_err(state_error)?
            {
                if raw != bytes {
                    return Err(state_error("original label application body changed"));
                }
                return Ok(sorted(vec![
                    self.selection.declaration.clone(),
                    self.handler.clone(),
                    self.semantics.state_contract.clone(),
                ]));
            }
        }
        for definition in graph.selected_extensions().definitions() {
            let raw =
                canonical::canonical_json(&serde_json::to_value(definition).map_err(state_error)?)
                    .map_err(state_error)?;
            if reference
                == &canonical::content_ref(&raw, "application/json").map_err(state_error)?
            {
                if raw != bytes
                    || definition.selection() != &self.selection
                    || definition.handler_identity() != &self.handler
                    || definition.semantic_contract() != &self.semantics
                {
                    return Err(state_error("original label definition body changed"));
                }
                return Ok(sorted(vec![
                    self.selection.declaration.clone(),
                    self.handler.clone(),
                    self.semantics.state_contract.clone(),
                ]));
            }
        }
        Err(state_error("unknown installed label body codec"))
    }
}

impl ExtensionInstallationAuthority for ClockLabelPolicy {
    fn content(&self, r: &ContentRef, max: usize) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .objects
            .get(r)
            .ok_or_else(|| fail("unknown installed label body"))?;
        if bytes.len() > max {
            return Err(fail("label body exceeds reserved read credit"));
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(bytes.len())
            .map_err(|_| fail("label read credit allocation"))?;
        result.extend_from_slice(bytes);
        Ok(result)
    }
    fn authenticate_namespace(
        &self,
        d: &ExtensionDeclaration,
        s: &ExtensionSelection,
    ) -> Result<(), EvidenceError> {
        if d != &self.declaration || s != &self.selection {
            return Err(fail("unknown source-installed label namespace/version"));
        }
        Ok(())
    }
    fn authenticate_core_contract(
        &self,
        _: &Id,
        _: u16,
        _: &ContentRef,
    ) -> Result<(), EvidenceError> {
        Err(fail("Clock label imports no core prerequisite"))
    }
    fn authenticate_schema(&self, s: &SchemaRef) -> Result<(), EvidenceError> {
        if s != &self.declaration.schema {
            return Err(fail("unknown Clock label schema"));
        }
        Ok(())
    }
    fn authenticate_handler(
        &self,
        d: &ExtensionDeclaration,
        r: &ContentRef,
        s: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        if d != &self.declaration || r != &self.handler || s != &self.semantics {
            return Err(fail("unknown Clock label handler or semantic axes"));
        }
        super::measure_current_host(&self.host).map_err(|error| fail(error.to_string()))
    }
}

impl ExtensionSemanticHandler for ClockLabelPolicy {
    fn identity(&self) -> &ContentRef {
        &self.handler
    }
    fn semantics(&self) -> &ExtensionSemanticContract {
        &self.semantics
    }
    fn validate_application(
        &self,
        a: &ExtensionApplication<'_>,
        d: &ExtensionDeclaration,
        s: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        if d != &self.declaration {
            return Err(fail("altered Clock label declaration"));
        }
        self.check_application(a, s)
    }
}

impl ExtensionQualificationAuthority for ClockLabelPolicy {
    fn actual_features(
        &self,
        a: &ExtensionApplication<'_>,
        _: usize,
    ) -> Result<IdSet, EvidenceError> {
        self.check_application(
            a,
            &ExtensionUse {
                selection: self.selection.clone(),
                parameters: serde_json::json!({"label":PARAMETERS}),
            },
        )?;
        Ok(vec![])
    }
    fn qualify_dependency(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionUse,
        _: &ExtensionDeclaration,
        _: &ExtensionDeclaration,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(fail("Clock label has no qualified imported prerequisite"))
    }
    fn qualify_application(
        &self,
        a: &ExtensionApplication<'_>,
        d: &ExtensionDeclaration,
        s: &ExtensionUse,
        c: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        if d != &self.declaration || c != &self.semantics {
            return Err(fail("unknown installed Clock label qualification"));
        }
        self.check_application(a, s)
    }
}

impl NativeExtensionPreservationPolicy for ClockLabelPolicy {
    fn authenticate_selection(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        super::measure_current_host(&self.host).map_err(state_error)?;
        self.check_graph(graph)
    }
    fn policy(&self, max: usize) -> Result<(ContentRef, Vec<u8>), StateError> {
        // The typed source-owned contract is fixed independently of its local
        // lookup table. A different valid content identity cannot select new
        // state or timing effects under this installed preservation profile.
        let expected = canonical::canonical_json(&serde_json::json!({
            "schema_version":1,"implementation":"crucible.installed-clock.metadata-preservation.v1",
            "host_build":self.host.hash,"native_codec":"host/native-continuation-v1",
            "native_profile":"host/exact-v1","original_scope":"immutable durable world",
            "state_effects":"none","time_effects":"none","unknown_dependencies":"refuse",
        }))
        .map_err(state_error)?;
        if canonical::content_ref(&expected, "application/json").map_err(state_error)?
            != self.preservation
            || self.objects.get(&self.preservation).map(Vec::as_slice) != Some(expected.as_slice())
        {
            return Err(state_error("installed Clock preservation policy changed"));
        }
        let bytes = ExtensionInstallationAuthority::content(self, &self.preservation, max)
            .map_err(state_error)?;
        Ok((self.preservation.clone(), bytes))
    }
    fn dependencies(
        &self,
        g: &AdmittedGraph,
        r: &ContentRef,
        b: &[u8],
        max: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let row = self.selected_dependencies(g, r, b)?;
        if row.len() > max {
            return Err(state_error("Clock label dependency edge credit"));
        }
        Ok(row)
    }
}

fn sorted(mut refs: Vec<ContentRef>) -> Vec<ContentRef> {
    refs.sort();
    refs.dedup();
    refs
}

fn put(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    bytes: Vec<u8>,
    media: &str,
) -> Result<ContentRef, super::NodeObservedError> {
    let reference = canonical::content_ref(&bytes, media)?;
    objects.insert(reference.clone(), bytes);
    Ok(reference)
}

fn put_json(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    body: &impl serde::Serialize,
) -> Result<ContentRef, super::NodeObservedError> {
    put(
        objects,
        canonical::canonical_json(&serde_json::to_value(body)?)?,
        "application/json",
    )
}
