//! Retains only actual qualified applications and their complete publication closure.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crucible_node_contract::{
    ContentRef, ExtensionApplicability, ExtensionDependency, ExtensionLocation, ExtensionUse,
    Extensions, HashRef, Id, Validate, canonical,
};
use serde::{Serialize, Serializer, ser::SerializeSeq};

use crate::node_admission::{
    AdmissionCode, AdmissionError, AdmissionStage, evidence::bounded_core,
};

use super::context::{
    ExtensionApplication, ExtensionApplicationScope, ExtensionRecordKind, ExtensionRecordPath,
};
use super::frozen::{DefinitionView, SemanticContractView, serialize_semantics};
use super::registry::{InstalledDefinition, failure, schema_error, trust_error};
use super::{
    AdmittedExtensionDefinition, ExtensionImpact, ExtensionSemanticContract,
    InstalledExtensionRegistry,
};

/// Retains one exact application after independent installed qualification.
#[derive(Clone, Debug, Serialize)]
pub struct AdmittedExtensionApplication {
    scope: ExtensionApplicationScope,
    selected: ExtensionUse,
    handler_identity: ContentRef,
    #[serde(serialize_with = "serialize_semantics")]
    semantic_contract: ExtensionSemanticContract,
}

impl AdmittedExtensionApplication {
    /// Borrows the actual record scope, including durable node and world identity.
    pub fn scope(&self) -> &ExtensionApplicationScope {
        &self.scope
    }

    /// Borrows exact declaration, version, schema, and validated parameters.
    pub fn selected(&self) -> &ExtensionUse {
        &self.selected
    }

    /// Borrows the independently authenticated installed interpretation identity.
    pub fn handler_identity(&self) -> &ContentRef {
        &self.handler_identity
    }

    /// Borrows the actual frozen interpretation qualified for this application.
    pub fn semantic_contract(&self) -> &ExtensionSemanticContract {
        &self.semantic_contract
    }
}

/// Holds immutable selected semantics without allowing caller-issued admission.
///
/// Unselected installed definitions do not appear in this set. Archive codecs
/// must preserve the exact application records and complete immutable object
/// inventory and qualify their state/timing implications independently. Merely
/// copying this inventory cannot provide native capture support.
#[derive(Default)]
pub struct AdmittedExtensionSet {
    applications: Vec<AdmittedExtensionApplication>,
    definitions: BTreeMap<ContentRef, AdmittedExtensionDefinition>,
    objects: BTreeMap<ContentRef, Rc<[u8]>>,
    application_bytes: usize,
    qualification_checks: usize,
}

impl std::fmt::Debug for AdmittedExtensionSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedExtensionSet")
            .field("applications", &self.applications.len())
            .field("definitions", &self.definitions.len())
            .field("objects", &self.objects.len())
            .field("application_bytes", &self.application_bytes)
            .field("qualification_checks", &self.qualification_checks)
            .finish()
    }
}

impl AdmittedExtensionSet {
    /// Iterates exact applications in deterministic graph-admission order.
    pub fn applications(&self) -> impl ExactSizeIterator<Item = &AdmittedExtensionApplication> {
        self.applications.iter()
    }

    /// Iterates each direct or prerequisite definition with its own frozen semantics.
    pub fn definitions(&self) -> impl ExactSizeIterator<Item = &AdmittedExtensionDefinition> {
        self.definitions.values()
    }

    /// Iterates complete selected immutable definition and dependency bodies.
    pub fn objects(&self) -> impl ExactSizeIterator<Item = (&ContentRef, &[u8])> {
        self.objects
            .iter()
            .map(|(reference, bytes)| (reference, bytes.as_ref()))
    }

    /// Reports whether the graph selected no registered extension semantics.
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }

    /// Computes a deterministic identity independent of unselected registry entries.
    ///
    /// # Errors
    /// Refuses inability to encode already bounded selected records.
    pub fn identity(&self) -> Result<HashRef, crucible_node_contract::ContractError> {
        if self.is_empty() {
            // The original empty selection has no interpretation to widen.
            #[derive(Serialize)]
            struct EmptyIdentity {
                applications: [u8; 0],
                definitions: [u8; 0],
            }
            return canonical::json_hash(
                "cnp.selected-extensions.v1",
                &EmptyIdentity {
                    applications: [],
                    definitions: [],
                },
            );
        }

        #[derive(Serialize)]
        struct Identity<'a> {
            schema_version: u16,
            applications: &'a [AdmittedExtensionApplication],
            definitions: Definitions<'a>,
        }
        canonical::json_hash(
            "cnp.selected-extensions.v2",
            &Identity {
                schema_version: 2,
                applications: &self.applications,
                definitions: Definitions(&self.definitions),
            },
        )
    }
}

struct Definitions<'a>(&'a BTreeMap<ContentRef, AdmittedExtensionDefinition>);

impl Serialize for Definitions<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for definition in self.0.values() {
            sequence.serialize_element(definition)?;
        }
        sequence.end()
    }
}

impl InstalledExtensionRegistry {
    pub(super) fn admit_map(
        &self,
        application: &ExtensionApplication<'_>,
        extensions: &Extensions,
        admitted: &mut AdmittedExtensionSet,
    ) -> Result<(), AdmissionError> {
        self.admit_map_for_purpose(application, extensions, admitted, None)
    }

    pub(super) fn admit_map_for_purpose(
        &self,
        application: &ExtensionApplication<'_>,
        extensions: &Extensions,
        admitted: &mut AdmittedExtensionSet,
        collection: Option<&crate::node_admission::InstalledConformancePlan>,
    ) -> Result<(), AdmissionError> {
        if extensions.is_empty() {
            return Ok(());
        }
        check_shapes(extensions)?;
        let count = admitted
            .applications
            .len()
            .checked_add(extensions.len())
            .ok_or_else(|| {
                failure(
                    AdmissionCode::BoundMismatch,
                    "bounded applications",
                    "application count overflow",
                )
            })?;
        if count > self.limits.maximum_applications {
            return Err(scoped(
                application,
                AdmissionCode::BoundMismatch,
                "bounded applications",
                "too many selected applications",
            ));
        }
        bounded_core(extensions, self.limits.maximum_application_bytes)?;
        bounded_core(application.scope(), self.limits.maximum_application_bytes)?;

        // Reserve the whole map before validator callbacks. Failed qualification
        // never inserts a partially selected record or exposes a success seal.
        admitted
            .applications
            .try_reserve(extensions.len())
            .map_err(|_| {
                scoped(
                    application,
                    AdmissionCode::BoundMismatch,
                    "reserved application slots",
                    "unable to reserve application custody",
                )
            })?;
        let mut pending = Vec::new();
        pending.try_reserve_exact(extensions.len()).map_err(|_| {
            scoped(
                application,
                AdmissionCode::BoundMismatch,
                "bounded parameter validation slots",
                "unable to reserve parameter custody",
            )
        })?;
        for (identifier, raw) in extensions {
            let selected: ExtensionUse = serde_json::from_value(raw.clone()).map_err(|error| {
                scoped(
                    application,
                    AdmissionCode::InvalidSchema,
                    "closed exact extension selection",
                    &error.to_string(),
                )
            })?;
            selected
                .validate()
                .map_err(|error| with_subject(application, schema_error(error)))?;
            if selected.selection.identifier.as_str() != identifier {
                return Err(scoped(
                    application,
                    AdmissionCode::IdentityMismatch,
                    "map key equals selected identifier",
                    "extension map key names another contract",
                ));
            }
            let installed = self
                .definitions
                .get(&selected.selection.declaration)
                .ok_or_else(|| {
                    scoped(
                        application,
                        AdmissionCode::UnknownInterface,
                        "authenticated installed semantics",
                        "selected definition is not installed",
                    )
                })?;
            if installed.selection != selected.selection {
                return Err(scoped(
                    application,
                    AdmissionCode::IdentityMismatch,
                    "exact installed definition/version/schema",
                    "selected fields differ from authenticated declaration",
                ));
            }
            let body_bytes = bounded_core(&selected, self.limits.maximum_application_bytes)?;
            if u64::try_from(body_bytes).map_or(true, |length| {
                length > installed.declaration.limits.maximum_message_bytes.get()
            }) || installed.declaration.limits.maximum_objects.get() == 0
                || installed.declaration.limits.maximum_allocation_bytes.get()
                    < u64::try_from(body_bytes).unwrap_or(u64::MAX)
            {
                return Err(scoped(
                    application,
                    AdmissionCode::BoundMismatch,
                    "declared finite extension allowances",
                    "selected body exceeds declared message/object/allocation allowance",
                ));
            }
            validate_context(application, installed)?;
            let dependencies = self.dependency_plan(installed)?;
            pending.push((installed, selected, dependencies));
        }

        // Count actual retained interpretations before qualification callbacks.
        #[derive(Serialize)]
        struct ApplicationView<'a> {
            scope: &'a ExtensionApplicationScope,
            selected: &'a ExtensionUse,
            handler_identity: &'a ContentRef,
            semantic_contract: SemanticContractView<'a>,
        }
        let mut definitions = BTreeSet::new();
        let mut total = admitted.application_bytes;
        for (installed, selected, _) in &pending {
            self.selected_closure(installed, &mut definitions)?;
            let bytes = bounded_core(
                &ApplicationView {
                    scope: application.scope(),
                    selected,
                    handler_identity: &installed.handler_identity,
                    semantic_contract: SemanticContractView::from(&installed.semantics),
                },
                self.limits.maximum_application_bytes,
            )?;
            total = add_metadata_credit(
                application,
                total,
                bytes,
                self.limits.maximum_total_application_bytes,
            )?;
        }
        for reference in &definitions {
            if admitted.definitions.contains_key(reference) {
                continue;
            }
            let installed = self.definitions.get(reference).ok_or_else(|| {
                failure(
                    AdmissionCode::IdentityMismatch,
                    "sealed prerequisite definition",
                    "installed prerequisite vanished",
                )
            })?;
            let bytes = bounded_core(
                &DefinitionView {
                    selection: &installed.selection,
                    handler_identity: &installed.handler_identity,
                    semantic_contract: SemanticContractView::from(&installed.semantics),
                },
                self.limits.maximum_application_bytes,
            )?;
            total = add_metadata_credit(
                application,
                total,
                bytes,
                self.limits.maximum_total_application_bytes,
            )?;
        }

        let mut checks = admitted.qualification_checks;
        for (_, _, dependencies) in &pending {
            checks = dependencies
                .len()
                .checked_mul(2)
                .and_then(|dependency_checks| checks.checked_add(dependency_checks))
                .and_then(|checks| checks.checked_add(3))
                .ok_or_else(|| {
                    scoped(
                        application,
                        AdmissionCode::BoundMismatch,
                        "bounded qualification work",
                        "qualification credit overflow",
                    )
                })?;
            if checks > self.limits.maximum_qualification_checks {
                return Err(scoped(
                    application,
                    AdmissionCode::BoundMismatch,
                    "reserved direct/transitive qualification work",
                    "selected dependency callbacks exceed remaining check credit",
                ));
            }
        }

        for (installed, selected, dependencies) in &pending {
            if let Some(plan) = collection {
                plan.authenticate_extension_scope(application)
                    .map_err(|error| with_subject(application, trust_error(error)))?;
            }
            for (dependent, prerequisite) in dependencies {
                ensure_handler_unchanged(prerequisite)
                    .map_err(|error| with_subject(application, error))?;
                self.check_features(application, prerequisite)?;
                match collection {
                    Some(plan) => plan.authenticate_extension_dependency(
                        application,
                        selected,
                        &dependent.declaration,
                        &prerequisite.declaration,
                        &prerequisite.semantics,
                    ),
                    None => prerequisite.qualification.qualify_dependency(
                        application,
                        selected,
                        &dependent.declaration,
                        &prerequisite.declaration,
                        &prerequisite.semantics,
                    ),
                }
                .map_err(|error| with_subject(application, trust_error(error)))?;
                ensure_handler_unchanged(prerequisite)
                    .map_err(|error| with_subject(application, error))?;
            }
            self.check_features(application, installed)?;
            ensure_handler_unchanged(installed)
                .map_err(|error| with_subject(application, error))?;
            if let Some(plan) = collection {
                plan.authenticate_extension_scope(application)
                    .map_err(|error| with_subject(application, trust_error(error)))?;
            }
            installed
                .handler
                .validate_application(application, &installed.declaration, selected)
                .map_err(|error| with_subject(application, trust_error(error)))?;
            match collection {
                Some(plan) => plan.authenticate_extension_application(
                    application,
                    &installed.declaration,
                    selected,
                    &installed.semantics,
                ),
                None => installed.qualification.qualify_application(
                    application,
                    &installed.declaration,
                    selected,
                    &installed.semantics,
                ),
            }
            .map_err(|error| with_subject(application, trust_error(error)))?;
            ensure_handler_unchanged(installed)
                .map_err(|error| with_subject(application, error))?;
        }

        // A later callback can touch a handler from this or a previous map.
        // Revalidate the bounded complete closure before inserting any custody.
        for reference in admitted.definitions.keys().chain(
            definitions
                .iter()
                .filter(|reference| !admitted.definitions.contains_key(*reference)),
        ) {
            let installed = self.definitions.get(reference).ok_or_else(|| {
                failure(
                    AdmissionCode::IdentityMismatch,
                    "sealed installed dependency closure",
                    "installed prerequisite vanished",
                )
            })?;
            ensure_handler_unchanged(installed)
                .map_err(|error| with_subject(application, error))?;
        }

        if let Some(plan) = collection {
            plan.authenticate_extension_scope(application)
                .map_err(|error| with_subject(application, trust_error(error)))?;
        }
        for reference in &definitions {
            let installed = self.definitions.get(reference).ok_or_else(|| {
                failure(
                    AdmissionCode::IdentityMismatch,
                    "sealed installed dependency closure",
                    "installed prerequisite vanished",
                )
            })?;
            for object in &installed.objects {
                let bytes = self.objects.get(object).ok_or_else(|| {
                    failure(
                        AdmissionCode::IdentityMismatch,
                        "verified selected publication bytes",
                        "installed object custody is missing",
                    )
                })?;
                admitted.objects.insert(object.clone(), Rc::clone(bytes));
            }
            admitted
                .definitions
                .entry(reference.clone())
                .or_insert_with(|| {
                    AdmittedExtensionDefinition::new(
                        installed.selection.clone(),
                        installed.handler_identity.clone(),
                        installed.semantics.clone(),
                    )
                });
        }
        for (installed, selected, _) in pending {
            admitted.applications.push(AdmittedExtensionApplication {
                scope: application.scope().clone(),
                selected,
                handler_identity: installed.handler_identity.clone(),
                semantic_contract: installed.semantics.clone(),
            });
        }
        admitted.application_bytes = total;
        admitted.qualification_checks = checks;
        Ok(())
    }

    fn check_features(
        &self,
        application: &ExtensionApplication<'_>,
        installed: &InstalledDefinition,
    ) -> Result<(), AdmissionError> {
        if installed.declaration.required_features.is_empty() {
            return Ok(());
        }
        let actual = installed
            .qualification
            .actual_features(application, self.limits.maximum_definitions)
            .map_err(|error| with_subject(application, trust_error(error)))?;
        if actual.len() > self.limits.maximum_definitions
            || actual.windows(2).any(|pair| pair[0] >= pair[1])
            || installed
                .declaration
                .required_features
                .iter()
                .any(|feature| actual.binary_search(feature).is_err())
        {
            return Err(scoped(
                application,
                AdmissionCode::FeatureMismatch,
                "authenticated actual prerequisite features",
                "required feature is absent or feature inventory is unsupported",
            ));
        }
        Ok(())
    }

    fn dependency_plan<'a>(
        &'a self,
        root: &'a InstalledDefinition,
    ) -> Result<Vec<(&'a InstalledDefinition, &'a InstalledDefinition)>, AdmissionError> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root];
        let mut edges = Vec::new();
        while let Some(dependent) = pending.pop() {
            if !seen.insert(&dependent.selection.declaration) {
                continue;
            }
            for dependency in &dependent.declaration.dependencies {
                let ExtensionDependency::Extension { selection } = dependency else {
                    continue;
                };
                if edges.len() >= self.limits.maximum_dependencies {
                    return Err(failure(
                        AdmissionCode::BoundMismatch,
                        "bounded dependency callback inventory",
                        "selected prerequisite edges exceed reserved bound",
                    ));
                }
                let prerequisite =
                    self.definitions
                        .get(&selection.declaration)
                        .ok_or_else(|| {
                            failure(
                                AdmissionCode::IdentityMismatch,
                                "installed exact prerequisite",
                                "selected dependency is missing",
                            )
                        })?;
                edges.try_reserve(1).map_err(|_| {
                    failure(
                        AdmissionCode::BoundMismatch,
                        "reserved dependency plan slots",
                        "unable to reserve dependency plan",
                    )
                })?;
                edges.push((dependent, prerequisite));
                pending.try_reserve(1).map_err(|_| {
                    failure(
                        AdmissionCode::BoundMismatch,
                        "reserved pending prerequisite slots",
                        "unable to reserve pending dependency traversal",
                    )
                })?;
                pending.push(prerequisite);
            }
        }
        Ok(edges)
    }

    fn selected_closure(
        &self,
        installed: &InstalledDefinition,
        selected: &mut BTreeSet<ContentRef>,
    ) -> Result<(), AdmissionError> {
        let mut pending = vec![&installed.selection.declaration];
        while let Some(reference) = pending.pop() {
            if !selected.insert(reference.clone()) {
                continue;
            }
            if selected.len() > self.limits.maximum_definitions {
                return Err(failure(
                    AdmissionCode::BoundMismatch,
                    "bounded selected definition closure",
                    "selected definition count exceeds ceiling",
                ));
            }
            let entry = self.definitions.get(reference).ok_or_else(|| {
                failure(
                    AdmissionCode::IdentityMismatch,
                    "installed prerequisite custody",
                    "selected dependency is unavailable",
                )
            })?;
            for dependency in &entry.declaration.dependencies {
                if let ExtensionDependency::Extension { selection } = dependency {
                    pending.try_reserve(1).map_err(|_| {
                        failure(
                            AdmissionCode::BoundMismatch,
                            "reserved selected closure slots",
                            "unable to reserve selected dependency traversal",
                        )
                    })?;
                    pending.push(&selection.declaration);
                }
            }
        }
        Ok(())
    }
}

fn add_metadata_credit(
    application: &ExtensionApplication<'_>,
    total: usize,
    bytes: usize,
    maximum: usize,
) -> Result<usize, AdmissionError> {
    total
        .checked_add(bytes)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| {
            scoped(
                application,
                AdmissionCode::BoundMismatch,
                "finite frozen interpretation credit",
                "selected semantic snapshots exceed remaining metadata ceiling",
            )
        })
}

fn ensure_handler_unchanged(installed: &InstalledDefinition) -> Result<(), AdmissionError> {
    if installed.handler.identity() != &installed.handler_identity
        || installed.handler.semantics() != &installed.semantics
    {
        return Err(failure(
            AdmissionCode::IdentityMismatch,
            "immutable authenticated handler",
            "installed handler changed after authentication",
        ));
    }
    Ok(())
}

fn validate_context(
    application: &ExtensionApplication<'_>,
    installed: &InstalledDefinition,
) -> Result<(), AdmissionError> {
    let kind = application.scope().record_kind();
    let semantics = &installed.semantics;
    if !semantics.locations.contains(&kind) {
        return Err(scoped(
            application,
            AdmissionCode::UnknownInterface,
            "installed handler for actual location",
            "handler does not implement this record kind",
        ));
    }
    if semantics.impact == ExtensionImpact::Behavior && !kind.is_durable() {
        return Err(scoped(
            application,
            AdmissionCode::IdentityMismatch,
            "behavior bound to durable compatibility",
            "operational wrapper cannot select additional behavior",
        ));
    }
    let clause = installed
        .declaration
        .applicability
        .iter()
        .find(|clause| clause.location == location(kind))
        .ok_or_else(|| {
            scoped(
                application,
                AdmissionCode::UnknownInterface,
                "declared actual applicability",
                "definition has no applicability clause for this location",
            )
        })?;
    if !clause.operation_kinds.is_empty() {
        return Err(scoped(
            application,
            AdmissionCode::UnknownInterface,
            "graph record application without method selection",
            "method-scoped selector cannot apply to a graph record",
        ));
    }
    if let Some(node) = application.node() {
        let binding = application.binding().ok_or_else(|| {
            scoped(
                application,
                AdmissionCode::IdentityMismatch,
                "actual selected node contract",
                "node binding is absent",
            )
        })?;
        let contract = &binding.compatibility.operating_contract;
        if (!semantics.roles.is_empty()
            && !node.roles.iter().any(|role| semantics.roles.contains(role)))
            || (!clause.roles.is_empty()
                && !node.roles.iter().any(|role| clause.roles.contains(role)))
            || (!semantics.modes.is_empty() && !semantics.modes.contains(&contract.mode))
            || (!clause.modes.is_empty() && !clause.modes.contains(&contract.mode))
            || semantics
                .facets
                .iter()
                .chain(&clause.facets)
                .any(|required| !contract.facets.iter().any(|facet| &facet.id == required))
        {
            return Err(scoped(
                application,
                AdmissionCode::FeatureMismatch,
                "actual role/mode/facet compatibility",
                "required selectors are not realized in the selected node",
            ));
        }
    } else if !semantics.roles.is_empty()
        || !semantics.facets.is_empty()
        || !semantics.modes.is_empty()
        || !clause.roles.is_empty()
        || !clause.facets.is_empty()
        || !clause.modes.is_empty()
    {
        return Err(scoped(
            application,
            AdmissionCode::FeatureMismatch,
            "applicable actual node selectors",
            "node-only restrictions have no actual node scope",
        ));
    }
    validate_endpoint_selectors(application, clause, &semantics.interfaces)
}

fn validate_endpoint_selectors(
    application: &ExtensionApplication<'_>,
    clause: &ExtensionApplicability,
    interfaces: &BTreeSet<Id>,
) -> Result<(), AdmissionError> {
    let path = application.scope().record_path();
    let (port_id, lane_id) = match path {
        ExtensionRecordPath::Port { port } => (Some(port), None),
        ExtensionRecordPath::Lane { port, lane }
        | ExtensionRecordPath::LaneSchema { port, lane, .. } => (Some(port), Some(lane)),
        _ => (None, None),
    };
    let port = port_id.and_then(|id| application.node()?.ports.iter().find(|port| &port.id == id));
    let lane = lane_id.and_then(|id| port?.lanes.iter().find(|lane| &lane.id == id));
    let interface = port.map(|port| &port.interface_id).or_else(|| {
        let connection = match path {
            ExtensionRecordPath::Connection { connection }
            | ExtensionRecordPath::ConnectionSchema { connection, .. } => connection,
            _ => return None,
        };
        application
            .world()
            .connections
            .iter()
            .find(|edge| &edge.id == connection)
            .map(|edge| &edge.interface_id)
    });
    if (!clause.ports.is_empty() && port.is_none_or(|port| !clause.ports.contains(&port.id)))
        || (!clause.lanes.is_empty() && lane.is_none_or(|lane| !clause.lanes.contains(&lane.id)))
        || clause
            .direction
            .is_some_and(|direction| lane.is_none_or(|lane| lane.direction != direction))
        || (!interfaces.is_empty()
            && interface.is_none_or(|interface| !interfaces.contains(interface)))
    {
        return Err(scoped(
            application,
            AdmissionCode::FeatureMismatch,
            "actual directed port/lane/interface compatibility",
            "selectors differ or actual endpoint is absent",
        ));
    }
    Ok(())
}

fn location(kind: ExtensionRecordKind) -> ExtensionLocation {
    match kind {
        ExtensionRecordKind::NodeDescriptor => ExtensionLocation::NodeDescriptor,
        ExtensionRecordKind::PortDescriptor => ExtensionLocation::PortDescriptor,
        ExtensionRecordKind::LaneDescriptor => ExtensionLocation::LaneDescriptor,
        ExtensionRecordKind::SchemaRef => ExtensionLocation::SchemaRef,
        ExtensionRecordKind::FacetSelection => ExtensionLocation::FacetSelection,
        ExtensionRecordKind::OperatingContract => ExtensionLocation::OperatingContract,
        ExtensionRecordKind::CapabilityProfile => ExtensionLocation::CapabilityProfile,
        ExtensionRecordKind::GuaranteeProfile => ExtensionLocation::GuaranteeProfile,
        ExtensionRecordKind::ArtifactIdentity => ExtensionLocation::ArtifactIdentity,
        ExtensionRecordKind::ImplementationIdentity => ExtensionLocation::ImplementationIdentity,
        ExtensionRecordKind::BindingCompatibility => ExtensionLocation::BindingCompatibility,
        ExtensionRecordKind::NodeBinding => ExtensionLocation::NodeBinding,
        ExtensionRecordKind::LiveAuthority => ExtensionLocation::LiveAuthority,
        ExtensionRecordKind::WorldBinding => ExtensionLocation::WorldBinding,
        ExtensionRecordKind::NodeBindingRef => ExtensionLocation::NodeBindingRef,
        ExtensionRecordKind::OwnerBinding => ExtensionLocation::OwnerBinding,
        ExtensionRecordKind::ConnectionDescriptor => ExtensionLocation::ConnectionDescriptor,
    }
}

pub(super) fn check_shapes(extensions: &Extensions) -> Result<(), AdmissionError> {
    fn visit(
        value: &serde_json::Value,
        depth: usize,
        count: &mut usize,
    ) -> Result<(), AdmissionError> {
        *count = count.checked_add(1).ok_or_else(|| {
            failure(
                AdmissionCode::BoundMismatch,
                "bounded JSON values",
                "value count overflow",
            )
        })?;
        if *count > 65_536 {
            return Err(failure(
                AdmissionCode::BoundMismatch,
                "bounded JSON values",
                "extension map exceeds 65536 values",
            ));
        }
        if depth >= 64 && (value.is_array() || value.is_object()) {
            return Err(failure(
                AdmissionCode::BoundMismatch,
                "bounded JSON container depth",
                "extension nesting exceeds 64 containers",
            ));
        }
        match value {
            serde_json::Value::Array(values) => {
                for child in values {
                    visit(child, depth + 1, count)?;
                }
            }
            serde_json::Value::Object(values) => {
                for child in values.values() {
                    visit(child, depth + 1, count)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    if extensions.len() > 65_536 {
        return Err(failure(
            AdmissionCode::BoundMismatch,
            "bounded extension identifiers",
            "extension map exceeds 65536 entries",
        ));
    }
    let mut count = 0usize;
    for value in extensions.values() {
        visit(value, 1, &mut count)?;
    }
    Ok(())
}

fn with_subject(
    application: &ExtensionApplication<'_>,
    mut error: AdmissionError,
) -> AdmissionError {
    error.subject = application.subject();
    error
}

fn scoped(
    application: &ExtensionApplication<'_>,
    code: AdmissionCode,
    required: &str,
    observed: &str,
) -> AdmissionError {
    crate::node_admission::error::refuse(
        AdmissionStage::Nodes,
        application.subject(),
        code,
        required,
        observed,
    )
}
