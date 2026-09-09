//! Validated interface catalogs and checked binding/effect-plan handles.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aos_ability_model::{
    encode_canonical, ArtifactReference, Binding, BindingId, BindingPlanDocument, DecisionNode,
    DesiredStateDocument, Diagnostic, DiagnosticClass, DiagnosticCode, DiagnosticPhase,
    EffectPlanDocument, EnvironmentDocument, InterfaceDocument, InterfaceKey, MergeNode,
    MethodReference, Operation, PackageDocument, PlanId, PlanNodeKey, ProviderReadiness,
    RequiredFeature, ScopedOperationKey, VersionedDocument,
};
use aos_contract::Sha256Digest;

use crate::authority::{authorize_invocation, InvocationAuthorizationError};
use crate::binding::validate_binding_document;
use crate::effect::validate_effect_document;
use crate::error::push_diagnostic;
use crate::schema::{validate_schema_definition, SchemaPath};
use crate::ValidationErrors;

/// Owns an exact validated interface catalog and supported format features.
#[derive(Clone, Debug)]
pub struct ValidationContext {
    supported_features: BTreeSet<RequiredFeature>,
    interfaces: Arc<BTreeMap<InterfaceKey, InterfaceDocument>>,
}

impl ValidationContext {
    /// Constructs a context after validating every interface descriptor.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics for an invalid document, unsupported
    /// required feature, invalid schema, duplicate exact key, or method whose
    /// target resource differs from its owning version-1 interface.
    pub fn new(
        supported_features: BTreeSet<RequiredFeature>,
        interface_documents: impl IntoIterator<Item = InterfaceDocument>,
    ) -> Result<Self, ValidationErrors> {
        let mut interfaces = BTreeMap::new();
        let mut diagnostics = Vec::new();
        let limits = aos_ability_model::ABILITY_LIMITS_V1;
        let mut aggregate_bytes = 0_u64;

        for (index, document) in interface_documents.into_iter().enumerate() {
            if index >= limits.max_graph_nodes as usize {
                push_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        DiagnosticCode::LimitExceeded,
                        DiagnosticClass::InvalidContract,
                        DiagnosticPhase::Schema,
                        vec!["interfaces".to_string()],
                        "interface catalog exceeds the version-1 entry limit".to_string(),
                    ),
                );
                break;
            }
            let path = vec!["interfaces".to_string(), index.to_string()];
            for feature in &document.required_features {
                if !supported_features.contains(feature) {
                    push_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            DiagnosticCode::UnsupportedRequiredFeature,
                            DiagnosticClass::InvalidContract,
                            DiagnosticPhase::Schema,
                            path.clone(),
                            format!("unsupported required feature '{}'", feature.as_str()),
                        ),
                    );
                }
            }

            let bytes = match encode_canonical(&document) {
                Ok(bytes) => bytes,
                Err(error) => {
                    push_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            DiagnosticCode::UnsupportedSchema,
                            DiagnosticClass::InvalidContract,
                            DiagnosticPhase::Schema,
                            path,
                            error.to_string(),
                        ),
                    );
                    continue;
                }
            };
            aggregate_bytes = aggregate_bytes.saturating_add(bytes.len() as u64);
            if aggregate_bytes > limits.max_document_bytes {
                push_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        DiagnosticCode::LimitExceeded,
                        DiagnosticClass::InvalidContract,
                        DiagnosticPhase::Schema,
                        vec!["interfaces".to_string()],
                        "interface catalog exceeds the version-1 aggregate byte limit".to_string(),
                    ),
                );
                break;
            }
            let key = InterfaceKey {
                name: document.interface.name.clone(),
                abi: document.interface.abi,
                descriptor: Sha256Digest::separated(InterfaceDocument::SCHEMA, bytes),
            };

            validate_interface_document(&document, index, &mut diagnostics);
            if interfaces.insert(key, document).is_some() {
                push_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        DiagnosticCode::DuplicateIdentity,
                        DiagnosticClass::InvalidContract,
                        DiagnosticPhase::Schema,
                        vec!["interfaces".to_string(), index.to_string()],
                        "duplicate exact interface descriptor".to_string(),
                    ),
                );
            }
        }

        if diagnostics.is_empty() {
            Ok(Self {
                supported_features,
                interfaces: Arc::new(interfaces),
            })
        } else {
            Err(ValidationErrors::new(diagnostics))
        }
    }

    /// Returns the supported required-feature set.
    #[must_use]
    pub fn supported_features(&self) -> &BTreeSet<RequiredFeature> {
        &self.supported_features
    }

    /// Resolves one exact interface descriptor from the validated catalog.
    #[must_use]
    pub fn interface(&self, key: &InterfaceKey) -> Option<&InterfaceDocument> {
        self.interfaces.get(key)
    }

    pub(crate) fn interfaces(&self) -> &BTreeMap<InterfaceKey, InterfaceDocument> {
        &self.interfaces
    }

    pub(crate) fn shared_interfaces(&self) -> Arc<BTreeMap<InterfaceKey, InterfaceDocument>> {
        Arc::clone(&self.interfaces)
    }

    /// Validates a binding plan without acquiring providers or resources.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics when identities, bindings, grants,
    /// guarantees, lifetimes, policy commitments, or request coverage fail.
    pub fn validate_binding_plan(
        &self,
        document: BindingPlanDocument,
        inputs: BindingValidationInputs,
    ) -> Result<CheckedBindingPlan, ValidationErrors> {
        validate_binding_document(self, document, inputs)
    }

    /// Validates a finite effect graph against one exact checked binding plan.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics when graph references, method contracts,
    /// value schemas, authority, conditional branches, resource ownership, or
    /// scheduling invariants fail.
    pub fn validate_effect_plan(
        &self,
        document: EffectPlanDocument,
        binding_plan: CheckedBindingPlan,
    ) -> Result<CheckedEffectPlan, ValidationErrors> {
        validate_effect_document(self, document, binding_plan)
    }
}

/// Supplies the exact documents whose digests a binding plan commits to.
#[derive(Clone, Debug)]
pub struct BindingValidationInputs {
    /// Supplies the observed target environment and provider inventory.
    pub environment: EnvironmentDocument,
    /// Supplies the normalized desired state being bound.
    pub desired_state: DesiredStateDocument,
    /// Supplies exact package manifests for desired provider instances.
    pub packages: Vec<PackageDocument>,
}

/// Retains a semantically validated binding plan and exact lookup indexes.
#[derive(Clone, Debug)]
pub struct CheckedBindingPlan {
    pub(crate) id: PlanId,
    pub(crate) document: BindingPlanDocument,
    pub(crate) inputs: BindingValidationInputs,
    pub(crate) binding_indices: BTreeMap<BindingId, usize>,
    pub(crate) provider_states: BTreeMap<BindingId, BindingProviderState>,
    pub(crate) planned_providers: BTreeSet<aos_ability_model::InstanceId>,
    pub(crate) executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BindingProviderState {
    Available,
    Planned,
    PureComposition,
    Unavailable,
}

impl CheckedBindingPlan {
    /// Returns the domain-separated canonical plan identity.
    #[must_use]
    pub const fn id(&self) -> PlanId {
        self.id
    }

    /// Returns the exact checked portable document.
    #[must_use]
    pub const fn document(&self) -> &BindingPlanDocument {
        &self.document
    }

    /// Resolves a binding by its plan-local identity.
    #[must_use]
    pub fn binding(&self, id: &BindingId) -> Option<&Binding> {
        self.binding_indices
            .get(id)
            .map(|index| &self.document.bindings[*index])
    }

    /// Returns all bindings in canonical document order.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.document.bindings
    }

    /// Returns the checked target environment input.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentDocument {
        &self.inputs.environment
    }

    /// Returns the checked normalized desired-state input.
    #[must_use]
    pub const fn desired_state(&self) -> &DesiredStateDocument {
        &self.inputs.desired_state
    }

    /// Returns exact checked package manifests used for provider resolution.
    #[must_use]
    pub fn packages(&self) -> &[PackageDocument] {
        &self.inputs.packages
    }

    /// Returns providers that require a checked readiness path before use.
    #[must_use]
    pub fn planned_providers(&self) -> &BTreeSet<aos_ability_model::InstanceId> {
        &self.planned_providers
    }

    pub(crate) fn provider_state(&self, binding: &BindingId) -> Option<BindingProviderState> {
        self.provider_states.get(binding).copied()
    }

    /// Reports whether this plan retains unresolved deployment obligations.
    #[must_use]
    pub fn has_unresolved_obligations(&self) -> bool {
        !self.document.obligations.is_empty()
    }

    /// Reports whether every deployment obligation is discharged.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.executable
    }
}

/// Retains a semantically validated effect plan and scheduling indexes.
#[derive(Clone, Debug)]
pub struct CheckedEffectPlan {
    pub(crate) id: PlanId,
    pub(crate) document: EffectPlanDocument,
    pub(crate) binding_plan: CheckedBindingPlan,
    pub(crate) operation_indices: BTreeMap<ScopedOperationKey, usize>,
    pub(crate) decision_indices: BTreeMap<ScopedOperationKey, usize>,
    pub(crate) merge_indices: BTreeMap<ScopedOperationKey, usize>,
    pub(crate) readiness_indices: BTreeMap<BindingId, usize>,
    pub(crate) dispatch_order: Vec<PlanNodeKey>,
    pub(crate) interfaces: Arc<BTreeMap<InterfaceKey, InterfaceDocument>>,
    pub(crate) artifact_index: BTreeMap<Sha256Digest, ArtifactReference>,
    pub(crate) required_runtime_artifacts: Vec<ArtifactReference>,
    pub(crate) executable: bool,
}

impl CheckedEffectPlan {
    /// Returns the domain-separated canonical plan identity.
    #[must_use]
    pub const fn id(&self) -> PlanId {
        self.id
    }

    /// Returns the exact checked portable document.
    #[must_use]
    pub const fn document(&self) -> &EffectPlanDocument {
        &self.document
    }

    /// Returns the exact checked binding plan authorizing this graph.
    #[must_use]
    pub const fn binding_plan(&self) -> &CheckedBindingPlan {
        &self.binding_plan
    }

    /// Resolves an operation by scoped identity.
    #[must_use]
    pub fn operation(&self, key: &ScopedOperationKey) -> Option<&Operation> {
        self.operation_indices
            .get(key)
            .map(|index| &self.document.operations[*index])
    }

    /// Returns operations in canonical document order.
    #[must_use]
    pub fn operations(&self) -> &[Operation] {
        &self.document.operations
    }

    /// Resolves the exact assignment-readiness declaration for a planned binding.
    #[must_use]
    pub fn provider_readiness(&self, binding: &BindingId) -> Option<&ProviderReadiness> {
        self.readiness_indices
            .get(binding)
            .map(|index| &self.document.provider_readiness[*index])
    }

    /// Checks one primary, reconcile, cancel, or compensate invocation against
    /// the exact interface descriptor and binding grants retained by this plan.
    ///
    /// Runtime admission calls this again with fresh policy, provider, and
    /// resource evidence before dispatching the method.
    ///
    /// # Errors
    ///
    /// Returns an error if `operation` is not the exact checked graph member,
    /// its binding is unavailable, or the method exceeds its descriptor,
    /// provider scope, mediation setting, or selected role grant.
    pub fn authorize_invocation(
        &self,
        operation: &Operation,
        method: &MethodReference,
    ) -> Result<(), InvocationAuthorizationError> {
        if self.operation(&operation.key) != Some(operation) {
            return Err(InvocationAuthorizationError::UnknownOperation);
        }
        let binding = self
            .binding_plan
            .binding(&operation.binding)
            .ok_or(InvocationAuthorizationError::UnknownBinding)?;

        authorize_invocation(&self.interfaces, binding, operation, method)
    }

    /// Resolves a conditional decision by scoped identity.
    #[must_use]
    pub fn decision(&self, key: &ScopedOperationKey) -> Option<&DecisionNode> {
        self.decision_indices
            .get(key)
            .map(|index| &self.document.decisions[*index])
    }

    /// Returns decisions in canonical document order.
    #[must_use]
    pub fn decisions(&self) -> &[DecisionNode] {
        &self.document.decisions
    }

    /// Resolves a conditional merge by scoped identity.
    #[must_use]
    pub fn merge(&self, key: &ScopedOperationKey) -> Option<&MergeNode> {
        self.merge_indices
            .get(key)
            .map(|index| &self.document.merges[*index])
    }

    /// Returns merges in canonical document order.
    #[must_use]
    pub fn merges(&self) -> &[MergeNode] {
        &self.document.merges
    }

    /// Returns all declared graph edges in canonical order.
    #[must_use]
    pub fn edges(&self) -> &[aos_ability_model::DependencyEdge] {
        &self.document.edges
    }

    /// Returns a deterministic topological order over scheduling edges.
    #[must_use]
    pub fn dispatch_order(&self) -> &[PlanNodeKey] {
        &self.dispatch_order
    }

    /// Returns the complete validator-derived artifact roots required to
    /// interpret, recover, and execute this checked plan.
    #[must_use]
    pub fn required_runtime_artifacts(&self) -> &[ArtifactReference] {
        &self.required_runtime_artifacts
    }

    /// Reports whether binding and effect obligations permit runtime admission.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.executable
    }
}

fn validate_interface_document(
    document: &InterfaceDocument,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    let root = SchemaPath::root()
        .child("interfaces")
        .child(index.to_string())
        .child("interface");
    validate_schema_definition(
        &document.interface.request,
        &root.child("request"),
        1,
        limits.max_structural_depth,
        limits.max_string_bytes,
        limits.max_collection_items,
        diagnostics,
    );
    for (name, output) in &document.interface.outputs {
        validate_schema_definition(
            &output.schema,
            &root.child("outputs").child(name.as_str()),
            1,
            limits.max_structural_depth,
            limits.max_string_bytes,
            limits.max_collection_items,
            diagnostics,
        );
    }
    check_strict_order(
        &document.interface.guarantees,
        &root.child("guarantees"),
        diagnostics,
    );

    for (name, method) in &document.interface.methods {
        let method_path = root.child("methods").child(name.as_str());
        validate_schema_definition(
            &method.parameters,
            &method_path.child("parameters"),
            1,
            limits.max_structural_depth,
            limits.max_string_bytes,
            limits.max_collection_items,
            diagnostics,
        );
        validate_schema_definition(
            &method.outcome.completion_evidence,
            &method_path.child("outcome").child("completion_evidence"),
            1,
            limits.max_structural_depth,
            limits.max_string_bytes,
            limits.max_collection_items,
            diagnostics,
        );
        validate_schema_definition(
            &method.outcome.observation_evidence,
            &method_path.child("outcome").child("observation_evidence"),
            1,
            limits.max_structural_depth,
            limits.max_string_bytes,
            limits.max_collection_items,
            diagnostics,
        );
        for (output_name, output) in &method.outputs {
            validate_schema_definition(
                &output.schema,
                &method_path.child("outputs").child(output_name.as_str()),
                1,
                limits.max_structural_depth,
                limits.max_string_bytes,
                limits.max_collection_items,
                diagnostics,
            );
        }
        check_strict_order(
            &method.permitted_operations,
            &method_path.child("permitted_operations"),
            diagnostics,
        );
        check_strict_order(
            &method.guarantees,
            &method_path.child("guarantees"),
            diagnostics,
        );
        if method.target_resource != document.interface.name {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MethodContractMismatch,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Schema,
                    method_path.components().to_vec(),
                    "version-1 method target must be its exact owning interface".to_string(),
                ),
            );
        }
    }
}

pub(crate) fn check_strict_order<T: Ord>(
    values: &[T],
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::NonCanonicalOrder,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Schema,
                path.components().to_vec(),
                "values must be strictly sorted without duplicates".to_string(),
            ),
        );
    }
}

pub(crate) fn diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    phase: DiagnosticPhase,
    path: Vec<String>,
    message: String,
) -> Diagnostic {
    Diagnostic {
        code,
        class,
        phase,
        path,
        message: message.chars().take(512).collect(),
        request: None,
        operation: None,
        resource: None,
        live_effect_may_have_occurred: false,
    }
}
