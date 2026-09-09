//! Binding-plan identity, coverage, guarantee, and grant validation.

mod package;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::document::ProviderState;
use aos_ability_model::identity::{compare_instance_ids, compare_request_ids};
use aos_ability_model::{
    AuthorityGrant, Binding, BindingPlanDocument, Diagnostic, DiagnosticClass, DiagnosticCode,
    DiagnosticPhase, ImplementationKind, InstanceId, InterfaceKey, PackageDocument, PlanId,
    RequestId, RequirementDeclaration, RequirementStrength, ResourceLifetime, ValueExpression,
    VersionedDocument, compare_resource_ids,
};
use aos_contract::Sha256Digest;

use crate::ValidationErrors;
use crate::authority::{ArtifactIndex, authorize_materialized_references};
use crate::error::push_diagnostic;
use crate::graph::{
    BindingProviderState, BindingValidationInputs, CheckedBindingPlan, ValidationContext,
    check_strict_order, diagnostic,
};
use crate::schema::{SchemaPath, validate_value};
use package::{validate_declared_root_requests, validate_package_document};

#[derive(Clone, Debug, Default)]
struct BindingInputIndex {
    packages: BTreeMap<Sha256Digest, usize>,
    package_catalogs: Vec<PackageProviderIndex>,
    inventory_by_instance: BTreeMap<InstanceId, Vec<usize>>,
    enabled_desired_by_instance: BTreeMap<InstanceId, Vec<usize>>,
    in_scope_instances: BTreeSet<InstanceId>,
    requests: BTreeMap<RequestId, usize>,
}

#[derive(Clone, Debug, Default)]
struct PackageProviderIndex {
    providers: BTreeMap<(InterfaceKey, Sha256Digest), usize>,
    exports: BTreeSet<(InterfaceKey, Sha256Digest)>,
}

/// Retains validated binding inputs and indexes for deterministic candidate search.
#[derive(Clone, Debug)]
pub struct PreparedBindingCandidates {
    context: ValidationContext,
    plan: BindingPlanDocument,
    inputs: BindingValidationInputs,
    input_index: BindingInputIndex,
    resources: BTreeSet<aos_ability_model::ResourceId>,
    requests: BTreeMap<RequestId, usize>,
}

impl PreparedBindingCandidates {
    /// Applies the common semantic binding checks to one candidate.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics when the request is unknown or the
    /// candidate violates interface, provider-evidence, authority, guarantee,
    /// lifetime, ordering, resource-scope, or mediation constraints.
    pub fn validate(&self, binding: &Binding) -> Result<(), ValidationErrors> {
        if let Err(error) = preflight_candidate_binding(binding) {
            return Err(ValidationErrors::new(vec![binding_diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                0,
                error.to_string(),
                binding,
            )]));
        }
        let Some(request_index) = self.requests.get(&binding.request) else {
            return Err(ValidationErrors::new(vec![binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                0,
                "binding references an unknown request".to_string(),
                binding,
            )]));
        };
        let mut diagnostics = Vec::new();
        validate_binding(
            &self.context,
            &self.plan,
            &self.inputs,
            &self.input_index,
            binding,
            &self.plan.requests[*request_index],
            &self.resources,
            0,
            &mut diagnostics,
        );

        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::new(diagnostics))
        }
    }
}

fn preflight_candidate_binding(binding: &Binding) -> Result<(), String> {
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    let mut items = binding.guarantees.len();
    for grant in [&binding.caller_grant, &binding.provider_grant] {
        items = items
            .saturating_add(grant.methods.len())
            .saturating_add(grant.contributions.len())
            .saturating_add(grant.resources.len());
        for permission in &grant.resources {
            items = items.saturating_add(permission.operations.len());
        }
    }
    if items as u64 > limits.max_collection_items {
        return Err("binding candidate exceeds the version-1 collection item limit".to_string());
    }
    if binding.implementation.artifact.store_path.len() as u64 > limits.max_string_bytes {
        return Err("binding candidate exceeds the version-1 string limit".to_string());
    }
    let mut writer = CandidateSizeWriter::new(limits.max_document_bytes);
    serde_json::to_writer(&mut writer, binding).map_err(|error| {
        if writer.exceeded {
            "binding candidate exceeds the version-1 encoded byte limit".to_string()
        } else {
            error.to_string()
        }
    })
}

struct CandidateSizeWriter {
    remaining: u64,
    exceeded: bool,
}

impl CandidateSizeWriter {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for CandidateSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "binding candidate exceeds its encoded byte limit",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn prepare_binding_candidates(
    context: &ValidationContext,
    environment_document: &aos_ability_model::EnvironmentDocument,
    desired_state_document: &aos_ability_model::DesiredStateDocument,
    packages: &[PackageDocument],
) -> Result<PreparedBindingCandidates, ValidationErrors> {
    let mut preflight_diagnostics = Vec::new();
    preflight_candidate_inputs(
        environment_document,
        desired_state_document,
        packages,
        &mut preflight_diagnostics,
    );
    if !preflight_diagnostics.is_empty() {
        return Err(ValidationErrors::new(preflight_diagnostics));
    }

    let inputs = BindingValidationInputs {
        environment: environment_document.clone(),
        desired_state: desired_state_document.clone(),
        packages: packages.to_vec(),
    };
    let mut diagnostics = Vec::new();
    let desired_state = match inputs.desired_state.content_digest() {
        Ok(digest) => digest,
        Err(error) => {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["desired_state".to_string()],
                    error.to_string(),
                ),
            );
            return Err(ValidationErrors::new(diagnostics));
        }
    };
    let environment = match inputs.environment.content_digest() {
        Ok(digest) => digest,
        Err(error) => {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["environment".to_string()],
                    error.to_string(),
                ),
            );
            return Err(ValidationErrors::new(diagnostics));
        }
    };
    let resources = merged_resource_revisions(
        &inputs.environment.resources,
        &inputs.desired_state.resources,
    );
    let required_features = inputs
        .environment
        .required_features
        .iter()
        .chain(&inputs.desired_state.required_features)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let plan = BindingPlanDocument {
        schema: BindingPlanDocument::SCHEMA.to_string(),
        required_features,
        desired_state,
        environment,
        policy_revision: inputs.environment.policy_revision,
        requests: inputs.desired_state.child_requests.clone(),
        bindings: Vec::new(),
        resources,
        obligations: Vec::new(),
    };
    let Some(input_index) = validate_binding_inputs(context, &plan, &inputs, &mut diagnostics)
    else {
        return Err(ValidationErrors::new(diagnostics));
    };
    for (index, request) in plan.requests.iter().enumerate() {
        validate_request(
            request,
            index,
            context,
            &input_index.in_scope_instances,
            &mut diagnostics,
        );
    }
    if !diagnostics.is_empty() {
        return Err(ValidationErrors::new(diagnostics));
    }

    let requests = plan
        .requests
        .iter()
        .enumerate()
        .map(|(index, request)| (request.id.clone(), index))
        .collect();
    let resources = plan
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    Ok(PreparedBindingCandidates {
        context: context.clone(),
        plan,
        inputs,
        input_index,
        resources,
        requests,
    })
}

fn preflight_candidate_inputs(
    environment: &aos_ability_model::EnvironmentDocument,
    desired_state: &aos_ability_model::DesiredStateDocument,
    packages: &[PackageDocument],
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (name, result) in [
        ("environment", environment.content_digest()),
        ("desired_state", desired_state.content_digest()),
    ] {
        if let Err(error) = result {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![name.to_string()],
                    error.to_string(),
                ),
            );
        }
    }

    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    if packages.len() > limits.max_graph_nodes as usize {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["packages".to_string()],
                "package input catalog exceeds the version-1 entry limit".to_string(),
            ),
        );
        return;
    }

    let mut aggregate_bytes = 0_u64;
    for (index, package) in packages.iter().enumerate() {
        match aos_ability_model::encode_canonical(package) {
            Ok(bytes) => aggregate_bytes = aggregate_bytes.saturating_add(bytes.len() as u64),
            Err(error) => push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string(), index.to_string()],
                    error.to_string(),
                ),
            ),
        }
        if aggregate_bytes > limits.max_document_bytes {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::LimitExceeded,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string()],
                    "package input catalog exceeds the version-1 aggregate byte limit".to_string(),
                ),
            );
            break;
        }
    }
}

pub(crate) fn validate_binding_document(
    context: &ValidationContext,
    document: BindingPlanDocument,
    inputs: BindingValidationInputs,
) -> Result<CheckedBindingPlan, ValidationErrors> {
    let mut diagnostics = Vec::new();

    let id = match document.content_digest() {
        Ok(digest) => PlanId(digest),
        Err(error) => {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    Vec::new(),
                    error.to_string(),
                ),
            );
            return Err(ValidationErrors::new(diagnostics));
        }
    };
    for feature in &document.required_features {
        if !context.supported_features().contains(feature) {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedRequiredFeature,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["required_features".to_string()],
                    format!("unsupported required feature '{}'", feature.as_str()),
                ),
            );
        }
    }

    let Some(input_index) = validate_binding_inputs(context, &document, &inputs, &mut diagnostics)
    else {
        return Err(ValidationErrors::new(diagnostics));
    };

    check_order_by(
        &document.requests,
        |left, right| compare_request_ids(&left.id, &right.id),
        "requests",
        &mut diagnostics,
    );
    check_order_by(
        &document.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "resources",
        &mut diagnostics,
    );
    for (index, resource) in document.resources.iter().enumerate() {
        if !input_index
            .in_scope_instances
            .contains(&resource.resource.provider)
        {
            let mut item = diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                vec!["resources".to_string(), index.to_string()],
                "plan resource provider is outside the supplied environment and desired state"
                    .to_string(),
            );
            item.resource = Some(resource.resource.clone());
            push_diagnostic(&mut diagnostics, item);
        }
    }
    check_order_by(
        &document.bindings,
        |left, right| left.id.cmp(&right.id),
        "bindings",
        &mut diagnostics,
    );
    check_order_by(
        &document.obligations,
        |left, right| left.key.cmp(&right.key),
        "obligations",
        &mut diagnostics,
    );

    let requests: BTreeMap<_, _> = document
        .requests
        .iter()
        .enumerate()
        .map(|(index, request)| (request.id.clone(), index))
        .collect();
    let resources: BTreeSet<_> = document
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    let mut request_bindings: BTreeMap<RequestId, usize> = BTreeMap::new();
    let mut request_obligations: BTreeMap<RequestId, usize> = BTreeMap::new();
    let mut binding_indices = BTreeMap::new();
    let mut provider_states = BTreeMap::new();
    let mut planned_providers = BTreeSet::new();

    for (index, binding) in document.bindings.iter().enumerate() {
        if binding_indices.insert(binding.id.clone(), index).is_some() {
            push_diagnostic(
                &mut diagnostics,
                binding_diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    DiagnosticClass::InvalidContract,
                    index,
                    "duplicate binding identity".to_string(),
                    binding,
                ),
            );
        }
        *request_bindings.entry(binding.request.clone()).or_default() += 1;

        let Some(request_index) = requests.get(&binding.request) else {
            push_diagnostic(
                &mut diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    index,
                    "binding references an unknown request".to_string(),
                    binding,
                ),
            );
            continue;
        };
        let request = &document.requests[*request_index];
        let provider_state = validate_binding(
            context,
            &document,
            &inputs,
            &input_index,
            binding,
            request,
            &resources,
            index,
            &mut diagnostics,
        );
        provider_states.insert(binding.id.clone(), provider_state);
        if provider_state == BindingProviderState::Planned {
            planned_providers.insert(binding.provider.clone());
        }
    }

    validate_contributions(
        context,
        &document,
        &inputs,
        &input_index,
        &binding_indices,
        &resources,
        &mut diagnostics,
    );

    for (index, obligation) in document.obligations.iter().enumerate() {
        *request_obligations
            .entry(obligation.request.clone())
            .or_default() += 1;
        if !requests.contains_key(&obligation.request) {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![
                    "obligations".to_string(),
                    index.to_string(),
                    "request".to_string(),
                ],
                "obligation references an unknown request".to_string(),
            );
            item.request = Some(obligation.request.clone());
            push_diagnostic(&mut diagnostics, item);
        }
        if obligation
            .resource
            .as_ref()
            .is_some_and(|resource| !resources.contains(resource))
        {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![
                    "obligations".to_string(),
                    index.to_string(),
                    "resource".to_string(),
                ],
                "obligation references an unknown plan resource".to_string(),
            );
            item.request = Some(obligation.request.clone());
            item.resource = obligation.resource.clone();
            push_diagnostic(&mut diagnostics, item);
        }
    }

    for (index, request) in document.requests.iter().enumerate() {
        validate_request(
            request,
            index,
            context,
            &input_index.in_scope_instances,
            &mut diagnostics,
        );
        let binding_count = request_bindings
            .get(&request.id)
            .copied()
            .unwrap_or_default();
        let obligation_count = request_obligations
            .get(&request.id)
            .copied()
            .unwrap_or_default();
        if binding_count > 1 || (binding_count == 1 && obligation_count != 0) {
            let mut item = diagnostic(
                DiagnosticCode::DuplicateIdentity,
                DiagnosticClass::AmbiguousBinding,
                DiagnosticPhase::Binding,
                vec!["requests".to_string(), index.to_string()],
                "request must have one binding or one or more unresolved obligations, never both"
                    .to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(&mut diagnostics, item);
        } else if binding_count == 0 && obligation_count == 0 {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnsatisfiedObligation,
                DiagnosticPhase::Binding,
                vec!["requests".to_string(), index.to_string()],
                "request has neither a binding nor an explicit deployment obligation".to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(&mut diagnostics, item);
        }
    }

    if diagnostics.is_empty() {
        let executable = document.obligations.is_empty() && planned_providers.is_empty();
        Ok(CheckedBindingPlan {
            id,
            document,
            inputs,
            binding_indices,
            provider_states,
            planned_providers,
            executable,
        })
    } else {
        Err(ValidationErrors::new(diagnostics))
    }
}

fn validate_binding_inputs(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BindingInputIndex> {
    let environment_digest =
        validate_input_document(context, &inputs.environment, "environment", diagnostics)?;
    let desired_digest =
        validate_input_document(context, &inputs.desired_state, "desired_state", diagnostics)?;
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    if inputs.packages.len() > limits.max_graph_nodes as usize {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["packages".to_string()],
                "package input catalog exceeds the version-1 entry limit".to_string(),
            ),
        );
        return None;
    }

    let mut package_digests = Vec::with_capacity(inputs.packages.len());
    let mut aggregate_package_bytes = 0_u64;
    for package in &inputs.packages {
        let digest = validate_input_document(context, package, "packages", diagnostics)?;
        let encoded_len = match aos_ability_model::encode_canonical(package) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => return None,
        };
        aggregate_package_bytes = aggregate_package_bytes.saturating_add(encoded_len);
        if aggregate_package_bytes > limits.max_document_bytes {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::LimitExceeded,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string()],
                    "package input catalog exceeds the version-1 aggregate byte limit".to_string(),
                ),
            );
            return None;
        }
        package_digests.push(digest);
    }

    let mut input_index = BindingInputIndex {
        package_catalogs: (0..inputs.packages.len())
            .map(|_| PackageProviderIndex::default())
            .collect(),
        ..BindingInputIndex::default()
    };
    for (provider_index, provider) in inputs.environment.providers.iter().enumerate() {
        input_index
            .inventory_by_instance
            .entry(provider.provider.clone())
            .or_default()
            .push(provider_index);
        if provider.provider.environment == inputs.environment.environment {
            input_index
                .in_scope_instances
                .insert(provider.provider.clone());
        }
    }
    for (desired_index, desired) in inputs.desired_state.instances.iter().enumerate() {
        if !desired.enabled {
            continue;
        }
        input_index
            .enabled_desired_by_instance
            .entry(desired.instance.clone())
            .or_default()
            .push(desired_index);
        if desired.instance.environment == inputs.environment.environment {
            input_index
                .in_scope_instances
                .insert(desired.instance.clone());
        }
    }
    for (request_index, request) in inputs.desired_state.child_requests.iter().enumerate() {
        input_index
            .requests
            .entry(request.id.clone())
            .or_insert(request_index);
    }

    if environment_digest != plan.environment {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["environment".to_string()],
                "binding plan environment digest does not match the supplied document".to_string(),
            ),
        );
    }
    if desired_digest != plan.desired_state {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["desired_state".to_string()],
                "binding plan desired-state digest does not match the supplied document"
                    .to_string(),
            ),
        );
    }
    if plan.requests != inputs.desired_state.child_requests {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["requests".to_string()],
                "binding-plan requests do not exactly match the committed desired-state requests"
                    .to_string(),
            ),
        );
    }
    let expected_resources = merged_resource_revisions(
        &inputs.environment.resources,
        &inputs.desired_state.resources,
    );
    if plan.resources != expected_resources {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["resources".to_string()],
                "binding-plan resources do not exactly match the canonical current and desired resource union"
                    .to_string(),
            ),
        );
    }
    if inputs.desired_state.environment != environment_digest
        || inputs.environment.policy_revision != plan.policy_revision
    {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                vec!["policy_revision".to_string()],
                "desired environment or policy commitment is inconsistent with binding inputs"
                    .to_string(),
            ),
        );
    }

    check_order_by(
        &inputs.environment.providers,
        |left, right| {
            compare_instance_ids(&left.provider, &right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
        },
        "environment.providers",
        diagnostics,
    );
    check_order_by(
        &inputs.environment.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "environment.resources",
        diagnostics,
    );
    check_order_by(
        &inputs.environment.controllers,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "environment.controllers",
        diagnostics,
    );
    for (index, provider) in inputs.environment.providers.iter().enumerate() {
        if provider.provider.environment != inputs.environment.environment {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::BindingPrincipalMismatch,
                    DiagnosticClass::Unauthorized,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                    ],
                    "provider inventory entry belongs to a different environment".to_string(),
                ),
            );
        }
        if context.interface(&provider.interface).is_none() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                    ],
                    "provider inventory names an interface absent from the validated catalog"
                        .to_string(),
                ),
            );
        }
        let incarnation_is_valid = match provider.state {
            ProviderState::Available => provider.incarnation.is_some(),
            ProviderState::Declared
            | ProviderState::Planned
            | ProviderState::Unavailable
            | ProviderState::Stale => provider.incarnation.is_none(),
        };
        if !incarnation_is_valid {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                        "incarnation".to_string(),
                    ],
                    "exactly available provider inventory must carry a live incarnation"
                        .to_string(),
                ),
            );
        }
        check_strict_order(
            &provider.guarantees,
            &SchemaPath::root()
                .child("environment")
                .child("providers")
                .child(index.to_string())
                .child("guarantees"),
            diagnostics,
        );
    }

    check_order_by(
        &inputs.desired_state.instances,
        |left, right| compare_instance_ids(&left.instance, &right.instance),
        "desired_state.instances",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.child_requests,
        |left, right| compare_request_ids(&left.id, &right.id),
        "desired_state.child_requests",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "desired_state.resources",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.outputs,
        |left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.interface.cmp(&right.interface))
                .then_with(|| left.port.cmp(&right.port))
        },
        "desired_state.outputs",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.controllers,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "desired_state.controllers",
        diagnostics,
    );
    validate_controller_continuity(inputs, diagnostics);
    for (index, desired) in inputs.desired_state.instances.iter().enumerate() {
        if desired.instance.environment != inputs.environment.environment {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::BindingPrincipalMismatch,
                    DiagnosticClass::Unauthorized,
                    DiagnosticPhase::Binding,
                    vec![
                        "desired_state".to_string(),
                        "instances".to_string(),
                        index.to_string(),
                    ],
                    "desired instance belongs to a different environment".to_string(),
                ),
            );
        }
    }

    for (index, (package, digest)) in inputs
        .packages
        .iter()
        .zip(package_digests.iter().copied())
        .enumerate()
    {
        if input_index.packages.insert(digest, index).is_some() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string(), index.to_string()],
                    "duplicate exact package document".to_string(),
                ),
            );
        }
        input_index.package_catalogs[index] =
            validate_package_document(context, package, index, diagnostics);
    }
    check_strict_order(
        &package_digests,
        &SchemaPath::root().child("packages"),
        diagnostics,
    );
    for (index, desired) in inputs.desired_state.instances.iter().enumerate() {
        if !input_index.packages.contains_key(&desired.package) {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![
                        "desired_state".to_string(),
                        "instances".to_string(),
                        index.to_string(),
                    ],
                    "desired instance references a package absent from the exact input catalog"
                        .to_string(),
                ),
            );
            continue;
        }
        let package = &inputs.packages[input_index.packages[&desired.package]];
        validate_declared_root_requests(
            desired,
            package,
            &inputs.desired_state.child_requests,
            &input_index.requests,
            index,
            diagnostics,
        );
    }
    Some(input_index)
}

fn validate_controller_continuity(
    inputs: &BindingValidationInputs,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let current_resources: BTreeSet<_> = inputs
        .environment
        .resources
        .iter()
        .map(|revision| &revision.resource)
        .collect();
    let desired_resources: BTreeSet<_> = inputs
        .desired_state
        .resources
        .iter()
        .map(|revision| &revision.resource)
        .collect();
    let current_controllers: BTreeMap<_, _> = inputs
        .environment
        .controllers
        .iter()
        .map(|assignment| (&assignment.resource, &assignment.controller))
        .collect();

    for assignment in &inputs.desired_state.controllers {
        if current_resources.contains(&assignment.resource)
            && desired_resources.contains(&assignment.resource)
            && current_controllers
                .get(&assignment.resource)
                .is_some_and(|current| *current != &assignment.controller)
        {
            let mut item = diagnostic(
                DiagnosticCode::ConflictingController,
                DiagnosticClass::ResourceConflict,
                DiagnosticPhase::Binding,
                vec!["desired_state".to_string(), "controllers".to_string()],
                "retained resource changes lifecycle controller without an explicit transfer contract"
                    .to_string(),
            );
            item.resource = Some(assignment.resource.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

fn merged_resource_revisions(
    current: &[aos_ability_model::ResourceRevision],
    desired: &[aos_ability_model::ResourceRevision],
) -> Vec<aos_ability_model::ResourceRevision> {
    let mut revisions: BTreeMap<_, _> = current
        .iter()
        .map(|revision| (revision.resource.clone(), revision.clone()))
        .collect();
    revisions.extend(
        desired
            .iter()
            .map(|revision| (revision.resource.clone(), revision.clone())),
    );
    revisions.into_values().collect()
}

fn validate_input_document<T: VersionedDocument>(
    context: &ValidationContext,
    document: &T,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Sha256Digest> {
    for feature in document.required_features() {
        if !context.supported_features().contains(feature) {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedRequiredFeature,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![field.to_string(), "required_features".to_string()],
                    format!("unsupported required feature '{}'", feature.as_str()),
                ),
            );
        }
    }
    match document.content_digest() {
        Ok(digest) => Some(digest),
        Err(error) => {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![field.to_string()],
                    error.to_string(),
                ),
            );
            None
        }
    }
}

fn validate_request(
    request: &aos_ability_model::BindingRequest,
    index: usize,
    context: &ValidationContext,
    in_scope_instances: &BTreeSet<InstanceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_strict_order(
        &request.methods,
        &SchemaPath::root()
            .child("requests")
            .child(index.to_string())
            .child("methods"),
        diagnostics,
    );
    check_strict_order(
        &request.guarantees,
        &SchemaPath::root()
            .child("requests")
            .child(index.to_string())
            .child("guarantees"),
        diagnostics,
    );
    if request.accepted_interfaces.is_empty() {
        let mut item = diagnostic(
            DiagnosticCode::BindingInterfaceMismatch,
            DiagnosticClass::IncompatibleInterface,
            DiagnosticPhase::Binding,
            vec![
                "requests".to_string(),
                index.to_string(),
                "accepted_interfaces".to_string(),
            ],
            "request must name at least one exact accepted interface".to_string(),
        );
        item.request = Some(request.id.clone());
        push_diagnostic(diagnostics, item);
    }
    if !in_scope_instances.contains(&request.id.consumer) {
        let mut item = diagnostic(
            DiagnosticCode::BindingPrincipalMismatch,
            DiagnosticClass::Unauthorized,
            DiagnosticPhase::Binding,
            vec!["requests".to_string(), index.to_string(), "id".to_string()],
            "request consumer is outside the supplied environment and desired state".to_string(),
        );
        item.request = Some(request.id.clone());
        push_diagnostic(diagnostics, item);
    }
    for interface in &request.accepted_interfaces {
        if context.interface(interface).is_none() {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::IncompatibleInterface,
                DiagnosticPhase::Binding,
                vec![
                    "requests".to_string(),
                    index.to_string(),
                    "accepted_interfaces".to_string(),
                ],
                "request names an interface absent from the validated catalog".to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

fn validate_binding(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    binding: &Binding,
    request: &aos_ability_model::BindingRequest,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> BindingProviderState {
    let interface = context.interface(&binding.interface);
    if !request.accepted_interfaces.contains(&binding.interface) {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding interface is not one of the request's exact descriptors".to_string(),
                binding,
            ),
        );
    }
    let Some(interface) = interface else {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding interface is absent from the validated catalog".to_string(),
                binding,
            ),
        );
        return BindingProviderState::Unavailable;
    };

    let planned_provider =
        validate_provider_evidence(binding, inputs, input_index, index, diagnostics);
    let aggregation = binding_aggregation(inputs, input_index, binding);

    if binding.policy_revision != plan.policy_revision {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                index,
                "binding policy revision differs from the plan commitment".to_string(),
                binding,
            ),
        );
    }
    if binding.caller_grant.principal != request.id.consumer
        || binding.provider_grant.principal != binding.provider
    {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                index,
                "caller/provider grant principals do not match the request and selected provider"
                    .to_string(),
                binding,
            ),
        );
    }
    if binding.lifetime < request.lifetime {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding lifetime is shorter than the requested lifetime".to_string(),
                binding,
            ),
        );
    }

    check_strict_order(
        &binding.guarantees,
        &SchemaPath::root()
            .child("bindings")
            .child(index.to_string())
            .child("guarantees"),
        diagnostics,
    );
    for guarantee in &request.guarantees {
        if !binding.guarantees.contains(guarantee)
            || !interface.interface.guarantees.contains(guarantee)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingGuarantee,
                    DiagnosticClass::IncompatibleInterface,
                    index,
                    "binding does not supply an exact requested interface guarantee".to_string(),
                    binding,
                ),
            );
        }
    }
    for guarantee in &binding.guarantees {
        if !interface.interface.guarantees.contains(guarantee) {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingGuarantee,
                    DiagnosticClass::IncompatibleInterface,
                    index,
                    "binding asserts a guarantee absent from its exact interface descriptor"
                        .to_string(),
                    binding,
                ),
            );
        }
    }
    for method in &request.methods {
        if !interface.interface.methods.contains_key(method)
            || !binding.caller_grant.methods.contains(method)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MethodNotGranted,
                    DiagnosticClass::Unauthorized,
                    index,
                    "requested method is absent from the interface or caller grant".to_string(),
                    binding,
                ),
            );
        }
    }
    validate_grant_methods(
        &binding.caller_grant,
        binding,
        interface,
        index,
        "caller_grant",
        diagnostics,
    );
    validate_grant_methods(
        &binding.provider_grant,
        binding,
        interface,
        index,
        "provider_grant",
        diagnostics,
    );
    if !binding.mediation_allowed
        && (!binding.provider_grant.methods.is_empty()
            || !binding.provider_grant.contributions.is_empty()
            || !binding.provider_grant.resources.is_empty())
    {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MediationNotGranted,
                DiagnosticClass::Unauthorized,
                index,
                "provider implementation authority requires explicit mediation permission"
                    .to_string(),
                binding,
            ),
        );
    }

    validate_grant(
        &binding.caller_grant,
        binding,
        resources,
        aggregation,
        index,
        "caller_grant",
        diagnostics,
    );
    validate_grant(
        &binding.provider_grant,
        binding,
        resources,
        aggregation,
        index,
        "provider_grant",
        diagnostics,
    );
    planned_provider
}

fn validate_provider_evidence(
    binding: &Binding,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> BindingProviderState {
    let mut exact_provider_found = false;
    let mut provider_state = BindingProviderState::Unavailable;
    let pinned_package_kind = binding.provider_package.and_then(|digest| {
        input_index.packages.get(&digest).and_then(|package_index| {
            package_supplies_binding(
                &inputs.packages[*package_index],
                &input_index.package_catalogs[*package_index],
                binding,
            )
        })
    });
    if binding.provider_package.is_some() && pinned_package_kind.is_none() {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "binding's exact provider package does not supply its implementation and export"
                    .to_string(),
                binding,
            ),
        );
    }
    if pinned_package_kind == Some(PackageProviderKind::PureComposition) {
        exact_provider_found = true;
        provider_state = BindingProviderState::PureComposition;
    }
    if binding.provider_package.is_none() && binding.implementation.handler.is_none() {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "pure composition binding requires an exact provider package pin".to_string(),
                binding,
            ),
        );
    }

    for inventory_index in input_index
        .inventory_by_instance
        .get(&binding.provider)
        .into_iter()
        .flatten()
    {
        let inventory = &inputs.environment.providers[*inventory_index];
        let reference_matches = inventory.interface == binding.interface
            && inventory.implementation == binding.implementation;
        let state_is_usable = matches!(
            inventory.state,
            ProviderState::Planned | ProviderState::Available
        );
        let package_evidence_valid = match binding.provider_package {
            Some(_) => pinned_package_kind.is_some(),
            None => binding.implementation.handler.is_some(),
        };
        if !reference_matches || !state_is_usable || !package_evidence_valid {
            continue;
        }

        exact_provider_found = true;
        provider_state = match inventory.state {
            ProviderState::Available => BindingProviderState::Available,
            ProviderState::Planned => BindingProviderState::Planned,
            ProviderState::Declared | ProviderState::Unavailable | ProviderState::Stale => {
                BindingProviderState::Unavailable
            }
        };
        for guarantee in &binding.guarantees {
            if !inventory.guarantees.contains(guarantee) {
                push_diagnostic(
                    diagnostics,
                    binding_diagnostic(
                        DiagnosticCode::MissingGuarantee,
                        DiagnosticClass::UnavailableProvider,
                        index,
                        "binding asserts a guarantee absent from the selected provider inventory"
                            .to_string(),
                        binding,
                    ),
                );
            }
        }
    }

    if !exact_provider_found {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "binding has no exact usable environment inventory or desired-package provider evidence"
                    .to_string(),
                binding,
            ),
        );
    }
    provider_state
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PackageProviderKind {
    PureComposition,
    TerminalHandler,
}

fn package_supplies_binding(
    package: &PackageDocument,
    package_index: &PackageProviderIndex,
    binding: &Binding,
) -> Option<PackageProviderKind> {
    let provider_index = package_index
        .providers
        .get(&(binding.interface.clone(), binding.implementation.descriptor))?;
    let implementation = &package.implementation.providers[*provider_index];
    if implementation.artifact != binding.implementation.artifact {
        return None;
    }
    if !package_index
        .exports
        .contains(&(binding.interface.clone(), binding.implementation.descriptor))
    {
        return None;
    }

    match &implementation.implementation {
        ImplementationKind::PureComposition {
            compose_entry,
            transition_entry,
        } => (binding.implementation.handler.is_none()
            && package.module_entry_points.get(compose_entry)
                == Some(&binding.implementation.artifact)
            && package.module_entry_points.get(transition_entry)
                == Some(&binding.implementation.artifact))
        .then_some(PackageProviderKind::PureComposition),
        ImplementationKind::TerminalHandler { handler } => {
            (binding.implementation.handler.as_ref() == Some(handler)
                && package
                    .implementation
                    .handlers
                    .get(handler)
                    .is_some_and(|descriptor| {
                        descriptor.artifact == binding.implementation.artifact
                    }))
            .then_some(PackageProviderKind::TerminalHandler)
        }
    }
}

fn validate_grant_methods(
    grant: &AuthorityGrant,
    binding: &Binding,
    interface: &aos_ability_model::InterfaceDocument,
    index: usize,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for method in &grant.methods {
        if !interface.interface.methods.contains_key(method) {
            let mut item = binding_diagnostic(
                DiagnosticCode::MethodNotGranted,
                DiagnosticClass::Unauthorized,
                index,
                "grant names a method absent from the binding's exact interface descriptor"
                    .to_string(),
                binding,
            );
            item.path.push(field.to_string());
            item.path.push("methods".to_string());
            push_diagnostic(diagnostics, item);
        }
    }
}

fn validate_grant(
    grant: &AuthorityGrant,
    binding: &Binding,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    aggregation: Option<&aos_ability_model::AggregationContract>,
    index: usize,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let root = SchemaPath::root()
        .child("bindings")
        .child(index.to_string())
        .child(field.to_string());
    check_strict_order(&grant.methods, &root.child("methods"), diagnostics);
    check_order_by(
        &grant.contributions,
        |left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.slot.cmp(&right.slot))
        },
        "contributions",
        diagnostics,
    );
    for permission in &grant.contributions {
        if permission.aggregate.provider != binding.provider
            || aggregation
                .is_none_or(|contract| contract.controller_group != permission.aggregate.group)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::ResourceScopeEscape,
                    DiagnosticClass::Unauthorized,
                    index,
                    "contribution permission differs from the selected provider's authenticated aggregate"
                        .to_string(),
                    binding,
                ),
            );
        }
    }
    check_order_by(
        &grant.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        field,
        diagnostics,
    );
    for (permission_index, permission) in grant.resources.iter().enumerate() {
        check_strict_order(
            &permission.operations,
            &root
                .child("resources")
                .child(permission_index.to_string())
                .child("operations"),
            diagnostics,
        );
        if !resources.contains(&permission.resource)
            || permission.resource.provider != binding.provider
        {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                index,
                "grant resource is outside the selected provider's authenticated plan resources"
                    .to_string(),
                binding,
            );
            item.resource = Some(permission.resource.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

fn validate_contributions(
    context: &ValidationContext,
    document: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    binding_indices: &BTreeMap<aos_ability_model::BindingId, usize>,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut occupied_slots = BTreeSet::new();
    let artifacts = retained_contribution_artifacts(inputs);
    for (index, contribution) in inputs.desired_state.contributions.iter().enumerate() {
        let path = SchemaPath::root()
            .child("desired_state")
            .child("contributions")
            .child(index.to_string());
        let Some(binding_index) = binding_indices.get(&contribution.grant) else {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                path.child("grant").components().to_vec(),
                "contribution references no selected binding caller grant".to_string(),
            );
            item.request = Some(contribution.request.clone());
            push_diagnostic(diagnostics, item);
            continue;
        };
        let binding = &document.bindings[*binding_index];
        let aggregation = binding_aggregation(inputs, input_index, binding);
        let authorized = binding.caller_grant.contributions.iter().any(|permission| {
            permission.aggregate == contribution.aggregate && permission.slot == contribution.slot
        });
        if binding.request != contribution.request
            || contribution.aggregate.provider != binding.provider
            || aggregation
                .is_none_or(|contract| contract.controller_group != contribution.aggregate.group)
            || !authorized
        {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                *binding_index,
                "contribution request, aggregate, or slot exceeds its selected caller grant"
                    .to_string(),
                binding,
            );
            item.path = path.components().to_vec();
            push_diagnostic(diagnostics, item);
        }
        if !occupied_slots.insert((contribution.aggregate.clone(), contribution.slot.clone()))
            && aggregation.is_none_or(|contract| contract.reject_slot_collisions)
        {
            let mut item = diagnostic(
                DiagnosticCode::DuplicateIdentity,
                DiagnosticClass::ResourceConflict,
                DiagnosticPhase::Binding,
                path.child("slot").components().to_vec(),
                "multiple contributions claim one exact aggregate slot".to_string(),
            );
            item.request = Some(contribution.request.clone());
            push_diagnostic(diagnostics, item);
        }
        let Some(interface) = context.interface(&binding.interface) else {
            continue;
        };
        let expression = ValueExpression::Literal {
            value: contribution.value.clone(),
        };
        if let Err(errors) = validate_value(&interface.interface.request, &expression) {
            for mut item in errors.into_diagnostics() {
                let mut prefixed = path.child("value").components().to_vec();
                prefixed.extend(item.path);
                item.path = prefixed;
                item.phase = DiagnosticPhase::Binding;
                item.request = Some(contribution.request.clone());
                push_diagnostic(diagnostics, item);
            }
            continue;
        }

        if let Err(error) = authorize_materialized_references(
            context.interface_catalog(),
            binding,
            &binding.caller_grant,
            &interface.interface.request,
            &contribution.value,
            &artifacts,
            resources,
            binding.lifetime,
            None,
        ) {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                *binding_index,
                format!("contribution value exceeds retained caller authority: {error}"),
                binding,
            );
            item.path = path.child("value").components().to_vec();
            push_diagnostic(diagnostics, item);
        }
    }
}

fn retained_contribution_artifacts(inputs: &BindingValidationInputs) -> ArtifactIndex {
    let mut artifacts = ArtifactIndex::new();
    for inventory in &inputs.environment.providers {
        insert_artifact(&mut artifacts, &inventory.implementation.artifact);
    }
    for package in &inputs.packages {
        insert_artifact(&mut artifacts, &package.package.payload);
        insert_artifact(&mut artifacts, &package.package.source);
        for artifact in &package.artifacts {
            insert_artifact(&mut artifacts, artifact);
        }
        for artifact in package.module_entry_points.values() {
            insert_artifact(&mut artifacts, artifact);
        }
        for provider in &package.implementation.providers {
            insert_artifact(&mut artifacts, &provider.artifact);
        }
        for handler in package.implementation.handlers.values() {
            insert_artifact(&mut artifacts, &handler.artifact);
        }
    }
    artifacts
}

fn insert_artifact(index: &mut ArtifactIndex, artifact: &aos_ability_model::ArtifactReference) {
    index
        .entry(artifact.content)
        .or_insert_with(|| artifact.clone());
}

fn binding_aggregation<'a>(
    inputs: &'a BindingValidationInputs,
    input_index: &BindingInputIndex,
    binding: &Binding,
) -> Option<&'a aos_ability_model::AggregationContract> {
    let package = binding
        .provider_package
        .and_then(|digest| input_index.packages.get(&digest))
        .map(|index| &inputs.packages[*index])?;
    package
        .exports
        .iter()
        .find(|export| {
            export.interface == binding.interface
                && export.implementation == binding.implementation.descriptor
        })
        .and_then(|export| export.aggregation.as_ref())
}

fn check_order_by<T>(
    values: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !values
        .windows(2)
        .all(|pair| compare(&pair[0], &pair[1]) == Ordering::Less)
    {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::NonCanonicalOrder,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![field.to_string()],
                "values must be strictly sorted without duplicate identities".to_string(),
            ),
        );
    }
}

fn binding_diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    index: usize,
    message: String,
    binding: &Binding,
) -> Diagnostic {
    let mut item = diagnostic(
        code,
        class,
        DiagnosticPhase::Binding,
        vec!["bindings".to_string(), index.to_string()],
        message,
    );
    item.request = Some(binding.request.clone());
    item
}

#[allow(dead_code)]
fn lifetime_covers(available: ResourceLifetime, requested: ResourceLifetime) -> bool {
    available >= requested
}
