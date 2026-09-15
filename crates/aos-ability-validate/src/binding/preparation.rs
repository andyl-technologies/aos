//! Candidate preparation before complete binding-plan validation.

use super::*;

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
    let mut writer = BoundedWriter::new(
        limits.max_document_bytes,
        "binding candidate exceeds its encoded byte limit",
    );
    serde_json::to_writer(&mut writer, binding).map_err(|error| {
        if writer.exceeded() {
            "binding candidate exceeds the version-1 encoded byte limit".to_string()
        } else {
            error.to_string()
        }
    })
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
            &input_index.request_packages,
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
