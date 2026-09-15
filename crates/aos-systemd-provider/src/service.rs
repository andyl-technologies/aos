//! Runtime reconciliation for provider-neutral services realized by systemd.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics, ResourceId,
    ResourceReference, RevisionId,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};
use serde_json::{Map, Value};

use crate::materialize::{
    ServicePaths, materialize_service, remove_service, service_is_absent, service_matches,
    service_paths_for,
};
use crate::model::{
    PROVIDER_CONTEXT_SCHEMA, ProviderContext, SERVICE_REALIZATION_SCHEMA, ServiceFacetIdentity,
    ServiceRealization, empty_outputs,
};
use crate::render::{RenderedService, render_service};
use crate::{decode_value, provider_context, require_resource_contexts, target_context, value};

const ETC_ROOT: &str = "/etc";
const SERVICE_LIFECYCLE_INTERFACE: &str = "aos.service.lifecycle";
const SERVICE_READINESS_INTERFACE: &str = "aos.service.readiness";
const SERVICE_RELOAD_INTERFACE: &str = "aos.service.reload";
const SERVICE_TEMPLATE_DEFINITION_INTERFACE: &str = "aos.service.template-definition";

pub(crate) async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;

    let realization: ServiceRealization = decode_value(&request.resource_spec.realization)?;
    let rendered = render_service(&realization)?;
    let facet = require_method(&request.method, &request.semantics, &realization)?;
    let expected = expected_request(&request.resource_spec.value, facet)?;
    let references = all_service_resource_references(&request.resource_spec.value, &realization)?;
    require_resource_contexts(&references, &request.resources)?;
    validate_template_reuse(
        &request.resource_spec.value,
        &realization,
        &request.resources,
    )?;
    let paths = service_paths_for(
        Path::new(ETC_ROOT),
        &rendered.primary_unit,
        request.resource_spec.revision,
        &rendered,
    );

    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect(
        &manager,
        facet,
        &expected,
        &realization,
        &request.resource_spec.resource,
        request.resource_spec.revision,
        &rendered,
        &paths,
        Goal::Desired,
    )
    .await?;
    let context = provider_context(
        &manager,
        inspection.unit_identity.clone(),
        inspection.files_match,
    )?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if inspection.files_match && inspection.manager_is_current {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation: inspection.observation,
        native_context: context,
        supported_purposes,
    })
}

pub(crate) async fn invoke(invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("invocation method is not bound to its durable recovery contract");
    }
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;

    let realization: ServiceRealization = decode_value(&bound.resource_spec.realization)?;
    let rendered = render_service(&realization)?;
    let selected_facet = require_method(&invocation.method, &invocation.semantics, &realization)?;
    let primary_facet = require_method(
        &invocation.request.method,
        &invocation.request.semantics,
        &realization,
    )?;
    if selected_facet.interface != primary_facet.interface {
        bail!("service recovery cannot cross feature interfaces");
    }
    let expected = expected_request(&bound.resource_spec.value, primary_facet)?;
    if invocation.request.inputs != expected {
        bail!("invocation inputs differ from the checked service facet");
    }
    let references = all_service_resource_references(&bound.resource_spec.value, &realization)?;
    require_resource_contexts(&references, &invocation.request.resources)?;
    validate_template_reuse(
        &bound.resource_spec.value,
        &realization,
        &invocation.request.resources,
    )?;

    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != PROVIDER_CONTEXT_SCHEMA {
        bail!("unsupported provider context schema");
    }
    let manager = PinnedSystemdManager::connect().await?;
    if manager.incarnation().bus_id() != provider.manager_bus_id
        || manager.incarnation().owner() != provider.manager_owner
    {
        bail!("systemd manager changed after admission");
    }
    let paths = service_paths_for(
        Path::new(ETC_ROOT),
        &rendered.primary_unit,
        bound.resource_spec.revision,
        &rendered,
    );

    let primary_method = invocation.request.method.method.as_str();
    let selected_method = invocation.method.method.as_str();
    let goal = match primary_method {
        "stop" => Goal::Stopped,
        "release" => Goal::Absent,
        _ => Goal::Desired,
    };
    if invocation.purpose == InvocationPurpose::Effect {
        apply_method(
            &manager,
            selected_method,
            &realization,
            &bound.resource_spec.resource,
            bound.resource_spec.revision,
            &rendered,
            &paths,
        )
        .await?;
    } else if invocation.purpose != InvocationPurpose::Reconcile || selected_method != "observe" {
        bail!("systemd service provider does not advertise this invocation purpose");
    }

    let inspection = inspect(
        &manager,
        primary_facet,
        &expected,
        &realization,
        &bound.resource_spec.resource,
        bound.resource_spec.revision,
        &rendered,
        &paths,
        goal,
    )
    .await?;
    let disposition = if inspection.complete {
        InvocationDisposition::Completed
    } else {
        InvocationDisposition::SafeToRetry
    };
    let outputs = if inspection.complete {
        outputs_for(primary_method, &inspection.observation, &invocation)?
    } else {
        empty_outputs()
    };

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition,
        evidence: inspection.observation,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

async fn apply_method(
    manager: &PinnedSystemdManager,
    method: &str,
    realization: &ServiceRealization,
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
    paths: &ServicePaths,
) -> Result<()> {
    let unit_name = &rendered.primary_unit;
    match method {
        "observe" => return Ok(()),
        "start" | "restart" | "reload" | "materialize" => {
            materialize_service(Path::new(ETC_ROOT), unit_name, revision, resource, rendered)?;
            manager.daemon_reload().await?;
        }
        "release" => {
            remove_service(paths, rendered, resource, revision)?;
            manager.daemon_reload().await?;
            return Ok(());
        }
        "stop" => {}
        _ => bail!("unsupported systemd service effect method"),
    }

    let identity = match manager.unit_identity(unit_name).await {
        Ok(identity) => identity,
        Err(error) if error.is_no_such_unit() && method == "stop" => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if method == "materialize" {
        return Ok(());
    }
    if !realization.enabled && method != "stop" {
        if manager.is_active_exact(unit_name, &identity).await? {
            let outcome = manager.stop_unit_exact(unit_name, &identity).await?;
            if !outcome.result.is_done() {
                bail!("systemd stop job completed as {}", outcome.result.label());
            }
        }
        return Ok(());
    }
    let outcome = match method {
        "start" => {
            manager
                .start_unit_exact_current(unit_name, &identity)
                .await?
        }
        "restart" => manager.restart_unit_exact(unit_name, &identity).await?,
        "reload" => manager.reload_unit_exact(unit_name, &identity).await?,
        "stop" => manager.stop_unit_exact(unit_name, &identity).await?,
        _ => return Ok(()),
    };
    if !outcome.result.is_done() {
        bail!(
            "systemd {method} job completed as {}",
            outcome.result.label()
        );
    }
    if !service_matches(paths, rendered, resource, revision)? && method != "stop" {
        bail!("systemd service bytes changed during the manager operation");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Goal {
    Desired,
    Stopped,
    Absent,
}

struct Inspection {
    observation: AbilityValue,
    unit_identity: Option<String>,
    files_match: bool,
    manager_is_current: bool,
    complete: bool,
}

#[allow(clippy::too_many_arguments)]
async fn inspect(
    manager: &PinnedSystemdManager,
    facet: &ServiceFacetIdentity,
    expected: &AbilityValue,
    realization: &ServiceRealization,
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
    paths: &ServicePaths,
    goal: Goal,
) -> Result<Inspection> {
    let files_before = service_matches(paths, rendered, resource, revision)?;
    let absent_before = service_is_absent(paths)?;
    let unit_identity = match manager.unit_identity(&rendered.primary_unit).await {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let (active_state, manager_is_current) = if let Some(identity) = &unit_identity {
        let state = manager
            .active_state_exact(&rendered.primary_unit, identity)
            .await?;
        let needs_reload = manager
            .needs_daemon_reload_exact(&rendered.primary_unit, identity)
            .await?;
        (Some(state), !needs_reload)
    } else {
        (None, false)
    };
    let files_after = service_matches(paths, rendered, resource, revision)?;
    let absent_after = service_is_absent(paths)?;
    let files_match = files_before && files_after;
    let files_absent = absent_before && absent_after;
    let active = active_state
        .as_ref()
        .is_some_and(UnitActiveState::is_active);
    let failed = matches!(active_state, Some(UnitActiveState::Failed));
    let state_matches = match goal {
        Goal::Desired if realization.enabled => active,
        Goal::Desired | Goal::Stopped => !active,
        Goal::Absent => unit_identity.is_none(),
    };
    let complete = match goal {
        Goal::Desired | Goal::Stopped => files_match && manager_is_current && state_matches,
        Goal::Absent => files_absent && state_matches,
    };
    let mut discrepancies = Vec::new();
    if matches!(goal, Goal::Absent) {
        if !files_absent {
            discrepancies.push("unit".to_string());
        }
    } else if !files_match {
        discrepancies.push("unit".to_string());
    }
    if !manager_is_current && !matches!(goal, Goal::Absent) {
        discrepancies.push("manager-reload".to_string());
    }
    if !state_matches {
        discrepancies.push("state".to_string());
    }
    discrepancies.sort();
    let lifecycle_state = matches!(
        facet.interface.name.as_str(),
        SERVICE_LIFECYCLE_INTERFACE | SERVICE_READINESS_INTERFACE
    );
    let state = if lifecycle_state {
        if failed {
            "failed"
        } else if active {
            "ready"
        } else if realization.enabled && matches!(goal, Goal::Desired) {
            "inactive"
        } else {
            "disabled"
        }
    } else if failed {
        "failed"
    } else if complete && realization.enabled {
        "applied"
    } else if complete {
        "disabled"
    } else {
        "pending"
    };
    let observation = observation(facet, expected, state, files_match, discrepancies)?;

    Ok(Inspection {
        observation,
        unit_identity,
        files_match,
        manager_is_current,
        complete,
    })
}

fn require_method<'a>(
    method: &MethodReference,
    semantics: &MethodSemantics,
    realization: &'a ServiceRealization,
) -> Result<&'a ServiceFacetIdentity> {
    if realization.schema != SERVICE_REALIZATION_SCHEMA {
        bail!("service realization uses an unsupported schema");
    }
    let matches = realization
        .facets
        .iter()
        .filter(|facet| facet.interface == method.interface)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("service method does not select one authenticated facet");
    }
    let facet = matches[0];
    let expected = if method.interface.name.as_str() == SERVICE_LIFECYCLE_INTERFACE {
        if facet.facet.as_str() != "lifecycle" {
            bail!("service lifecycle interface selects another facet");
        }
        match method.method.as_str() {
            "observe" => MethodSemantics::ordinary(AccessMode::Read),
            "start" | "restart" | "reload" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            "stop" => MethodSemantics::provider_stop(),
            _ => bail!("unsupported service lifecycle method"),
        }
    } else if method.interface.name.as_str() == SERVICE_TEMPLATE_DEFINITION_INTERFACE {
        if facet.facet.as_str() != "lifecycle" {
            bail!("service template definition selects another facet");
        }
        match method.method.as_str() {
            "materialize" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            "observe" => MethodSemantics::ordinary(AccessMode::Read),
            "release" => MethodSemantics::provider_stop(),
            _ => bail!("unsupported service template-definition method"),
        }
    } else {
        if method.method.as_str() != "observe" {
            bail!("service feature handlers expose observation only");
        }
        MethodSemantics::ordinary(AccessMode::Read)
    };
    if *semantics != expected {
        bail!("service method carries mismatched semantics");
    }
    Ok(facet)
}

fn expected_request(value: &AbilityValue, facet: &ServiceFacetIdentity) -> Result<AbilityValue> {
    let aggregate = value
        .as_json()
        .as_object()
        .context("service desired value is not an object")?;
    let selected = aggregate
        .get(facet.facet.as_str())
        .and_then(Value::as_object)
        .context("service realization facet is absent from its desired value")?;
    let mut expected = selected.clone();
    expected.insert(
        "service".to_string(),
        aggregate
            .get("service")
            .context("service desired value has no logical key")?
            .clone(),
    );
    if facet.interface.name.as_str() != SERVICE_TEMPLATE_DEFINITION_INTERFACE {
        expected.insert(
            "enabled".to_string(),
            aggregate
                .get("enabled")
                .context("service desired value has no enablement")?
                .clone(),
        );
    }
    AbilityValue::new(Value::Object(expected)).map_err(Into::into)
}

fn service_resource_references(value: &AbilityValue) -> Result<Vec<ResourceReference>> {
    const DEPENDENCY_FIELDS: &[&str] = &[
        "prerequisites",
        "after",
        "before",
        "requires",
        "wants",
        "requisite",
        "conflicts",
        "binds_to",
        "part_of",
        "upholds",
        "required_by",
        "wanted_by",
        "required_mounts",
    ];

    let document = value
        .as_json()
        .as_object()
        .context("service desired value is not an object")?;
    let mut references = Vec::new();
    if let Some(dependencies) = document.get("dependencies") {
        for field in DEPENDENCY_FIELDS {
            if let Some(values) = dependencies.get(*field) {
                references.extend(
                    serde_json::from_value::<Vec<ResourceReference>>(values.clone())
                        .with_context(|| format!("decoding service dependency '{field}'"))?,
                );
            }
        }
    }
    if let Some(handlers) = document
        .get("failure_policy")
        .and_then(|policy| policy.get("handlers"))
    {
        references.extend(
            serde_json::from_value::<Vec<ResourceReference>>(handlers.clone())
                .context("decoding service failure handlers")?,
        );
    }
    if let Some(bindings) = document
        .get("activation")
        .and_then(|activation| activation.get("bindings"))
        .and_then(Value::as_array)
    {
        for binding in bindings {
            references.push(
                serde_json::from_value(
                    binding
                        .get("resource")
                        .context("service activation binding has no resource")?
                        .clone(),
                )
                .context("decoding service activation resource")?,
            );
        }
    }
    if let Some(selection) = document
        .get("instantiation")
        .and_then(|instantiation| instantiation.get("selection"))
        && selection.get("kind").and_then(Value::as_str) == Some("instance")
    {
        references.push(
            serde_json::from_value(
                selection
                    .get("template_resource")
                    .context("service instance has no template resource")?
                    .clone(),
            )
            .context("decoding service template resource")?,
        );
    }
    let mut unique = Vec::with_capacity(references.len());
    for reference in references {
        if !unique.contains(&reference) {
            unique.push(reference);
        }
    }
    Ok(unique)
}

fn all_service_resource_references(
    value: &AbilityValue,
    realization: &ServiceRealization,
) -> Result<Vec<ResourceReference>> {
    let mut references = service_resource_references(value)?;
    for reference in &realization.prerequisites {
        if !references.contains(reference) {
            references.push(reference.clone());
        }
    }
    Ok(references)
}

fn validate_template_reuse(
    desired: &AbilityValue,
    realization: &ServiceRealization,
    contexts: &[aos_provider_protocol::ResourceContext],
) -> Result<()> {
    let desired = desired
        .as_json()
        .as_object()
        .context("service desired value is not an object")?;
    let selection = desired
        .get("instantiation")
        .and_then(|value| value.get("selection"));
    if selection
        .and_then(|value| value.get("kind"))
        .and_then(Value::as_str)
        != Some("instance")
    {
        return Ok(());
    }
    let selection = selection.context("service instance has no instantiation selection")?;
    let reference: ResourceReference = serde_json::from_value(
        selection
            .get("template_resource")
            .context("service instance has no template resource")?
            .clone(),
    )
    .context("decoding service template resource")?;
    let matches = contexts
        .iter()
        .filter(|context| context.reference == reference)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("service instance does not have one exact static-template context");
    }
    if reference.interface.name.as_str() != SERVICE_TEMPLATE_DEFINITION_INTERFACE
        || reference.operations.len() != 1
        || reference.operations[0].as_str() != "observe"
    {
        bail!("service instance template reference has invalid interface authority");
    }
    let context = matches[0];
    let bound = validate_resource_context(context)?;
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != PROVIDER_CONTEXT_SCHEMA || !provider.unit_owned {
        bail!("service template context does not prove a present owned definition");
    }

    let template: ServiceRealization = decode_value(&bound.resource_spec.realization)?;
    let template_name = match &template.systemd_unit {
        crate::model::ServiceUnitIdentity::Unit { unit_name }
            if unit_name.ends_with("@.service") =>
        {
            unit_name
        }
        _ => bail!("service template context does not publish a static template identity"),
    };
    match &realization.systemd_unit {
        crate::model::ServiceUnitIdentity::TemplateInstance {
            template_unit_name, ..
        } if template_unit_name == template_name => {}
        _ => bail!("service instance realization does not reuse its selected template identity"),
    }
    if !realization.units.is_empty() {
        bail!("service template instance attempts to materialize instance-specific unit bytes");
    }

    let template_desired = bound
        .resource_spec
        .value
        .as_json()
        .as_object()
        .context("service template desired value is not an object")?;
    require_reusable_facets(desired, template_desired)?;
    if template_desired
        .get("instantiation")
        .and_then(|value| value.get("selection"))
        .and_then(|value| value.get("kind"))
        .and_then(Value::as_str)
        != Some("template")
    {
        bail!("service template context desired value is not a static definition");
    }
    Ok(())
}

fn reusable_facets(value: &Map<String, Value>) -> Map<String, Value> {
    let mut reusable = value.clone();
    reusable.remove("service");
    reusable.remove("enabled");
    reusable.remove("instantiation");
    reusable
}

fn require_reusable_facets(
    instance: &Map<String, Value>,
    template: &Map<String, Value>,
) -> Result<()> {
    if reusable_facets(instance) != reusable_facets(template) {
        bail!("service template instance changes reusable template facets");
    }
    Ok(())
}

fn observation(
    facet: &ServiceFacetIdentity,
    expected: &AbilityValue,
    state: &str,
    complete: bool,
    discrepancies: Vec<String>,
) -> Result<AbilityValue> {
    let mut fields = Map::new();
    fields.insert(
        "schema".to_string(),
        Value::String(facet.observation_schema.clone()),
    );
    fields.insert("expected".to_string(), expected.as_json().clone());
    if complete {
        fields.insert("observed".to_string(), expected.as_json().clone());
    }
    fields.insert("state".to_string(), Value::String(state.to_string()));
    fields.insert(
        "discrepancies".to_string(),
        serde_json::to_value(discrepancies)?,
    );
    if facet.interface.name.as_str() == SERVICE_RELOAD_INTERFACE {
        let available = expected
            .as_json()
            .get("strategy")
            .and_then(Value::as_str)
            .is_some_and(|strategy| strategy != "unsupported");
        fields.insert("available".to_string(), Value::Bool(available));
    }
    AbilityValue::new(Value::Object(fields)).map_err(Into::into)
}

fn outputs_for(
    method: &str,
    observation: &AbilityValue,
    invocation: &Invocation,
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    outputs.insert(LocalKey::new("observation")?, observation.clone());
    if matches!(method, "start" | "restart" | "reload" | "materialize") {
        outputs.insert(
            LocalKey::new("retained-resource")?,
            value(&invocation.request.target)?,
        );
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        AbilityValue, AccessMode, InterfaceKey, LocalKey, MethodReference, MethodSemantics,
    };
    use aos_contract::Sha256Digest;

    use super::{
        SERVICE_RELOAD_INTERFACE, SERVICE_TEMPLATE_DEFINITION_INTERFACE,
        all_service_resource_references, expected_request, observation, require_method,
        require_reusable_facets, service_resource_references,
    };
    use crate::model::{
        SERVICE_REALIZATION_SCHEMA, ServiceFacetIdentity, ServiceRealization, ServiceUnitIdentity,
        SystemdUnitDocument, SystemdUnitIdentity,
    };

    fn interface(name: &str, digest_byte: u8) -> InterfaceKey {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "abi": 1,
            "descriptor": Sha256Digest::from_bytes([digest_byte; 32]).to_string(),
        }))
        .expect("interface fixture is valid")
    }

    fn realization() -> ServiceRealization {
        ServiceRealization {
            schema: SERVICE_REALIZATION_SCHEMA.to_string(),
            systemd_unit: ServiceUnitIdentity::Unit {
                unit_name: "example.service".to_string(),
            },
            units: vec![SystemdUnitDocument {
                systemd_unit: SystemdUnitIdentity {
                    unit_name: "example.service".to_string(),
                },
                sections: Vec::new(),
            }],
            facets: vec![
                ServiceFacetIdentity {
                    interface: interface("aos.service.lifecycle", 1),
                    facet: LocalKey::new("lifecycle").expect("facet parses"),
                    observation_schema: "aos.ability.service-lifecycle-observation/v1".to_string(),
                },
                ServiceFacetIdentity {
                    interface: interface("aos.service.logging", 2),
                    facet: LocalKey::new("logging").expect("facet parses"),
                    observation_schema: "aos.ability.service-logging-observation/v1".to_string(),
                },
            ],
            links: Vec::new(),
            prerequisites: Vec::new(),
            enabled: true,
        }
    }

    #[test]
    fn service_methods_are_limited_by_the_authenticated_facet_catalog() {
        let realization = realization();
        let lifecycle = MethodReference {
            interface: realization.facets[0].interface.clone(),
            method: LocalKey::new("start").expect("method parses"),
        };
        let logging = MethodReference {
            interface: realization.facets[1].interface.clone(),
            method: LocalKey::new("observe").expect("method parses"),
        };

        assert!(
            require_method(
                &lifecycle,
                &MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
                &realization,
            )
            .is_ok()
        );
        assert!(
            require_method(
                &logging,
                &MethodSemantics::ordinary(AccessMode::Read),
                &realization,
            )
            .is_ok()
        );
        assert!(
            require_method(
                &logging,
                &MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
                &realization,
            )
            .is_err()
        );

        let mut template = realization;
        template.facets[0].interface = interface(SERVICE_TEMPLATE_DEFINITION_INTERFACE, 3);
        let materialize = MethodReference {
            interface: template.facets[0].interface.clone(),
            method: LocalKey::new("materialize").expect("method parses"),
        };
        assert!(
            require_method(
                &materialize,
                &MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
                &template,
            )
            .is_ok()
        );
    }

    #[test]
    fn expected_feature_request_is_reconstructed_from_the_merged_resource() {
        let realization = realization();
        let value = AbilityValue::new(serde_json::json!({
            "service": "main",
            "enabled": true,
            "lifecycle": { "description": "Example" },
            "logging": { "standard_output": "structured" },
        }))
        .expect("service value is bounded");
        let expected = expected_request(&value, &realization.facets[1])
            .expect("logging request is reconstructed");

        assert_eq!(
            expected.as_json(),
            &serde_json::json!({
                "service": "main",
                "enabled": true,
                "standard_output": "structured",
            })
        );

        let mut template = realization;
        template.facets[0].interface = interface(SERVICE_TEMPLATE_DEFINITION_INTERFACE, 3);
        let expected = expected_request(&value, &template.facets[0])
            .expect("template request is reconstructed");
        assert_eq!(
            expected.as_json(),
            &serde_json::json!({
                "service": "main",
                "description": "Example",
            })
        );
    }

    #[test]
    fn template_instances_may_change_only_identity_enablement_and_selection() {
        let template = serde_json::json!({
            "service": "worker-template",
            "enabled": false,
            "lifecycle": {"description": "Worker", "start": []},
            "logging": {"standard_output": "structured"},
            "instantiation": {"selection": {"kind": "template", "template": "worker"}},
        });
        let instance = serde_json::json!({
            "service": "worker-instance",
            "enabled": true,
            "lifecycle": {"description": "Worker", "start": []},
            "logging": {"standard_output": "structured"},
            "instantiation": {"selection": {
                "kind": "instance",
                "instance": "east/one",
                "template_resource": null,
            }},
        });
        let template = template.as_object().expect("template fixture is an object");
        let instance = instance.as_object().expect("instance fixture is an object");

        assert!(require_reusable_facets(instance, template).is_ok());

        let mut changed = instance.clone();
        changed.insert(
            "logging".to_string(),
            serde_json::json!({"standard_output": "discard"}),
        );
        assert!(require_reusable_facets(&changed, template).is_err());
    }

    #[test]
    fn reload_observation_reports_exact_strategy_availability() {
        let facet = ServiceFacetIdentity {
            interface: interface(SERVICE_RELOAD_INTERFACE, 4),
            facet: LocalKey::new("reload").expect("facet parses"),
            observation_schema: "aos.ability.service-reload-observation/v1".to_string(),
        };
        let expected = AbilityValue::new(serde_json::json!({
            "service": "main",
            "enabled": true,
            "strategy": "unsupported",
            "commands": [],
        }))
        .expect("reload request is bounded");

        let observed = observation(&facet, &expected, "applied", true, Vec::new())
            .expect("observation is bounded");

        assert_eq!(observed.as_json()["available"], false);
    }

    #[test]
    fn every_resource_bearing_service_facet_requires_a_checked_context() {
        let first = serde_json::json!({
            "interface": interface("aos.kernel.modules", 3),
            "resource": {
                "provider": {
                    "environment": {"authority": "test", "key": "host", "stage": "host"},
                    "key": "kmod"
                },
                "key": "configured"
            },
            "operations": ["observe"],
            "lifetime": "instance"
        });
        let second = serde_json::json!({
            "interface": interface("aos.service.lifecycle", 4),
            "resource": {
                "provider": {
                    "environment": {"authority": "test", "key": "host", "stage": "host"},
                    "key": "systemd"
                },
                "key": "dependency"
            },
            "operations": ["observe"],
            "lifetime": "instance"
        });
        let value = AbilityValue::new(serde_json::json!({
            "service": "main",
            "enabled": true,
            "lifecycle": {},
            "dependencies": {
                "prerequisites": [first.clone()],
                "after": [second.clone()],
                "requires": [second.clone()]
            },
            "activation": {
                "bindings": [{
                    "name": "modules",
                    "resource": first,
                    "relationship": "dependency"
                }]
            },
            "instantiation": {
                "selection": {
                    "kind": "instance",
                    "instance": "blue",
                    "template_resource": second
                }
            }
        }))
        .expect("service fixture is bounded");

        let references = service_resource_references(&value).expect("references decode");

        assert_eq!(references.len(), 2);
    }

    #[test]
    fn realization_prerequisites_require_checked_contexts() {
        let value = AbilityValue::new(serde_json::json!({
            "service": "main",
            "enabled": true,
            "lifecycle": {},
        }))
        .expect("service fixture is bounded");
        let reference: aos_ability_model::ResourceReference =
            serde_json::from_value(serde_json::json!({
            "interface": interface("aos.filesystem.entry", 5),
            "resource": {
                "provider": {
                    "environment": {"authority": "test", "key": "host", "stage": "host"},
                    "key": "filesystem"
                },
                "key": "directory"
            },
            "operations": ["observe"],
            "lifetime": "instance"
            }))
            .expect("resource reference fixture is valid");
        let mut realization = realization();
        realization.prerequisites.push(reference.clone());

        let references = all_service_resource_references(&value, &realization)
            .expect("realization references decode");

        assert_eq!(references, vec![reference]);
    }
}
