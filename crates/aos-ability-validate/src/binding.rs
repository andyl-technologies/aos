//! Binding-plan identity, coverage, guarantee, and grant validation.

mod package;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::ProviderState;
use aos_ability_model::identity::{compare_instance_ids, compare_request_ids};
use aos_ability_model::{
    AccessMode, AuthorityGrant, Binding, BindingPlanDocument, BindingSource, Diagnostic,
    DiagnosticClass, DiagnosticCode, DiagnosticPhase, InstanceId, InterfaceKey,
    PROVIDER_STATE_FORMAT_V1, PackageDocument, PlanId, ProviderImplementation, RequestId,
    RequirementDeclaration, RequirementStrength, ResourceReference, ValueExpression,
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
use crate::schema::{SchemaPath, validate_materialized_value, validate_value};
use aos_contract::limits::BoundedWriter;
use package::{validate_declared_root_requests, validate_package_document};

pub(crate) fn validate_package_contract(
    context: &ValidationContext,
    package: PackageDocument,
) -> Result<PackageDocument, ValidationErrors> {
    let mut diagnostics = Vec::new();
    validate_input_document(context, &package, "packages", &mut diagnostics);
    validate_package_document(context, &package, 0, true, &mut diagnostics);

    if diagnostics.is_empty() {
        Ok(package)
    } else {
        Err(ValidationErrors::new(diagnostics))
    }
}

#[derive(Clone, Debug, Default)]
struct BindingInputIndex {
    packages: BTreeMap<Sha256Digest, usize>,
    package_catalogs: Vec<PackageProviderIndex>,
    inventory_by_instance: BTreeMap<InstanceId, Vec<usize>>,
    enabled_desired_by_instance: BTreeMap<InstanceId, Vec<usize>>,
    in_scope_instances: BTreeSet<InstanceId>,
    request_authorities: BTreeMap<InstanceId, aos_ability_model::DeclarationAuthority>,
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

#[path = "binding/document.rs"]
mod document;
#[path = "binding/grants.rs"]
mod grants;
#[path = "binding/preparation.rs"]
mod preparation;

pub(crate) use document::validate_binding_document;
use document::{merged_resource_revisions, validate_binding_inputs, validate_input_document};
#[cfg(test)]
use grants::grant_resource_in_scope;
use grants::{
    binding_diagnostic, check_order_by, validate_binding, validate_contributions, validate_request,
};
pub(crate) use preparation::prepare_binding_candidates;

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        EnvironmentId, ExecutionStage, LocalKey, ResourceId, ResourcePermission,
    };

    use super::*;

    #[test]
    fn provider_observation_scope_is_exact_and_read_only() {
        let instance = |name: &str| InstanceId {
            environment: EnvironmentId {
                authority: LocalKey::new("test").unwrap(),
                key: LocalKey::new("host").unwrap(),
                stage: ExecutionStage::Host,
            },
            key: LocalKey::new(name).unwrap(),
        };
        let provider = instance("provider");
        let caller = instance("caller");
        let foreign = instance("foreign");
        let resource = |owner: InstanceId| ResourceId {
            provider: owner,
            key: LocalKey::new("resource").unwrap(),
        };
        let caller_resource = resource(caller.clone());
        let resources = BTreeSet::from([
            caller_resource.clone(),
            resource(foreign.clone()),
            resource(provider.clone()),
        ]);
        let permission = |resource, access| ResourcePermission {
            resource,
            access,
            operations: Vec::new(),
        };

        assert!(grant_resource_in_scope(
            &permission(caller_resource.clone(), AccessMode::Read),
            &resources,
            &provider,
            &caller,
            true,
        ));
        assert!(!grant_resource_in_scope(
            &permission(caller_resource, AccessMode::SharedWrite),
            &resources,
            &provider,
            &caller,
            true,
        ));
        assert!(!grant_resource_in_scope(
            &permission(resource(foreign), AccessMode::Read),
            &resources,
            &provider,
            &caller,
            true,
        ));
        assert!(grant_resource_in_scope(
            &permission(resource(provider.clone()), AccessMode::ExclusiveWrite),
            &resources,
            &provider,
            &caller,
            false,
        ));
    }
}
