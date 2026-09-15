//! Shared checked command-handler lifecycle for block-storage resources.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{AbilityValue, AccessMode, LocalKey, MethodSemantics, ResourceReference};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde_json::json;

/// Supplies one package-owned block-storage terminal implementation.
pub trait Backend {
    /// Returns the exact private terminal interface name.
    fn interface_name(&self) -> &'static str;

    /// Returns the mutating method name.
    fn action_method(&self) -> &'static str;

    /// Returns the runtime path output name.
    fn path_output(&self) -> &'static str;

    /// Resolves the runtime method input against the admitted resource value.
    ///
    /// Most block-storage terminals consume the resource value verbatim. A
    /// controller may instead pass a checked runtime result alongside that
    /// value when its terminal method declares a distinct parameter schema.
    fn invocation_desired(
        &self,
        admitted: &AbilityValue,
        inputs: &AbilityValue,
    ) -> Result<AbilityValue> {
        ensure!(admitted == inputs, "bound inputs differ");
        Ok(admitted.clone())
    }

    /// Validates one desired request and its selected realization.
    fn admit_context(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        target: &ResourceReference,
        revision: aos_ability_model::RevisionId,
        resources: &[ResourceContext],
    ) -> Result<AbilityValue>;

    /// Observes the exact desired resource without mutation.
    fn observe(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        target: &ResourceReference,
        revision: aos_ability_model::RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation>;

    /// Observes the resource during admission before runtime results exist.
    ///
    /// Terminals whose desired value is available only at runtime override
    /// this hook and report an absent revision until transition inputs resolve.
    fn observe_admission(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        target: &ResourceReference,
        revision: aos_ability_model::RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation> {
        self.observe(desired, realization, target, revision, context)
    }

    /// Applies the exact desired resource.
    fn apply(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        target: &ResourceReference,
        revision: aos_ability_model::RevisionId,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()>;

    /// Releases only state owned by the exact resource.
    fn release(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        target: &ResourceReference,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()>;
}

/// Reports one backend observation and its optional exact path result.
pub struct BackendObservation {
    /// Carries method-typed observation evidence.
    pub evidence: AbilityValue,
    /// Reports whether the exact requested revision is ready.
    pub ready: bool,
    /// Reports whether the resource is absent or unmanaged after release.
    pub released: bool,
    /// Carries the exact runtime path when ready.
    pub path: Option<String>,
    /// Reports ambiguity that prevents an automatic retry decision.
    pub unknown: bool,
}

/// Handles the shared command-provider protocol for one backend.
pub struct Provider<B> {
    backend: B,
}

impl<B: Backend> Provider<B> {
    /// Constructs a provider around one package-owned backend.
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Handles one canonical provider invocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope, authority, desired resource,
    /// realization, dependencies, provider context, or native operation fails.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let value = match purpose {
            "admit" => {
                let request: AdmissionRequest =
                    aos_contract::canonical::from_slice(input, "block-storage admission")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "block-storage invocation")?;
                ensure!(
                    invocation.schema == INVOCATION_SCHEMA,
                    "unsupported invocation schema"
                );
                ensure!(
                    purpose == purpose_name(invocation.purpose),
                    "purpose differs from argv"
                );
                serde_json::to_value(self.invoke(invocation)?)?
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };
        aos_contract::canonical::canonical_json(&value)
            .context("encoding canonical block-storage response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(
            self.backend.interface_name(),
            self.backend.action_method(),
            request.method.interface.name.as_str(),
            request.method.method.as_str(),
            &request.semantics,
        )?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;
        require_prerequisites(&request.resource_spec.value, &request.resources)?;
        let context = self.backend.admit_context(
            &request.resource_spec.value,
            &request.resource_spec.realization,
            &request.target,
            request.resource_spec.revision,
            &request.resources,
        )?;
        let observation = self.backend.observe_admission(
            &request.resource_spec.value,
            &request.resource_spec.realization,
            &request.target,
            request.resource_spec.revision,
            &context,
        )?;
        let supported_purposes = if request.method.method.as_str() == "observe" {
            SupportedPurposes::from_ordered(vec![InvocationPurpose::Effect])
        } else {
            SupportedPurposes::from_ordered(vec![
                InvocationPurpose::Effect,
                InvocationPurpose::Reconcile,
                InvocationPurpose::Cancel,
            ])
        }
        .context("constructing canonical purpose support")?;

        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision: if observation.ready {
                AdmissionRevision::Present {
                    revision: request.resource_spec.revision,
                }
            } else {
                AdmissionRevision::Absent
            },
            incarnation: Some(request.assignment.incarnation),
            observation: observation.evidence,
            native_context: context,
            supported_purposes,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method is not durably bound"
        );
        validate_method(
            self.backend.interface_name(),
            self.backend.action_method(),
            invocation.request.method.interface.name.as_str(),
            invocation.request.method.method.as_str(),
            &invocation.request.semantics,
        )?;
        validate_method(
            self.backend.interface_name(),
            self.backend.action_method(),
            invocation.method.interface.name.as_str(),
            invocation.method.method.as_str(),
            &invocation.semantics,
        )?;
        validate_resource_contexts(&invocation.request.resources)?;
        ensure!(
            resource_set_digest(&invocation.request.resources)?
                == invocation.request.native_context_digest,
            "resource contexts differ from their authenticated digest"
        );
        let target = exact_context(&invocation.request.resources, &invocation.request.target)?;
        let bound = validate_resource_context(target)?;
        ensure!(
            invocation
                .request
                .target
                .operations
                .binary_search(&invocation.method.method)
                .is_ok(),
            "invocation method is outside the target resource authority"
        );
        require_prerequisites(&bound.resource_spec.value, &invocation.request.resources)?;
        let expected_context = self.backend.admit_context(
            &bound.resource_spec.value,
            &bound.resource_spec.realization,
            &invocation.request.target,
            bound.resource_spec.revision,
            &invocation.request.resources,
        )?;
        ensure!(
            expected_context == bound.provider_context,
            "provider context differs from admission"
        );
        let desired = self
            .backend
            .invocation_desired(&bound.resource_spec.value, &invocation.request.inputs)?;

        let observing = invocation.request.method.method.as_str() == "observe";
        let removing = invocation.request.method.method.as_str() == "release";
        let before = self.backend.observe(
            &desired,
            &bound.resource_spec.realization,
            &invocation.request.target,
            bound.resource_spec.revision,
            &expected_context,
        )?;
        let observation = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => before,
            InvocationPurpose::Effect if invocation.control.cancelled => {
                return result(
                    InvocationDisposition::RejectedBeforeEffect,
                    before,
                    &invocation,
                    self.backend.path_output(),
                    false,
                );
            }
            InvocationPurpose::Effect
                if invocation.method.method.as_str() == self.backend.action_method() =>
            {
                self.backend.apply(
                    &desired,
                    &bound.resource_spec.realization,
                    &invocation.request.target,
                    target.revision,
                    &expected_context,
                    invocation.control.attempt_remaining_millis,
                )?;
                self.backend.observe(
                    &desired,
                    &bound.resource_spec.realization,
                    &invocation.request.target,
                    bound.resource_spec.revision,
                    &expected_context,
                )?
            }
            InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
                self.backend.release(
                    &desired,
                    &bound.resource_spec.realization,
                    &invocation.request.target,
                    &expected_context,
                    invocation.control.attempt_remaining_millis,
                )?;
                self.backend.observe(
                    &desired,
                    &bound.resource_spec.realization,
                    &invocation.request.target,
                    bound.resource_spec.revision,
                    &expected_context,
                )?
            }
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel => before,
            InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => {
                return result(
                    InvocationDisposition::InterventionRequired,
                    before,
                    &invocation,
                    self.backend.path_output(),
                    false,
                );
            }
            _ => bail!("unsupported block-storage method or purpose"),
        };
        let complete = if observing {
            true
        } else if removing {
            observation.released
        } else {
            observation.ready
        };
        let disposition = if complete {
            InvocationDisposition::Completed
        } else if observation.unknown {
            if invocation.purpose == InvocationPurpose::Reconcile {
                InvocationDisposition::StillIndeterminate
            } else {
                InvocationDisposition::Indeterminate
            }
        } else if invocation.purpose == InvocationPurpose::Cancel {
            InvocationDisposition::RejectedBeforeEffect
        } else {
            InvocationDisposition::SafeToRetry
        };
        result(
            disposition,
            observation,
            &invocation,
            self.backend.path_output(),
            complete && !observing && !removing,
        )
    }
}

fn result(
    disposition: InvocationDisposition,
    observation: BackendObservation,
    invocation: &Invocation,
    path_output: &str,
    retained: bool,
) -> Result<InvocationResult> {
    let mut outputs = BTreeMap::new();
    if disposition == InvocationDisposition::Completed {
        outputs.insert(LocalKey::new("observation")?, observation.evidence.clone());
        if retained {
            outputs.insert(
                LocalKey::new("retained-resource")?,
                ability_value(serde_json::to_value(&invocation.request.target)?)?,
            );
            outputs.insert(
                LocalKey::new(path_output)?,
                ability_value(json!(
                    observation.path.context("ready observation has no path")?
                ))?,
            );
        }
    }
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition,
        evidence: observation.evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn validate_method(
    interface: &str,
    action: &str,
    actual_interface: &str,
    method: &str,
    semantics: &MethodSemantics,
) -> Result<()> {
    ensure!(
        actual_interface == interface,
        "method selects another interface"
    );
    let expected = match method {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "release" => MethodSemantics::provider_stop(),
        method if method == action => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        _ => bail!("unsupported block-storage method"),
    };
    ensure!(
        *semantics == expected,
        "method carries mismatched semantics"
    );
    Ok(())
}

fn require_prerequisites(value: &AbilityValue, resources: &[ResourceContext]) -> Result<()> {
    let prerequisites = value
        .as_json()
        .get("prerequisites")
        .and_then(serde_json::Value::as_array)
        .context("block-storage request has no prerequisite list")?;
    for prerequisite in prerequisites {
        let reference: ResourceReference = serde_json::from_value(prerequisite.clone())?;
        exact_context(resources, &reference)?;
    }
    Ok(())
}

fn exact_context<'a>(
    resources: &'a [ResourceContext],
    reference: &ResourceReference,
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "resource reference has no exact unique context"
    );
    Ok(matches[0])
}

/// Converts a JSON value into one bounded ability value.
pub fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing bounded ability value")
}

const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}
