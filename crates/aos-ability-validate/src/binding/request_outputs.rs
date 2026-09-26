//! Exact selected-request output lookup for deferred binding values.

use super::*;

pub(super) struct RequestOutputResolver<'a> {
    context: &'a ValidationContext,
    plan: &'a BindingPlanDocument,
    request_indices: BTreeMap<RequestId, usize>,
    binding_indices: BTreeMap<RequestId, Vec<usize>>,
}

impl<'a> RequestOutputResolver<'a> {
    pub(super) fn new(context: &'a ValidationContext, plan: &'a BindingPlanDocument) -> Self {
        let request_indices = plan
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| (request.id.clone(), index))
            .collect();
        let mut binding_indices: BTreeMap<RequestId, Vec<usize>> = BTreeMap::new();
        for (index, binding) in plan.bindings.iter().enumerate() {
            binding_indices
                .entry(binding.request.clone())
                .or_default()
                .push(index);
        }

        Self {
            context,
            plan,
            request_indices,
            binding_indices,
        }
    }

    pub(super) fn request(&self, id: &RequestId) -> Option<&BindingRequest> {
        self.request_indices
            .get(id)
            .map(|index| &self.plan.requests[*index])
    }

    pub(super) fn validate(
        &self,
        recipient: &BindingRequest,
        expected: &aos_ability_model::ValueSchema,
        reference: &aos_ability_model::RequestOutputReference,
        path: &SchemaPath,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        self.validate_for_lifetime(
            recipient,
            recipient.lifetime,
            expected,
            reference,
            path,
            diagnostics,
        );
    }

    pub(super) fn validate_for_lifetime(
        &self,
        recipient: &BindingRequest,
        lifetime: aos_ability_model::ResourceLifetime,
        expected: &aos_ability_model::ValueSchema,
        reference: &aos_ability_model::RequestOutputReference,
        path: &SchemaPath,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        let fail = |code, class, message: &str, diagnostics: &mut Vec<Diagnostic>| {
            let mut item = diagnostic(
                code,
                class,
                DiagnosticPhase::Binding,
                path.components().to_vec(),
                message.to_string(),
            );
            item.request = Some(recipient.id.clone());
            push_diagnostic(diagnostics, item);
        };

        if reference.request == recipient.id {
            fail(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                "request output cannot refer to its own request",
                diagnostics,
            );
            return;
        }
        let Some(producer) = self.request(&reference.request) else {
            fail(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                "request output names an absent producer request",
                diagnostics,
            );
            return;
        };
        let Some([index]) = self
            .binding_indices
            .get(&reference.request)
            .map(Vec::as_slice)
        else {
            fail(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                "request output producer requires one exact selected binding",
                diagnostics,
            );
            return;
        };
        let binding = &self.plan.bindings[*index];
        let Some(descriptor) = self
            .context
            .interface(&binding.interface)
            .and_then(|interface| {
                interface
                    .interface
                    .outputs
                    .get(&reference.output)
                    .or_else(|| {
                        let mut matching_methods = producer.methods.iter().filter_map(|method| {
                            interface
                                .interface
                                .methods
                                .get(method)
                                .and_then(|method| method.outputs.get(&reference.output))
                        });
                        let selected = matching_methods.next()?;
                        matching_methods.next().is_none().then_some(selected)
                    })
            })
        else {
            fail(
                DiagnosticCode::MissingReference,
                DiagnosticClass::IncompatibleInterface,
                "request output has no unique descriptor in its selected interface and methods",
                diagnostics,
            );
            return;
        };

        if descriptor.schema != *expected {
            fail(
                DiagnosticCode::ValueTypeMismatch,
                DiagnosticClass::IncompatibleInterface,
                "request output schema differs from its consuming value schema",
                diagnostics,
            );
        }
        if descriptor.phase != aos_ability_model::ValuePhase::Runtime {
            fail(
                DiagnosticCode::ResultPhaseMismatch,
                DiagnosticClass::InvalidContract,
                "request output is not available in the runtime phase",
                diagnostics,
            );
        }
        if descriptor.lifetime < lifetime {
            fail(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::InvalidContract,
                "request output cannot outlive its producing value",
                diagnostics,
            );
        }
        if descriptor.visibility == aos_ability_model::ValueVisibility::Private
            && recipient.id.consumer != binding.provider
        {
            fail(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                "private request output escapes its producing provider",
                diagnostics,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        OutputDescriptor, RequestOutputReference, ResourceLifetime, ValueExpression, ValuePhase,
        ValueSchema, ValueVisibility,
    };

    use crate::test_support::{key, plan_fixture};

    use super::*;

    #[test]
    fn selected_runtime_output_validates_inside_a_nested_binding_value() {
        let mut fixture = plan_fixture();
        fixture.interfaces[0].interface.outputs.insert(
            key("result"),
            OutputDescriptor {
                description: "Selected runtime result.".to_string(),
                schema: ValueSchema::Boolean,
                phase: ValuePhase::Runtime,
                visibility: ValueVisibility::Public,
                lifetime: ResourceLifetime::Instance,
            },
        );
        fixture.refresh_interface();

        let producer = fixture.binding_plan.requests[0].id.clone();
        let mut recipient = fixture.binding_plan.requests[0].clone();
        recipient.id.key = key("recipient");
        let resolver = RequestOutputResolver::new(&fixture.context, &fixture.binding_plan);
        let expression = ValueExpression::Object {
            fields: BTreeMap::from([(
                "value".to_string(),
                ValueExpression::RequestOutput {
                    reference: RequestOutputReference {
                        request: producer,
                        output: key("result"),
                    },
                },
            )]),
        };
        let schema = ValueSchema::Record {
            fields: BTreeMap::from([(key("value"), ValueSchema::Boolean)]),
            optional_fields: Vec::new(),
        };
        let validate_output = |expected: &ValueSchema,
                               reference: &RequestOutputReference,
                               path: &SchemaPath,
                               diagnostics: &mut Vec<Diagnostic>| {
            resolver.validate(&recipient, expected, reference, path, diagnostics);
        };

        validate_binding_value(&schema, &expression, &validate_output)
            .expect("exact selected runtime output must validate");
        assert!(crate::schema::validate_value(&schema, &expression).is_err());
    }

    #[test]
    fn selected_method_runtime_output_validates() {
        let mut fixture = plan_fixture();
        let method = fixture.interfaces[0]
            .interface
            .methods
            .get_mut(&key("observe"))
            .expect("fixture has an observe method");
        let descriptor = method
            .outputs
            .get_mut(&key("ready"))
            .expect("fixture has a ready output");
        descriptor.phase = ValuePhase::Runtime;
        descriptor.lifetime = ResourceLifetime::Instance;
        fixture.refresh_interface();

        let producer = fixture.binding_plan.requests[0].id.clone();
        let mut recipient = fixture.binding_plan.requests[0].clone();
        recipient.id.key = key("recipient");
        let resolver = RequestOutputResolver::new(&fixture.context, &fixture.binding_plan);
        let mut diagnostics = Vec::new();

        resolver.validate(
            &recipient,
            &ValueSchema::Boolean,
            &RequestOutputReference {
                request: producer,
                output: key("ready"),
            },
            &SchemaPath::root(),
            &mut diagnostics,
        );

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn repeated_selected_method_output_is_ambiguous() {
        let mut fixture = plan_fixture();
        let mut method = fixture.interfaces[0].interface.methods[&key("observe")].clone();
        let descriptor = method
            .outputs
            .get_mut(&key("ready"))
            .expect("fixture has a ready output");
        descriptor.phase = ValuePhase::Runtime;
        descriptor.lifetime = ResourceLifetime::Instance;
        fixture.interfaces[0]
            .interface
            .methods
            .insert(key("inspect"), method);
        fixture.refresh_interface();

        let producer = &mut fixture.binding_plan.requests[0];
        producer.methods.push(key("inspect"));
        let mut recipient = producer.clone();
        recipient.id.key = key("recipient");
        let reference = RequestOutputReference {
            request: producer.id.clone(),
            output: key("ready"),
        };
        let resolver = RequestOutputResolver::new(&fixture.context, &fixture.binding_plan);
        let mut diagnostics = Vec::new();

        resolver.validate(
            &recipient,
            &ValueSchema::Boolean,
            &reference,
            &SchemaPath::root(),
            &mut diagnostics,
        );

        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == DiagnosticCode::MissingReference)
        );
    }

    #[test]
    fn request_output_rejects_wrong_schema_phase_and_lifetime() {
        let mut fixture = plan_fixture();
        fixture.interfaces[0].interface.outputs.insert(
            key("result"),
            OutputDescriptor {
                description: "Planning-only result.".to_string(),
                schema: ValueSchema::Boolean,
                phase: ValuePhase::Planning,
                visibility: ValueVisibility::Public,
                lifetime: ResourceLifetime::Attempt,
            },
        );
        fixture.refresh_interface();

        let producer = fixture.binding_plan.requests[0].id.clone();
        let mut recipient = fixture.binding_plan.requests[0].clone();
        recipient.id.key = key("recipient");
        recipient.lifetime = ResourceLifetime::Instance;
        let resolver = RequestOutputResolver::new(&fixture.context, &fixture.binding_plan);
        let reference = RequestOutputReference {
            request: producer,
            output: key("result"),
        };
        let mut diagnostics = Vec::new();

        resolver.validate(
            &recipient,
            &ValueSchema::String {
                max_length: 16,
                syntax: None,
            },
            &reference,
            &SchemaPath::root(),
            &mut diagnostics,
        );

        for expected in [
            DiagnosticCode::ValueTypeMismatch,
            DiagnosticCode::ResultPhaseMismatch,
            DiagnosticCode::ResourceScopeEscape,
        ] {
            assert!(diagnostics.iter().any(|item| item.code == expected));
        }
    }

    #[test]
    fn resource_realization_uses_the_resource_lifetime() {
        let mut fixture = plan_fixture();
        fixture.interfaces[0].interface.outputs.insert(
            key("result"),
            OutputDescriptor {
                description: "Attempt-scoped runtime result.".to_string(),
                schema: ValueSchema::Boolean,
                phase: ValuePhase::Runtime,
                visibility: ValueVisibility::Public,
                lifetime: ResourceLifetime::Attempt,
            },
        );
        fixture.refresh_interface();

        let producer = fixture.binding_plan.requests[0].id.clone();
        let mut recipient = fixture.binding_plan.requests[0].clone();
        recipient.id.key = key("recipient");
        recipient.lifetime = ResourceLifetime::Attempt;
        let reference = RequestOutputReference {
            request: producer,
            output: key("result"),
        };
        let resolver = RequestOutputResolver::new(&fixture.context, &fixture.binding_plan);
        let mut diagnostics = Vec::new();

        resolver.validate_for_lifetime(
            &recipient,
            ResourceLifetime::Instance,
            &ValueSchema::Boolean,
            &reference,
            &SchemaPath::root(),
            &mut diagnostics,
        );

        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == DiagnosticCode::ResourceScopeEscape)
        );
    }
}
