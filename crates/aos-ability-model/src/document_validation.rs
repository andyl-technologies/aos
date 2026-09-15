//! Versioned document invariant validation.

use super::*;

impl VersionedDocument for InterfaceDocument {
    const SCHEMA: &'static str = "aos.ability.interface/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        validate_interface_depth(&self.interface, limits)?;
        validate_interface_prose(&self.interface, limits)
    }

    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        #[derive(Serialize)]
        struct SemanticOutput<'a> {
            schema: &'a ValueSchema,
            phase: crate::interface::ValuePhase,
            visibility: crate::interface::ValueVisibility,
            lifetime: crate::ResourceLifetime,
        }

        #[derive(Serialize)]
        struct SemanticMethod<'a> {
            semantics: &'a crate::interface::MethodSemantics,
            parameters: &'a ValueSchema,
            target_resource: &'a InterfaceName,
            outputs: BTreeMap<&'a LocalKey, SemanticOutput<'a>>,
            permitted_operations: &'a [LocalKey],
            guarantees: &'a [GuaranteeKey],
            outcome: &'a crate::interface::OutcomeSemantics,
        }

        #[derive(Serialize)]
        struct SemanticInterface<'a> {
            name: &'a InterfaceName,
            abi: NonZeroU32,
            request: &'a ValueSchema,
            #[serde(skip_serializing_if = "Option::is_none")]
            configuration: &'a Option<ValueSchema>,
            outputs: BTreeMap<&'a LocalKey, SemanticOutput<'a>>,
            methods: BTreeMap<&'a LocalKey, SemanticMethod<'a>>,
            lifecycle: &'a crate::interface::LifecycleSemantics,
            aggregation: &'a crate::interface::AggregationContract,
            guarantees: &'a [GuaranteeKey],
        }

        #[derive(Serialize)]
        struct SemanticInterfaceDocument<'a> {
            schema: &'a str,
            required_features: &'a [RequiredFeature],
            interface: SemanticInterface<'a>,
        }

        #[derive(Serialize)]
        struct DescriptorEnvelope<'a> {
            domain: &'static str,
            document: SemanticInterfaceDocument<'a>,
        }

        fn semantic_output(descriptor: &crate::interface::OutputDescriptor) -> SemanticOutput<'_> {
            SemanticOutput {
                schema: &descriptor.schema,
                phase: descriptor.phase,
                visibility: descriptor.visibility,
                lifetime: descriptor.lifetime,
            }
        }

        let outputs = self
            .interface
            .outputs
            .iter()
            .map(|(name, descriptor)| (name, semantic_output(descriptor)))
            .collect();
        let methods = self
            .interface
            .methods
            .iter()
            .map(|(name, method)| {
                (
                    name,
                    SemanticMethod {
                        semantics: &method.semantics,
                        parameters: &method.parameters,
                        target_resource: &method.target_resource,
                        outputs: method
                            .outputs
                            .iter()
                            .map(|(name, descriptor)| (name, semantic_output(descriptor)))
                            .collect(),
                        permitted_operations: &method.permitted_operations,
                        guarantees: &method.guarantees,
                        outcome: &method.outcome,
                    },
                )
            })
            .collect();

        let envelope = DescriptorEnvelope {
            domain: Self::SCHEMA,
            document: SemanticInterfaceDocument {
                schema: &self.schema,
                required_features: &self.required_features,
                interface: SemanticInterface {
                    name: &self.interface.name,
                    abi: self.interface.abi,
                    request: &self.interface.request,
                    configuration: &self.interface.configuration,
                    outputs,
                    methods,
                    lifecycle: &self.interface.lifecycle,
                    aggregation: &self.interface.aggregation,
                    guarantees: &self.interface.guarantees,
                },
            },
        };
        let bytes =
            aos_contract::canonical::to_vec(&envelope).map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;

        Ok(Sha256Digest::of_bytes(bytes))
    }
}

impl VersionedDocument for PackageDocument {
    const SCHEMA: &'static str = "aos.ability.package/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        validate_package_option_declarations(&self.option_declarations, limits)?;
        for provider in &self.implementation.providers {
            validate_documentation_text(
                "provider implementation description",
                &provider.description,
                limits,
            )?;
            if let Some(schema) = &provider.desired_schema {
                ensure_schema_depth(schema, limits)?;
            }
            for requirement in &provider.requirements {
                validate_documentation_text(
                    "provider requirement description",
                    &requirement.description,
                    limits,
                )?;
            }
        }
        for requirement in &self.requirements {
            validate_documentation_text(
                "package requirement description",
                &requirement.description,
                limits,
            )?;
        }
        for guarantee in self.guarantees.values() {
            if guarantee.semantics.is_empty()
                || guarantee.semantics.chars().any(char::is_control)
                || guarantee.semantics.len() as u64 > limits.max_string_bytes
                || guarantee.description.is_empty()
                || guarantee.description.chars().any(char::is_control)
                || guarantee.description.len() as u64 > limits.max_string_bytes
            {
                return Err(DocumentError::Decode {
                    label: Self::SCHEMA.to_string(),
                    source: anyhow::anyhow!(
                        "package guarantee semantics and description must be non-empty and control-free"
                    ),
                });
            }
        }
        for handler in self.implementation.handlers.values() {
            ensure_schema_depth(&handler.arguments, limits)?;
            ensure_schema_depth(&handler.result, limits)?;
        }
        for qualification in self.qualification.implementations.values() {
            if qualification.conformance_families.is_empty()
                || qualification
                    .conformance_families
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(DocumentError::Decode {
                    label: Self::SCHEMA.to_string(),
                    source: anyhow::anyhow!(
                        "package qualification families must be non-empty and strictly ordered"
                    ),
                });
            }
            ensure_schema_depth(&qualification.observer.arguments, limits)?;
            ensure_schema_depth(&qualification.observer.result, limits)?;
        }
        if let Some(probe) = &self.qualification.package_probe {
            validate_package_probe(probe, &self.artifacts, limits)?;
        }
        Ok(())
    }

    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        #[derive(Serialize)]
        struct SemanticGuarantee<'a> {
            name: &'a InterfaceName,
            version: std::num::NonZeroU32,
            semantics: &'a str,
        }

        #[derive(Serialize)]
        struct SemanticPackageSubject<'a> {
            name: &'a LocalKey,
            version: &'a str,
            payload: crate::ArtifactIdentity,
            source: crate::ArtifactIdentity,
        }

        #[derive(Serialize)]
        struct SemanticModuleLocator<'a> {
            artifact: crate::ArtifactIdentity,
            path: &'a RelativePath,
        }

        #[derive(Serialize)]
        struct SemanticHandler<'a> {
            artifact: crate::ArtifactIdentity,
            entry_point: &'a str,
            arguments: &'a ValueSchema,
            result: &'a ValueSchema,
        }

        #[derive(Serialize)]
        struct SemanticPackageImplementation<'a> {
            providers: Vec<Sha256Digest>,
            handlers: BTreeMap<&'a LocalKey, SemanticHandler<'a>>,
        }

        #[derive(Serialize)]
        struct SemanticPackageQualification<'a> {
            package_probe: Option<SemanticPackageProbe<'a>>,
            implementations: BTreeMap<&'a Sha256Digest, SemanticQualification<'a>>,
        }

        #[derive(Serialize)]
        struct SemanticPackageProbe<'a> {
            primary: SemanticPackageProbeOperation<'a>,
            bad_input: SemanticPackageProbeOperation<'a>,
        }

        #[derive(Serialize)]
        struct SemanticPackageProbeOperation<'a> {
            input: &'a str,
            operation: &'a str,
            expected: &'a str,
            files: BTreeMap<&'a RelativePath, SemanticPackageProbeTemplate<'a>>,
            steps: Vec<SemanticPackageProbeStep<'a>>,
            artifacts: &'a [crate::PackageProbeArtifact],
        }

        #[derive(Serialize)]
        struct SemanticPackageProbeStep<'a> {
            argv: Vec<SemanticPackageProbeTemplate<'a>>,
            stdin: Option<SemanticPackageProbeTemplate<'a>>,
            stdout: Option<SemanticPackageProbeTemplate<'a>>,
            stderr: Option<SemanticPackageProbeTemplate<'a>>,
            exit_code: u8,
            timeout_seconds: Option<u16>,
            observes_rejection: bool,
        }

        #[derive(Serialize)]
        struct SemanticPackageProbeTemplate<'a> {
            fragments: Vec<SemanticPackageProbeTemplateFragment<'a>>,
        }

        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        enum SemanticPackageProbeTemplateFragment<'a> {
            Literal {
                text: &'a str,
            },
            ArtifactRoot {
                artifact: crate::ArtifactIdentity,
            },
            ArtifactPath {
                artifact: crate::ArtifactIdentity,
                path: &'a RelativePath,
            },
            WorkPath {
                path: &'a RelativePath,
            },
            Harness {
                tool: crate::PackageProbeHarness,
            },
        }

        #[derive(Serialize)]
        struct SemanticExport<'a> {
            name: &'a LocalKey,
            interface: &'a InterfaceKey,
            implementation: Sha256Digest,
        }

        #[derive(Serialize)]
        struct SemanticOptionDeclaration<'a> {
            path: &'a [String],
            structured_type: &'a crate::OptionType,
            default: Option<&'a AbilityValue>,
            visibility: crate::OptionVisibility,
            read_only: bool,
            contributable: bool,
        }

        #[derive(Serialize)]
        struct SemanticQualification<'a> {
            adapter: &'a LocalKey,
            scope: &'a LocalKey,
            observation_kind: &'a LocalKey,
            conformance_families: &'a [LocalKey],
            observer: SemanticHandler<'a>,
        }

        #[derive(Serialize)]
        struct SemanticRequirement<'a> {
            alias: &'a LocalKey,
            accepted_interfaces: &'a [crate::InterfaceSelector],
            methods: &'a [LocalKey],
            guarantees: &'a [GuaranteeKey],
            strength: crate::interface::RequirementStrength,
            fallback: &'a Option<crate::interface::RequirementFallback>,
        }

        #[derive(Serialize)]
        struct SemanticPackage<'a> {
            schema: &'a str,
            required_features: &'a [RequiredFeature],
            package: SemanticPackageSubject<'a>,
            artifacts: Vec<crate::ArtifactIdentity>,
            interfaces: &'a BTreeMap<LocalKey, InterfaceKey>,
            guarantees: BTreeMap<LocalKey, SemanticGuarantee<'a>>,
            package_module: Option<SemanticModuleLocator<'a>>,
            option_declarations: Vec<SemanticOptionDeclaration<'a>>,
            exports: Vec<SemanticExport<'a>>,
            requirements: Vec<SemanticRequirement<'a>>,
            implementation: SemanticPackageImplementation<'a>,
            qualification: SemanticPackageQualification<'a>,
        }

        let guarantees = self
            .guarantees
            .iter()
            .map(|(alias, guarantee)| {
                (
                    alias.clone(),
                    SemanticGuarantee {
                        name: &guarantee.name,
                        version: guarantee.version,
                        semantics: &guarantee.semantics,
                    },
                )
            })
            .collect();
        let providers = self
            .implementation
            .providers
            .iter()
            .map(|provider| provider.descriptor_digest())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;
        let handlers = self
            .implementation
            .handlers
            .iter()
            .map(|(name, handler)| {
                (
                    name,
                    SemanticHandler {
                        artifact: handler.artifact.identity(),
                        entry_point: &handler.entry_point,
                        arguments: &handler.arguments,
                        result: &handler.result,
                    },
                )
            })
            .collect();
        let qualification = self
            .qualification
            .implementations
            .iter()
            .map(|(implementation, qualification)| {
                (
                    implementation,
                    SemanticQualification {
                        adapter: &qualification.adapter,
                        scope: &qualification.scope,
                        observation_kind: &qualification.observation_kind,
                        conformance_families: &qualification.conformance_families,
                        observer: SemanticHandler {
                            artifact: qualification.observer.artifact.identity(),
                            entry_point: &qualification.observer.entry_point,
                            arguments: &qualification.observer.arguments,
                            result: &qualification.observer.result,
                        },
                    },
                )
            })
            .collect();
        fn semantic_template(
            template: &crate::PackageProbeTemplate,
        ) -> SemanticPackageProbeTemplate<'_> {
            SemanticPackageProbeTemplate {
                fragments: template
                    .fragments
                    .iter()
                    .map(|fragment| match fragment {
                        crate::PackageProbeTemplateFragment::Literal { text } => {
                            SemanticPackageProbeTemplateFragment::Literal { text }
                        }
                        crate::PackageProbeTemplateFragment::ArtifactRoot { artifact } => {
                            SemanticPackageProbeTemplateFragment::ArtifactRoot {
                                artifact: artifact.identity(),
                            }
                        }
                        crate::PackageProbeTemplateFragment::ArtifactPath { artifact, path } => {
                            SemanticPackageProbeTemplateFragment::ArtifactPath {
                                artifact: artifact.identity(),
                                path,
                            }
                        }
                        crate::PackageProbeTemplateFragment::WorkPath { path } => {
                            SemanticPackageProbeTemplateFragment::WorkPath { path }
                        }
                        crate::PackageProbeTemplateFragment::Harness { tool } => {
                            SemanticPackageProbeTemplateFragment::Harness { tool: *tool }
                        }
                    })
                    .collect(),
            }
        }

        fn semantic_operation(
            operation: &crate::PackageProbeOperation,
        ) -> SemanticPackageProbeOperation<'_> {
            SemanticPackageProbeOperation {
                input: &operation.input,
                operation: &operation.operation,
                expected: &operation.expected,
                files: operation
                    .files
                    .iter()
                    .map(|(path, template)| (path, semantic_template(template)))
                    .collect(),
                steps: operation
                    .steps
                    .iter()
                    .map(|step| SemanticPackageProbeStep {
                        argv: step.argv.iter().map(semantic_template).collect(),
                        stdin: step.stdin.as_ref().map(semantic_template),
                        stdout: step.stdout.as_ref().map(semantic_template),
                        stderr: step.stderr.as_ref().map(semantic_template),
                        exit_code: step.exit_code,
                        timeout_seconds: step.timeout_seconds,
                        observes_rejection: step.observes_rejection,
                    })
                    .collect(),
                artifacts: &operation.artifacts,
            }
        }
        let package_probe =
            self.qualification
                .package_probe
                .as_ref()
                .map(|probe| SemanticPackageProbe {
                    primary: semantic_operation(&probe.primary),
                    bad_input: semantic_operation(&probe.bad_input),
                });
        let semantic = SemanticPackage {
            schema: &self.schema,
            required_features: &self.required_features,
            package: SemanticPackageSubject {
                name: &self.package.name,
                version: &self.package.version,
                payload: self.package.payload.identity(),
                source: self.package.source.identity(),
            },
            artifacts: self
                .artifacts
                .iter()
                .map(ArtifactReference::identity)
                .collect(),
            interfaces: &self.interfaces,
            guarantees,
            package_module: self
                .package_module
                .as_ref()
                .map(|module| SemanticModuleLocator {
                    artifact: module.artifact.identity(),
                    path: &module.path,
                }),
            option_declarations: self
                .option_declarations
                .iter()
                .map(|declaration| SemanticOptionDeclaration {
                    path: &declaration.path,
                    structured_type: &declaration.structured_type,
                    default: match &declaration.default {
                        Some(crate::DocumentedValue::Literal { value }) => Some(value),
                        Some(crate::DocumentedValue::Text { .. }) | None => None,
                    },
                    visibility: declaration.visibility,
                    read_only: declaration.read_only,
                    contributable: declaration.contributable,
                })
                .collect(),
            exports: self
                .exports
                .iter()
                .map(|export| SemanticExport {
                    name: &export.name,
                    interface: &export.interface,
                    implementation: export.implementation,
                })
                .collect(),
            requirements: self
                .requirements
                .iter()
                .map(|requirement| SemanticRequirement {
                    alias: &requirement.alias,
                    accepted_interfaces: &requirement.accepted_interfaces,
                    methods: &requirement.methods,
                    guarantees: &requirement.guarantees,
                    strength: requirement.strength,
                    fallback: &requirement.fallback,
                })
                .collect(),
            implementation: SemanticPackageImplementation {
                providers,
                handlers,
            },
            qualification: SemanticPackageQualification {
                package_probe,
                implementations: qualification,
            },
        };

        let bytes =
            aos_contract::canonical::to_vec(&semantic).map_err(|source| DocumentError::Decode {
                label: Self::SCHEMA.to_string(),
                source,
            })?;

        Ok(Sha256Digest::separated(Self::SCHEMA, bytes))
    }
}

impl VersionedDocument for DesiredStateDocument {
    const SCHEMA: &'static str = "aos.ability.desired/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        for output in &self.outputs {
            ensure_expression_depth(&output.value, limits)?;
        }
        Ok(())
    }
}

impl VersionedDocument for EffectPlanDocument {
    const SCHEMA: &'static str = "aos.ability.effect-plan/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }

    fn limit_profile(&self) -> Option<&LimitProfile> {
        Some(&self.limits)
    }

    fn validate_structure(&self, limits: &LimitProfile) -> Result<(), DocumentError> {
        for operation in &self.operations {
            ensure_expression_depth(&operation.inputs, limits)?;
        }
        for merge in &self.merges {
            for output in merge.outputs.values() {
                ensure_schema_depth(&output.descriptor.schema, limits)?;
            }
        }
        Ok(())
    }
}
