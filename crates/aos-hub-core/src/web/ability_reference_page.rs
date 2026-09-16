//! Authenticated public ability contracts on package browse pages.

use std::fmt::Write as _;

use super::console_render::urlencode;
use super::render::{escape, hash_value};

/// One release-pinned ability reference prepared for browser rendering.
#[derive(Debug, Clone)]
pub struct PackageAbilityReferencePanel {
    /// Exact release shown by the enclosing package page.
    pub release: String,
    /// Registry commit that authenticated the generated reference.
    pub indexed_commit: String,
    /// Exact target platform carrying the signed package projection.
    pub platform: String,
    /// Bounded public projection of the checked signed package document.
    pub reference: aos_doc_model::PackageAbilityReference,
    /// Exact retained locator used when matching private deployment overlays.
    pub locator: crate::db::PackageAbilityReferenceLocator,
}

/// One authenticated, fresh private deployment assertion prepared for rendering.
#[derive(Debug, Clone)]
pub struct PackageAbilityDeploymentPanel {
    /// Bounded reporter-authored plan and observation projection.
    pub overlay: aos_doc_model::PackageAbilityDeploymentOverlay,
    /// Labels the bearer authority that submitted the assertion.
    pub authority: String,
    /// Hub receipt time, independent of the reporter clock.
    pub received_at: i64,
    /// Hub-computed expiry time.
    pub expires_at: i64,
}

/// Renders a release-pinned package ability reference section.
#[must_use]
pub fn section(
    slug: &str,
    panel: Option<&PackageAbilityReferencePanel>,
    unavailable: bool,
    deployments: Option<&[PackageAbilityDeploymentPanel]>,
    deployments_unavailable: bool,
) -> String {
    let mut html =
        String::from("<section id=\"abilities\" class=\"package-abilities\"><h2>Abilities</h2>");
    let Some(panel) = panel else {
        if unavailable {
            html.push_str(
                "<p class=\"warn\">An authenticated ability reference is unavailable for this release.</p>",
            );
        } else {
            html.push_str(
                "<p class=\"dim\">No authenticated ability contract was published for this package in this release.</p>",
            );
            html.push_str(&aos_doc_model::render_absent_package_ability_reference_html());
        }
        html.push_str("</section>");
        return html;
    };

    let checked_graph = match super::ability_reference_inspection::section(panel) {
        Ok(graph) => graph,
        Err(_) => {
            html.push_str(
                "<p class=\"warn\">The authenticated public contract could not be checked by the shared ability inspector.</p></section>",
            );
            return html;
        }
    };

    let reference = &panel.reference;
    let _ = write!(
        html,
        "<p>Public contract for <strong>{}</strong> <code>{}</code> on <code>{}</code>, authenticated by release <a href=\"/{}/-/releases/{}\">{}</a>.</p>",
        escape(reference.package.as_str()),
        escape(&reference.version),
        escape(&panel.platform),
        escape(slug),
        urlencode(&panel.release),
        escape(&panel.release),
    );
    let _ = write!(
        html,
        "<dl class=\"meta\"><dt>Supported environment</dt><dd>{}</dd><dt>Release commit</dt><dd>{}</dd></dl>",
        escape(&panel.platform),
        hash_value(&panel.indexed_commit),
    );
    let _ = write!(
        html,
        "<p><a href=\"/{}/-/api/v1/packages/{}/abilities?version={}&amp;platform={}&amp;release={}\">Canonical ability reference JSON</a></p>",
        escape(slug),
        urlencode(reference.package.as_str()),
        urlencode(&reference.version),
        urlencode(&panel.platform),
        urlencode(&panel.release),
    );

    html.push_str(&checked_graph);

    html.push_str(&aos_doc_model::render_package_ability_reference_html(
        reference,
    ));

    if let Some(deployments) = deployments {
        html.push_str("<h3>Private deployment state</h3>");
        if deployments_unavailable {
            html.push_str(
                "<p class=\"warn\">Fresh deployment assertions are temporarily unavailable.</p>",
            );
        } else if deployments.is_empty() {
            html.push_str(
                "<p class=\"dim\">No fresh assertion matches this exact release, package, version, platform, and ability contract.</p>",
            );
        }
        for deployment in deployments {
            deployment_section(&mut html, deployment);
        }
    }

    html.push_str("</section>");
    html
}

fn deployment_section(html: &mut String, panel: &PackageAbilityDeploymentPanel) {
    let overlay = &panel.overlay;
    let _ = write!(
        html,
        "<article class=\"ability-deployment\"><h4>{}</h4><p class=\"dim\">Private reporter bearer assertion; reported {} · received {} · expires {} · sequence {}</p><dl class=\"meta\"><dt>Authority</dt><dd>{}</dd><dt>Environment</dt><dd>{}/{}/{}</dd><dt>Plan</dt><dd>{}</dd><dt>Policy revision</dt><dd>{}</dd><dt>Plan state</dt><dd>{}</dd></dl>",
        escape(overlay.deployment.as_str()),
        overlay.reported_at_unix_seconds,
        panel.received_at,
        panel.expires_at,
        overlay.sequence,
        escape(&panel.authority),
        escape(overlay.plan.environment.authority.as_str()),
        escape(overlay.plan.environment.key.as_str()),
        scalar(&overlay.plan.environment.stage),
        hash_value(&overlay.plan.plan.0.to_string()),
        hash_value(&overlay.plan.policy_revision.0.to_string()),
        scalar(&overlay.plan.state),
    );
    if overlay.plan.exports.is_empty() {
        html.push_str("<p class=\"dim\">The plan selects no exports from this package.</p>");
    } else {
        html.push_str("<table><thead><tr><th>export</th><th>interface</th><th>exact provider</th><th>observation</th></tr></thead><tbody>");
        for export in &overlay.plan.exports {
            let provider = export
                .provider
                .as_ref()
                .map(instance_identity)
                .unwrap_or_else(|| "unresolved".to_string());
            let observation = overlay
                .observations
                .iter()
                .find(|observation| {
                    observation.export == export.export
                        && export.provider.as_ref() == Some(&observation.instance)
                })
                .map(observation_summary)
                .unwrap_or_else(|| "not reported".to_string());
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{} ABI {} · {}</td><td>{}</td><td>{}</td></tr>",
                escape(export.export.as_str()),
                escape(export.interface.name.as_str()),
                export.interface.abi,
                hash_value(&export.interface.descriptor.to_string()),
                escape(&provider),
                escape(&observation),
            );
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</article>");
}

fn instance_identity(instance: &aos_ability_model::InstanceId) -> String {
    format!(
        "{}/{}/{}/{}",
        instance.environment.authority.as_str(),
        instance.environment.key.as_str(),
        scalar(&instance.environment.stage),
        instance.key.as_str(),
    )
}

fn observation_summary(observation: &aos_doc_model::AbilityDeploymentObservation) -> String {
    let revision = observation
        .revision
        .as_ref()
        .map(|revision| revision.0.to_string())
        .unwrap_or_else(|| "unknown revision".to_string());
    format!(
        "{}; observed {}; revision {}",
        scalar(&observation.state),
        observation.observed_at_unix_seconds,
        revision,
    )
}

fn scalar(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value)
        .map(|encoded| encoded.trim_matches('"').to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{
        AggregationContract, AggregationScope, ArtifactReference, EnvironmentId, ExecutionStage,
        InstanceId, InterfaceDescriptor, InterfaceDocument, InterfaceName, LifecycleSemantics,
        LocalKey, PlanId, ProviderImplementation, RequiredFeature, RequirementDeclaration,
        RequirementStrength, RevisionId, ValueSchema,
    };
    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn hub_uses_the_cross_frontend_golden_graph_slice() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = aos_ability_inspect::test_support::reference_inspection_fixture()?;
        let reference = fixture.reference;
        let canonical_json = reference.canonical_json()?;
        let panel = PackageAbilityReferencePanel {
            release: reference.version.clone(),
            indexed_commit: "b".repeat(64),
            platform: "x86_64-linux".to_string(),
            locator: crate::db::PackageAbilityReferenceLocator {
                indexed_commit: "b".repeat(64),
                package_name: reference.package.as_str().to_string(),
                package_version: reference.version.clone(),
                platform: "x86_64-linux".to_string(),
                manifest_sha256: reference.manifest_sha256.to_string(),
                package_digest: reference.package_digest.to_string(),
                canonical_json,
            },
            reference,
        };
        let query = aos_ability_inspect::GraphQuery::decode(&fixture.query)?;

        let slice = super::super::ability_reference_inspection::checked_slice(&panel, &query)?;

        assert_eq!(slice.canonical_bytes()?, fixture.slice);
        Ok(())
    }

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).expect("valid local key")
    }

    fn panel() -> PackageAbilityReferencePanel {
        let aggregation = AggregationContract {
            scope: AggregationScope::ProviderInstance,
            key: key("service"),
            controller_group: key("service"),
            reject_slot_collisions: true,
            merge_contract: None,
        };
        let interface = InterfaceDocument {
            schema: "aos.ability.interface/v1".into(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
            interface: InterfaceDescriptor {
                description: "Describes this ability interface.".to_string(),
                name: InterfaceName::new("aos.test.service").expect("interface name"),
                abi: std::num::NonZeroU32::new(1).expect("nonzero ABI"),
                request: ValueSchema::Boolean,
                configuration: Some(ValueSchema::String {
                    max_length: 64,
                    syntax: None,
                }),
                outputs: BTreeMap::new(),
                methods: BTreeMap::new(),
                lifecycle: LifecycleSemantics {
                    persistent_delete_method: None,
                },
                aggregation: aggregation.clone(),
                guarantees: Vec::new(),
            },
        };
        let interface_key = interface.interface_key().expect("interface key");
        let mut unexported_interface = interface.clone();
        unexported_interface.interface.name =
            InterfaceName::new("aos.test.internal").expect("interface name");
        unexported_interface.interface.description =
            "Describes an unexported package-owned interface.".to_string();
        let export_requirement = RequirementDeclaration {
            description: "Describes this consumed ability.".to_string(),
            alias: key("service-runtime"),
            accepted_interfaces: vec![interface_key.clone().into()],
            methods: Vec::new(),
            guarantees: Vec::new(),
            strength: RequirementStrength::Required,
            fallback: None,
        };
        let implementation = ProviderImplementation {
            name: key("server"),
            description: "Implements the test service interface.".to_string(),
            interface: interface_key.clone(),
            guarantees: Vec::new(),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"provider-content"),
                store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
                nar_hash: Sha256Digest::of_bytes(b"provider-nar"),
                closure: Sha256Digest::of_bytes(b"provider-closure"),
            },
            requirements: vec![export_requirement.clone()],
            desired_schema: None,
            provider_module: None,
            handler: None,
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation identity");
        let reference = aos_doc_model::PackageAbilityReference {
            schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.into(),
            required_features: vec![
                RequiredFeature::new("abilities-v1").expect("feature"),
                RequiredFeature::new(aos_doc_model::ABILITY_REFERENCE_PROVIDER_REQUIREMENTS_V1)
                    .expect("provider requirements feature"),
            ],
            package: key("demo"),
            version: "1.2.3".into(),
            manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
            package_digest: Sha256Digest::of_bytes(b"package"),
            interfaces: BTreeMap::from([
                (key("internal-interface"), unexported_interface),
                (key("service-interface"), interface),
            ]),
            guarantees: BTreeMap::new(),
            option_declarations: Vec::new(),
            implementations: vec![implementation],
            exports: vec![aos_doc_model::AbilityExportReference {
                name: key("server"),
                interface: interface_key.clone(),
                implementation: implementation_key,
                requirements: vec![export_requirement],
            }],
            requirements: vec![RequirementDeclaration {
                description: "Describes this consumed ability.".to_string(),
                alias: key("network"),
                accepted_interfaces: vec![interface_key.into()],
                methods: Vec::new(),
                guarantees: Vec::new(),
                strength: RequirementStrength::Required,
                fallback: None,
            }],
            handlers: Vec::new(),
        };
        let canonical_json = reference.canonical_json().expect("canonical reference");
        PackageAbilityReferencePanel {
            release: "1.2.3".into(),
            indexed_commit: "a".repeat(64),
            platform: "x86_64-linux".into(),
            reference,
            locator: crate::db::PackageAbilityReferenceLocator {
                indexed_commit: "a".repeat(64),
                package_name: "demo".into(),
                package_version: "1.2.3".into(),
                platform: "x86_64-linux".into(),
                manifest_sha256: Sha256Digest::of_bytes(b"manifest").to_string(),
                package_digest: Sha256Digest::of_bytes(b"package").to_string(),
                canonical_json,
            },
        }
    }

    fn deployment_panel(reference: &PackageAbilityReferencePanel) -> PackageAbilityDeploymentPanel {
        let environment = EnvironmentId {
            authority: key("fleet"),
            key: key("production"),
            stage: ExecutionStage::Host,
        };
        let provider = InstanceId {
            environment: environment.clone(),
            key: key("demo-east"),
        };
        let export = &reference.reference.exports[0];
        let interface = export.interface.clone();
        let revision = RevisionId(Sha256Digest::of_bytes(b"revision"));

        PackageAbilityDeploymentPanel {
            overlay: aos_doc_model::PackageAbilityDeploymentOverlay {
                schema: aos_doc_model::ABILITY_DEPLOYMENT_OVERLAY_SCHEMA.into(),
                required_features: aos_doc_model::ability_deployment_supported_features()
                    .expect("deployment features")
                    .into_iter()
                    .collect(),
                deployment: key("production"),
                sequence: 7,
                package: aos_doc_model::AbilityDeploymentPackage {
                    registry_commit: reference.locator.indexed_commit.clone(),
                    package: reference.reference.package.clone(),
                    version: reference.reference.version.clone(),
                    platform: reference.platform.clone(),
                    manifest_sha256: reference.reference.manifest_sha256,
                    package_digest: reference.reference.package_digest,
                },
                plan: aos_doc_model::AbilityDeploymentPlan {
                    environment,
                    plan: PlanId(Sha256Digest::of_bytes(b"plan")),
                    policy_revision: RevisionId(Sha256Digest::of_bytes(b"policy")),
                    transaction: None,
                    state: aos_doc_model::AbilityDeploymentPlanState::Committed,
                    exports: vec![aos_doc_model::AbilityDeploymentExport {
                        export: export.name.clone(),
                        interface,
                        implementation: export.implementation,
                        provider: Some(provider.clone()),
                        resources: Vec::new(),
                        binding_revision: Some(revision.clone()),
                    }],
                },
                observations: vec![aos_doc_model::AbilityDeploymentObservation {
                    export: export.name.clone(),
                    instance: provider,
                    state: aos_doc_model::AbilityDeploymentObservationState::Available,
                    revision: Some(revision),
                    evidence: Vec::new(),
                    observed_at_unix_seconds: 90,
                }],
                reported_at_unix_seconds: 100,
                valid_for_seconds: 60,
            },
            authority: "reporter-bearer:service_account:deployer".into(),
            received_at: 101,
            expires_at: 150,
        }
    }

    #[test]
    fn renders_release_pinned_public_contract_without_runtime_claims() {
        let html = section("demo", Some(&panel()), false, None, false);

        assert!(html.contains("href=\"/demo/-/releases/1.2.3\""));
        assert!(html.contains("Declared export <code>server</code>"));
        assert!(html.contains("<code>aos.test.service</code> ABI 1"));
        assert!(html.contains("internal-interface"));
        assert!(html.contains("Describes an unexported package-owned interface."));
        assert!(html.contains("Request or contribution schema"));
        assert!(html.contains("operator-owned provider instance configuration schema"));
        assert!(html.contains("&quot;max_length&quot;: 64"));
        assert!(html.contains("Provided abilities"));
        assert!(html.contains("Consumed abilities"));
        assert!(html.contains("<strong>network</strong>"));
        assert!(html.contains("<strong>service-runtime</strong>"));
        assert!(html.contains("consumed by <code>export server</code>"));
        assert!(html.contains("public schemas only, never deployed instance values"));
        assert!(html.contains("or observed runtime state"));
        assert!(!html.contains("Private deployment state"));
        assert!(!html.contains("reporter-bearer:"));
    }

    #[test]
    fn shared_inspector_rejection_hides_contract_and_deployment_projections() {
        let mut reference = panel();
        reference.reference.required_features = vec![
            RequiredFeature::new(aos_doc_model::ABILITY_REFERENCE_PROVIDER_REQUIREMENTS_V1)
                .expect("provider requirements feature"),
            RequiredFeature::new("future-reference-semantics-v1").expect("future feature"),
        ];
        reference.locator.canonical_json = reference
            .reference
            .canonical_json()
            .expect("canonical unsupported reference");
        let deployment = deployment_panel(&reference);

        let html = section("demo", Some(&reference), false, Some(&[deployment]), false);

        assert_eq!(
            html,
            concat!(
                "<section id=\"abilities\" class=\"package-abilities\"><h2>Abilities</h2>",
                "<p class=\"warn\">The authenticated public contract could not be checked by ",
                "the shared ability inspector.</p></section>",
            )
        );
        assert!(!html.contains("future-reference-semantics-v1"));
        assert!(!html.contains("Provided abilities"));
        assert!(!html.contains("Consumed abilities"));
        assert!(!html.contains("Private deployment state"));
        assert!(!html.contains("reporter-bearer:"));
    }

    #[test]
    fn packages_without_ability_projections_still_document_both_ability_directions() {
        let html = section("demo", None, false, None, false);

        assert!(html.contains("Provided abilities"));
        assert!(html.contains("No provided abilities are declared."));
        assert!(html.contains("Consumed abilities"));
        assert!(html.contains("No consumed abilities are declared."));
    }

    #[test]
    fn states_when_an_interface_declares_no_operator_configuration() {
        let mut panel = panel();
        let interface = panel
            .reference
            .interfaces
            .values_mut()
            .next()
            .expect("retained interface");
        interface.interface.configuration = None;
        let interface_key = interface.interface_key().expect("interface key");
        let implementation = &mut panel.reference.implementations[0];
        implementation.interface = interface_key.clone();
        implementation.requirements[0].accepted_interfaces = vec![interface_key.clone().into()];
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation identity");
        panel.reference.exports[0].interface = interface_key.clone();
        panel.reference.exports[0].implementation = implementation_key;
        panel.reference.exports[0].requirements[0].accepted_interfaces =
            vec![interface_key.clone().into()];
        panel.reference.requirements[0].accepted_interfaces = vec![interface_key.into()];
        panel.locator.canonical_json = panel
            .reference
            .canonical_json()
            .expect("canonical reference without configuration");

        let html = section("demo", Some(&panel), false, None, false);

        assert!(html.contains("No operator-owned provider instance configuration is declared."));
    }

    #[test]
    fn renders_exact_private_selection_and_observation_authority() {
        let reference = panel();
        let deployment = deployment_panel(&reference);

        let html = section("demo", Some(&reference), false, Some(&[deployment]), false);

        assert!(html.contains("Private reporter bearer assertion; reported 100"));
        assert!(html.contains("fleet/production/host/demo-east"));
        assert!(html.contains("available; observed 90; revision sha256:"));
        assert!(html.contains("reporter-bearer:service_account:deployer"));
    }
}
