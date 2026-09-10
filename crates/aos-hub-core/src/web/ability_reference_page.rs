//! Authenticated public ability contracts on package browse pages.

use std::fmt::Write as _;

use aos_ability_model::{AbilityActivationMode, RequirementStrength, ValueSchema};

use super::console_render::urlencode;
use super::render::{escape, hash_value};

/// One release-pinned ability reference prepared for browser rendering.
#[derive(Debug, Clone)]
pub struct PackageAbilityReferencePanel {
    /// Exact release shown by the enclosing package page.
    pub release: String,
    /// Registry commit that authenticated the generated reference.
    pub indexed_commit: String,
    /// Exact target platform carrying the ability companion.
    pub platform: String,
    /// Bounded public projection of the signed companion documents.
    pub reference: aos_doc_model::PackageAbilityReference,
}

/// Renders a release-pinned package ability reference section.
#[must_use]
pub fn section(
    slug: &str,
    panel: Option<&PackageAbilityReferencePanel>,
    unavailable: bool,
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
        }
        html.push_str("</section>");
        return html;
    };

    let reference = &panel.reference;
    let activation = match reference.activation_mode {
        AbilityActivationMode::ContractsOnly => "contracts only",
        AbilityActivationMode::StructuredEffects => "structured effects",
    };
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
        "<dl class=\"meta\"><dt>Activation</dt><dd>{activation}</dd><dt>Supported environment</dt><dd>{}</dd><dt>Release commit</dt><dd>{}</dd><dt>Manifest</dt><dd>{}</dd><dt>Package contract</dt><dd>{}</dd></dl>",
        escape(&panel.platform),
        hash_value(&panel.indexed_commit),
        hash_value(&reference.manifest_sha256.to_string()),
        hash_value(&reference.package_digest.to_string()),
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

    html.push_str("<h3>Provides</h3>");
    if reference.exports.is_empty() {
        html.push_str("<p class=\"dim\">This package publishes no provider interfaces.</p>");
    }
    for export in &reference.exports {
        let interface = &export.interface.interface;
        let anchor = format!("ability-export-{}", export.name.as_str());
        let _ = write!(
            html,
            "<article class=\"ability-contract\"><h4 id=\"{}\">{}: {} <a href=\"#{}\">ABI {}</a></h4><p class=\"dim\">Descriptor {} · implementation {}</p>",
            escape(&anchor),
            escape(export.name.as_str()),
            escape(interface.name.as_str()),
            escape(&anchor),
            interface.abi,
            hash_value(&export.interface.interface_key().map(|key| key.descriptor.to_string()).unwrap_or_else(|_| "invalid".into())),
            hash_value(&export.implementation.to_string()),
        );
        html.push_str("<h5>Configuration request</h5>");
        schema(&mut html, &interface.request);

        if interface.outputs.is_empty() {
            html.push_str("<p class=\"dim\">No aggregate outputs.</p>");
        } else {
            html.push_str("<h5>Outputs</h5><ul>");
            for (name, output) in &interface.outputs {
                let _ = write!(
                    html,
                    "<li><code>{}</code> — {}, {}, {}</li>",
                    escape(name.as_str()),
                    scalar(&output.phase),
                    scalar(&output.visibility),
                    scalar(&output.lifetime),
                );
            }
            html.push_str("</ul>");
        }

        if !interface.methods.is_empty() {
            html.push_str("<h5>Methods</h5><ul>");
            for (name, method) in &interface.methods {
                let _ = write!(
                    html,
                    "<li><code>{}</code> — {} targeting <code>{}</code>",
                    escape(name.as_str()),
                    scalar(&method.operation_family),
                    escape(method.target_resource.as_str()),
                );
                if !method.permitted_operations.is_empty() {
                    let operations = method
                        .permitted_operations
                        .iter()
                        .map(|operation| escape(operation.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = write!(html, " (operations: {operations})");
                }
                html.push_str("</li>");
            }
            html.push_str("</ul>");
        }

        let lifecycle = &interface.lifecycle;
        let _ = write!(
            html,
            "<h5>Lifecycle</h5><ul><li>Stable resource identity: {}</li><li>Release ephemeral resources on disable: {}</li><li>Retain persistent state by default: {}</li>",
            yes_no(lifecycle.stable_resource_identity),
            yes_no(lifecycle.releases_ephemeral_on_disable),
            yes_no(lifecycle.retains_persistent_by_default),
        );
        if let Some(method) = &lifecycle.persistent_delete_method {
            let _ = write!(
                html,
                "<li>Persistent deletion method: <code>{}</code></li>",
                escape(method.as_str())
            );
        }
        html.push_str("</ul>");

        if let Some(aggregation) = &export.aggregation {
            let _ = write!(
                html,
                "<h5>Contribution consumption</h5><p>Scoped per provider instance with key <code>{}</code> and controller group <code>{}</code>. Slot collisions are {}.</p>",
                escape(aggregation.key.as_str()),
                escape(aggregation.controller_group.as_str()),
                if aggregation.reject_slot_collisions { "rejected" } else { "allowed" },
            );
        }
        html.push_str("</article>");
    }

    html.push_str("<h3>Requires</h3>");
    if reference.requirements.is_empty() {
        html.push_str(
            "<p class=\"dim\">This package declares no lower-interface requirements.</p>",
        );
    } else {
        html.push_str("<ul class=\"ability-requirements\">");
        for requirement in &reference.requirements {
            let strength = match requirement.strength {
                RequirementStrength::Required => "required",
                RequirementStrength::Advisory => "advisory",
            };
            let _ = write!(
                html,
                "<li><strong>{}</strong> <span class=\"dim\">({strength})</span><ul>",
                escape(requirement.alias.as_str()),
            );
            for accepted in &requirement.accepted_interfaces {
                let _ = write!(
                    html,
                    "<li>{} ABI {} · {}</li>",
                    escape(accepted.name.as_str()),
                    accepted.abi,
                    hash_value(&accepted.descriptor.to_string()),
                );
            }
            if !requirement.methods.is_empty() {
                let methods = requirement
                    .methods
                    .iter()
                    .map(|method| format!("<code>{}</code>", escape(method.as_str())))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = write!(html, "<li>Methods: {methods}</li>");
            }
            if requirement.fallback.is_some() {
                html.push_str("<li>Has an authenticated fallback output contract.</li>");
            }
            html.push_str("</ul></li>");
        }
        html.push_str("</ul>");
    }

    if !reference.ownership.is_empty() {
        html.push_str("<h3>Structured effect ownership</h3><ul>");
        for path in &reference.ownership {
            let display = if path.as_slice().is_empty() {
                "/".to_string()
            } else {
                path.as_slice()
                    .iter()
                    .map(|component| component.as_str())
                    .collect::<Vec<_>>()
                    .join("/")
            };
            let _ = write!(html, "<li><code>{}</code></li>", escape(&display));
        }
        html.push_str("</ul>");
    }

    if !reference.handlers.is_empty() {
        html.push_str("<h3>Structured effect handlers</h3>");
        for handler in &reference.handlers {
            let _ = write!(
                html,
                "<article class=\"ability-handler\"><h4>{}</h4><p>Authenticated entry point <code>{}</code></p><h5>Arguments</h5>",
                escape(handler.name.as_str()),
                escape(&handler.entry_point),
            );
            schema(&mut html, &handler.arguments);
            html.push_str("<h5>Result</h5>");
            schema(&mut html, &handler.result);
            html.push_str("</article>");
        }
    }

    html.push_str("<p class=\"dim\">This is a signed package contract. Live provider selection, assignment health, and observed runtime state belong to deployment views.</p></section>");
    html
}

fn schema(html: &mut String, value: &ValueSchema) {
    let rendered = serde_json::to_string_pretty(value)
        .unwrap_or_else(|_| "{\"kind\":\"unavailable\"}".to_string());
    let _ = write!(html, "<pre>{}</pre>", escape(&rendered));
}

fn scalar(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value)
        .map(|encoded| encoded.trim_matches('"').to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{
        AbilityActivationMode, InterfaceDescriptor, InterfaceDocument, InterfaceName,
        LifecycleSemantics, LocalKey, RequiredFeature, RequirementDeclaration, ScopePath,
    };
    use aos_contract::Sha256Digest;

    use super::*;

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).expect("valid local key")
    }

    fn panel() -> PackageAbilityReferencePanel {
        let interface = InterfaceDocument {
            schema: "aos.ability.interface/v1".into(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
            interface: InterfaceDescriptor {
                name: InterfaceName::new("aos.test.service").expect("interface name"),
                abi: std::num::NonZeroU32::new(1).expect("nonzero ABI"),
                request: ValueSchema::Boolean,
                outputs: BTreeMap::new(),
                methods: BTreeMap::new(),
                lifecycle: LifecycleSemantics {
                    stable_resource_identity: true,
                    releases_ephemeral_on_disable: true,
                    retains_persistent_by_default: false,
                    persistent_delete_method: None,
                },
                guarantees: Vec::new(),
            },
        };
        let interface_key = interface.interface_key().expect("interface key");
        PackageAbilityReferencePanel {
            release: "1.2.3".into(),
            indexed_commit: "a".repeat(64),
            platform: "x86_64-linux".into(),
            reference: aos_doc_model::PackageAbilityReference {
                schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.into(),
                required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
                package: key("demo"),
                version: "1.2.3".into(),
                manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
                package_digest: Sha256Digest::of_bytes(b"package"),
                activation_mode: AbilityActivationMode::StructuredEffects,
                exports: vec![aos_doc_model::AbilityExportReference {
                    name: key("server"),
                    interface,
                    aggregation: None,
                    implementation: Sha256Digest::of_bytes(b"implementation"),
                }],
                requirements: vec![RequirementDeclaration {
                    alias: key("network"),
                    accepted_interfaces: vec![interface_key],
                    methods: Vec::new(),
                    guarantees: Vec::new(),
                    strength: RequirementStrength::Required,
                    fallback: None,
                }],
                handlers: Vec::new(),
                ownership: vec![ScopePath::new(vec![key("services")]).expect("scope")],
            },
        }
    }

    #[test]
    fn renders_release_pinned_public_contract_without_runtime_claims() {
        let html = section("demo", Some(&panel()), false);

        assert!(html.contains("href=\"/demo/-/releases/1.2.3\""));
        assert!(html.contains("server: aos.test.service"));
        assert!(html.contains("href=\"#ability-export-server\">ABI 1</a>"));
        assert!(html.contains("<strong>network</strong>"));
        assert!(html.contains("Structured effect ownership"));
        assert!(html.contains("signed package contract"));
        assert!(html.contains("observed runtime state belong to deployment views"));
    }
}
