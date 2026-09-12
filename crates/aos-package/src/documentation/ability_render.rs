//! Safe terminal, HTML, and roff rendering for static package ability declarations.
//!
//! These views describe only the authenticated declaration carried by a
//! package companion. They deliberately omit activation, provider selection,
//! assignments, health, and observed runtime state.

use std::fmt::Write as _;

use anyhow::Result;
use aos_ability_model::{AbilityActivationMode, RequirementStrength, ValueSchema};
use aos_doc_model::PackageAbilityReference;

const SCOPE_NOTICE: &str = concat!(
    "Authenticated static package declaration. This section does not report activation, ",
    "provider selection, assignments, health, or observed runtime state. Operator ",
    "configuration sections show public schemas only, never deployed instance values."
);

pub(super) fn plain(reference: &PackageAbilityReference) -> Result<String> {
    let mut output = String::from("\nDECLARED ABILITIES\n------------------\n");
    let _ = writeln!(output, "{SCOPE_NOTICE}");
    let _ = writeln!(
        output,
        "declared activation mode\t{}",
        activation_mode(reference.activation_mode)
    );
    let _ = writeln!(output, "manifest identity\t{}", reference.manifest_sha256);
    let _ = writeln!(
        output,
        "package contract identity\t{}",
        reference.package_digest
    );

    output.push_str("\nDECLARED PROVIDES\n");
    if reference.exports.is_empty() {
        output.push_str("No provider interfaces are declared.\n");
    }
    for export in &reference.exports {
        let interface = &export.interface.interface;
        let descriptor = export.interface.interface_key()?.descriptor;
        let _ = writeln!(
            output,
            "declared export\t{}\t{}\tABI {}",
            export.name.as_str(),
            interface.name.as_str(),
            interface.abi
        );
        let _ = writeln!(output, "  descriptor identity\t{descriptor}");
        let _ = writeln!(
            output,
            "  implementation identity\t{}",
            export.implementation
        );
        output.push_str("  declared request or contribution schema\n");
        indented_schema(&mut output, &interface.request, "    ")?;
        if let Some(configuration) = &interface.configuration {
            output.push_str("  declared operator-owned provider instance configuration schema\n");
            indented_schema(&mut output, configuration, "    ")?;
        } else {
            output.push_str("  no operator-owned provider instance configuration is declared\n");
        }

        for (name, declared_output) in &interface.outputs {
            let _ = writeln!(
                output,
                "  declared aggregate output\t{}\t{}\t{}\t{}",
                name.as_str(),
                scalar(&declared_output.phase)?,
                scalar(&declared_output.visibility)?,
                scalar(&declared_output.lifetime)?
            );
        }
        for (name, method) in &interface.methods {
            let operations = method
                .permitted_operations
                .iter()
                .map(|operation| operation.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                output,
                "  declared method\t{}\t{}\ttarget {}\toperations [{}]",
                name.as_str(),
                scalar(&method.operation_family)?,
                method.target_resource.as_str(),
                operations
            );
        }

        let lifecycle = &interface.lifecycle;
        let _ = writeln!(
            output,
            "  declared lifecycle\tstable identity={}\trelease ephemeral={}\tretain persistent={}",
            yes_no(lifecycle.stable_resource_identity),
            yes_no(lifecycle.releases_ephemeral_on_disable),
            yes_no(lifecycle.retains_persistent_by_default)
        );
        if let Some(method) = &lifecycle.persistent_delete_method {
            let _ = writeln!(
                output,
                "  declared persistent deletion method\t{}",
                method.as_str()
            );
        }
        if let Some(aggregation) = &export.aggregation {
            let _ = writeln!(
                output,
                "  declared contribution aggregation\tkey {}\tcontroller group {}\tslot collisions {}",
                aggregation.key.as_str(),
                aggregation.controller_group.as_str(),
                if aggregation.reject_slot_collisions {
                    "rejected"
                } else {
                    "allowed"
                }
            );
        }
    }

    output.push_str("\nDECLARED REQUIRES\n");
    if reference.requirements.is_empty() {
        output.push_str("No lower-interface requirements are declared.\n");
    }
    for requirement in &reference.requirements {
        let _ = writeln!(
            output,
            "declared requirement\t{}\t{}",
            requirement.alias.as_str(),
            requirement_strength(requirement.strength)
        );
        for accepted in &requirement.accepted_interfaces {
            let _ = writeln!(
                output,
                "  accepted interface\t{}\tABI {}\t{}",
                accepted.name.as_str(),
                accepted.abi,
                accepted.descriptor
            );
        }
        if !requirement.methods.is_empty() {
            let methods = requirement
                .methods
                .iter()
                .map(|method| method.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(output, "  declared methods\t{methods}");
        }
        if requirement.fallback.is_some() {
            output.push_str("  authenticated fallback output contract declared\n");
        }
    }

    if !reference.ownership.is_empty() {
        output.push_str("\nDECLARED STRUCTURED EFFECT OWNERSHIP\n");
        for path in &reference.ownership {
            let _ = writeln!(output, "ownership root\t{}", scope_path(path));
        }
    }
    if !reference.handlers.is_empty() {
        output.push_str("\nDECLARED STRUCTURED EFFECT HANDLERS\n");
        for handler in &reference.handlers {
            let entry_point = safe_plain_text(&handler.entry_point);
            let _ = writeln!(
                output,
                "declared handler\t{}\tentry point {}",
                handler.name.as_str(),
                entry_point
            );
            output.push_str("  declared arguments schema\n");
            indented_schema(&mut output, &handler.arguments, "    ")?;
            output.push_str("  declared result schema\n");
            indented_schema(&mut output, &handler.result, "    ")?;
        }
    }

    Ok(output)
}

pub(super) fn html(reference: &PackageAbilityReference) -> Result<String> {
    let mut output =
        String::from("<section id=\"declared-abilities\"><h2>Declared abilities</h2><p>");
    escape_html_into(SCOPE_NOTICE, &mut output);
    output.push_str("</p><dl><dt>Declared activation mode</dt><dd>");
    escape_html_into(activation_mode(reference.activation_mode), &mut output);
    output.push_str("</dd><dt>Manifest identity</dt><dd><code>");
    escape_html_into(&reference.manifest_sha256.to_string(), &mut output);
    output.push_str("</code></dd><dt>Package contract identity</dt><dd><code>");
    escape_html_into(&reference.package_digest.to_string(), &mut output);
    output.push_str("</code></dd></dl><h3>Declared provides</h3>");

    if reference.exports.is_empty() {
        output.push_str("<p>No provider interfaces are declared.</p>");
    }
    for export in &reference.exports {
        let interface = &export.interface.interface;
        let descriptor = export.interface.interface_key()?.descriptor;
        output.push_str("<article><h4>Declared export <code>");
        escape_html_into(export.name.as_str(), &mut output);
        output.push_str("</code></h4><dl><dt>Interface</dt><dd><code>");
        escape_html_into(interface.name.as_str(), &mut output);
        let _ = write!(output, "</code> ABI {}</dd>", interface.abi);
        output.push_str("<dt>Descriptor identity</dt><dd><code>");
        escape_html_into(&descriptor.to_string(), &mut output);
        output.push_str("</code></dd><dt>Implementation identity</dt><dd><code>");
        escape_html_into(&export.implementation.to_string(), &mut output);
        output.push_str("</code></dd></dl><h5>Declared request or contribution schema</h5>");
        schema_html(&mut output, &interface.request)?;
        if let Some(configuration) = &interface.configuration {
            output.push_str(
                "<h5>Declared operator-owned provider instance configuration schema</h5>",
            );
            schema_html(&mut output, configuration)?;
        } else {
            output
                .push_str("<p>No operator-owned provider instance configuration is declared.</p>");
        }

        if !interface.outputs.is_empty() {
            output.push_str("<h5>Declared aggregate outputs</h5><ul>");
            for (name, declared_output) in &interface.outputs {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> - ");
                escape_html_into(&scalar(&declared_output.phase)?, &mut output);
                output.push_str(", ");
                escape_html_into(&scalar(&declared_output.visibility)?, &mut output);
                output.push_str(", ");
                escape_html_into(&scalar(&declared_output.lifetime)?, &mut output);
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }
        if !interface.methods.is_empty() {
            output.push_str("<h5>Declared methods</h5><ul>");
            for (name, method) in &interface.methods {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> - ");
                escape_html_into(&scalar(&method.operation_family)?, &mut output);
                output.push_str(" targeting <code>");
                escape_html_into(method.target_resource.as_str(), &mut output);
                output.push_str("</code>");
                if !method.permitted_operations.is_empty() {
                    output.push_str("; operations: ");
                    for (index, operation) in method.permitted_operations.iter().enumerate() {
                        if index > 0 {
                            output.push_str(", ");
                        }
                        output.push_str("<code>");
                        escape_html_into(operation.as_str(), &mut output);
                        output.push_str("</code>");
                    }
                }
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }

        let lifecycle = &interface.lifecycle;
        output.push_str("<h5>Declared lifecycle contract</h5><ul>");
        let _ = write!(
            output,
            "<li>Stable resource identity: {}</li><li>Release ephemeral resources on disable: {}</li><li>Retain persistent state by default: {}</li>",
            yes_no(lifecycle.stable_resource_identity),
            yes_no(lifecycle.releases_ephemeral_on_disable),
            yes_no(lifecycle.retains_persistent_by_default)
        );
        if let Some(method) = &lifecycle.persistent_delete_method {
            output.push_str("<li>Declared persistent deletion method: <code>");
            escape_html_into(method.as_str(), &mut output);
            output.push_str("</code></li>");
        }
        output.push_str("</ul>");

        if let Some(aggregation) = &export.aggregation {
            output.push_str("<h5>Declared contribution aggregation</h5><p>Key <code>");
            escape_html_into(aggregation.key.as_str(), &mut output);
            output.push_str("</code>; controller group <code>");
            escape_html_into(aggregation.controller_group.as_str(), &mut output);
            output.push_str("</code>; slot collisions are ");
            output.push_str(if aggregation.reject_slot_collisions {
                "rejected"
            } else {
                "allowed"
            });
            output.push_str(".</p>");
        }
        output.push_str("</article>");
    }

    output.push_str("<h3>Declared requires</h3>");
    if reference.requirements.is_empty() {
        output.push_str("<p>No lower-interface requirements are declared.</p>");
    } else {
        output.push_str("<ul>");
        for requirement in &reference.requirements {
            output.push_str("<li>Declared requirement <strong>");
            escape_html_into(requirement.alias.as_str(), &mut output);
            output.push_str("</strong> (");
            output.push_str(requirement_strength(requirement.strength));
            output.push_str(")<ul>");
            for accepted in &requirement.accepted_interfaces {
                output.push_str("<li>Accepted interface <code>");
                escape_html_into(accepted.name.as_str(), &mut output);
                let _ = write!(output, "</code> ABI {} - <code>", accepted.abi);
                escape_html_into(&accepted.descriptor.to_string(), &mut output);
                output.push_str("</code></li>");
            }
            if !requirement.methods.is_empty() {
                output.push_str("<li>Declared methods: ");
                for (index, method) in requirement.methods.iter().enumerate() {
                    if index > 0 {
                        output.push_str(", ");
                    }
                    output.push_str("<code>");
                    escape_html_into(method.as_str(), &mut output);
                    output.push_str("</code>");
                }
                output.push_str("</li>");
            }
            if requirement.fallback.is_some() {
                output.push_str("<li>Authenticated fallback output contract declared.</li>");
            }
            output.push_str("</ul></li>");
        }
        output.push_str("</ul>");
    }

    if !reference.ownership.is_empty() {
        output.push_str("<h3>Declared structured effect ownership</h3><ul>");
        for path in &reference.ownership {
            output.push_str("<li><code>");
            escape_html_into(&scope_path(path), &mut output);
            output.push_str("</code></li>");
        }
        output.push_str("</ul>");
    }
    if !reference.handlers.is_empty() {
        output.push_str("<h3>Declared structured effect handlers</h3>");
        for handler in &reference.handlers {
            output.push_str("<article><h4>Declared handler <code>");
            escape_html_into(handler.name.as_str(), &mut output);
            output.push_str("</code></h4><p>Authenticated entry point <code>");
            escape_html_into(&handler.entry_point, &mut output);
            output.push_str("</code></p><h5>Declared arguments schema</h5>");
            schema_html(&mut output, &handler.arguments)?;
            output.push_str("<h5>Declared result schema</h5>");
            schema_html(&mut output, &handler.result)?;
            output.push_str("</article>");
        }
    }

    output.push_str("</section>");
    Ok(output)
}

pub(super) fn roff(reference: &PackageAbilityReference) -> Result<String> {
    let plain = plain(reference)?;
    let mut output = String::from(".SH \"DECLARED ABILITIES\"\n.nf\n");
    for line in plain
        .strip_prefix("\nDECLARED ABILITIES\n------------------\n")
        .unwrap_or(&plain)
        .lines()
    {
        if line.starts_with('.') || line.starts_with('\'') {
            output.push_str("\\&");
        }
        for character in line.chars() {
            if character == '\\' {
                output.push_str("\\e");
            } else {
                output.push(character);
            }
        }
        output.push('\n');
    }
    output.push_str(".fi\n");
    Ok(output)
}

fn indented_schema(output: &mut String, schema: &ValueSchema, indent: &str) -> Result<()> {
    for line in serde_json::to_string_pretty(schema)?.lines() {
        let _ = writeln!(output, "{indent}{line}");
    }
    Ok(())
}

fn schema_html(output: &mut String, schema: &ValueSchema) -> Result<()> {
    output.push_str("<pre>");
    escape_html_into(&serde_json::to_string_pretty(schema)?, output);
    output.push_str("</pre>");
    Ok(())
}

fn scalar(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_string(value)?.trim_matches('"').to_string())
}

fn scope_path(path: &aos_ability_model::ScopePath) -> String {
    if path.as_slice().is_empty() {
        "/".to_string()
    } else {
        path.as_slice()
            .iter()
            .map(|component| component.as_str())
            .collect::<Vec<_>>()
            .join("/")
    }
}

fn safe_plain_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

const fn activation_mode(mode: AbilityActivationMode) -> &'static str {
    match mode {
        AbilityActivationMode::ContractsOnly => "contracts only",
        AbilityActivationMode::StructuredEffects => "structured effects",
    }
}

const fn requirement_strength(strength: RequirementStrength) -> &'static str {
    match strength {
        RequirementStrength::Required => "required",
        RequirementStrength::Advisory => "advisory",
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn escape_html_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character if character.is_control() => {
                let _ = write!(output, "&#x{:x};", u32::from(character));
            }
            _ => output.push(character),
        }
    }
}
