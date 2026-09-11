//! Presentation helpers for checked public ability references.

use aos_ability_model::{InterfaceKey, ValueSchema};
use aos_doc_model::{AbilityExportReference, PackageAbilityReference};
use serde_json::{Value, json};

use super::super::markdown_code_span;

pub(super) fn selector(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> Value {
    json!({
        "package": reference.package.as_str(),
        "version": reference.version,
        "export": export.name.as_str(),
        "interface": key.name.as_str(),
        "abi": key.abi,
        "descriptor": key.descriptor,
        "manifestSha256": reference.manifest_sha256,
        "packageDigest": reference.package_digest,
        "implementation": export.implementation
    })
}

pub(super) fn selector_matches(
    selected: &Value,
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
    key: &InterfaceKey,
) -> bool {
    selected.get("package").and_then(Value::as_str) == Some(reference.package.as_str())
        && selected.get("version").and_then(Value::as_str) == Some(&reference.version)
        && selected.get("export").and_then(Value::as_str) == Some(export.name.as_str())
        && selected.get("interface").and_then(Value::as_str) == Some(key.name.as_str())
        && selected.get("abi").and_then(Value::as_u64) == Some(u64::from(key.abi.get()))
        && selected.get("descriptor").and_then(Value::as_str)
            == Some(key.descriptor.to_string().as_str())
        && selected.get("manifestSha256").and_then(Value::as_str)
            == Some(reference.manifest_sha256.to_string().as_str())
        && selected.get("packageDigest").and_then(Value::as_str)
            == Some(reference.package_digest.to_string().as_str())
        && selected.get("implementation").and_then(Value::as_str)
            == Some(export.implementation.to_string().as_str())
}

pub(super) fn ability_markdown(
    reference: &PackageAbilityReference,
    export: &AbilityExportReference,
) -> String {
    let interface = &export.interface.interface;
    let key = export.interface.interface_key().ok();
    let methods = interface
        .methods
        .keys()
        .map(|method| markdown_code_span(method.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let guarantees = interface
        .guarantees
        .iter()
        .map(|guarantee| {
            format!(
                "{} v{} ({})",
                markdown_code_span(guarantee.name.as_str()),
                guarantee.version,
                markdown_code_span(&guarantee.descriptor.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let request = schema_summary(&interface.request);
    let configuration = interface
        .configuration
        .as_ref()
        .map(schema_summary)
        .unwrap_or_else(|| "none".to_string());
    let outputs = interface
        .outputs
        .keys()
        .map(|output| markdown_code_span(output.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} · ability ABI {}\n\nExport {} from package {} {}. Descriptor {}.\n\nRequest: {}. Configuration: {}. Outputs: {}. Methods: {}. Guarantees: {}.\n\nAuthenticated manifest {} · package contract {} · implementation {}. Static reference only; authorization and runtime availability require deployment/runtime evidence.",
        markdown_code_span(interface.name.as_str()),
        interface.abi,
        markdown_code_span(export.name.as_str()),
        markdown_code_span(reference.package.as_str()),
        markdown_code_span(&reference.version),
        markdown_code_span(
            &key.map(|value| value.descriptor.to_string())
                .unwrap_or_else(|| "invalid descriptor".to_string())
        ),
        request,
        configuration,
        if outputs.is_empty() { "none" } else { &outputs },
        if methods.is_empty() { "none" } else { &methods },
        if guarantees.is_empty() {
            "none"
        } else {
            &guarantees
        },
        markdown_code_span(&reference.manifest_sha256.to_string()),
        markdown_code_span(&reference.package_digest.to_string()),
        markdown_code_span(&export.implementation.to_string()),
    )
}

pub(super) fn ambiguity_markdown(
    matches: &[(&PackageAbilityReference, &AbilityExportReference)],
) -> String {
    let mut markdown = String::from(
        "Multiple authenticated ability contracts match this name. Select a package, version, export, ABI, and descriptor:\n",
    );
    for (reference, export) in matches {
        let interface = &export.interface.interface;
        let descriptor = export
            .interface
            .interface_key()
            .map(|key| key.descriptor.to_string())
            .unwrap_or_else(|_| "invalid descriptor".to_string());
        markdown.push_str(&format!(
            "\n- package {} {}, export {}, ABI {}, descriptor {}",
            markdown_code_span(reference.package.as_str()),
            markdown_code_span(&reference.version),
            markdown_code_span(export.name.as_str()),
            interface.abi,
            markdown_code_span(&descriptor),
        ));
    }
    markdown
}

pub(super) fn schema_summary(schema: &ValueSchema) -> String {
    match schema {
        ValueSchema::Boolean => "boolean".to_string(),
        ValueSchema::Integer { minimum, maximum } => format!("integer {minimum}..={maximum}"),
        ValueSchema::String { max_length, syntax } => {
            format!("string (max {max_length} bytes, syntax {syntax:?})")
        }
        ValueSchema::StringEnum { values } => format!("one of {}", values.join(", ")),
        ValueSchema::List { max_items, .. } => format!("list (max {max_items} items)"),
        ValueSchema::Map { max_entries, .. } => format!("map (max {max_entries} entries)"),
        ValueSchema::Record { fields, .. } => format!(
            "record {{{}}}",
            fields
                .keys()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueSchema::TaggedUnion { tag, variants } => format!(
            "tagged union by {} ({})",
            tag.as_str(),
            variants
                .keys()
                .map(|variant| variant.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueSchema::Optional { value } => format!("optional {}", schema_summary(value)),
        ValueSchema::ArtifactReference => "artifact reference".to_string(),
        ValueSchema::ResourceReference => "resource reference".to_string(),
        ValueSchema::ProviderAssignment => "provider assignment".to_string(),
        ValueSchema::OperationResultReference => "operation result reference".to_string(),
    }
}
