//! Rendering of symbolic systemd text retained in provider realizations.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use anyhow::{Result, bail};
use aos_ability_model::ABILITY_LIMITS_V1;

use crate::model::{
    SemanticSubstitution, SemanticSubstitutionEncoding, SemanticSubstitutionSource,
    SemanticUnitText, ServiceUnitIdentity, SystemdSection, SystemdUnitDocument,
};

const MARKER_PREFIX: &str = "@@AOS_SYSTEMD_SUBSTITUTION:";
const MARKER_SUFFIX: &str = "@@";

#[cfg(test)]
fn marker(key: &aos_ability_model::LocalKey) -> String {
    format!("{MARKER_PREFIX}{}{MARKER_SUFFIX}", key.as_str())
}

pub(crate) fn render_semantic_text(document: &SemanticUnitText) -> Result<Vec<u8>> {
    validate_template(&document.template)?;

    let mut rendered = String::with_capacity(document.template.len());
    let mut remaining = document.template.as_str();
    let mut consumed = BTreeSet::new();

    while let Some(marker_start) = remaining.find(MARKER_PREFIX) {
        rendered.push_str(&remaining[..marker_start]);

        let key_start = marker_start + MARKER_PREFIX.len();
        let marker_tail = &remaining[key_start..];
        let key_end = marker_tail.find(MARKER_SUFFIX).ok_or_else(|| {
            anyhow::anyhow!("systemd semantic text has an unterminated substitution")
        })?;
        let key = aos_ability_model::LocalKey::new(&marker_tail[..key_end])?;
        let substitution = document.substitutions.get(&key).ok_or_else(|| {
            anyhow::anyhow!("systemd semantic text names an unknown substitution")
        })?;

        rendered.push_str(&render_substitution(substitution)?);
        consumed.insert(key);
        remaining = &marker_tail[key_end + MARKER_SUFFIX.len()..];

        if rendered.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
            bail!("rendered systemd text exceeds the ability document byte limit");
        }
    }

    rendered.push_str(remaining);
    if consumed.len() != document.substitutions.len() {
        bail!("systemd semantic text contains an unused substitution");
    }
    if rendered.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        bail!("rendered systemd text exceeds the ability document byte limit");
    }
    Ok(rendered.into_bytes())
}

pub(crate) fn render_unit_document(document: &SystemdUnitDocument) -> Result<Vec<u8>> {
    crate::render::validate_unit_name(&document.systemd_unit.unit_name)?;
    render_sections(&document.sections)
}

pub(crate) fn render_sections(sections: &[SystemdSection]) -> Result<Vec<u8>> {
    if sections.is_empty() {
        bail!("systemd document has no sections");
    }

    let mut rendered = Vec::new();
    for (section_index, section) in sections.iter().enumerate() {
        if section_index != 0 {
            rendered.push(b'\n');
        }
        rendered.extend_from_slice(format!("[{}]\n", section.name.as_str()).as_bytes());

        for directive in &section.directives {
            validate_directive_name(&directive.name)?;
            rendered.extend_from_slice(directive.name.as_bytes());
            rendered.push(b'=');
            rendered.extend_from_slice(&render_semantic_text(&directive.value)?);
            rendered.push(b'\n');

            if rendered.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
                bail!("rendered systemd unit exceeds the ability document byte limit");
            }
        }
    }

    Ok(rendered)
}

fn validate_template(template: &str) -> Result<()> {
    if template.contains(['\0', '\n', '\r'])
        || template.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes
    {
        bail!("systemd semantic text has an invalid template");
    }
    Ok(())
}

fn validate_directive_name(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || (index != 0 && (byte.is_ascii_digit() || byte == b'-'))
        })
    {
        bail!("systemd unit document has an invalid directive name");
    }
    Ok(())
}

fn render_substitution(substitution: &SemanticSubstitution) -> Result<String> {
    validate_affix(&substitution.prefix)?;
    validate_affix(&substitution.suffix)?;

    let value = match &substitution.source {
        SemanticSubstitutionSource::ArtifactPath {
            artifact,
            relative_path,
        } => {
            validate_relative_path(relative_path)?;
            let root = Path::new(&artifact.store_path);
            if !root.is_absolute() || !artifact.store_path.starts_with("/nix/store/") {
                bail!("systemd artifact substitution has an invalid store root");
            }
            root.join(relative_path)
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("systemd artifact path is not UTF-8"))?
                .to_string()
        }
        SemanticSubstitutionSource::ExecutionPath { value }
        | SemanticSubstitutionSource::GroupName { value }
        | SemanticSubstitutionSource::PrincipalName { value }
        | SemanticSubstitutionSource::RuntimeString { value } => value.clone(),
        SemanticSubstitutionSource::SystemdUnitName { identity } => {
            resolve_unit_identity(identity)?.0
        }
    };
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("systemd substitution value contains a forbidden character");
    }

    let combined = format!("{}{}{}", substitution.prefix, value, substitution.suffix);
    match substitution.encoding {
        SemanticSubstitutionEncoding::Escaped => Ok(escape_systemd(&combined)),
        SemanticSubstitutionEncoding::Quoted => Ok(format!("\"{}\"", escape_systemd(&combined))),
        SemanticSubstitutionEncoding::Raw => Ok(combined),
    }
}

pub(crate) fn resolve_unit_identity(identity: &ServiceUnitIdentity) -> Result<(String, String)> {
    match identity {
        ServiceUnitIdentity::Unit { unit_name } => {
            crate::render::validate_unit_name(unit_name)?;
            Ok((unit_name.clone(), unit_name.clone()))
        }
        ServiceUnitIdentity::TemplateInstance {
            template_unit_name,
            instance,
        } => {
            crate::render::validate_unit_name(template_unit_name)?;
            let stem = template_unit_name
                .strip_suffix("@.service")
                .ok_or_else(|| {
                    anyhow::anyhow!("systemd template instance names a non-template service unit")
                })?;
            let escaped = escape_unit_component(instance)?;
            let unit_name = format!("{stem}@{escaped}.service");
            crate::render::validate_unit_name(&unit_name)?;
            Ok((unit_name, template_unit_name.clone()))
        }
    }
}

fn escape_unit_component(value: &str) -> Result<String> {
    if value.is_empty() {
        bail!("systemd template instance is empty");
    }

    let mut escaped = String::with_capacity(value.len());
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'/' {
            escaped.push('-');
        } else if byte.is_ascii_alphanumeric()
            || matches!(byte, b':' | b'_')
            || (byte == b'.' && index != 0)
        {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(escaped, "\\x{byte:02x}")?;
        }
    }
    Ok(escaped)
}

fn validate_affix(value: &str) -> Result<()> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        bail!("systemd substitution affix contains a forbidden character");
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("systemd artifact substitution has an invalid relative path");
    }
    Ok(())
}

fn escape_systemd(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('%', "%%")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{ArtifactReference, LocalKey};
    use aos_contract::Sha256Digest;

    use super::{marker, render_semantic_text, render_unit_document, resolve_unit_identity};
    use crate::model::{
        SemanticSubstitution, SemanticSubstitutionEncoding, SemanticSubstitutionSource,
        SemanticUnitText, ServiceUnitIdentity,
    };

    fn artifact() -> ArtifactReference {
        ArtifactReference {
            content: Sha256Digest::from_bytes([1; 32]),
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example".to_string(),
            nar_hash: Sha256Digest::from_bytes([2; 32]),
            closure: Sha256Digest::from_bytes([3; 32]),
        }
    }

    #[test]
    fn symbolic_artifact_paths_render_once_without_rescanning_values() {
        let key = LocalKey::new("s-artifact").expect("test substitution key is valid");
        let injected_marker = marker(&LocalKey::new("s-other").expect("marker key is valid"));
        let mut substitutions = BTreeMap::new();
        substitutions.insert(
            key.clone(),
            SemanticSubstitution {
                prefix: String::new(),
                suffix: format!(" --literal={injected_marker}"),
                encoding: SemanticSubstitutionEncoding::Quoted,
                source: SemanticSubstitutionSource::ArtifactPath {
                    artifact: artifact(),
                    relative_path: "bin/example".to_string(),
                },
            },
        );
        let document = SemanticUnitText {
            template: format!("ExecStart={}", marker(&key)),
            substitutions,
        };

        let rendered = render_semantic_text(&document).expect("semantic text renders");

        assert_eq!(
            String::from_utf8(rendered).expect("rendered text is UTF-8"),
            format!(
                "ExecStart=\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example/bin/example --literal={injected_marker}\""
            )
        );
    }

    #[test]
    fn unresolved_expression_cannot_decode_as_a_concrete_substitution() {
        let unresolved = serde_json::json!({
            "template": "Environment=@@AOS_SYSTEMD_SUBSTITUTION:s-value@@",
            "substitutions": {
                "s-value": {
                    "prefix": "KEY=",
                    "suffix": "",
                    "encoding": "quoted",
                    "source": {
                        "kind": "runtime-string",
                        "value": {
                            "_type": "aos-request-output-reference",
                            "request": "producer",
                            "output": "value"
                        }
                    }
                }
            }
        });

        assert!(serde_json::from_value::<SemanticUnitText>(unresolved).is_err());
    }

    #[test]
    fn template_instances_use_systemd_utf8_filename_escaping_without_hashing_identity() {
        let identity = ServiceUnitIdentity::TemplateInstance {
            template_unit_name: "worker@.service".to_string(),
            instance: "east/naïve-a".to_string(),
        };

        let (unit_name, source_name) =
            resolve_unit_identity(&identity).expect("logical instance resolves");

        assert_eq!(unit_name, r"worker@east-na\xc3\xafve\x2da.service");
        assert_eq!(source_name, "worker@.service");
    }

    #[test]
    fn missing_unknown_and_unused_substitutions_fail_closed() {
        let key = LocalKey::new("s-value").expect("test substitution key is valid");
        let substitution = SemanticSubstitution {
            prefix: String::new(),
            suffix: String::new(),
            encoding: SemanticSubstitutionEncoding::Raw,
            source: SemanticSubstitutionSource::ExecutionPath {
                value: "/run/example".to_string(),
            },
        };
        let mut substitutions = BTreeMap::new();
        substitutions.insert(key.clone(), substitution);

        let unknown = SemanticUnitText {
            template: "Path=@@AOS_SYSTEMD_SUBSTITUTION:s-unknown@@".to_string(),
            substitutions: substitutions.clone(),
        };
        assert!(render_semantic_text(&unknown).is_err());

        let unused = SemanticUnitText {
            template: "Path=/run/example".to_string(),
            substitutions,
        };
        assert!(render_semantic_text(&unused).is_err());

        let missing_suffix = SemanticUnitText {
            template: format!("Path={}", marker(&key).trim_end_matches("@@")),
            substitutions: BTreeMap::new(),
        };
        assert!(render_semantic_text(&missing_suffix).is_err());
    }

    #[test]
    fn one_unit_document_renders_all_sections_with_the_same_substitutions() {
        let document = serde_json::from_value(serde_json::json!({
            "systemd_unit": {"unit_name": "example.service"},
            "sections": [
                {
                    "name": "Unit",
                    "directives": [{
                        "name": "Description",
                        "value": {"template": "Example", "substitutions": {}}
                    }]
                },
                {
                    "name": "Service",
                    "directives": [{
                        "name": "ExecStart",
                        "value": {
                            "template": "@@AOS_SYSTEMD_SUBSTITUTION:s-path@@",
                            "substitutions": {
                                "s-path": {
                                    "prefix": "",
                                    "suffix": "",
                                    "encoding": "quoted",
                                    "source": {
                                        "kind": "artifact-path",
                                        "artifact": artifact(),
                                        "relative_path": "bin/example"
                                    }
                                }
                            }
                        }
                    }]
                }
            ]
        }))
        .expect("unit document is typed");

        let rendered = render_unit_document(&document).expect("unit document renders");

        assert_eq!(
            String::from_utf8(rendered).expect("rendered unit is UTF-8"),
            "[Unit]\nDescription=Example\n\n[Service]\nExecStart=\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example/bin/example\"\n"
        );
    }
}
