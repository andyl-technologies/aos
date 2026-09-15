//! Deterministic systemd drop-in rendering from checked realizations.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::model::{
    PackagedUnitRealization, REALIZATION_SCHEMA, SERVICE_REALIZATION_SCHEMA,
    ServiceLinkRelationship, ServiceRealization,
};
use crate::semantic::{render_sections, render_unit_document, resolve_unit_identity};

pub(crate) const DROP_IN_FILE: &str = "overrides.conf";

pub(crate) struct RenderedUnit {
    pub(crate) source: PathBuf,
    pub(crate) drop_in: Vec<u8>,
}

pub(crate) struct RenderedServiceUnit {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct RenderedService {
    pub(crate) primary_unit: String,
    pub(crate) units: Vec<RenderedServiceUnit>,
    pub(crate) links: Vec<RenderedServiceLink>,
}

pub(crate) struct RenderedServiceLink {
    pub(crate) path: String,
    pub(crate) target: String,
}

pub(crate) fn validate_unit_name(name: &str) -> Result<()> {
    const SUFFIXES: &[&str] = &[
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".path",
        ".mount",
        ".automount",
        ".swap",
        ".device",
    ];

    if name.is_empty() || name.len() > 255 || !SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
    {
        bail!("systemd realization contains an invalid unit name");
    }
    let bytes = name.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b':' | b'-') {
            index += 1;
            continue;
        }
        if byte == b'\\'
            && bytes.get(index + 1) == Some(&b'x')
            && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(index + 3).is_some_and(u8::is_ascii_hexdigit)
        {
            index += 4;
            continue;
        }
        bail!("systemd realization contains an invalid unit name");
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("systemd realization contains a non-relative unit file");
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("systemd realization unit file escapes its artifact");
    }
    Ok(())
}

pub(crate) fn render(realization: &PackagedUnitRealization) -> Result<RenderedUnit> {
    if realization.schema != REALIZATION_SCHEMA {
        bail!("systemd realization uses an unsupported schema");
    }
    validate_unit_name(&realization.systemd_unit.unit_name)?;
    validate_relative_path(&realization.source.unit_file)?;
    let drop_in = render_sections(&realization.drop_in)?;

    let artifact_root = checked_store_root(&realization.source.artifact.store_path)?;
    let source = artifact_root.join(&realization.source.unit_file);
    let canonical_source = source
        .canonicalize()
        .with_context(|| format!("resolving packaged unit {}", source.display()))?;
    let canonical_root = artifact_root
        .canonicalize()
        .with_context(|| format!("resolving artifact root {}", artifact_root.display()))?;
    if !canonical_source.starts_with(&canonical_root) || !canonical_source.is_file() {
        bail!("packaged unit is not a regular file contained by its artifact");
    }

    Ok(RenderedUnit { source, drop_in })
}

pub(crate) fn render_service(realization: &ServiceRealization) -> Result<RenderedService> {
    if realization.schema != SERVICE_REALIZATION_SCHEMA {
        bail!("systemd service realization uses an unsupported schema");
    }

    let (primary_unit, primary_source) = resolve_unit_identity(&realization.systemd_unit)?;
    let mut units = Vec::with_capacity(realization.units.len());
    for unit in &realization.units {
        units.push(RenderedServiceUnit {
            name: unit.systemd_unit.unit_name.clone(),
            bytes: render_unit_document(unit)?,
        });
    }
    units.sort_by(|left, right| left.name.cmp(&right.name));
    if units.windows(2).any(|pair| pair[0].name == pair[1].name) {
        bail!("systemd service realization contains duplicate unit names");
    }

    if realization.facets.is_empty() {
        bail!("systemd service realization has no authenticated facets");
    }
    let encoded_facets = realization
        .facets
        .iter()
        .map(aos_contract::canonical::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("canonicalizing service facet catalog")?;
    if encoded_facets.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("systemd service facet catalog is not unique and canonically ordered");
    }

    let primary_is_materialized = units.iter().any(|unit| unit.name == primary_unit);
    if primary_source == primary_unit && !primary_is_materialized {
        bail!("systemd service realization omits its primary unit document");
    }
    if primary_source != primary_unit && primary_is_materialized {
        bail!("systemd template instance must not materialize an instance-specific unit");
    }

    let mut links = realization
        .links
        .iter()
        .map(checked_link)
        .collect::<Result<Vec<_>>>()?;
    links.sort_by(|left, right| left.path.cmp(&right.path));
    if links.windows(2).any(|pair| pair[0].path == pair[1].path) {
        bail!("systemd service realization contains duplicate installation links");
    }
    if links.iter().any(|link| {
        let child = link.path.rsplit('/').next();
        child != Some(primary_unit.as_str())
            && !units.iter().any(|unit| Some(unit.name.as_str()) == child)
    }) {
        bail!("systemd service link names a unit outside its realization");
    }

    Ok(RenderedService {
        primary_unit,
        units,
        links,
    })
}

fn checked_link(link: &crate::model::RealizedServiceLink) -> Result<RenderedServiceLink> {
    let (parent, _) = resolve_unit_identity(&link.parent)?;
    let (child, child_source) = resolve_unit_identity(&link.child)?;
    let relationship = match link.relationship {
        ServiceLinkRelationship::Requires => "requires",
        ServiceLinkRelationship::Wants => "wants",
    };
    let path = format!("{parent}.{relationship}/{child}");
    validate_install_path(&path)?;
    Ok(RenderedServiceLink {
        path,
        target: format!("../{child_source}"),
    })
}

fn validate_install_path(path: &str) -> Result<()> {
    let components = Path::new(path).components().collect::<Vec<_>>();
    if components.len() != 2
        || !components
            .iter()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!("systemd service link has an invalid relative path");
    }
    let directory = components[0].as_os_str().to_string_lossy();
    let leaf = components[1].as_os_str().to_string_lossy();
    if !(directory.ends_with(".wants") || directory.ends_with(".requires")) {
        bail!("systemd service link uses an unsupported installation relationship");
    }
    validate_unit_name(&leaf)
}

fn checked_store_root(store_path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(store_path);
    if !path.is_absolute() || !store_path.starts_with("/nix/store/") {
        bail!("artifact reference has an invalid store path");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::LocalKey;

    use super::{render_service, validate_relative_path, validate_unit_name};
    use crate::model::{
        SERVICE_REALIZATION_SCHEMA, ServiceFacetIdentity, ServiceRealization, ServiceUnitIdentity,
        SystemdUnitDocument, SystemdUnitIdentity,
    };

    #[test]
    fn unit_names_and_relative_paths_are_closed() {
        assert!(validate_unit_name("systemd-zram-setup@.service").is_ok());
        assert!(validate_unit_name("").is_err());
        assert!(validate_unit_name("../escape.service").is_err());
        assert!(validate_relative_path("lib/systemd/system/example.service").is_ok());
        assert!(validate_relative_path("../example.service").is_err());
        assert!(validate_relative_path("/example.service").is_err());
    }

    #[test]
    fn service_realization_rejects_duplicate_units() {
        let interface = serde_json::from_value(serde_json::json!({
            "name": "aos.service.lifecycle",
            "abi": 1,
            "descriptor": format!("sha256:{}", "1".repeat(64)),
        }))
        .expect("interface identity is valid");
        let realization = ServiceRealization {
            schema: SERVICE_REALIZATION_SCHEMA.to_string(),
            systemd_unit: ServiceUnitIdentity::Unit {
                unit_name: "example.service".to_string(),
            },
            units: vec![
                SystemdUnitDocument {
                    systemd_unit: SystemdUnitIdentity {
                        unit_name: "example.service".to_string(),
                    },
                    sections: vec![],
                },
                SystemdUnitDocument {
                    systemd_unit: SystemdUnitIdentity {
                        unit_name: "example.service".to_string(),
                    },
                    sections: vec![],
                },
            ],
            facets: vec![ServiceFacetIdentity {
                interface,
                facet: LocalKey::new("lifecycle").expect("facet parses"),
                observation_schema: "aos.ability.service-lifecycle-observation/v1".to_string(),
            }],
            links: Vec::new(),
            prerequisites: Vec::new(),
            enabled: true,
        };

        assert!(render_service(&realization).is_err());
    }
}
