//! Build-time materialization using the same semantic renderer as live reconciliation.

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::model::{
    Activation, PackagedUnitRealization, REALIZATION_SCHEMA, SERVICE_REALIZATION_SCHEMA,
    STATIC_MANIFEST_SCHEMA, ServiceRealization, ServiceUnitIdentity, StaticPrimaryUnit,
    StaticUnitManifest, StaticUnitManifestEntry,
};
use crate::render::{DROP_IN_FILE, render, render_service};

pub(crate) fn run() -> Result<()> {
    let input_path = env::var("realizationPath").context("render input path is not set")?;
    let output_path = env::var("out").context("render output path is not set")?;
    let bytes = fs::read(&input_path).context("reading static systemd realization")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("decoding realization")?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("static systemd realization has no schema"))?;

    match schema {
        REALIZATION_SCHEMA => render_packaged_unit(value, Path::new(&output_path)),
        SERVICE_REALIZATION_SCHEMA => render_service_unit(value, Path::new(&output_path)),
        _ => bail!("static systemd realization uses an unsupported schema"),
    }
}

fn render_service_unit(value: serde_json::Value, output: &Path) -> Result<()> {
    let realization: ServiceRealization =
        serde_json::from_value(value).context("decoding service realization")?;
    let rendered = render_service(&realization)?;
    let systemd_root = output.join("lib/systemd/system");
    fs::create_dir_all(&systemd_root).context("creating static systemd output")?;

    let mut entries = Vec::with_capacity(rendered.units.len() + rendered.links.len());
    for unit in rendered.units {
        let relative_path = format!("lib/systemd/system/{}", unit.name);
        fs::write(output.join(&relative_path), &unit.bytes)
            .context("writing static service unit")?;
        entries.push(StaticUnitManifestEntry::File {
            path: relative_path,
            content: aos_contract::Sha256Digest::of_bytes(&unit.bytes),
        });
    }
    for link in rendered.links {
        let relative_path = format!("lib/systemd/system/{}", link.path);
        let path = output.join(&relative_path);
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("static service link has no parent"))?;
        fs::create_dir_all(parent).context("creating static service installation directory")?;
        symlink(&link.target, path).context("linking static service installation")?;
        entries.push(StaticUnitManifestEntry::Symlink {
            path: relative_path,
            target: link.target,
        });
    }

    entries.sort_by(|left, right| manifest_path(left).cmp(manifest_path(right)));
    let logical_instance = match &realization.systemd_unit {
        ServiceUnitIdentity::Unit { .. } => None,
        ServiceUnitIdentity::TemplateInstance { instance, .. } => Some(instance.clone()),
    };
    write_manifest(
        output,
        StaticUnitManifest {
            schema: STATIC_MANIFEST_SCHEMA.to_string(),
            primary: StaticPrimaryUnit {
                unit_name: rendered.primary_unit,
                logical_instance,
            },
            entries,
        },
    )?;

    Ok(())
}

fn render_packaged_unit(value: serde_json::Value, output: &Path) -> Result<()> {
    let realization: PackagedUnitRealization =
        serde_json::from_value(value).context("decoding packaged-unit realization")?;
    let rendered = render(&realization)?;
    let systemd_root = output.join("lib/systemd/system");
    fs::create_dir_all(&systemd_root).context("creating static systemd output")?;

    let unit_name = &realization.systemd_unit.unit_name;
    let source_path = format!("lib/systemd/system/{unit_name}");
    symlink(&rendered.source, output.join(&source_path)).context("linking static packaged unit")?;
    let mut entries = vec![StaticUnitManifestEntry::Symlink {
        path: source_path,
        target: rendered.source.to_string_lossy().into_owned(),
    }];
    let drop_in_root = systemd_root.join(format!("{unit_name}.d"));
    fs::create_dir(&drop_in_root).context("creating static packaged-unit drop-in directory")?;
    let drop_in_path = format!("lib/systemd/system/{unit_name}.d/{DROP_IN_FILE}");
    fs::write(output.join(&drop_in_path), &rendered.drop_in)
        .context("writing static packaged-unit drop-in")?;
    entries.push(StaticUnitManifestEntry::File {
        path: drop_in_path,
        content: aos_contract::Sha256Digest::of_bytes(&rendered.drop_in),
    });

    if realization.activation == Activation::Enabled {
        let wants = systemd_root.join("multi-user.target.wants");
        fs::create_dir(&wants).context("creating static packaged-unit activation directory")?;
        let target = format!("../{unit_name}");
        let activation_path = format!("lib/systemd/system/multi-user.target.wants/{unit_name}");
        symlink(&target, output.join(&activation_path))
            .context("linking static packaged-unit activation")?;
        entries.push(StaticUnitManifestEntry::Symlink {
            path: activation_path,
            target,
        });
    }

    entries.sort_by(|left, right| manifest_path(left).cmp(manifest_path(right)));
    write_manifest(
        output,
        StaticUnitManifest {
            schema: STATIC_MANIFEST_SCHEMA.to_string(),
            primary: StaticPrimaryUnit {
                unit_name: unit_name.clone(),
                logical_instance: None,
            },
            entries,
        },
    )?;

    Ok(())
}

fn manifest_path(entry: &StaticUnitManifestEntry) -> &str {
    match entry {
        StaticUnitManifestEntry::File { path, .. }
        | StaticUnitManifestEntry::Symlink { path, .. } => path,
    }
}

fn write_manifest(output: &Path, manifest: StaticUnitManifest) -> Result<()> {
    let manifest_root = output.join("share/aos");
    fs::create_dir_all(&manifest_root).context("creating static manifest directory")?;
    let bytes = aos_contract::canonical::to_vec(&manifest)
        .context("encoding canonical static systemd manifest")?;
    fs::write(manifest_root.join("systemd-unit-manifest.json"), bytes)
        .context("writing static systemd manifest")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::render_service_unit;
    use crate::model::{STATIC_MANIFEST_SCHEMA, ServiceRealization, StaticUnitManifest};
    use crate::render::render_service;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aos-systemd-static-render-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn static_and_runtime_paths_use_identical_semantic_bytes() {
        let value = serde_json::json!({
            "schema": "aos.systemd.service-realization/v2",
            "systemd_unit": {"kind": "unit", "unit_name": "example.service"},
            "units": [{
                "systemd_unit": {"unit_name": "example.service"},
                "sections": [{
                    "name": "Service",
                    "directives": [{
                        "name": "ExecStart",
                        "value": {
                            "template": "@@AOS_SYSTEMD_SUBSTITUTION:s-path@@",
                            "substitutions": {
                                "s-path": {
                                    "prefix": "",
                                    "suffix": " --serve",
                                    "encoding": "quoted",
                                    "source": {
                                        "kind": "execution-path",
                                        "value": "/run/example"
                                    }
                                }
                            }
                        }
                    }]
                }]
            }],
            "facets": [{
                "interface": {
                    "name": "aos.service.lifecycle",
                    "abi": 1,
                    "descriptor": format!("sha256:{}", "1".repeat(64))
                },
                "facet": "lifecycle",
                "observation_schema": "aos.ability.service-lifecycle-observation/v1"
            }],
            "links": [{
                "parent": {"kind": "unit", "unit_name": "multi-user.target"},
                "child": {"kind": "unit", "unit_name": "example.service"},
                "relationship": "wants"
            }],
            "prerequisites": [],
            "enabled": true
        });
        let realization: ServiceRealization =
            serde_json::from_value(value.clone()).expect("service realization decodes");
        let expected = render_service(&realization)
            .expect("runtime rendering succeeds")
            .units
            .remove(0)
            .bytes;
        let output = temporary_directory();

        render_service_unit(value, &output).expect("static rendering succeeds");

        assert_eq!(
            fs::read(output.join("lib/systemd/system/example.service"))
                .expect("static unit is readable"),
            expected
        );
        assert_eq!(
            fs::read_link(
                output.join("lib/systemd/system/multi-user.target.wants/example.service")
            )
            .expect("static activation link is readable"),
            std::path::Path::new("../example.service")
        );
        let manifest: StaticUnitManifest = serde_json::from_slice(
            &fs::read(output.join("share/aos/systemd-unit-manifest.json"))
                .expect("static manifest is readable"),
        )
        .expect("static manifest decodes");
        assert_eq!(manifest.schema, STATIC_MANIFEST_SCHEMA);
        assert_eq!(manifest.primary.unit_name, "example.service");
        assert_eq!(manifest.primary.logical_instance, None);
        assert_eq!(manifest.entries.len(), 2);

        fs::remove_dir_all(output).expect("temporary static output is removable");
    }
}
