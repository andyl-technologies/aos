//! Validates narrow host policy overlays on authenticated package units.
//!
//! Primary units remain signed package artifacts. An evaluated package module
//! may emit explicitly authorized resource, scheduling, and mount drop-ins;
//! these cannot add commands, identities, privilege grants, or arbitrary
//! dependencies. Mount requirements are the only supported dependency policy.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};

use super::materialize::{ConfigManifest, EtcEntry};

/// Validates opted-in direct unit drop-ins declared by signed package modules.
pub(super) fn validate_package_unit_policy(manifest: &ConfigManifest) -> Result<()> {
    for (package, pin) in &manifest.package_outputs {
        let Some(expose) = &pin.expose else {
            continue;
        };
        let authorization = manifest
            .inputs
            .config_modules
            .package_names
            .iter()
            .position(|name| name == package)
            .and_then(|index| manifest.inputs.config_modules.authorizations.get(index));

        for unit in &expose.units {
            let prefix = format!("systemd/system/{unit}.d/");
            // Apply the new projection contract only to units with signed
            // module policy declarations. Existing operator policy for other
            // packages retains its previous semantics.
            if !authorization.is_some_and(|auth| {
                auth.artifacts
                    .etc
                    .iter()
                    .any(|path| path.starts_with(&prefix))
            }) {
                continue;
            }
            for (path, entry) in &manifest.etc {
                let Some(filename) = path.strip_prefix(&prefix) else {
                    continue;
                };
                if filename.contains('/') || !filename.ends_with(".conf") {
                    bail!("package unit policy {path:?} is not a direct .conf drop-in");
                }
                if manifest.ownership.etc.get(path) != Some(package)
                    || !authorization.is_some_and(|auth| auth.artifacts.etc.contains(path))
                {
                    bail!(
                        "package unit policy {path:?} lacks exact authenticated {package:?} ownership"
                    );
                }
                let EtcEntry::Text { text, mode } = entry else {
                    bail!("package unit policy {path:?} must be an inline regular file");
                };
                if !matches!(mode.as_str(), "0444" | "0644") {
                    bail!("package unit policy {path:?} has an unsafe file mode");
                }

                validate_policy_text(unit, text)
                    .with_context(|| format!("validating package unit policy {path:?}"))?;
            }
        }
    }

    Ok(())
}

fn validate_policy_text(unit: &str, text: &str) -> Result<()> {
    let mut section = "";
    let mut seen = BTreeSet::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            if !matches!(section, "Unit" | "Service" | "Slice") {
                bail!("unsupported policy section {section:?}");
            }
            continue;
        }
        let (key, value) = line.split_once('=').context("policy line has no '='")?;
        if !seen.insert((section, key)) || value.is_empty() {
            bail!("duplicate or empty package policy directive {key:?}");
        }

        let valid = match (section, key) {
            ("Unit", "RequiresMountsFor") if unit.ends_with(".service") => {
                value.split_ascii_whitespace().all(safe_absolute_path)
            }
            ("Service", "CPUSchedulingPolicy") if unit.ends_with(".service") => {
                matches!(value, "other" | "batch" | "idle")
            }
            ("Service", "IOSchedulingClass") if unit.ends_with(".service") => {
                matches!(value, "best-effort" | "idle")
            }
            ("Service", "IOSchedulingPriority") if unit.ends_with(".service") => {
                bounded_integer(value, 0, 7)
            }
            ("Service", "OOMScoreAdjust") if unit.ends_with(".service") => {
                bounded_integer(value, 0, 1000)
            }
            ("Slice", "CPUQuota") if unit.ends_with(".slice") => value
                .strip_suffix('%')
                .is_some_and(|number| bounded_integer(number, 1, i64::MAX)),
            ("Slice", "MemoryHigh" | "MemoryMax" | "MemorySwapMax") if unit.ends_with(".slice") => {
                memory_limit(value)
            }
            _ => false,
        };
        if !valid {
            bail!("unsupported or invalid package policy directive [{section}] {key}={value}");
        }
    }
    if seen.is_empty() {
        bail!("package policy drop-in has no directives");
    }

    Ok(())
}

fn bounded_integer(value: &str, min: i64, max: i64) -> bool {
    value
        .parse::<i64>()
        .is_ok_and(|number| number >= min && number <= max)
}

fn memory_limit(value: &str) -> bool {
    if matches!(value, "0" | "infinity") {
        return true;
    }
    if let Some(number) = value.strip_suffix('%') {
        return bounded_integer(number, 1, 100);
    }
    let number = value.trim_end_matches(['K', 'M', 'G', 'T']);
    value.len() - number.len() <= 1 && bounded_integer(number, 1, i64::MAX)
}

fn safe_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.split('/').all(|part| part != "." && part != "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_PATH: &str = "systemd/system/builder.service.d/30-policy.conf";

    fn policy_manifest() -> ConfigManifest {
        serde_json::from_value(serde_json::json!({
            "schema": "aos.config-manifest/v1", "units": {}, "etc": {
                POLICY_PATH: {"kind": "text", "mode": "0444", "text": "[Service]\nCPUSchedulingPolicy=idle\n"}
            }, "storePaths": [], "module_abi": 1, "packages": ["builder"],
            "packageOutputs": {"builder": {
                "version": "1", "platform": "x86_64-linux", "registry": "fixture",
                "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder", "closure": [],
                "expose": {"target": "aos-pkg-builder.target", "units": ["builder.service"]}
            }}, "graph": {"edges": {}}, "config": {}, "credentials": {},
            "inputs": {
                "base_lib": {"store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base", "abi_hash": "hash", "module_abi": 1},
                "evaluator": {"store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nix", "store_hash": "hash"},
                "config_modules": {"closure_hash": "hash", "count": 1, "store_paths": [], "nar_hashes": [],
                    "package_names": ["builder"], "module_abi_compat": [], "authorizations": [{
                        "owns": ["builder"], "contributes": {}, "artifacts": {"etc": [POLICY_PATH], "units": [], "users": [], "groups": []}
                    }]},
                "host_nix": {"content_hash": "hash", "trust_mode": "platform", "platform": "fixture", "signer_key": null, "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host"},
                "instance_facts": {"facts_hash": "hash", "platform": "fixture", "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-facts"}
            }, "ownership": {"etc": {POLICY_PATH: "builder"}, "units": {}, "jobScripts": {}, "users": {}, "presets": {}, "storePaths": {}}
        }))
        .unwrap()
    }

    #[test]
    fn requires_exact_signed_path_and_package_owner() {
        let manifest = policy_manifest();
        validate_package_unit_policy(&manifest).unwrap();

        for owner in ["@host", "@base", "other"] {
            let mut changed = manifest.clone();
            changed
                .ownership
                .etc
                .insert(POLICY_PATH.to_owned(), owner.to_owned());
            assert!(validate_package_unit_policy(&changed).is_err());
        }

        let mut undeclared = manifest.clone();
        let path = "systemd/system/builder.service.d/40-undeclared.conf";
        undeclared
            .etc
            .insert(path.to_owned(), manifest.etc[POLICY_PATH].clone());
        undeclared
            .ownership
            .etc
            .insert(path.to_owned(), "builder".to_owned());
        assert!(validate_package_unit_policy(&undeclared).is_err());

        let mut symlink = manifest.clone();
        symlink.etc.insert(
            POLICY_PATH.to_owned(),
            EtcEntry::Symlink {
                target: "../../../alternate.conf".to_owned(),
            },
        );
        assert!(validate_package_unit_policy(&symlink).is_err());
    }

    #[test]
    fn leaves_unrelated_operator_and_legacy_unit_policy_unchanged() {
        let mut manifest = policy_manifest();
        let path = "systemd/system/unrelated.service.d/local.conf";
        manifest.etc.insert(
            path.to_owned(),
            EtcEntry::Text {
                text: "[Service]\nExecStart=/operator-command\n".to_owned(),
                mode: "0644".to_owned(),
            },
        );
        manifest
            .ownership
            .etc
            .insert(path.to_owned(), "@host".to_owned());
        validate_package_unit_policy(&manifest).unwrap();

        manifest.inputs.config_modules.authorizations[0]
            .artifacts
            .etc
            .clear();
        manifest
            .ownership
            .etc
            .insert(POLICY_PATH.to_owned(), "@host".to_owned());
        validate_package_unit_policy(&manifest).unwrap();
    }

    #[test]
    fn accepts_bounded_service_and_slice_policy() {
        validate_policy_text(
            "builder.service",
            "[Unit]\nRequiresMountsFor=/var/cache/build\n",
        )
        .unwrap();
        validate_policy_text(
            "builder.service",
            "[Service]\nCPUSchedulingPolicy=idle\nIOSchedulingClass=best-effort\nIOSchedulingPriority=5\nOOMScoreAdjust=500\n",
        )
        .unwrap();
        validate_policy_text(
            "aos-pkg-builder.slice",
            "[Slice]\nCPUQuota=200%\nMemoryHigh=50%\nMemoryMax=70%\nMemorySwapMax=0\n",
        )
        .unwrap();
    }

    #[test]
    fn rejects_privilege_and_execution_changes_and_directive_injection() {
        for policy in [
            "[Service]\nExecStart=/arbitrary\n",
            "[Service]\nUser=root\n",
            "[Service]\nCPUSchedulingPolicy=fifo\n",
            "[Service]\nIOSchedulingPriority=8\n",
            "[Service]\nOOMScoreAdjust=-1000\n",
            "[Service]\nIOSchedulingPriority=1\nIOSchedulingPriority=2\n",
            "[Unit]\nRequiresMountsFor=/var/%i\n",
            "[Unit]\nRequiresMountsFor=/var/../nix\n",
            "[Unit]\nRequiresMountsFor=/var/cache\\\nExecStart=/arbitrary\n",
            "[Socket]\nListenStream=/tmp/alternate\n",
            "[Slice]\nMemoryMax=101%\n",
        ] {
            assert!(
                validate_policy_text("builder.service", policy).is_err(),
                "{policy}"
            );
        }
        assert!(
            validate_policy_text("builder.socket", "[Unit]\nRequiresMountsFor=/var\n").is_err()
        );
    }
}
