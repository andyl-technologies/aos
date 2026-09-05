//! Tests for config-module interface derivation and validation of builder-authored claims.

use super::{derive_owned_root_names, scan_config_module_interface};
use crate::registry_ops::store_paths::TARGET_PLATFORM_RELATIVE_PATH;
use crate::types::{OwnedRoot, RootContribution};
use std::fs;
use tempfile::TempDir;

#[test]
fn publication_validates_explicit_same_name_owned_root() {
    let declarations = vec!["nginx.enable".to_string(), "nginx.virtualHosts".to_string()];
    let owned = vec![OwnedRoot {
        root: "nginx".to_string(),
        interface_abi: 1,
        contributable: vec!["virtualHosts".to_string()],
    }];

    assert_eq!(
        derive_owned_root_names(&declarations, "nginx", &owned),
        vec!["nginx".to_string()]
    );
    assert!(derive_owned_root_names(&declarations, "nginx", &[]).is_empty());
}

#[test]
fn config_interface_scan_excludes_own_write_from_requires() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::write(
        tmp.path().join("module.nix"),
        "{ config, ... }: { config.web.enable = true; }\n",
    )
    .expect("write module");

    let (contributes, capabilities, requires) =
        scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

    assert!(contributes.is_empty());
    assert!(capabilities.is_empty());
    assert!(requires.is_empty());
}

#[test]
fn config_interface_scan_excludes_module_system_metadata() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::write(
        tmp.path().join("module.nix"),
        "{ config, ... }: {\n  config._module.strict = true;\n  config.web.port = config._module.args.port;\n}\n",
    )
    .expect("write module");

    let (contributes, capabilities, requires) =
        scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

    assert!(contributes.is_empty());
    assert!(capabilities.is_empty());
    assert!(requires.is_empty());
}

#[test]
fn config_interface_scan_separates_foreign_reads_writes_and_capabilities() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::write(
        tmp.path().join("module.nix"),
        "{ config, ... }: {\n  config.nginx.virtualHosts = {};\n  config.system.capabilities.dns = true;\n  config.web.port = config.redis.port;\n}\n",
    )
    .expect("write module");

    let authored = vec![RootContribution {
        root: "nginx".to_string(),
        interface_abi: 1,
        paths: vec!["virtualHosts".to_string()],
    }];
    let (contributes, capabilities, requires) =
        scan_config_module_interface(tmp.path(), "web", &[], &authored).expect("scan module");

    assert_eq!(
        contributes,
        vec![RootContribution {
            root: "nginx".to_string(),
            interface_abi: 1,
            paths: vec!["virtualHosts".to_string()],
        }]
    );
    assert_eq!(capabilities, vec!["system.capabilities.dns"]);
    assert_eq!(requires, vec!["redis.port"]);
}

#[test]
fn config_interface_scan_does_not_trust_assignment_text_in_comments_or_strings() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::write(
        tmp.path().join("module.nix"),
        "{ ... }: {\n  # config.nginx.enable = true;\n  config.web.note = \"config.redis.enable = true\";\n}\n",
    )
    .expect("write module");

    let (contributes, capabilities, _requires) =
        scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

    assert!(contributes.is_empty());
    assert!(capabilities.is_empty());
}

#[test]
fn config_interface_scan_does_not_reinterpret_owned_config_suffixes() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::write(
        tmp.path().join("module.nix"),
        "{ config, ... }: {\n  config = {\n    cloudcore.config.runtime.CLOUDCORE_ENABLED = true;\n    cloudcore.config.listener.PORT = config.cloudcore.https.port;\n  };\n}\n",
    )
    .expect("write module");

    let (contributes, capabilities, requires) =
        scan_config_module_interface(tmp.path(), "cloudcore", &["cloudcore".to_string()], &[])
            .expect("scan module");

    assert!(contributes.is_empty());
    assert!(capabilities.is_empty());
    assert!(requires.is_empty());
}

#[test]
fn config_interface_scan_accepts_only_generated_expose_metadata() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::create_dir(tmp.path().join("generated")).expect("create generated directory");
    fs::write(tmp.path().join("module.nix"), "{ ... }: {}\n").expect("write module");
    fs::write(
        tmp.path().join("generated/expose-config.json"),
        "{\"schema\":\"aos.expose-config/v1\"}\n",
    )
    .expect("write generated exposure metadata");

    scan_config_module_interface(tmp.path(), "web", &[], &[])
        .expect("scan generated exposure metadata");

    fs::write(tmp.path().join("authored.json"), "{}\n").expect("write unauthorized helper");
    let error = scan_config_module_interface(tmp.path(), "web", &[], &[])
        .expect_err("reject unauthorized non-Nix helper");
    assert!(error.to_string().contains("non-Nix helper"), "{error:#}");
}

#[test]
fn config_interface_scan_accepts_only_the_canonical_target_platform_marker() {
    let tmp = TempDir::new().expect("temporary config module");
    fs::create_dir(tmp.path().join("nix-support")).expect("create nix-support directory");
    fs::write(tmp.path().join("module.nix"), "{ ... }: {}\n").expect("write module");
    fs::write(
        tmp.path().join(TARGET_PLATFORM_RELATIVE_PATH),
        "x86_64-linux\n",
    )
    .expect("write target platform marker");

    scan_config_module_interface(tmp.path(), "web", &[], &[])
        .expect("scan canonical target platform metadata");

    fs::write(tmp.path().join("nix-support/helper"), "not Nix\n")
        .expect("write unauthorized nix-support helper");
    let error = scan_config_module_interface(tmp.path(), "web", &[], &[])
        .expect_err("reject neighboring nix-support helper");
    assert!(error.to_string().contains("non-Nix helper"), "{error:#}");
}
