//! Regression tests for package, desired-set, image, and configuration dispatch.
//!
//! Effectful dispatch runs in a subprocess so AOS-root environment overrides
//! cannot leak into concurrently executing tests.

use std::process::Command;

use aos_package_manager::environment::RuntimeRequirement;
use aos_package_manager::{PackageCommand, RuntimeConfigCommand};
use clap::Parser;
use tempfile::TempDir;

#[derive(Parser)]
struct TestCli {
    #[command(subcommand)]
    command: PackageCommand,
}

fn parse(arguments: &[&str]) -> PackageCommand {
    TestCli::try_parse_from(std::iter::once("apm").chain(arguments.iter().copied()))
        .expect("valid command")
        .command
}

#[test]
fn package_commands_select_the_same_scope_consistently() {
    for arguments in [
        vec!["install", "nginx", "curl"],
        vec!["remove", "nginx"],
        vec!["reinstall", "nginx"],
        vec!["upgrade"],
        vec!["full-upgrade"],
        vec!["autoremove"],
        vec!["hold", "nginx"],
        vec!["unhold", "nginx"],
        vec!["verify", "nginx"],
        vec!["source", "nginx"],
        vec!["rollback"],
        vec!["gc"],
    ] {
        let user = parse(&arguments);
        assert!(!user.is_system(), "{arguments:?}");
        assert_eq!(user.runtime_requirement(), RuntimeRequirement::Portable);

        let mut system_arguments = arguments.clone();
        system_arguments.push("--system");
        let system = parse(&system_arguments);
        assert!(system.is_system(), "{system_arguments:?}");
        assert_eq!(system.runtime_requirement(), RuntimeRequirement::AosRoot);
    }
}

#[test]
fn image_and_configuration_operations_have_separate_commands() {
    for arguments in [
        &["image", "install", "aos"][..],
        &["image", "upgrade"][..],
        &["image", "rollback", "--generation", "2"][..],
        &["image", "list"][..],
        &["image", "prepare", "aos"][..],
    ] {
        let command = parse(arguments);
        assert!(command.is_system());
        assert_eq!(command.runtime_requirement(), RuntimeRequirement::LiveAos);
    }

    let system_download = parse(&["image", "download", "aos", "--format", "qcow2", "--system"]);
    assert!(system_download.is_system());
    assert_eq!(
        system_download.runtime_requirement(),
        RuntimeRequirement::AosRoot
    );

    let portable_download = parse(&["image", "download", "aos", "--format", "qcow2"]);
    assert!(!portable_download.is_system());
    assert_eq!(
        portable_download.runtime_requirement(),
        RuntimeRequirement::Portable
    );
    let config = parse(&["config", "rollback", "--generation", "2"]);
    assert!(matches!(
        config,
        PackageCommand::Config {
            command: RuntimeConfigCommand::Rollback {
                generation: Some(2),
                ..
            },
        }
    ));
    assert_eq!(config.runtime_requirement(), RuntimeRequirement::AosRoot);
}

#[test]
fn system_registry_scope_precedes_the_registry_operation() {
    let command = parse(&[
        "registry",
        "--system",
        "add",
        "https://registry.example.test",
    ]);
    assert!(command.is_system());
    assert!(
        TestCli::try_parse_from([
            "apm",
            "registry",
            "add",
            "--system",
            "https://registry.example.test",
        ])
        .is_err()
    );
}

#[test]
fn desired_set_application_requires_explicit_system_scope() {
    assert!(TestCli::try_parse_from(["apm", "apply", "--from", "desired.toml"]).is_err());
    assert!(TestCli::try_parse_from(["apm", "apply", "--system"]).is_err());
    assert!(parse(&["apply", "--system", "--from", "desired.toml"]).is_system());

    for arguments in [
        &["apm", "reconcile", "--system", "--from", "desired.toml"][..],
        &["apm", "install", "--system", "--from", "desired.toml"][..],
        &["apm", "install", "--system", "aos", "--image", "raw"][..],
        &["apm", "upgrade", "--system", "--reboot"][..],
        &["apm", "rollback", "--system", "--image"][..],
    ] {
        assert!(TestCli::try_parse_from(arguments).is_err(), "{arguments:?}");
    }
}

#[test]
fn system_package_dispatch_does_not_require_image_generation_authority() {
    let root = TempDir::new().expect("root fixture");
    std::fs::create_dir_all(root.path().join("etc")).expect("identity directory");
    std::fs::write(
        root.path().join("etc/os-release"),
        "ID=aos\nAOS_PACKAGE_MODULE_LIBRARY=/nix/store/00000000000000000000000000000000-module-library\n",
    )
    .expect("AOS identity");
    std::fs::write(root.path().join("desired.toml"), "packages = []\n").expect("empty desired set");

    let result = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "system_dispatch_child", "--nocapture"])
        .env("AOS_PACKAGE_SCOPE_CHILD", "1")
        .env("AOS_ROOT", root.path())
        .env_remove("AOS_RUNTIME")
        .env_remove("AOS_CONTAINER_READ_ONLY")
        .env_remove("AOS_CONFIG_DIR")
        .env("AOS_PROFILE_ROOT", root.path().join("var/lib/profiles"))
        .env("APM_SYSTEM_CONFIG_DIR", root.path().join("etc/apm"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env("HOME", root.path().join("home"))
        .output()
        .expect("dispatch subprocess");
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!root.path().join("var/lib/profiles/image").exists());
    assert!(!root.path().join("var/lib/profiles/system").exists());
}

#[test]
fn system_dispatch_child() {
    if std::env::var_os("AOS_PACKAGE_SCOPE_CHILD").is_none() {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().expect("async runtime");
    let printer = aos_cli_ui::output::Printer::new(0, true, false);
    runtime.block_on(async {
        for arguments in [
            &["upgrade", "--system"][..],
            &["full-upgrade", "--system"][..],
            &["rollback", "--system", "--list"][..],
        ] {
            aos_package_manager::run(&parse(arguments), true, true, &printer)
                .await
                .unwrap_or_else(|error| panic!("{arguments:?}: {error:#}"));
        }
        let desired = std::path::PathBuf::from(std::env::var_os("AOS_ROOT").expect("root"))
            .join("desired.toml");
        aos_package_manager::run(
            &parse(&[
                "apply",
                "--system",
                "--from",
                desired.to_str().expect("path"),
            ]),
            true,
            true,
            &printer,
        )
        .await
        .expect("empty reconciliation without image authority");

        let install_error = aos_package_manager::run(
            &parse(&["install", "--system", "nginx"]),
            true,
            true,
            &printer,
        )
        .await
        .expect_err("no registry provides nginx");
        assert!(
            install_error.to_string().contains("nginx"),
            "{install_error:#}"
        );

        aos_package_manager::run(&parse(&["image", "upgrade"]), true, true, &printer)
            .await
            .expect_err("image command requires boot identity");
        aos_package_manager::run(&parse(&["config", "rollback"]), true, true, &printer)
            .await
            .expect_err("configuration command requires retained config authority");
    });
}
