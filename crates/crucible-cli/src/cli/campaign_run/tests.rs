//! Tests campaign run, save, and resume CLI projection.

use super::*;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AssertionViolationWitness, BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue, ObservationEventLogProof,
    ObservationQuantumBoundary, ObservationStopProof, SelectableDeclaration, Selection,
    SelectionOrigin,
};
use crucible_daemon::LinuxQemuAttemptHostConfig;
use crucible_daemon::qemu_campaign_lifecycle::{
    run_guarded_default_campaign_test_fixture_with_choice_offer,
    run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer,
};
use tempfile::TempDir;

#[test]
fn native_resume_loads_the_explicit_guarded_deployment_before_backend_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = TempDir::new()?;
    let deployment = temporary.path().join("executor.toml");
    write_resume_deployment(&deployment)?;
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.campaign_deployment = Some(deployment);

    // The real deployment loader must succeed before the executor refuses the
    // deliberately nonproduction backend, without acquiring host resources.
    let error =
        run_local_qemu_campaign_resume_workflow(&ResolvedLocalBackend::Double, &plan, &evidence)
            .error_or_panic("nonproduction backend must be refused");

    assert!(
        error
            .to_string()
            .contains("campaign QEMU resume requires a resolved production backend"),
        "explicit deployment did not reach the executor: {error}"
    );
    Ok(())
}

#[test]
fn native_resume_refuses_missing_malformed_and_mutable_explicit_deployments()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temporary = TempDir::new()?;
    let deployment = temporary.path().join("executor.toml");
    let evidence = resume_evidence(Schedule::empty(), VirtualTime { ticks: 5 });
    let mut plan = default_resume_plan(&evidence, temporary.path());
    plan.campaign_deployment = Some(deployment.clone());

    let error =
        run_local_qemu_campaign_resume_workflow(&ResolvedLocalBackend::Double, &plan, &evidence)
            .error_or_panic("missing deployment must be refused");
    assert!(
        error
            .to_string()
            .contains("packaged-executor metadata error")
    );

    write_resume_deployment(&deployment)?;
    std::fs::write(&deployment, "schema = [invalid")?;
    let error =
        run_local_qemu_campaign_resume_workflow(&ResolvedLocalBackend::Double, &plan, &evidence)
            .error_or_panic("malformed deployment must be refused");
    assert!(
        error
            .to_string()
            .contains("packaged-executor TOML is invalid")
    );

    write_resume_deployment(&deployment)?;
    std::fs::set_permissions(&deployment, std::fs::Permissions::from_mode(0o644))?;
    let error =
        run_local_qemu_campaign_resume_workflow(&ResolvedLocalBackend::Double, &plan, &evidence)
            .error_or_panic("mutable deployment must be refused");
    assert!(
        error
            .to_string()
            .contains("exact-owner mode-0600 bounded file")
    );
    Ok(())
}

fn write_resume_deployment(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let deployment = format!(
        r#"schema = "crucible.campaign-packaged-executor"
version = 2
cgroup_root = "/sys/fs/cgroup/crucible"
run_root = "/var/lib/crucible/attempts"
attempt_namespace = "resume-explicit-deployment"
first_project_id = 10000
project_id_count = 2
child_user_id = 2000
child_group_id = 2000
maximum_tasks = 64
maximum_inodes = 4096
finish_timeout_ms = 30000
maximum_slots = 2
maximum_vcpus = 4
maximum_resident_bytes = 1073741824
maximum_disk_bytes = 2147483648
maximum_execution_quanta = 100000
maximum_checkpoint_bytes = 1073741824
worker_count = 2
host_architecture = "{}"
qemu_profile = "deterministic-tcg-v1"

[operations]
listener_workers = 2
pending_connections = 16
requests_per_connection = 16
accept_poll_interval_ms = 25
exchange_read_timeout_ms = 1000
exchange_write_timeout_ms = 1000
runtime_poll_interval_ms = 250
planner_scan_limit = 16
planner_input_bytes = 1048576
planner_fuel = 64
executor_scan_limit = 16
worker_slots_per_campaign = 2
"#,
        std::env::consts::ARCH,
    );
    std::fs::write(path, deployment)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

trait TestValue<T> {
    #[track_caller]
    fn or_panic(self, message: &str) -> T;
}

impl<T> TestValue<T> for Option<T> {
    #[track_caller]
    fn or_panic(self, message: &str) -> T {
        self.unwrap_or_else(|| panic!("{message}"))
    }
}

impl<T, E> TestValue<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    #[track_caller]
    fn or_panic(self, message: &str) -> T {
        self.unwrap_or_else(|error| panic!("{message}: {error:?}"))
    }
}

trait TestError<E> {
    #[track_caller]
    fn error_or_panic(self, message: &str) -> E;
}

impl<T, E> TestError<E> for Result<T, E> {
    #[track_caller]
    fn error_or_panic(self, message: &str) -> E {
        match self {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}

#[path = "tests/capacity.rs"]
mod capacity;
#[path = "tests/resume.rs"]
mod resume;
#[path = "tests/routes.rs"]
mod routes;
#[path = "tests/save_assertions.rs"]
mod save_assertions;
#[path = "tests/save_support.rs"]
mod save_support;
#[path = "tests/support.rs"]
mod support;

use save_assertions::*;
use save_support::*;
use support::*;
