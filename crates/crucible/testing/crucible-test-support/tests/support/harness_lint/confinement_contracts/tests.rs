//! Exercises exact operational declarations without admitting sibling routes.

use super::super::{
    finding_contains, operational_public_exports, package_source_confinement_findings,
    public_export_findings, source_pairs,
};
use super::*;

fn export_findings(path: &str, source: &str) -> Vec<String> {
    let package = path.split('/').next().unwrap();
    let path = Path::new(path);
    let approved = operational_public_exports(package, Path::new(package), path);
    public_export_findings(path, source, approved)
}

#[test]
fn exact_operational_exports_keep_their_reviewed_types_and_visibility() {
    for contract in CONTRACTS {
        assert!(
            export_findings(contract.path, contract.source).is_empty(),
            "reviewed declaration refused: {}: {}",
            contract.path,
            contract.source,
        );

        let foreign = contract.path.replace("src/", "src/unreviewed/");
        assert!(
            !export_findings(&foreign, contract.source).is_empty(),
            "declaration accepted from a foreign source: {foreign}",
        );
    }
}

#[test]
fn operational_reexports_refuse_aliases_foreign_targets_and_wildcards() {
    for contract in CONTRACTS
        .iter()
        .filter(|contract| contract.source.contains(" use "))
    {
        let aliased = if let Some(at) = contract.source.find("::{") {
            let end = contract.source[at..].find(',').unwrap() + at;
            format!(
                "{} as ForeignOwner{}",
                &contract.source[..end],
                &contract.source[end..]
            )
        } else {
            contract.source.replace(';', " as ForeignOwner;")
        };
        let wildcard = contract.source.split_once("use ").unwrap().0.to_owned() + "use foreign::*;";
        let foreign = contract.source.replacen("use ", "use foreign::", 1);
        for source in [aliased, wildcard, foreign] {
            assert!(
                !export_findings(contract.path, &source).is_empty(),
                "changed reexport accepted: {source}",
            );
        }
    }
}

#[test]
fn authenticated_service_conversion_cannot_change_start_arithmetic_or_visibility() {
    let contract = CONTRACTS
        .iter()
        .find(|contract| contract.source.contains("fn from_service_interval("))
        .unwrap();
    for (before, after) in [
        ("pub(crate)", "pub"),
        ("checked_sub", "checked_add"),
        ("now_ns - start_ns", "now_ns + start_ns"),
        ("checked_mul(1000)", "checked_mul(1001)"),
        (
            "Some(span),\n            started,",
            "Some(span),\n            host_now(),",
        ),
        (
            "-> Result<Self, HostSupervisionError>",
            "-> std::time::Instant",
        ),
    ] {
        assert!(
            contract.source.contains(before),
            "missing mutation target: {before}"
        );
        let changed = contract.source.replacen(before, after, 1);
        assert!(
            !export_findings(contract.path, &changed).is_empty(),
            "changed original conversion accepted: {before} -> {after}"
        );
    }
}

#[test]
fn retained_phase_verification_cannot_enter_new_work_or_skip_original_checks() {
    let contract = CONTRACTS
        .iter()
        .find(|contract| contract.source.contains("fn verify_retained_phase("))
        .unwrap();
    for (before, after) in [
        ("pub(crate)", "pub"),
        ("self.supervisor.verify_original_live()?;", ""),
        ("decision.state == HostOperationState::Completed", "true"),
        (
            "return Ok(());",
            "self.supervisor.begin(HostOperationClass::Preparation)?; return Ok(());",
        ),
        ("decision.require_running(self.id)", "Ok(())"),
    ] {
        assert!(
            contract.source.contains(before),
            "missing mutation target: {before}"
        );
        let changed = contract.source.replacen(before, after, 1);
        assert!(
            !export_findings(contract.path, &changed).is_empty(),
            "changed retained verifier accepted: {before} -> {after}"
        );
    }
}

#[test]
fn neighboring_same_line_export_cannot_borrow_an_exact_contract() {
    let contract = &CONTRACTS[0];
    let source = format!(
        "{} pub(crate) use target_dispatcher::ForeignDispatcher;",
        contract.source
    );
    let findings = export_findings(contract.path, &source);
    assert_eq!(findings.len(), 1, "{findings:?}");

    let source = format!(
        "pub(crate) use target_dispatcher::ForeignDispatcher; {}",
        contract.source
    );
    let findings = export_findings(contract.path, &source);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn prepared_supervision_cannot_renew_origins_or_expose_private_clocks() {
    let declaration = |needle: &str| {
        CONTRACTS
            .iter()
            .find(|contract| {
                contract
                    .path
                    .ends_with("host_supervision/prepared_start.rs")
                    && contract.source.contains(needle)
            })
            .unwrap()
    };

    for (item, before, after) in [
        (
            "pub struct PreparedHostOperationSupervisor",
            "started: Instant",
            "pub started: Instant",
        ),
        ("pub fn prepare(", "budgets.validate(outer.is_some())?;", ""),
        ("pub fn prepare(", "checked_add(1)", "wrapping_add(1)"),
        (
            "pub fn prepare(",
            "-> Result<PreparedHostOperationSupervisor, HostSupervisionError>",
            "-> Result<Instant, HostSupervisionError>",
        ),
        ("pub fn publish(", "self.started,", "host_now(),"),
        (
            "pub fn publish(",
            "self.original_monotonic_ns,",
            "kernel_monotonic_ns()?,",
        ),
        ("pub fn publish(", "self.cap_id,", "foreign_cap_id,"),
        ("pub const fn cap_id(", "self.cap_id", "self.started"),
    ] {
        let contract = declaration(item);
        assert!(contract.source.contains(before), "missing target: {before}");
        let changed = contract.source.replacen(before, after, 1);
        assert!(
            !export_findings(contract.path, &changed).is_empty(),
            "changed prepared supervision accepted: {before} -> {after}"
        );
    }
}

#[test]
fn exact_guard_checks_and_completion_cannot_substitute_other_work() {
    for (item, before, after) in [
        (
            "pub fn belongs_to_supervisor(",
            "self.supervisor == *supervisor",
            "self.supervisor.shares_outer_cap(supervisor)",
        ),
        (
            "pub fn belongs_to_supervisor(",
            "self.supervisor == *supervisor",
            "true",
        ),
        (
            "pub fn complete_observed(",
            "self.complete_observed_with(|| {})",
            "self.complete_observed_with(|| perform_work())",
        ),
    ] {
        let contract = CONTRACTS
            .iter()
            .find(|contract| contract.source.contains(item))
            .unwrap();
        assert!(contract.source.contains(before), "missing target: {before}");
        let changed = contract.source.replacen(before, after, 1);
        assert!(
            !export_findings(contract.path, &changed).is_empty(),
            "changed guard operation accepted: {after}"
        );
    }
}

#[test]
fn watchdog_results_cannot_become_clock_exports_or_replay_join_ownership() {
    for item in [
        "pub(crate) struct ServiceWatchdogFailure",
        "pub(crate) enum ServiceWatchdogTrigger",
        "pub(crate) struct ServiceWatchdogStop",
    ] {
        let contract = CONTRACTS
            .iter()
            .find(|contract| contract.source.contains(item))
            .unwrap();
        for changed in [
            contract.source.replacen("pub(crate)", "pub", 1),
            contract
                .source
                .replacen('{', "{ pub clock: std::time::Instant,", 1),
        ] {
            assert!(!export_findings(contract.path, &changed).is_empty());
        }
    }

    let stop = CONTRACTS
        .iter()
        .find(|contract| contract.source.contains("fn stop_service_owned("))
        .unwrap();
    for (before, after) in [
        ("mut self", "&mut self"),
        ("self.service_stop_expired = Some(true);", ""),
        ("self.watcher.take()", "self.watcher.as_mut()"),
        (
            "self.operation_expired.take_service_failure()",
            "foreign_history()",
        ),
    ] {
        assert!(stop.source.contains(before), "missing target: {before}");
        let changed = stop.source.replacen(before, after, 1);
        assert!(
            !export_findings(stop.path, &changed).is_empty(),
            "changed owned watchdog stop accepted: {before} -> {after}"
        );
    }
}

#[test]
fn prepared_clock_boundary_keeps_state_routes_and_neighboring_exports_closed() {
    let contract = CONTRACTS
        .iter()
        .find(|contract| {
            contract
                .source
                .contains("pub struct PreparedHostOperationSupervisor")
        })
        .unwrap();
    for (addition, reason) in [
        (
            "use crucible_engine::State;",
            "host nondeterminism reaching State",
        ),
        (
            "use crucible_control_api::ControlClient;",
            "host nondeterminism reaches API/session route",
        ),
        (
            "pub fn clock(&self) -> std::time::Instant { self.started }",
            "public export from nondeterministic boundary",
        ),
    ] {
        let source = format!("{} {addition}", contract.source);
        let findings = package_source_confinement_findings(
            "crucible-host-resources",
            Path::new("crucible/host/crucible-host-resources"),
            &source_pairs(&[(contract.path, &source)]),
        );
        assert!(finding_contains(&findings, reason), "{findings:?}");
    }
}

#[test]
fn reviewed_owner_export_cannot_carry_a_clock_to_state_or_an_api_route() {
    let contract = CONTRACTS
        .iter()
        .find(|contract| contract.source.contains("AuthenticatedActorFamily"))
        .unwrap();
    for (route, reason) in [
        ("use crucible::State;", "host nondeterminism reaching State"),
        (
            "use crucible_control_api::ControlClient;",
            "host nondeterminism reaches API/session route",
        ),
    ] {
        let source = format!(
            "{} {route} fn observe() {{ consume(std::time::Instant::now()); }}",
            contract.source
        );
        let findings = package_source_confinement_findings(
            "crucible-host-resources",
            Path::new("crucible/host/crucible-host-resources"),
            &source_pairs(&[(contract.path, &source)]),
        );
        assert!(finding_contains(&findings, reason), "{findings:?}");
    }
}
