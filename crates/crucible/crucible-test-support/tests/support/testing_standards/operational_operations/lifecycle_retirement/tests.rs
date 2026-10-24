//! Rejects changed identities, repeated physical effects and erased failure history.

use super::super::super::super::{flaky_escape_failures, scrub_comments_and_strings};
use super::super::{
    Contract, identifier_count, mask_contract, read_companions, replace_one_obligation,
    source_pattern,
};
use super::{CONTRACTS, altered_expression, contract_diagnostics, omission_replacement};

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

impl Fixture {
    fn load(target: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contract = CONTRACTS
            .iter()
            .find(|contract| contract.target == target)
            .ok_or_else(|| std::io::Error::other("retirement contract target is absent"))?;
        let root = crate::workspace_root();
        let package = crate::workspace::package_path(&root.join("crates"), contract.package);
        let source = std::fs::read_to_string(package.join(format!("{}.rs", contract.target)))?;
        let fixture = Self {
            contract,
            code: scrub_comments_and_strings(&source),
            companions: read_companions(contract)?,
        };
        if fixture.rejects(&fixture.code, &fixture.companions) {
            let details = contract_diagnostics(contract, &fixture.code, &fixture.companions);
            return Err(std::io::Error::other(format!(
                "unmodified contract is not bound: {target}: {details:#?}"
            ))
            .into());
        }
        Ok(fixture)
    }

    fn rejects(&self, code: &str, companions: &[String]) -> bool {
        let masked = mask_contract(self.contract, code, companions);
        !flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty()
    }

    fn rejects_change(&self, before: &str, after: &str) {
        let changed = replace_one_obligation(&self.code, &source_pattern(before), after);
        assert!(
            self.rejects(&changed, &self.companions),
            "changed retirement cut was classified: {}: {before}",
            self.contract.target,
        );
    }
}

#[test]
fn retirement_contracts_cover_only_the_selected_eighteen_targets()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CONTRACTS.len(), 18);
    let mut failures = Vec::new();
    for (index, contract) in CONTRACTS.iter().enumerate() {
        assert_eq!(contract.package, "crucible-daemon");
        assert!(
            CONTRACTS[..index]
                .iter()
                .all(|other| other.target != contract.target)
        );
        assert!(!contract.target.contains("failure_classification"));
        assert!(!contract.target.contains("executor_worker"));
        assert!(!contract.target.contains("campaign_resume"));

        if let Err(source) = Fixture::load(contract.target) {
            failures.push(source.to_string());
        }
    }
    assert!(
        failures.is_empty(),
        "unmodified contract bindings:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn retirement_callbacks_require_same_epoch_owner_and_once_only_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let driver = Fixture::load("src/lifecycle_cleanup/driver")?;
    driver.rejects_change("expected != epoch", "expected != unrelated_epoch");
    driver.rejects_change(
        "prepared_driver::retry_prepared(slot, epoch)",
        "foreign_prepared_driver::retry_prepared(slot, epoch)",
    );
    driver.rejects_change(
        "body.matches_world_controls(controls)",
        "body.matches_world_controls(unrelated_controls)",
    );
    driver.rejects_change(
        "slot.body_destroyed_epoch.store(epoch, Ordering::Release); } retry_body_and_controls(slot, epoch)?;",
        "retry_body_and_controls(slot, epoch)?; slot.body_destroyed_epoch.store(epoch, Ordering::Release); }",
    );
    driver.rejects_change(
        "if no_world || native_returned",
        "if no_world || !native_returned",
    );

    let prepared = Fixture::load("src/lifecycle_cleanup/prepared_driver")?;
    prepared.rejects_change("if !prepared.body_closed", "if true");
    prepared.rejects_change(
        "(operations.retry)(owner.as_mut())",
        "(operations.retry)(foreign.as_mut())",
    );
    prepared.rejects_change(
        "prepared.pending_post_body = body; prepared.post_body_taken = true;",
        "prepared.post_body_taken = true; prepared.pending_post_body = body;",
    );

    let queued = Fixture::load("src/lifecycle_cleanup/queued_owner")?;
    queued.rejects_change("owner.retry_cleanup()", "foreign.retry_cleanup()");
    queued.rejects_change(
        "Some(previous) => previous.with_later_failure(first),",
        "Some(_previous) => first,",
    );
    queued.rejects_change(
        "terminal::destroy_payload(slot, owner)",
        "terminal::destroy_payload(other_slot, owner)",
    );
    Ok(())
}

#[test]
fn retirement_companions_require_failed_admission_and_independent_posts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::load("src/campaign_process/attached_retirement")?;
    let mut changed = fixture.companions.clone();
    let original = scrub_comments_and_strings(&changed[0]);
    changed[0] = replace_one_obligation(
        &original,
        &source_pattern(
            "self.cleanup.get_or_init(|| self.original.begin_original_cleanup_control().map(Arc::new))",
        ),
        "self.original.begin_original_cleanup_control().map(Arc::new)",
    );
    assert!(fixture.rejects(&fixture.code, &changed));

    let fixture = Fixture::load("src/packaged_qemu_executor/attached_retirement")?;
    let index = fixture
        .contract
        .companions
        .iter()
        .position(|binding| {
            binding
                .path
                .ends_with("packaged_qemu_executor/retirement.rs")
        })
        .ok_or_else(|| std::io::Error::other("dispatcher companion is absent"))?;
    let mut changed = fixture.companions.clone();
    let dispatcher = scrub_comments_and_strings(&changed[index]);
    changed[index] = replace_one_obligation(
        &dispatcher,
        &source_pattern("result.post = original.wait_slice().err();"),
        "result.post = None;",
    );
    assert!(fixture.rejects(&fixture.code, &changed));

    let post = Fixture::load("src/lifecycle_cleanup/post_body")?;
    post.rejects_change(
        "self.observer_first.get_or_insert(first);",
        "self.observer_first = Some(first);",
    );
    post.rejects_change(
        "if !self.returned || self.observer_returned || self.observer_panic_payload.is_some()",
        "if self.observer_returned",
    );
    Ok(())
}

#[test]
fn exact_retirement_calls_reject_foreign_arguments_and_additional_work()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(altered_expression("unreviewed_call()"), "unreviewed_call()");
    for contract in CONTRACTS {
        let fixture = Fixture::load(contract.target)?;
        for (expression, _) in contract.expressions {
            let changed = altered_expression(expression);
            assert_ne!(changed, *expression);
            fixture.rejects_change(expression, &changed);
        }
        for addition in [
            "fn unrelated() { retry_failed_test(); }",
            "fn unrelated() { loop { retry_failed_test(); } }",
            "fn unrelated() { thread::sleep(unbounded); }",
        ] {
            let changed = format!("{}\n{addition}", fixture.code);
            assert!(fixture.rejects(&changed, &fixture.companions));
        }
    }

    let fixture = Fixture::load("src/campaign_process")?;
    assert!(
        flaky_escape_failures(
            fixture.contract.package,
            fixture.contract.target,
            &fixture.code
        )
        .is_empty(),
        "unchanged import failed composed classification: {:#?}",
        contract_diagnostics(fixture.contract, &fixture.code, &fixture.companions),
    );
    let import = "retry_attached_retirement, verify_attached_start,";
    let replacement = omission_replacement(fixture.contract, import)
        .ok_or_else(|| std::io::Error::other("reviewed import mutant is absent"))?;
    let changed = replace_one_obligation(&fixture.code, &source_pattern(import), replacement);
    assert_ne!(changed, fixture.code);
    assert_eq!(identifier_count(&changed, "retry_attached_retirement"), 1);
    assert_eq!(
        mask_contract(fixture.contract, &changed, &fixture.companions),
        changed,
        "incomplete import satisfied its own contract: {:#?}",
        contract_diagnostics(fixture.contract, &changed, &fixture.companions),
    );
    assert!(
        fixture.rejects(&changed, &fixture.companions),
        "incomplete import lost its scanner witness: {:#?}",
        contract_diagnostics(fixture.contract, &changed, &fixture.companions),
    );
    assert!(
        !flaky_escape_failures(fixture.contract.package, fixture.contract.target, &changed)
            .is_empty(),
        "incomplete import passed composed classification: {:#?}",
        contract_diagnostics(fixture.contract, &changed, &fixture.companions),
    );
    assert!(omission_replacement(fixture.contract, "unrelated_obligation").is_none());
    Ok(())
}
