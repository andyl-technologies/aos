//! Rejects foreign Source selection, reordered last use and renewed Originals.

use super::super::{
    Contract, mask_contract, read_companions, replace_one_obligation, source_pattern,
};
use super::CONTRACTS;

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

impl Fixture {
    fn load(index: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[index];
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(contract)?;
        let details = super::super::lifecycle_retirement::contract_diagnostics(
            contract,
            &code,
            &companions,
        );
        assert!(details.is_empty(), "{}: {details:#?}", contract.target);
        let masked = mask_contract(contract, &code, &companions);
        assert_ne!(masked, code, "{} has no reviewed continuation", contract.target);
        assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        Ok(Self { contract, code, companions })
    }

    fn rejects(&self, code: &str, companions: &[String]) {
        assert_eq!(
            mask_contract(self.contract, code, companions),
            code,
            "{} accepted changed custody",
            self.contract.target,
        );
        assert!(
            !crate::flaky_escape_failures("unreviewed", "unreviewed", code).is_empty(),
            "{} lost its executable continuation witness",
            self.contract.target,
        );
    }

    fn reject_local(&self, before: &str, after: &str) {
        let changed = replace_one_obligation(&self.code, &source_pattern(before), after);
        assert_ne!(changed, self.code, "missing mutation input: {before}");
        self.rejects(&changed, &self.companions);
    }

    fn reject_companion(&self, suffix: &str, before: &str, after: &str) {
        let index = self.contract.companions.iter()
            .position(|binding| binding.path.ends_with(suffix))
            .expect("the actual producer companion is bound");
        let code = crate::scrub_comments_and_strings(&self.companions[index]);
        let changed = replace_one_obligation(&code, &source_pattern(before), after);
        assert_ne!(changed, code, "missing producer mutation input: {suffix}: {before}");
        let mut companions = self.companions.clone();
        companions[index] = changed;
        self.rejects(&self.code, &companions);
    }
}

#[test]
fn source_retirement_contracts_bind_each_actual_owner_and_saved_operation()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CONTRACTS.len(), 5);
    for index in 0..CONTRACTS.len() {
        let fixture = Fixture::load(index)?;
        fixture.rejects(&fixture.code, &[]);
    }
    Ok(())
}

#[test]
fn source_retirement_rejects_replay_alias_bypass_and_invented_return()
-> Result<(), Box<dyn std::error::Error>> {
    let preparation = Fixture::load(0)?;
    preparation.reject_local("self.world.retry_source_retirement_body()", "foreign.world.retry_source_retirement_body()");
    preparation.reject_local("if self.attempted { return Err(()); }", "if false { return Err(()); }");

    let rearm = Fixture::load(1)?;
    rearm.reject_local("if self.source.is_none()", "if true");
    rearm.reject_local("self.failure.lifecycle.take()", "foreign.lifecycle.take()");
    rearm.reject_local(".filter(|state| state.body_closed)", ".filter(|_| true)");

    let shared = Fixture::load(2)?;
    shared.reject_local("Arc::get_mut(shared)", "Arc::make_mut(shared)");
    shared.reject_local("if !self.parent_park.retry(shared)", "if false");
    shared.reject_local("body.matches_shared_selection(&self.selector)", "true");
    shared.reject_local(
        "self.source = Some(body.take_shared_body()); drop(self.shared.take());",
        "drop(self.shared.take()); self.source = Some(body.take_shared_body());",
    );

    let source = Fixture::load(3)?;
    source.reject_local("self.fork_target_is_owned() || self.parent_park_drain_is_owned()", "false");
    source.reject_local("state.shutdown_attempted = true;", "unrecorded_shutdown();");
    source.reject_local("if closed { state.body_closed = true;", "if true { state.body_closed = true;");
    source.reject_local("history.body_post.get_or_insert(first);", "discard_post(first);");
    source.reject_companion("native_pool/ledger.rs", "world.cleanup.get_or_init(", "world.cleanup.get_or_try_init(");

    let park = Fixture::load(4)?;
    park.reject_local("receipt.closed_request.is_some() && receipt.host_memberships_returned", "receipt.closed_request.is_some() || receipt.host_memberships_returned");
    park.reject_local("actual.same_role(selection)", "true");
    park.reject_companion("parent_park.rs", "self.matches_source(source_owner, &source)", "true");
    park.reject_companion("qmp/parent_park_drain.rs", "borrowed: Some(cleanup),", "borrowed: None,");
    park.reject_companion("node/parent_park_drain.rs", ".verify_node(native_binding)", ".verify_node(foreign_binding)");
    Ok(())
}
