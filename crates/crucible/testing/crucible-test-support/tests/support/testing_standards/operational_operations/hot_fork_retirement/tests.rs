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

#[test]
fn pre_vm_retirement_keeps_the_same_preborn_body_and_borrowed_abort()
-> Result<(), Box<dyn std::error::Error>> {
    let source = Fixture::load(3)?;

    for (before, after) in [
        (
            "Self::Preparation(preparation) => preparation.finish()",
            "Self::Preparation(_) => Ok(())",
        ),
        ("if !receiver.retry_retained_helper()", "if false"),
        (
            "self.directory_closing = true; drop(self.contract.take()); drop(self.directory.take());",
            "drop(self.contract.take()); drop(self.directory.take()); self.directory_closing = true;",
        ),
        ("if self.directory_closing", "if false"),
        ("lease.abort_without_process()?", "drop(lease)"),
        (
            "retained => Err(retained)",
            "retained => Ok(foreign_prepared)",
        ),
        (
            "self.lease = None; Err(CleanupError::Retained(\"fresh physical owners and local generation returned; diagnostic funding remains retained\",))",
            "self.lease = None; Ok(())",
        ),
        (
            "drop(self.node.take()); self.channels_closed = true;",
            "self.channels_closed = true; drop(self.node.take());",
        ),
    ] {
        source.reject_companion("qemu_lifecycle_launcher/retained_node.rs", before, after);
    }

    for (before, after) in [
        ("if self.retained_launch.is_some()", "if false"),
        (
            "self.retained_launch = Some(RetainedLaunch::Preparation(RetainedFreshPreparation::new(lease, run_directory, receiver,)));",
            "drop((lease, run_directory, receiver));",
        ),
        (
            "self.retained_launch = Some(RetainedLaunch::Preparation(preparation));",
            "drop(preparation);",
        ),
        ("self.retained_launch = other;", "drop(other);"),
        (
            ".prepare_fresh_artifacts_guarded(qemu_executable, root_image, process_contract)",
            ".prepare_fresh_artifacts_guarded(qemu_executable, root_image, foreign_contract)",
        ),
    ] {
        source.reject_companion("qemu_lifecycle_launcher/fresh_generation.rs", before, after);
    }

    for (before, after) in [
        (
            "abort_without_process(&mut self)",
            "abort_without_process(mut self)",
        ),
        (
            "let mut state = self.generations.try_lock()",
            "let mut state = self.generations.lock()",
        ),
        ("row.latest == Some(self.identity.generation())", "true"),
        (
            "state.nodes[index].latest = self.previous_generation;",
            "state.nodes[index].latest = None;",
        ),
    ] {
        source.reject_companion("qemu_resource_guard/generation_resource.rs", before, after);
    }

    let birth = source
        .contract
        .companions
        .iter()
        .find(|binding| {
            binding
                .path
                .ends_with("qemu_lifecycle_launcher/fresh_generation.rs")
        })
        .expect("the actual pre-helper construction is bound")
        .required[0]
        .0;
    let receiver = birth
        .find("let receiver = {")
        .expect("actual issued receiver block");
    let directory = birth
        .find("let run_directory = match")
        .expect("actual directory creation block");
    let installation = birth
        .find("self.retained_launch = Some")
        .expect("actual containing slot");
    assert!(receiver < directory && directory < installation);
    let receiver_block = &birth[receiver..directory];
    let directory_block = &birth[directory..installation];
    source.reject_companion(
        "qemu_lifecycle_launcher/fresh_generation.rs",
        &format!("{receiver_block}{directory_block}"),
        &format!("{directory_block}{receiver_block}"),
    );

    source.reject_companion(
        "qemu_lifecycle_launcher.rs",
        "failed.finish()?;",
        "discard(failed);",
    );
    source.reject_companion(
        "qemu_lifecycle_launcher.rs",
        "std::mem::size_of::<Self>()",
        "std::mem::size_of::<usize>()",
    );
    source.reject_companion(
        "qemu_lifecycle_launcher.rs",
        "let retained_source = Self::retained_control_bytes()?",
        "let retained_source = 0u64",
    );
    source.reject_companion(
        "qemu_lifecycle_launcher.rs",
        ".is_some_and(RetainedLaunch::is_preparation)",
        ".is_some_and(|_| false)",
    );
    source.reject_companion(
        "pending_construction/prepared.rs",
        "source.world().vm_nodes().iter().map(|node| &node.id), workers,",
        "foreign_nodes, workers,",
    );
    source.reject_companion(
        "spawn/helper_receiver.rs",
        "lender.controller().ok()?;",
        "foreign_lender.controller().ok()?;",
    );
    source.reject_companion(
        "original_node/helper_receiver.rs",
        "self.settle_helper(&mut slot, &receiver);",
        "pretend_settled();",
    );
    source.reject_companion(
        "generation_resource/tests.rs",
        "assert!(!pending.finished);",
        "assert!(pending.finished);",
    );
    source.reject_companion(
        "generation_resource/tests.rs",
        "assert!(!first.finished);",
        "assert!(first.finished);",
    );

    for (before, after) in [
        (
            ".filter(|slot| slot.active == Some(self.generation))",
            ".filter(|_| true)",
        ),
        (
            ".filter(|purpose| purpose.ready && purpose.sound)",
            ".filter(|_| true)",
        ),
        (
            "allocation.process_generation != expected || allocation.physical_retired",
            "false",
        ),
        (
            "let original = attempt.cleanup_entry()?;",
            "let original = fresh_cleanup()?;",
        ),
        (
            "let current = self.controller()?;",
            "let current = Arc::clone(&controller);",
        ),
        (
            "!Arc::ptr_eq(&controller, &current) || !controller.cleanup_matches(&original)",
            "!controller.cleanup_matches(&original)",
        ),
        (
            "!Arc::ptr_eq(&controller, &current) || !controller.cleanup_matches(&original)",
            "!Arc::ptr_eq(&controller, &current)",
        ),
        (
            "current.cleanup_matches(&self.original)",
            "true",
        ),
    ] {
        source.reject_companion("process_purpose/source_cleanup.rs", before, after);
    }
    source.reject_companion(
        "linux_attempt_host/original_node.rs",
        "self.cleanup.get_or_init(",
        "self.cleanup.get_or_try_init(",
    );
    source.reject_companion(
        "linux_attempt_host/original_roster.rs",
        "let original = controller.retained_cleanup()?;",
        "let original = fresh_cleanup()?;",
    );

    let launcher = source
        .contract
        .companions
        .iter()
        .find(|binding| binding.path.ends_with("qemu_lifecycle_launcher.rs"))
        .expect("the actual launcher companion remains bound once");
    for (index, method) in [
        (5, "fn take_target_construction_storage("),
        (6, "fn prepare_fork_target_for_node("),
        (7, "fn prepare_fork_target("),
        (8, "fn prepare_fork_target_run_directory("),
        (9, "fn parent_park_drain("),
        (10, "fn begin_execution_quantum("),
        (11, "fn check_operational_boundary("),
        (12, "fn prepare_terminal_exact_checkpoint("),
    ] {
        let clause = launcher.required[index].0;
        assert!(
            source_pattern(clause).starts_with(&source_pattern(method)),
            "wrong guard companion: {method}"
        );
        let guard = if index == 9 {
            r#"self.require_preparation_return().map_err(|_| {
                crate::ProductionVmParentParkDrainRefusal::Unavailable(
                    "pre-VM preparation retains its original cleanup",
                )
            })?;"#
        } else {
            "self.require_preparation_return()?;"
        };
        let original = crate::scrub_comments_and_strings(clause);
        let changed = replace_one_obligation(&original, &source_pattern(guard), "");
        assert_ne!(changed, original, "missing operational guard: {method}");
        source.reject_companion("qemu_lifecycle_launcher.rs", clause, &changed);
    }

    Ok(())
}
