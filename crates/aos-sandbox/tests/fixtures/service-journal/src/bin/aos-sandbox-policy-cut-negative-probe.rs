//! Rejects an absent Create beneath real protected Controller and source writers.
//!
//! The VM creates the fixed protected roots and runs this probe as the
//! controller UID. No Cache or root policy owner is opened by this fixture.

use std::{cell::Cell, error::Error, path::Path};

use aos_sandbox::journal::{Journal, JournalLimits};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    CurrentCreatePolicySourceErrorV1, with_current_parentless_create_ancestry_v1,
};
use aos_sandbox_core::{OperationId, SandboxId};

const CONTROLLER_UID: u32 = 811;
const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

fn main() {
    if let Err(error) = run() {
        eprintln!("protected policy cut negative qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let (mut controller, _) = Journal::open_protected_at_for_uid(
        Path::new(CONTROLLER_ROOT),
        CONTROLLER_JOURNAL,
        JournalLimits::default(),
        CONTROLLER_UID,
    )?;
    let (mut source_domains, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(CONTROLLER_UID)?;

    let entered = Cell::new(false);
    let result = with_current_parentless_create_ancestry_v1(
        &mut controller,
        &mut source_domains,
        OperationId::from_bytes([1; 16]),
        SandboxId::from_bytes([2; 16]),
        |_, _| entered.set(true),
    );
    if !matches!(result, Err(CurrentCreatePolicySourceErrorV1::NotCurrent)) || entered.get() {
        return Err("absent accepted Create entered the held Controller/source callback".into());
    }

    println!("protected-controller-source-missing-create:PASS");
    Ok(())
}
