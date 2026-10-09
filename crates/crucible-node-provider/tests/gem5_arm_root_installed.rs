//! Independently measures the installed closed ARM root model without authority.

// crucible-lint: allow rust-allow -- invalid actual native fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and validation failures are test-only.
#![allow(clippy::unwrap_used)]

use crucible_node_provider::gem5::InstalledArmRootMechanism;

#[test]
fn actual_source_owned_root_bundle_is_distinct_and_inert() {
    let measured = InstalledArmRootMechanism::load().unwrap();
    assert_eq!(
        measured.document()["policy_id"],
        "arm-linux-vexpress-atomic-root-functional-v1"
    );
    assert_eq!(
        measured.document()["artifacts"].as_object().unwrap().len(),
        33
    );
    assert_eq!(
        measured.document()["witness"]["publications"][0]["causal_parent"],
        "0"
    );
    assert!(measured.require_execution_admission().is_err());
}
