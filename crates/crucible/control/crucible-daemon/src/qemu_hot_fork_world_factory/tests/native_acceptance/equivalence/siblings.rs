//! Same-parent native sibling matrix under genuine complete host admission.

use super::*;

#[test]
#[ignore = "requires the operator-managed seventeen-world AOS paging environment"]
fn production_managed_source_keeps_bounded_native_siblings_live() {
    run_case(NativeEquivalenceCase::Siblings, true, 512, false);
}
