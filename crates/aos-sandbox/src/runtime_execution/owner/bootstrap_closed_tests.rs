//! Proofless fixed bootstrap must remain closed across cold invocations.

use super::{DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1};

#[test]
fn fixed_bootstrap_rejects_proofless_calls_across_retries() {
    for _ in 0..2 {
        assert!(matches!(
            DormantRuntimeExecutionOwnerV1::bootstrap_fixed(),
            Err(DormantRuntimeExecutionOwnerErrorV1::BootstrapProofRequired)
        ));
    }
}
