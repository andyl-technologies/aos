//! Remote-debug session identity surface tests.

use super::*;

#[test]
pub(super) fn cli_formats_live_session_reference_for_remote_debugging() {
    let session = crucible_api::SessionRef::new(
        crucible_api::SessionId::new(7),
        12,
        crucible::Seed::from_u64(42),
    );

    assert_eq!(
        canonical_debug_session_ref(session),
        "7:12:2a00000000000000000000000000000000000000000000000000000000000000"
    );
}
