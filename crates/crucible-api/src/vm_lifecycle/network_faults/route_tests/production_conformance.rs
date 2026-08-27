//! Focused production route conformance cases.

use super::*;

#[test]
fn token_bucket_preserves_ceil_surplus_without_rate_bias() {
    let action = action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut release = 0;
    for sequence in 0..3 {
        release =
            apply_network_token_bucket(&mut state, &action, &opportunity(sequence), 1, 3, 8, 0)
                .unwrap_or_else(|error| panic!("token service should succeed: {error}"));
    }
    assert_eq!(release, 8_000_000_000);
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkTokenBucket],
        "token-bucket-ceil-surplus",
        "token-ledger+release-coordinate",
    );
}
