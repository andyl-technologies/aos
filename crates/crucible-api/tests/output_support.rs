//! Finite metadata admission for process-neutral API integration fixtures.

pub fn budget() -> crucible::owned_decode::DecodeBudget {
    let scope = crucible::test_support::fixture_decode_scope(64 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite API fixture metadata: {error}"));
    let budget = crucible::owned_decode::current_budget()
        .unwrap_or_else(|| panic!("fixture must install its authored metadata account"));
    drop(scope);
    budget
}
