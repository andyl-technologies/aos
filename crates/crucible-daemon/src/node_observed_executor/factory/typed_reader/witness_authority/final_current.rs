//! Reauthenticates full host scope after delegation and before host seal retention.
//!
//! Delegated source custody may already retain an original. Later refusal keeps
//! that custody; it does not fabricate rollback. This private ordering helper
//! grants no authority to generic callers or source-supplied validator pointers.

use crucible_node_provider::ProviderError;

pub(super) fn authenticate<T, U>(
    current: impl Fn() -> Result<(), ProviderError>,
    delegated: impl FnOnce() -> Result<T, ProviderError>,
    seal: impl FnOnce(T) -> Result<U, ProviderError>,
) -> Result<U, ProviderError> {
    current()?;
    let original = delegated()?;
    current()?;
    seal(original)
}

#[cfg(test)]
mod tests {
    use super::authenticate;
    use std::cell::Cell;

    fn stale() -> crucible_node_provider::ProviderError {
        crucible_node_provider::ProviderError::Contract(
            crucible_node_contract::ContractError::Invalid {
                field: "modeled current source scope",
                reason: "withdrawn original installation".into(),
            },
        )
    }

    #[test]
    fn delegated_late_revocation_retains_source_but_prevents_host_seal() {
        let current = Cell::new(true);
        let source_retained = Cell::new(false);
        let host_retained = Cell::new(false);

        let result = authenticate(
            || if current.get() { Ok(()) } else { Err(stale()) },
            || {
                source_retained.set(true);
                current.set(false);
                Ok(())
            },
            |()| {
                host_retained.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(source_retained.get());
        assert!(!host_retained.get());
    }

    #[test]
    fn withdrawn_before_delegate_and_delegated_refusal_never_seal() {
        let delegated = Cell::new(false);
        let sealed = Cell::new(false);
        let result = authenticate(
            || Err(stale()),
            || {
                delegated.set(true);
                Ok(())
            },
            |()| {
                sealed.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!delegated.get());
        assert!(!sealed.get());

        let result = authenticate(
            || Ok(()),
            || Err::<(), _>(stale()),
            |()| {
                sealed.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!sealed.get());
    }

    #[test]
    fn original_delegate_value_reaches_seal_after_both_current_checks() {
        let checks = Cell::new(0);
        let original = String::from("same retained source original");
        let result = authenticate(
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            || Ok(original),
            |value| {
                assert_eq!(checks.get(), 2);
                Ok(value)
            },
        );
        assert_eq!(
            result.ok().as_deref(),
            Some("same retained source original")
        );
    }
}
