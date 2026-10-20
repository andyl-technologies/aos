//! Checks domain admission policy without acquiring a filesystem capability.

use super::check_domain;
use crate::store::{InvalidReason, StoreErrorKind};

#[test]
fn private_shared_cache_is_refused_before_host_open() {
    let error = check_domain("private:consumer").unwrap_err();

    assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
}

#[test]
fn malformed_domain_is_not_an_implicit_public_route() {
    for domain in ["", "tenant:", "group:", "public:other", "unknown"] {
        let error = check_domain(domain).unwrap_err();

        assert_eq!(
            error.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            "{domain:?}"
        );
    }
}
