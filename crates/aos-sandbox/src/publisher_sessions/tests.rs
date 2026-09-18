//! Kernel-independent publisher table configuration and sentinel checks.

use super::*;

#[test]
fn invalid_limits_and_reserved_scopes_fail_without_kernel_state() {
    for maximum_sessions in [0, MAXIMUM_SESSIONS + 1] {
        assert!(matches!(
            PublisherSessionRegistry::new(PublisherSessionLimits { maximum_sessions }),
            Err(PublisherSessionError::InvalidLimit)
        ));
    }
    let scope = PublisherSessionScope {
        principal: PrincipalId::from_bytes([1; 16]),
        node: NodeId::from_bytes([2; 16]),
        project: ProjectId::from_bytes([3; 16]),
        cache_resource: ResourceId::from_bytes([4; 16]),
    };
    assert!(validate_scope(scope).is_ok());
    for invalid in [
        PublisherSessionScope {
            principal: PrincipalId::from_bytes([0; 16]),
            ..scope
        },
        PublisherSessionScope {
            node: NodeId::from_bytes([0; 16]),
            ..scope
        },
        PublisherSessionScope {
            project: ProjectId::from_bytes([0; 16]),
            ..scope
        },
        PublisherSessionScope {
            cache_resource: ResourceId::from_bytes([0; 16]),
            ..scope
        },
    ] {
        assert!(matches!(
            validate_scope(invalid),
            Err(PublisherSessionError::InvalidScope)
        ));
    }
}
