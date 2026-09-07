//! Kernel-independent session configuration and scope validation checks.

use super::*;

#[test]
fn table_limits_and_reserved_scope_bindings_are_rejected_without_kernel_state() {
    for maximum_sessions in [0, MAXIMUM_SESSIONS + 1] {
        assert!(matches!(
            LocalSessionRegistry::new(LocalSessionLimits { maximum_sessions }),
            Err(LocalSessionError::InvalidLimit)
        ));
    }

    let scope = LocalSessionScope {
        holder: PrincipalId::from_bytes([1; 16]),
        project: ProjectId::from_bytes([2; 16]),
        sandbox: SandboxId::from_bytes([3; 16]),
        incarnation: IncarnationId::from_bytes([4; 16]),
        epoch: AssignmentEpoch::new(1),
        cache_resource: ResourceId::from_bytes([5; 16]),
    };
    assert!(validate_scope(scope).is_ok());
    for invalid in [
        LocalSessionScope {
            holder: PrincipalId::from_bytes([0; 16]),
            ..scope
        },
        LocalSessionScope {
            project: ProjectId::from_bytes([0; 16]),
            ..scope
        },
        LocalSessionScope {
            sandbox: SandboxId::from_bytes([0; 16]),
            ..scope
        },
        LocalSessionScope {
            incarnation: IncarnationId::from_bytes([0; 16]),
            ..scope
        },
        LocalSessionScope {
            epoch: AssignmentEpoch::new(0),
            ..scope
        },
        LocalSessionScope {
            cache_resource: ResourceId::from_bytes([0; 16]),
            ..scope
        },
    ] {
        assert!(matches!(
            validate_scope(invalid),
            Err(LocalSessionError::InvalidScope)
        ));
    }
}
