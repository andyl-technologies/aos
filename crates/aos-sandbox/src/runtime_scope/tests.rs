//! Kernel-independent runtime-scope deadline rejection tests.

use super::*;

#[test]
fn expired_deadlines_fail_before_exchange() {
    assert!(matches!(
        transport::exchange_deadline(0),
        Err(RuntimeScopeError::Deadline)
    ));
    assert!(matches!(
        transport::check_deadline(0),
        Err(RuntimeScopeError::Deadline)
    ));
}
