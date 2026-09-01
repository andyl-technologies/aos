//! Tests scheduler propagation of node-local typed failures.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crucible::SchedulerError;

#[test]
fn resource_limit_coordinates_survive_node_and_scheduler_conversion() {
    let runtime = QemuAsyncDriverRuntimeError::resource_limit("storage_request_bytes", 3, 5, 7, 11);
    let node = QemuNodeError::from_async_driver(QemuAsyncDriverError::Runtime(runtime));
    let scheduler = SchedulerError::from(BackendError::from(node));

    assert!(matches!(
        scheduler,
        SchedulerError::ResourceLimit {
            field: "storage_request_bytes",
            current: 3,
            requested: 5,
            configured: 7,
            hard: 11,
        }
    ));
}
