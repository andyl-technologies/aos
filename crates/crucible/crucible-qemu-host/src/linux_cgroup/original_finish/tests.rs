//! Checks that the actual dispatcher cause survives an independent Original post.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use crucible_host_resources::test_support::TestAllocationObserver;
use std::error::Error;
use std::path::PathBuf;

#[derive(Debug)]
struct DispatcherIoCause(Box<str>);

impl std::fmt::Display for DispatcherIoCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DispatcherIoCause {}

#[test]
fn original_watcher_retains_dispatcher_payload_and_post_without_allocating() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Cleanup).unwrap();
    // Cleanup survives supervisor cancellation. Completing this actual guard
    // gives its independent post a deterministic terminal refusal instead.
    original.complete().unwrap();
    let after = original.wait_slice().unwrap_err();

    let path = PathBuf::from("component/retained-dispatcher");
    let path_pointer = path.as_os_str().as_encoded_bytes().as_ptr();
    let payload = DispatcherIoCause(String::from("existing dispatcher I/O cause").into_boxed_str());
    let payload_pointer = payload.0.as_ptr();
    let first =
        super::super::LinuxQemuTargetDispatcherError::new(path, std::io::Error::other(payload));
    let display = first.to_string();

    let (report, counts) = TestAllocationObserver::count(|| {
        refusal(OriginalWatcherCause::TargetJob(first), Some(after))
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(report.original_after, Some(after));
    let OriginalWatcherCause::TargetJob(retained) = &report.cause else {
        panic!("the actual dispatcher cause must remain typed");
    };
    assert_eq!(
        retained.path().as_os_str().as_encoded_bytes().as_ptr(),
        path_pointer
    );
    let payload = retained
        .io_error()
        .get_ref()
        .unwrap()
        .downcast_ref::<DispatcherIoCause>()
        .unwrap();
    assert_eq!(payload.0.as_ptr(), payload_pointer);
    assert_eq!(retained.to_string(), display);
    assert!(std::ptr::eq(
        report
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<super::super::LinuxQemuTargetDispatcherError>()
            .unwrap(),
        retained,
    ));
}
