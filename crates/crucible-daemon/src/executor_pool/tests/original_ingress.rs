//! Exercises actual mutex contention and cancellation at direct pool ingress.

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

#[test]
fn original_ingress_contention_returns_original_expiry_without_entering_actor() {
    let epoch = DaemonEpoch::from_bytes([0x7a; 16]).expect("epoch");
    let pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_millis(25)),
    )
    .expect("finite original");
    let original = Arc::new(
        supervisor
            .begin(HostOperationClass::Preparation)
            .expect("original"),
    );
    let alias = pool.service();
    let lock = alias.shared.executor.lock().expect("actual held actor");
    let mut ingress = pool
        .service()
        .bind_original(original)
        .expect("same original alias");
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let observer = thread::spawn(move || {
        sent.send(ingress.describe_executor())
            .expect("observed ingress")
    });

    let observed = received.recv_timeout(Duration::from_secs(2));
    drop(lock);
    observer.join().expect("actual fixture worker");
    assert!(matches!(
        observed,
        Ok(Err(LocalExecutorPoolServiceError::Original(_)))
    ));
    assert_eq!(
        pool.service.shared.state.load(Ordering::Acquire),
        POOL_RUNNING
    );
    pool.shutdown_and_join()
        .expect("independent fixture cleanup");
}

#[test]
fn original_ingress_cancellation_refuses_before_alias_publication() {
    let epoch = DaemonEpoch::from_bytes([0x7b; 16]).expect("epoch");
    let pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("original supervisor");
    let original = Arc::new(
        supervisor
            .begin(HostOperationClass::Preparation)
            .expect("original"),
    );
    supervisor.cancel().expect("cancel saved original");

    assert!(matches!(
        pool.service().bind_original(original),
        Err(LocalExecutorPoolServiceError::Original(_))
    ));
    assert!(pool.service.original.is_none());
    assert_eq!(
        pool.service.shared.state.load(Ordering::Acquire),
        POOL_RUNNING
    );
    pool.shutdown_and_join()
        .expect("independent fixture cleanup");
}
