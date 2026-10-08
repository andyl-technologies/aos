//! Regression fixtures for the original reconciliation readiness and refusals.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use super::*;

#[test]
fn recovered_pending_catalog_is_published_before_a_fresh_readiness_cycle() {
    #[derive(Default)]
    struct Calls {
        order: Vec<&'static str>,
    }

    let mut calls = Calls::default();
    let status = pending_first_reconciliation_cycle(
        &mut calls,
        |calls| {
            calls.order.push("recovery");
            Ok::<_, ()>(Some("durable pending catalog"))
        },
        |calls, pending| {
            calls.order.push("pending publication");
            assert_eq!(pending, "durable pending catalog");
            Ok::<_, ()>(())
        },
        |calls| {
            calls.order.push("bounded reconciliation");
            Ok::<_, ()>(())
        },
        |calls| {
            calls.order.push("fresh broker inventories");
            Ok::<_, ()>("fresh confirmed catalog")
        },
    )
    .unwrap();

    assert_eq!(status, "fresh confirmed catalog");
    assert_eq!(
        calls.order,
        [
            "recovery",
            "pending publication",
            "bounded reconciliation",
            "fresh broker inventories",
        ]
    );
}

#[test]
fn successful_pending_publication_does_not_satisfy_readiness() {
    #[derive(Default)]
    struct Calls {
        publication: usize,
        fresh_inventory: usize,
    }

    let mut calls = Calls::default();
    let result: Result<&str, &str> = pending_first_reconciliation_cycle(
        &mut calls,
        |_| Ok::<_, &'static str>(Some("durable pending catalog")),
        |calls, _| {
            calls.publication += 1;
            Ok(())
        },
        |_| Ok(()),
        |calls| {
            calls.fresh_inventory += 1;
            Err("fresh inventory unavailable")
        },
    );

    assert!(matches!(result, Err("fresh inventory unavailable")));
    assert_eq!(calls.publication, 1);
    assert_eq!(calls.fresh_inventory, 1);
    assert!(result.is_err(), "publication alone must not open readiness");
}

#[test]
fn reconciliation_failure_closes_readiness_before_broker_inventory() {
    #[derive(Default)]
    struct Calls {
        reconciliation: usize,
        broker_inventory: usize,
    }

    let mut calls = Calls::default();
    let result = pending_first_reconciliation_cycle(
        &mut calls,
        |_| Ok::<_, &'static str>(None::<()>),
        |_, _| Ok(()),
        |calls| {
            calls.reconciliation += 1;
            Err("reconciliation failed")
        },
        |calls| {
            calls.broker_inventory += 1;
            Ok("ready")
        },
    );

    assert!(matches!(result, Err("reconciliation failed")));
    assert_eq!(calls.reconciliation, 1);
    assert_eq!(calls.broker_inventory, 0);
    assert!(
        result.is_err(),
        "failed reconciliation must not open readiness"
    );
}

#[test]
fn protected_publication_retries_only_retained_recovery() {
    assert!(matches!(
        classify_protected_publication_error(ControllerHostPublicationError::RecoveryPending),
        CycleFailure::Retryable(_)
    ));
    assert!(matches!(
        classify_protected_publication_error(ControllerHostPublicationError::Conflict),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_protected_publication_error(ControllerHostPublicationError::Session(
            crate::DormantBrokerSessionHandshakeErrorV1::Deadline
        )),
        CycleFailure::Fatal(_)
    ));
}

#[test]
fn protected_handshake_authentication_failures_are_terminal() {
    use crate::DormantBrokerSessionHandshakeErrorV1 as HandshakeError;

    for error in [
        HandshakeError::EndpointRole,
        HandshakeError::RemoteInvalid,
        HandshakeError::KernelEvidence,
    ] {
        assert!(matches!(
            classify_protected_handshake_error(error),
            CycleFailure::Fatal(_)
        ));
    }
    for error in [HandshakeError::Transport, HandshakeError::Deadline] {
        assert!(matches!(
            classify_protected_handshake_error(error),
            CycleFailure::Retryable(_)
        ));
    }
}

#[test]
fn broker_retryability_is_preserved_across_inventory_classification() {
    use aos_proto::aos::sandbox::local::v1::BrokerErrorCode;

    let code = BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE;
    assert!(matches!(
        classify_mount_error(MountAttemptError::BrokerRejected {
            code,
            retryable: false,
        }),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_mount_error(MountAttemptError::BrokerRejected {
            code,
            retryable: true,
        }),
        CycleFailure::Retryable(_)
    ));
    assert!(matches!(
        classify_resource_error(ResourceInventoryError::BrokerRejected {
            code,
            retryable: false,
        }),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_resource_error(ResourceInventoryError::BrokerRejected {
            code,
            retryable: true,
        }),
        CycleFailure::Retryable(_)
    ));
}

#[test]
fn host_publication_retryability_is_preserved_through_reconciliation() {
    use aos_proto::aos::sandbox::local::v1::BrokerErrorCode;

    let rejected = |retryable| {
        HostCatalogReconciliationError::Publication(
            HostCatalogPublicationError::BrokerRejected {
                code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
                retryable,
            },
        )
    };

    assert!(matches!(
        classify_catalog_error(rejected(false)),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_catalog_error(rejected(true)),
        CycleFailure::Retryable(_)
    ));
}

#[test]
fn hostile_publication_and_transport_failures_are_terminal() {
    assert!(matches!(
        classify_publication_error(HostCatalogPublicationError::HostIdentity),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_publication_error(HostCatalogPublicationError::ReceiptMismatch),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_publication_error(HostCatalogPublicationError::Protocol(
            aos_sandbox_protocol::ProtocolValidationError::DescriptorTableMismatch,
        )),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_resource_error(ResourceInventoryError::Transport(
            SeqpacketError::EmptyRecord,
        )),
        CycleFailure::Fatal(_)
    ));
    assert!(matches!(
        classify_resource_error(ResourceInventoryError::Kernel(LinuxError::InvalidInput {
            field: "service cgroup",
            message: "invalid deployment contract".to_owned(),
        })),
        CycleFailure::Fatal(_)
    ));
}

#[test]
fn bounded_service_loss_remains_retryable() {
    assert!(matches!(
        classify_resource_error(ResourceInventoryError::Deadline),
        CycleFailure::Retryable(_)
    ));
    assert!(matches!(
        classify_publication_error(HostCatalogPublicationError::Transport(
            SeqpacketError::Closed,
        )),
        CycleFailure::Retryable(_)
    ));
    assert!(matches!(
        classify_mount_error(MountAttemptError::Preparation(
            MountCatalogPreparationError::Deadline,
        )),
        CycleFailure::Retryable(_)
    ));
}
