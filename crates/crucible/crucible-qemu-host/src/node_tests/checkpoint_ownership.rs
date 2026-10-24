//! Component controls for actual local checkpoint ownership and wire ordering.

#![cfg(test)]

use super::*;
pub(super) use crate::node::test_support::checkpoint_ownership::Ownership;

#[test]
fn checkpoint_retries_keep_one_original_and_one_transferred_alias() -> Result<(), Box<dyn Error>> {
    use crucible_host_resources::host_supervision::HostOperationClass;

    let ownership = Ownership::new(false)?;
    let mut node = scripted_node_with_options(
        shared_log(),
        ScriptedNodeOptions {
            checkpoint: Some(ownership.clone()),
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;
    node.synchronize_observed_time()?;
    node.pause_at_exact_checkpoint_boundary()?;
    let first = ownership
        .supervisor
        .operation_statuses()?
        .into_iter()
        .find(|status| status.class == HostOperationClass::Quiescence)
        .unwrap();

    node.pause_at_exact_checkpoint_boundary()?;
    let repeated = ownership
        .supervisor
        .operation_statuses()?
        .into_iter()
        .filter(|status| status.class == HostOperationClass::Quiescence)
        .collect::<Vec<_>>();
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated[0].operation_id, first.operation_id);
    assert_eq!(ownership.original_id(), Some(first.operation_id));
    assert_eq!(ownership.counts(), (1, 1));

    // The actual alias received over SCM_RIGHTS cancels the retained guard.
    ownership.cancel_from_peer()?;
    assert!(node.pause_at_exact_checkpoint_boundary().is_err());
    assert_eq!(ownership.counts(), (1, 1));
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn failed_stop_retains_original_credit_through_reap_and_transport_borrow()
-> Result<(), Box<dyn Error>> {
    let ownership = Ownership::new(true)?;
    let account = ownership.registration.host_services.clone();
    let peer_closed = ownership.peer_lifetime();
    let mut node = scripted_node_with_options(
        shared_log(),
        ScriptedNodeOptions {
            checkpoint: Some(ownership.clone()),
            fail_qmp_stop: true,
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;
    assert!(std::ptr::eq(
        node.host_io_runtime.host_operation_supervisor().unwrap(),
        &ownership.supervisor,
    ));
    node.synchronize_observed_time()?;

    let first = node.pause_at_exact_checkpoint_boundary().unwrap_err();
    assert!(first.to_string().contains("injected QMP stop failure"));
    assert_eq!(ownership.counts(), (1, 1));
    assert!(account.reserve_resources(0, 8, 1024 * 1024).is_err());
    node.shutdown_child()?;
    assert!(node.child_reaped());
    assert!(node.cleanup_physically_returned());
    assert!(node.host_io_runtime.ram_control_registration().is_none());
    assert!(
        account.reserve_resources(0, 8, 1024 * 1024).is_err(),
        "QMP transport still borrows the original after actual process reap"
    );
    assert!(!peer_closed());

    node.shutdown_child()?;
    assert!(node.cleanup_physically_returned());
    assert!(!peer_closed());
    assert_eq!(ownership.counts(), (1, 1));

    drop(node);
    assert!(!peer_closed(), "the actual caller still owns the transport");
    drop(ownership);
    assert!(peer_closed());
    assert!(account.reserve_resources(0, 8, 1024 * 1024).is_ok());
    Ok(())
}
