//! Exercises actual Clock adapter owners without granting installed qualification.

use super::*;

const MAXIMUM: usize = 64 * 1024 * 1024;

struct ModelClock;

impl HostModelQualification for ModelClock {
    fn authenticate_model(
        &self,
        model: &HostModel,
        _: &NodeDescriptor,
        _: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if matches!(model, HostModel::Clock(_)) {
            Ok(())
        } else {
            Err(failure("model-only Clock fixture differs"))
        }
    }
}

fn actual_clock() -> Result<HostModelNode, RuntimeError> {
    let (graph, _) = crate::node_admission::test_fixture_host_clock_execution();
    let node = graph.node_ids().next().ok_or(RuntimeError::UnknownNode)?;
    HostModelNode::new(
        &graph,
        node,
        HostModel::Clock(VirtualClock::new()),
        &ModelClock,
        HostModelResources::default(),
    )
    .map_err(|_| RuntimeError::InvalidReceipt)
}

#[test]
fn actual_clock_complete_row_accepts_exact_and_refuses_one_short() -> Result<(), RuntimeError> {
    let clock = actual_clock()?;
    let native_before = clock.initial.as_slice();
    let bytes = clock.original_clock_requested_backing_data(MAXIMUM)?;
    assert!(bytes > 0);
    assert_eq!(
        clock.original_clock_requested_backing_data(bytes),
        Ok(bytes)
    );
    assert_eq!(
        clock.original_clock_requested_backing_data(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(clock.initial.as_slice(), native_before);
    assert!(clock.completed.is_empty());
    assert!(clock.failed.is_empty());
    assert!(clock.readiness.is_none());
    Ok(())
}

#[test]
fn actual_initial_bank_spare_capacity_is_charged_without_changing_clock() -> Result<(), RuntimeError>
{
    let mut clock = actual_clock()?;
    let before = clock.original_clock_requested_backing_data(MAXIMUM)?;
    let old_capacity = clock.initial.capacity();
    let mut spare = Vec::with_capacity(old_capacity + 65536);
    spare.extend_from_slice(clock.initial.as_slice());
    let extra = spare.capacity() - old_capacity;
    clock.initial = Rc::new(spare);
    let after = clock.original_clock_requested_backing_data(MAXIMUM)?;
    assert_eq!(after - before, extra);
    assert!(
        matches!(clock.model.as_ref(), Some(HostModel::Clock(value)) if value.current_icount() == 0)
    );
    Ok(())
}

#[test]
fn actual_foreign_creator_refuses_before_zero_credit_or_owner_walk() -> Result<(), RuntimeError> {
    let mut clock = actual_clock()?;
    let original = clock.process;
    clock.process = original.wrapping_add(1);
    assert_eq!(
        clock.original_clock_requested_backing_data(0),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(
        clock.retained_requested_storage_precredit_scratch_data(),
        Err(RuntimeError::ForeignAuthority)
    );
    clock.process = original;
    assert!(clock.original_clock_requested_backing_data(MAXIMUM).is_ok());
    Ok(())
}

#[test]
fn actual_unknown_optional_owner_is_never_credited_as_empty() -> Result<(), RuntimeError> {
    let mut clock = actual_clock()?;
    clock.input_endpoint = Some(Endpoint {
        node_id: clock.route.node.clone(),
        port_id: clock.route.node.clone(),
        lane_id: clock.route.node.clone(),
    });
    assert_eq!(
        clock.original_clock_requested_backing_data(MAXIMUM),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(
        clock.retained_requested_storage_precredit_data(MAXIMUM),
        Err(RuntimeError::UnsupportedFacet)
    );
    Ok(())
}

#[test]
fn actual_preparation_alias_and_independent_banks_have_distinct_costs() -> Result<(), RuntimeError>
{
    let mut clock = actual_clock()?;
    let reference = canonical::content_ref(b"one", "application/json")
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    // These are retained data fields only: this control does not authenticate
    // readiness, source custody or an installed preparation capability.
    clock.public_preparation = Some(HostPublicPreparation {
        anchor: Rc::clone(&clock.original_model_session),
        token: clock.route.node.clone(),
        session: reference.clone(),
        session_bytes: Vec::with_capacity(8192),
        native_ready: reference,
        native_ready_bytes: Vec::with_capacity(4096),
        ready: None,
        history: Vec::with_capacity(7),
        previous: None,
    });
    let aliased = clock.original_clock_requested_backing_data(MAXIMUM)?;
    clock
        .public_preparation
        .as_mut()
        .ok_or(RuntimeError::InvalidReceipt)?
        .anchor = Rc::new(());
    let independent = clock.original_clock_requested_backing_data(MAXIMUM)?;
    let header = NodeRuntime::capture_protocol_shared_header_storage(1, 1, MAXIMUM)?;
    assert_eq!(independent - aliased, header);
    let preparation = clock
        .public_preparation
        .as_mut()
        .ok_or(RuntimeError::InvalidReceipt)?;
    let old = preparation.native_ready_bytes.capacity();
    preparation.native_ready_bytes.reserve(16384);
    let added = preparation.native_ready_bytes.capacity() - old;
    assert_eq!(
        clock.original_clock_requested_backing_data(MAXIMUM)? - independent,
        added
    );
    Ok(())
}
