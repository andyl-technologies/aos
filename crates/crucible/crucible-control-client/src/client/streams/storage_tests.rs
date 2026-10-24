//! Checks original allocation custody for actual boxed RPC receivers.

use super::*;
use crucible_control_api::admitted_output::test_support::{
    fixture_budget_with_counter, tracked_fixture_budget,
};
use std::sync::atomic::Ordering;

fn input_fields() -> Result<(Attached, RpcStreamingEventReceiver), ControlClientError> {
    let budget = crucible_control_api::admitted_output::test_support::fixture_budget().map_err(
        |source| client_output_admission(crucible_control_api::admitted_output::admission(source)),
    )?;
    let _scope = budget.enter();
    let attached = Attached::from_owned_fields(
        SessionRef::new(SessionId::new(1), 1, Seed::from_u64(7)),
        0,
        LiveStateKind::Loaded,
        RPC_PROTOCOL_VERSION,
        StreamingCapabilitySet {
            commands: Vec::new(),
            snapshot_on_attach: false,
        },
        None,
    )
    .map_err(client_output_admission)?;
    let (_sender, frames) = mpsc::channel(1);
    let receiver = RpcStreamingEventReceiver::new(frames, &budget)?;
    Ok((attached, receiver))
}

#[test]
fn boxed_receiver_retains_its_actual_credit_after_the_callers_budget_drops()
-> Result<(), Box<dyn std::error::Error>> {
    let (attached, receiver) = input_fields()?;
    let bytes = std::mem::size_of::<RpcWatchStreamBody>() as u64;
    let (budget, used) = fixture_budget_with_counter()?;
    let control_bytes = used.load(Ordering::SeqCst);

    let stream = RpcWatchStream::new(attached, receiver, &budget)?;
    drop(budget);

    assert_eq!(used.load(Ordering::SeqCst), control_bytes + bytes);
    assert_eq!(stream.attached().session.seed, Seed::from_u64(7));
    drop(stream);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn boxed_receiver_refuses_an_insufficient_original_allocation_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let (attached, receiver) = input_fields()?;
    let bytes = std::mem::size_of::<RpcWatchStreamBody>() as u64;
    let (budget, used) = tracked_fixture_budget(bytes - 1)?;
    let control_bytes = used.load(Ordering::SeqCst);

    let result = RpcWatchStream::new(attached, receiver, &budget);

    assert!(result.is_err());
    assert_eq!(used.load(Ordering::SeqCst), control_bytes);
    drop(budget);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}
