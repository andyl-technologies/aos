//! Genuine TX, pending-completion and retained-guard context regressions.

use super::*;
use crate::runtime::live_callbacks::control_callback_witness::ControlCallbackWitness;
use crate::runtime::live_callbacks::network_output_stop::context::capture;

#[test]
fn direct_tx_failure_context_retains_arm_admission_without_changing_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    for status in [0, -libc::EALREADY] {
        let mut fixture = OutputFixture::new()?;
        let mut state = fixture.state()?;
        state.control_callback_witness = std::sync::Arc::new(ControlCallbackWitness::new(true));
        TEST_REQUEST_VMSTOP_STATUS.set(status);
        let (armed, arm_records) = capture::during(|| state.on_network_tx(20, b"original"));
        armed?;
        assert!(arm_records.is_empty());
        let original = fixture.slot.snapshot();

        let (result, records) = capture::during(|| state.on_network_tx(21, b"replacement"));

        assert!(matches!(
            result,
            Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
                raw_icount: 20,
                observed_raw_icount: 21,
                ..
            })
        ));
        assert!(records.contains("phase=network-tx-direct"));
        assert!(records.contains(&format!(
            "pid={} arm_pid={}",
            std::process::id(),
            std::process::id()
        )));
        assert!(records.contains("origin=direct-tx"));
        assert!(records.contains("original_raw=20"));
        assert!(records.contains(&format!(
            "observed_raw=21 write_frontier=1 admission={status}"
        )));
        assert_eq!(fixture.slot.snapshot(), original);
        assert_eq!(fixture.outbound.write_index(), 1);
        assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    }
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    Ok(())
}

#[test]
fn completed_timer_tx_failure_identifies_pending_origin_and_preserve_phase()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.control_callback_witness = std::sync::Arc::new(ControlCallbackWitness::new(true));
    state.on_vcpu_init(0)?;
    state.publish_current_icount(20)?;
    TEST_ICOUNT_RAW.set(20);
    let pending = state.queued_idle_advance.enqueue(1_500)?;
    state.arm_idle_advance(20, 1_500, pending, None)?;
    state.on_network_tx(20, b"timer-frame")?;
    state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 1_500))?;
    let original = fixture.slot.snapshot();

    let (results, records) = capture::during(|| {
        (
            state.on_vcpu_resume(0, 21),
            state.on_network_tx(21, b"replacement"),
        )
    });

    assert!(matches!(
        results.0,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed { .. })
    ));
    assert!(records.contains("phase=vcpu-resume"));
    assert!(matches!(
        results.1,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed { .. })
    ));
    assert!(records.contains("origin=idle-advance-completion"));
    assert!(records.contains("admission=0"));
    assert_eq!(records.lines().count(), 1);
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.write_index(), 1);
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}

#[test]
fn disabled_context_keeps_identical_retained_guard_result_without_a_record()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.control_callback_witness = std::sync::Arc::new(ControlCallbackWitness::new(false));
    state.on_network_tx(20, b"original")?;
    let original = fixture.slot.snapshot();

    let (result, records) =
        capture::during(|| state.preserve_network_output_stop(21, "vcpu-resume"));

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
            raw_icount: 20,
            observed_raw_icount: 21,
            ..
        })
    ));
    assert!(records.is_empty());
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.write_index(), 1);
    Ok(())
}

#[test]
fn nested_admission_observation_does_not_borrow_or_change_original_guard()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.control_callback_witness = std::sync::Arc::new(ControlCallbackWitness::new(true));
    state.on_network_tx(20, b"original")?;
    let original_slot = fixture.slot.snapshot();
    let network = state.network.as_ref().ok_or("network fixture")?;
    let owner = network
        .output_stop
        .try_lock()
        .map_err(|_| "owned stop borrow")?;
    let original = owner.as_ref().cloned().ok_or("retained original")?;

    let before = state.on_network_tx(21, b"nested-before");
    original.observe_admission(-libc::EALREADY);
    let after = state.on_network_tx(21, b"nested-after");
    assert!(matches!(
        before,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopBorrowed)
    ));
    assert!(matches!(
        after,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopBorrowed)
    ));
    drop(owner);
    let (result, records) =
        capture::during(|| state.preserve_network_output_stop(21, "vcpu-resume"));

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed { .. })
    ));
    assert!(records.contains("admission=-114"));
    assert_eq!(fixture.slot.snapshot(), original_slot);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn delayed_original_admission_cannot_overwrite_a_genuine_new_output_arm()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.control_callback_witness = std::sync::Arc::new(ControlCallbackWitness::new(true));
    state.on_network_tx(20, b"original")?;
    let network = state.network.as_ref().ok_or("network fixture")?;
    let original = network
        .output_stop
        .try_lock()
        .map_err(|_| "owned stop borrow")?
        .as_ref()
        .cloned()
        .ok_or("retained original")?;
    assert!(
        fixture
            .outbound
            .dequeue(&fixture.outbound_entries)?
            .is_some()
    );
    state.on_network_tx(40, b"new-arm")?;
    let new_slot = fixture.slot.snapshot();

    original.observe_admission(-libc::EALREADY);
    let (result, records) = capture::during(|| state.on_network_tx(41, b"replacement"));

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
            raw_icount: 40,
            observed_raw_icount: 41,
            ..
        })
    ));
    assert!(records.contains("original_raw=40"));
    assert!(records.contains("write_frontier=2 admission=0"));
    assert_eq!(fixture.slot.snapshot(), new_slot);
    assert_eq!(fixture.outbound.read_index(), 1);
    assert_eq!(fixture.outbound.write_index(), 2);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 2);
    Ok(())
}
