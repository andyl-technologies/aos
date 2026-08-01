//! Delivery-regression and clock-regression lifecycle cases.

use super::*;

#[test]
fn stale_request_delivering_in_the_past_fails_loudly() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let mut device = EchoDevice::new(1000, 4);

    let stale = Request::new(0, 0, b"alpha".to_vec());
    let probe = ok(IoCore::new(SHIFT, NODE, 16, 16));
    let stale_delivery = ok(probe.compute_delivery_icount(&stale, device.latency_model()));
    assert_eq!(stale_delivery, 4);

    ok(core.advance_to(1000));
    ok(core.enqueue_request(stale));

    let result = core.process_inbox(&mut device);
    assert!(
        matches!(
            result,
            Err(DeviceError::DeliveryInPast {
                delivery_icount: 4,
                current_icount: 1000
            })
        ),
        "expected DeliveryInPast, got {result:?}"
    );
    assert!(core.next_exact_local_event().is_none());
}

#[test]
fn clock_never_moves_backward() {
    let mut core = ok(IoCore::new(SHIFT, NODE, 16, 16));
    ok(core.advance_to(100));
    assert!(matches!(
        core.advance_to(99),
        Err(DeviceError::ClockRegression { .. })
    ));
}
