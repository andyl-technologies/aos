//! Canonical retained-frame cadence and retry-bound tests.

use super::*;

#[test]
fn network_rx_fails_loudly_at_canonical_delivery_attempt_limit() {
    let network_rx = PluginNetworkRx::new();
    let mut queue = RecordingRxQueue::not_ready();
    let frame = frame(20, 1, 0, b"bounded");
    let first = network_rx
        .inject_due_frames_from_idle_context(&mut queue, 20, 20, std::slice::from_ref(&frame))
        .unwrap_or_else(|error| panic!("first bounded attempt should be admitted: {error}"));
    assert_eq!(first.retained_frame_key(), Some(frame.delivery_key()));
    frame
        .record_delivery_attempt(20, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
        .unwrap_or_else(|error| panic!("first retained attempt should be recorded: {error}"));
    frame
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("first retained attempt should authorize retry: {error}"));

    for attempt in 1..NETWORK_RX_DELIVERY_ATTEMPT_LIMIT {
        let current_icount = 20 + u64::from(attempt) * NETWORK_RX_RETRY_INTERVAL_ICOUNT;
        let injection = network_rx
            .inject_due_frames_from_idle_context(
                &mut queue,
                current_icount,
                current_icount,
                std::slice::from_ref(&frame),
            )
            .unwrap_or_else(|error| panic!("bounded attempt should be admitted: {error}"));
        assert_eq!(injection.retained_frame_key(), Some(frame.delivery_key()));
        frame
            .record_delivery_attempt(current_icount, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
            .unwrap_or_else(|error| panic!("retained attempt should be recorded: {error}"));
    }

    let terminal_icount =
        20 + u64::from(NETWORK_RX_DELIVERY_ATTEMPT_LIMIT) * NETWORK_RX_RETRY_INTERVAL_ICOUNT;
    assert_eq!(
        network_rx.inject_due_frames_from_idle_context(
            &mut queue,
            terminal_icount,
            terminal_icount,
            std::slice::from_ref(&frame),
        ),
        Err(NetworkRxError::DeliveryAttemptLimit {
            frame: frame.delivery_key(),
            current_icount: terminal_icount,
            source: FrameDeliveryAttemptError::LimitReached {
                attempts: NETWORK_RX_DELIVERY_ATTEMPT_LIMIT,
                limit: NETWORK_RX_DELIVERY_ATTEMPT_LIMIT,
            },
        })
    );
    assert_eq!(frame.delivery_attempts(), NETWORK_RX_DELIVERY_ATTEMPT_LIMIT);
}

#[test]
fn network_rx_retries_canonically_retained_past_frame() {
    let network_rx = PluginNetworkRx::new();
    let mut queue = RecordingRxQueue::ready();
    let late = frame(19, 1, 0, b"late");
    late.record_delivery_attempt(19, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
        .unwrap_or_else(|error| panic!("record retained attempt: {error}"));
    late.mark_delivery_retained()
        .unwrap_or_else(|error| panic!("mark retained frame: {error}"));
    let retry_icount = 19 + NETWORK_RX_RETRY_INTERVAL_ICOUNT;

    let waiting = network_rx
        .inject_due_frames_from_idle_context(
            &mut queue,
            retry_icount - 1,
            retry_icount - 1,
            std::slice::from_ref(&late),
        )
        .unwrap_or_else(|error| panic!("early retained retry should wait: {error}"));
    assert!(waiting.delivered_frame_keys().is_empty());
    assert!(waiting.retained_frame_key().is_none());
    assert!(queue.queued_payloads.is_empty());

    let injection = network_rx
        .inject_due_frames_from_idle_context(
            &mut queue,
            retry_icount,
            retry_icount,
            std::slice::from_ref(&late),
        )
        .unwrap_or_else(|error| panic!("retained frame should retry: {error}"));
    assert_eq!(injection.delivered_frame_keys(), &[late.delivery_key()]);
    assert_eq!(queue.queued_payloads, vec![b"late".to_vec()]);
}

#[test]
fn network_rx_overshoot_cannot_retry_twice_at_one_coordinate() {
    let network_rx = PluginNetworkRx::new();
    let mut queue = RecordingRxQueue::not_ready();
    let retained = frame(20, 1, 0, b"storm-safe");
    retained
        .record_delivery_attempt(20, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
        .unwrap_or_else(|error| panic!("record initial retained attempt: {error}"));
    retained
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("mark retained frame: {error}"));
    let overshot_icount = 20 + 10 * NETWORK_RX_RETRY_INTERVAL_ICOUNT;

    let retry = network_rx
        .inject_due_frames_from_idle_context(
            &mut queue,
            overshot_icount,
            overshot_icount,
            std::slice::from_ref(&retained),
        )
        .unwrap_or_else(|error| panic!("overshot retry should run once: {error}"));
    assert_eq!(retry.retained_frame_key(), Some(retained.delivery_key()));
    retained
        .record_delivery_attempt(overshot_icount, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
        .unwrap_or_else(|error| panic!("record overshot retained attempt: {error}"));

    let same_coordinate = network_rx
        .inject_due_frames_from_idle_context(
            &mut queue,
            overshot_icount,
            overshot_icount,
            std::slice::from_ref(&retained),
        )
        .unwrap_or_else(|error| panic!("same-coordinate callback should be suppressed: {error}"));
    assert!(same_coordinate.delivered_frame_keys().is_empty());
    assert!(same_coordinate.retained_frame_key().is_none());
    assert_eq!(retained.delivery_attempts(), 2);
    assert_eq!(retained.last_delivery_attempt_icount(), overshot_icount);
}

#[test]
fn network_rx_retained_head_authorizes_blocked_fifo_backlog() {
    let network_rx = PluginNetworkRx::new();
    let mut queue = RecordingRxQueue::ready();
    let retained = frame(18, 1, 0, b"retained");
    retained
        .record_delivery_attempt(18, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
        .unwrap_or_else(|error| panic!("record retained attempt: {error}"));
    retained
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("mark retained frame: {error}"));
    let successor = frame(19, 1, 1, b"successor");
    let retry_icount = 18 + NETWORK_RX_RETRY_INTERVAL_ICOUNT;

    let injection = network_rx
        .inject_due_frames_from_idle_context(
            &mut queue,
            retry_icount,
            retry_icount,
            &[retained, successor],
        )
        .unwrap_or_else(|error| panic!("retained backlog should retry: {error}"));

    assert_eq!(injection.delivered_frame_keys().len(), 2);
    assert_eq!(
        queue.queued_payloads,
        vec![b"retained".to_vec(), b"successor".to_vec()]
    );
}
