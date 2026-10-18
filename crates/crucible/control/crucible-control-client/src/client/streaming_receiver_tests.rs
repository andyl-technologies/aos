//! Streaming receiver buffering and lag tests.

use super::*;

fn receiver() -> RpcStreamingEventReceiver {
    let (_sender, frames) = mpsc::channel(1);
    RpcStreamingEventReceiver {
        frames,
        pending_events: VecDeque::new(),
        pending_state_updates: VecDeque::new(),
        skipped_events: 0,
        last_state_sequence: None,
    }
}

fn state_update(sequence: u64, state: LiveStateKind) -> StreamingStateUpdateFrame {
    StreamingStateUpdateFrame {
        sequence,
        update: StateUpdate {
            session: SessionRef::new(SessionId::new(1), 1, Seed::from_u64(1)),
            state,
        },
    }
}

fn event(sequence: u64) -> StreamingEventFrame {
    StreamingEventFrame {
        generation: 0,
        cursor: EventLogCursor::new(sequence),
        next_cursor: EventLogCursor::new(sequence + 1),
        event: OpenSetEventEnvelope {
            sequence,
            at: OpenSetEventTime {
                virtual_time_ticks: sequence,
                stamp_tick: sequence,
                stamp_retired: None,
                stamp_node: None,
            },
            source: OpenSetEventSource::Engine,
            level: EventLevel::Info,
            observational: false,
            payload: OpenSetPayload::new("crucible.event.evaluation_boundary", BTreeMap::new()),
        },
    }
}

#[test]
fn event_frame_preserves_exact_tick_and_optional_raw_witness() {
    let wire = b"crucible.rpc/event-frame\ngeneration=1\ncursor=7\nnext-cursor=8\nsequence=7\nvirtual-time-ticks=100\nstamp-tick=107\nstamp-retired=2\nstamp-node=6e6f64652d61\nsource=engine\nlevel=info\nobservational=false\nkind=crucible.event.evaluation_boundary\n";
    let frame = decode_streaming_event_frame(wire)
        .unwrap_or_else(|error| panic!("exact event frame should decode: {error}"));
    assert_eq!(frame.event.at.virtual_time_ticks, 100);
    assert_eq!(frame.event.at.stamp_tick, 107);
    assert_eq!(frame.event.at.stamp_retired, Some(2));
    assert_eq!(frame.event.at.stamp_node.as_deref(), Some("node-a"));

    let no_raw = String::from_utf8(wire.to_vec())
        .unwrap_or_else(|error| panic!("fixture must be UTF-8: {error}"))
        .replace("stamp-retired=2", "stamp-retired=none")
        .replace("stamp-node=6e6f64652d61", "stamp-node=none");
    let frame = decode_streaming_event_frame(no_raw.as_bytes())
        .unwrap_or_else(|error| panic!("event without raw witness should decode: {error}"));
    assert_eq!(frame.event.at.stamp_tick, 107);
    assert_eq!(frame.event.at.stamp_retired, None);
    assert_eq!(frame.event.at.stamp_node, None);

    let old_wire = no_raw.replace("stamp-tick=107", "icount-retired=2");
    assert!(decode_streaming_event_frame(old_wire.as_bytes()).is_err());
}

#[tokio::test]
async fn pending_state_updates_coalesce_to_the_latest_monotone_frame() {
    let mut receiver = receiver();
    for sequence in 1..=32 {
        receiver.push_pending_state_update(state_update(sequence, LiveStateKind::Running));
    }
    receiver.push_pending_state_update(state_update(31, LiveStateKind::Paused));
    receiver.push_pending_state_update(state_update(33, LiveStateKind::Stopped));

    assert_eq!(receiver.pending_state_updates.len(), 1);
    let update = receiver
        .recv_state_update()
        .await
        .unwrap_or_else(|error| panic!("latest state update should decode: {error}"))
        .unwrap_or_else(|| panic!("latest state update should remain buffered"));
    assert_eq!(update.sequence, 33);
    assert_eq!(update.update.state, LiveStateKind::Stopped);

    receiver.push_pending_state_update(state_update(32, LiveStateKind::Running));
    assert!(receiver.pending_state_updates.is_empty());
    assert!(
        receiver
            .recv_state_update()
            .await
            .unwrap_or_else(|error| panic!("closed state stream should remain valid: {error}"))
            .is_none()
    );
}

#[tokio::test]
async fn ready_rpc_frames_coalesce_before_state_delivery() {
    let (sender, frames) = mpsc::channel(64);
    let mut receiver = RpcStreamingEventReceiver {
        frames,
        pending_events: VecDeque::new(),
        pending_state_updates: VecDeque::new(),
        skipped_events: 0,
        last_state_sequence: None,
    };
    sender
        .send(Ok(RpcStreamingFrame::Event(event(0))))
        .await
        .unwrap_or_else(|error| panic!("event frame should enqueue: {error}"));
    for sequence in 1..=32 {
        sender
            .send(Ok(RpcStreamingFrame::StateUpdate(state_update(
                sequence,
                if sequence == 32 {
                    LiveStateKind::Stopped
                } else {
                    LiveStateKind::Running
                },
            ))))
            .await
            .unwrap_or_else(|error| panic!("state frame should enqueue: {error}"));
    }

    let update = receiver
        .recv_state_update()
        .await
        .unwrap_or_else(|error| panic!("ready state frames should decode: {error}"))
        .unwrap_or_else(|| panic!("latest ready state should be delivered"));
    assert_eq!(update.sequence, 32);
    assert_eq!(update.update.state, LiveStateKind::Stopped);
    assert_eq!(receiver.pending_events.len(), 1);
}

#[tokio::test]
async fn state_poll_preserves_a_full_scheduler_event_burst() {
    let (sender, frames) = mpsc::channel(64);
    let mut receiver = RpcStreamingEventReceiver {
        frames,
        pending_events: VecDeque::new(),
        pending_state_updates: VecDeque::new(),
        skipped_events: 0,
        last_state_sequence: None,
    };
    for sequence in 0..32 {
        sender
            .send(Ok(RpcStreamingFrame::Event(event(sequence))))
            .await
            .unwrap_or_else(|error| panic!("event frame should enqueue: {error}"));
    }
    sender
        .send(Ok(RpcStreamingFrame::StateUpdate(state_update(
            33,
            LiveStateKind::Stopped,
        ))))
        .await
        .unwrap_or_else(|error| panic!("state frame should enqueue: {error}"));

    let update = receiver
        .recv_state_update()
        .await
        .unwrap_or_else(|error| panic!("state update should decode: {error}"))
        .unwrap_or_else(|| panic!("state update should remain available"));
    assert_eq!(update.sequence, 33);
    for sequence in 0..32 {
        let observed = receiver
            .recv_event()
            .await
            .unwrap_or_else(|error| panic!("event burst must not lag: {error}"))
            .unwrap_or_else(|| panic!("event {sequence} should remain buffered"));
        assert_eq!(observed.event.sequence, sequence);
    }
}

#[tokio::test]
async fn pending_event_overflow_remains_fail_closed() {
    let mut receiver = receiver();
    for sequence in 0..=RPC_STREAM_PENDING_FRAME_CAPACITY as u64 {
        receiver.push_pending_event(event(sequence));
    }

    let error = match receiver.recv_event().await {
        Ok(_) => panic!("dropped canonical events must report lag"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ControlClientError::Streaming {
            source: StreamingApiError::EventStreamLagged { skipped: 1 }
        }
    ));
}
