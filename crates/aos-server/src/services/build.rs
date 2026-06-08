//! ConnectRPC implementation of `BuildService`.

use std::pin::Pin;
use std::sync::Arc;

use connectrpc::{ConnectError, Context, ErrorCode};
use futures_util::Stream;
use tokio_stream::StreamExt;

use aos_proto::aos::build::v1::*;

use crate::build::{BuildEvent as InternalBuildEvent, BuildEventKind};
use crate::routes::AppState;

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;

/// ConnectRPC build service backed by the shared `AppState`.
pub struct BuildServiceImpl {
    pub state: Arc<AppState>,
}

impl BuildService for BuildServiceImpl {
    async fn build(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<BuildRequestView<'static>>,
    ) -> Result<(ResponseStream<BuildEvent>, Context), ConnectError> {
        let view: &str = req.view;
        let drv_path: String = req.derivation.to_string();

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

        // Reject builds during drain.
        if self.state.drain.is_draining() {
            return Err(ConnectError::new(
                ErrorCode::Unavailable,
                "server is shutting down",
            ));
        }

        // Verify the .drv exists in the store.
        match self.state.store.is_valid_path(&drv_path) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ConnectError::new(
                    ErrorCode::InvalidArgument,
                    format!("derivation not found: {drv_path}"),
                ));
            }
            Err(e) => {
                return Err(ConnectError::new(
                    ErrorCode::Internal,
                    format!("store query: {e}"),
                ));
            }
        }

        // Get or start the build (deduplication).
        let handle = self
            .state
            .build_mgr
            .get_or_start(&self.state, view, &drv_path);

        // Replay all buffered events, then stream live ones.
        let replay_events = handle.log_buffer.events_from(0);
        let rx = handle.tx.subscribe();

        let highest_replayed = handle.log_buffer.all_events().last().map(|e| e.id);

        let replay_stream = tokio_stream::iter(
            replay_events
                .into_iter()
                .map(|e| Ok(internal_to_proto(&e, ""))),
        );

        let live_stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(
            move |result| match result {
                Ok(event) => {
                    if let Some(max_id) = highest_replayed {
                        if event.id <= max_id {
                            return None;
                        }
                    }
                    Some(Ok(internal_to_proto(&event, "")))
                }
                Err(_) => None, // lagged
            },
        );

        let combined = replay_stream.chain(live_stream);

        Ok((Box::pin(combined), ctx))
    }

    async fn build_closure(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<ClosureRequestView<'static>>,
    ) -> Result<(ResponseStream<BuildEvent>, Context), ConnectError> {
        let view: &str = req.view;
        let drvs: Vec<String> = req.derivations.iter().map(|s| s.to_string()).collect();

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

        if self.state.drain.is_draining() {
            return Err(ConnectError::new(
                ErrorCode::Unavailable,
                "server is shutting down",
            ));
        }

        if drvs.is_empty() {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "derivations list is empty",
            ));
        }

        // Verify all drvs exist.
        for drv_path in &drvs {
            match self.state.store.is_valid_path(drv_path) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ConnectError::new(
                        ErrorCode::InvalidArgument,
                        format!("derivation not found: {drv_path}"),
                    ));
                }
                Err(e) => {
                    return Err(ConnectError::new(
                        ErrorCode::Internal,
                        format!("store query: {e}"),
                    ));
                }
            }
        }

        // Start all builds and collect handles.
        let handles: Vec<_> = drvs
            .iter()
            .map(|drv| {
                let handle = self.state.build_mgr.get_or_start(&self.state, view, drv);
                (drv.clone(), handle)
            })
            .collect();

        // Create a merged channel that tags events with their drv.
        let (merged_tx, merged_rx) = tokio::sync::mpsc::channel::<BuildEvent>(4096);

        for (drv, handle) in handles {
            let tx = merged_tx.clone();

            tokio::spawn(async move {
                // Replay buffered events.
                for event in handle.log_buffer.events_from(0) {
                    let proto_event = internal_to_proto(&event, &drv);
                    if tx.send(proto_event).await.is_err() {
                        return;
                    }
                }

                // Stream live events.
                let mut rx = handle.tx.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            let proto_event = internal_to_proto(&event, &drv);
                            if tx.send(proto_event).await.is_err() {
                                return;
                            }
                            if matches!(
                                event.kind,
                                BuildEventKind::Complete { .. } | BuildEventKind::Error { .. }
                            ) {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
        drop(merged_tx);

        let stream = tokio_stream::wrappers::ReceiverStream::new(merged_rx).map(Ok);

        Ok((Box::pin(stream), ctx))
    }
}

/// Convert an internal `BuildEvent` to the proto `BuildEvent` message.
fn internal_to_proto(event: &InternalBuildEvent, drv_override: &str) -> BuildEvent {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    match &event.kind {
        BuildEventKind::Status { phase, drv } => BuildEvent {
            event_type: "status".into(),
            phase: phase.clone(),
            derivation: if drv_override.is_empty() {
                drv.clone()
            } else {
                drv_override.into()
            },
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
        BuildEventKind::Log { line } => BuildEvent {
            event_type: "log".into(),
            message: line.clone(),
            derivation: drv_override.into(),
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
        BuildEventKind::Complete {
            success,
            outputs,
            duration_secs,
        } => BuildEvent {
            event_type: "complete".into(),
            success: *success,
            outputs: outputs.clone(),
            duration_secs: *duration_secs,
            derivation: drv_override.into(),
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
        BuildEventKind::Error {
            drv,
            exit_code,
            log_tail,
        } => BuildEvent {
            event_type: "error".into(),
            derivation: if drv_override.is_empty() {
                drv.clone()
            } else {
                drv_override.into()
            },
            exit_code: *exit_code,
            log_tail: log_tail.clone(),
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
        BuildEventKind::DaemonUnavailable {
            attempt,
            max_attempts,
            message,
        } => BuildEvent {
            event_type: "daemon-unavailable".into(),
            message: message.clone(),
            attempt: *attempt,
            max_attempts: *max_attempts,
            derivation: drv_override.into(),
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
        BuildEventKind::Drain { message } => BuildEvent {
            event_type: "drain".into(),
            message: message.clone(),
            derivation: drv_override.into(),
            timestamp,
            event_id: event.id,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_for(kind: BuildEventKind) -> BuildEvent {
        internal_to_proto(&InternalBuildEvent { id: 7, kind }, "")
    }

    #[test]
    fn internal_build_events_map_every_activity_type_to_proto() {
        let status = proto_for(BuildEventKind::Status {
            phase: "queued".into(),
            drv: "/nix/store/example.drv".into(),
        });
        assert_eq!(status.event_type, "status");
        assert_eq!(status.phase, "queued");
        assert_eq!(status.derivation, "/nix/store/example.drv");
        assert_eq!(status.event_id, 7);

        let log = proto_for(BuildEventKind::Log {
            line: "building".into(),
        });
        assert_eq!(log.event_type, "log");
        assert_eq!(log.message, "building");

        let complete = proto_for(BuildEventKind::Complete {
            success: true,
            outputs: vec!["/nix/store/out".into()],
            duration_secs: 3,
        });
        assert_eq!(complete.event_type, "complete");
        assert!(complete.success);
        assert_eq!(complete.outputs, vec!["/nix/store/out"]);
        assert_eq!(complete.duration_secs, 3);

        let error = proto_for(BuildEventKind::Error {
            drv: "/nix/store/bad.drv".into(),
            exit_code: Some(42),
            log_tail: "failed".into(),
        });
        assert_eq!(error.event_type, "error");
        assert_eq!(error.derivation, "/nix/store/bad.drv");
        assert_eq!(error.exit_code, Some(42));
        assert_eq!(error.log_tail, "failed");

        let daemon = proto_for(BuildEventKind::DaemonUnavailable {
            attempt: 2,
            max_attempts: 3,
            message: "daemon unavailable".into(),
        });
        assert_eq!(daemon.event_type, "daemon-unavailable");
        assert_eq!(daemon.attempt, 2);
        assert_eq!(daemon.max_attempts, 3);
        assert_eq!(daemon.message, "daemon unavailable");

        let drain = proto_for(BuildEventKind::Drain {
            message: "server shutting down".into(),
        });
        assert_eq!(drain.event_type, "drain");
        assert_eq!(drain.message, "server shutting down");
    }

    #[test]
    fn closure_stream_derivation_override_applies_to_events_with_derivations() {
        let status = internal_to_proto(
            &InternalBuildEvent {
                id: 1,
                kind: BuildEventKind::Status {
                    phase: "building".into(),
                    drv: "/nix/store/original.drv".into(),
                },
            },
            "/nix/store/closure-member.drv",
        );
        assert_eq!(status.event_type, "status");
        assert_eq!(status.derivation, "/nix/store/closure-member.drv");

        let error = internal_to_proto(
            &InternalBuildEvent {
                id: 2,
                kind: BuildEventKind::Error {
                    drv: "/nix/store/original.drv".into(),
                    exit_code: None,
                    log_tail: "querying outputs failed".into(),
                },
            },
            "/nix/store/closure-member.drv",
        );
        assert_eq!(error.event_type, "error");
        assert_eq!(error.derivation, "/nix/store/closure-member.drv");
    }
}
