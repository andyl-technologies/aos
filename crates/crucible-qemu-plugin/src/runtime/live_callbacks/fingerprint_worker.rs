//! Ordered asynchronous publication of detached fingerprint captures.

use std::thread::{self, JoinHandle};

use super::*;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_FINGERPRINT};

/// One detached fingerprint capture queued for ordered digest publication.
enum LiveFingerprintDigestWork {
    /// Publishes asynchronously for an ordinary scheduler quantum.
    Publish(CapturedFingerprintSample),
    /// Publishes before acknowledging an exact stopped control boundary.
    PublishAndAcknowledge {
        captured: CapturedFingerprintSample,
        // crucible-lint: allow stringly-error -- the private worker channel transports a diagnostic that is immediately wrapped in the typed callback error.
        completion: mpsc::SyncSender<Result<(), String>>,
    },
}

/// Bounded owner thread that digests detached captures and publishes samples.
pub(super) struct LiveFingerprintDigestWorker {
    sender: Option<mpsc::SyncSender<LiveFingerprintDigestWork>>,
    failed: Arc<Mutex<Option<String>>>,
    join: Option<JoinHandle<()>>,
}

impl LiveFingerprintDigestWorker {
    pub(super) fn spawn(
        slot: StableFingerprintSlotHandle,
        quiescence: Arc<LiveWorkerQuiescence>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        let (sender, receiver) = mpsc::sync_channel::<LiveFingerprintDigestWork>(1);
        let failed = Arc::new(Mutex::new(None));
        let worker_failed = Arc::clone(&failed);
        let join = thread::Builder::new()
            .name("crucible-fingerprint-digest".to_owned())
            .spawn(move || {
                loop {
                    let idle = quiescence.idle(WORKER_FINGERPRINT);
                    let Ok(work) = receiver.recv() else {
                        break;
                    };
                    let pending = idle.received();
                    let _operation = pending.enter();
                    let (captured, completion) = match work {
                        LiveFingerprintDigestWork::Publish(captured) => (captured, None),
                        LiveFingerprintDigestWork::PublishAndAcknowledge {
                            captured,
                            completion,
                        } => (captured, Some(completion)),
                    };
                    let sample = captured.digest();
                    let result = slot
                        .get()
                        .publish(&sample)
                        .map_err(|error| error.to_string());
                    if let Some(completion) = completion {
                        let _completion_result = completion.send(result.clone());
                    }
                    if let Err(message) = result {
                        let mut failure = match worker_failed.lock() {
                            Ok(failure) => failure,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        *failure = Some(message);
                        break;
                    }
                }
            })
            .map_err(|error| LiveVcpuTimeCallbackError::FingerprintWorkerSpawn {
                message: error.to_string(),
            })?;
        Ok(Self {
            sender: Some(sender),
            failed,
            join: Some(join),
        })
    }

    pub(super) fn submit(
        &self,
        captured: CapturedFingerprintSample,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let failure = match self.failed.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(message) = failure.as_ref() {
            return Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed {
                message: message.clone(),
            });
        }
        drop(failure);
        let sender = self
            .sender
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        // This callback runs only at a scheduler boundary where guest time is
        // already fenced. Backpressure preserves every exact sample without
        // making host digest speed part of simulated execution.
        sender
            .send(LiveFingerprintDigestWork::Publish(captured))
            .map_err(|_error| LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)
    }

    pub(super) fn submit_and_wait(
        &self,
        captured: CapturedFingerprintSample,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let failure = match self.failed.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(message) = failure.as_ref() {
            return Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed {
                message: message.clone(),
            });
        }
        drop(failure);

        let (completion, completed) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?
            .send(LiveFingerprintDigestWork::PublishAndAcknowledge {
                captured,
                completion,
            })
            .map_err(|_error| LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?;
        completed
            .recv()
            .map_err(|_error| LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?
            .map_err(|message| LiveVcpuTimeCallbackError::FingerprintWorkerFailed { message })
    }
}

impl Drop for LiveFingerprintDigestWorker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(join) = self.join.take() {
            let _worker_result = join.join();
        }
    }
}
