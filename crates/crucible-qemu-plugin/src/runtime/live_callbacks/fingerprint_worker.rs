//! Ordered publication of detached fingerprint captures.

use std::thread::{self, JoinHandle};

use super::*;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_FINGERPRINT};

/// One requested capture queued before its control-boundary acknowledgement.
struct LiveFingerprintDigestWork {
    captured: CapturedFingerprintSample,
    capture_request: u32,
}

/// Typed diagnostic retained when publication fails in the digest worker.
#[derive(Clone)]
struct FingerprintPublicationFailure {
    message: String,
}

/// Bounded owner thread that digests detached captures and publishes samples.
pub(super) struct LiveFingerprintDigestWorker {
    sender: Option<mpsc::SyncSender<LiveFingerprintDigestWork>>,
    failed: Arc<Mutex<Option<FingerprintPublicationFailure>>>,
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
                    let sample = work.captured.digest();
                    let result = slot
                        .get()
                        .publish(&sample)
                        .map_err(|error| FingerprintPublicationFailure {
                            message: error.to_string(),
                        })
                        .and_then(|()| {
                            slot.get()
                                .acknowledge_capture_v1(work.capture_request)
                                .then_some(())
                                .ok_or_else(|| FingerprintPublicationFailure {
                                    message: format!(
                                        "fingerprint capture request {} changed before publication",
                                        work.capture_request
                                    ),
                                })
                        });
                    if let Err(publication_failure) = result {
                        let mut failure = match worker_failed.lock() {
                            Ok(failure) => failure,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        *failure = Some(publication_failure);
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
        capture_request: u32,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let failure = match self.failed.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(publication_failure) = failure.as_ref() {
            return Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed {
                message: publication_failure.message.clone(),
            });
        }
        drop(failure);

        self.sender
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)?
            .send(LiveFingerprintDigestWork {
                captured,
                capture_request,
            })
            .map_err(|_error| LiveVcpuTimeCallbackError::FingerprintWorkerUnavailable)
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
