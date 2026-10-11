//! Exact Abort records, terminal history and owned local task cancellation.
//!
//! The resume store adds these bounded closed records:
//! ```text
//! <scope>:<run>:abort   => AbortRecord
//! <scope>:<run>:retired => original terminal ResumeHead
//! ```
//! Logical retirement does not establish provider drain or erase grant history.

use std::future::Future;

use aos_proto_types::direct_upload::*;
use futures::{
    channel::oneshot,
    future::{AbortRegistration, Abortable, Aborted},
};
use serde::{Deserialize, Serialize};

use crate::direct_upload_model::{operation_id, CheckpointRecord, ResumeHead};

/// Original Abort control, retained before its first dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AbortRecord {
    /// Exact retained run, source and authenticated owner.
    original: ResumeHead,
    /// Exact batch/item identities and resource-version CAS.
    pub request: DirectBatch<DirectAbortRequest>,
}

impl CheckpointRecord for AbortRecord {
    fn merge(self, previous: Option<Self>) -> Result<Self, String> {
        if previous.as_ref().is_some_and(|old| old != &self) {
            return Err("The saved stop request changed; original progress was preserved".into());
        }

        Ok(self)
    }
}

impl AbortRecord {
    /// Constructs one Abort from the current exact authenticated session.
    ///
    /// # Errors
    /// Refuses unknown admission, pending completion or an already stopping run.
    pub(crate) fn new(head: &ResumeHead) -> Result<Self, String> {
        if !valid_direct_digest(&head.scope) || !valid_direct_digest(&head.run_nonce) {
            return Err("The saved original upload identity is invalid".into());
        }

        let status = head.session.as_ref().ok_or_else(|| {
            "Admission is unresolved. Choose the original file to resume before stopping it"
                .to_string()
        })?;
        validate_status(head, status)?;
        if head.complete.is_some()
            || !matches!(
                status.state,
                DirectSessionState::Creating | DirectSessionState::Active
            )
        {
            return Err("This original upload cannot accept a new stop request".into());
        }

        let item = DirectAbortRequest {
            session: status.session.clone(),
            operation_id: operation_id(
                "abort",
                &head.run_nonce,
                &(status.session.clone(), status.resource_version),
            )?,
            expected_resource_version: status.resource_version,
        };
        let request = DirectBatch {
            operation_id: operation_id("abort-batch", &head.run_nonce, &item)?,
            items: vec![item],
        };
        DirectUploadRequest::Abort(request.clone())
            .validate()
            .map_err(|_| "The saved stop request is invalid".to_string())?;

        Ok(Self {
            original: head.clone(),
            request,
        })
    }

    /// Checks a retained request against the same original before exact replay.
    ///
    /// # Errors
    /// Refuses another actor, source, run, session or substituted request.
    pub(crate) fn validate_for(&self, head: &ResumeHead) -> Result<(), String> {
        let rebuilt = Self::new(&self.original)?;
        let status = head
            .session
            .as_ref()
            .ok_or_else(|| "Original admission is unresolved".to_string())?;
        validate_status(&self.original, status)?;
        if self != &rebuilt
            || self.original.scope != head.scope
            || self.original.run_nonce != head.run_nonce
            || self.original.deployment_id != head.deployment_id
            || self.original.principal_id != head.principal_id
            || self.original.intent != head.intent
            || self.original.complete != head.complete
            || self.original.session.as_ref().map(|old| &old.placements) != Some(&status.placements)
        {
            return Err("The original stop request no longer matches this upload".into());
        }

        Ok(())
    }
}

/// Validates exact, monotonic original Status without deriving provider settlement.
///
/// # Errors
/// Refuses wrong original, stale revision or changed terminal logical state.
pub(crate) fn validate_status(head: &ResumeHead, next: &DirectSessionStatus) -> Result<(), String> {
    let old = head
        .session
        .as_ref()
        .ok_or_else(|| "Original admission is unresolved".to_string())?;
    next.validate_for(&old.session, &head.intent, &old.placements)
        .map_err(|_| "The original upload changed during readback".to_string())?;
    if next.resource_version.get() < old.resource_version.get()
        || (matches!(
            old.state,
            DirectSessionState::Committed | DirectSessionState::Aborted
        ) && next.state != old.state)
    {
        return Err("The upload readback is stale; original progress was preserved".into());
    }

    Ok(())
}

/// Checks both transaction reads before archiving and clearing an exact pointer.
///
/// # Errors
/// Refuses unresolved effects, another active run or contradictory old history.
pub(crate) fn retirement_ready(
    expected: &ResumeHead,
    active: Option<&ResumeHead>,
    archived: Option<&ResumeHead>,
) -> Result<bool, String> {
    if !valid_direct_digest(&expected.scope) || !valid_direct_digest(&expected.run_nonce) {
        return Err("The saved original upload identity is invalid".into());
    }
    let status = expected
        .session
        .as_ref()
        .ok_or_else(|| "Original admission is unresolved".to_string())?;
    validate_status(expected, status)?;
    if !matches!(
        status.state,
        DirectSessionState::Committed | DirectSessionState::Aborted
    ) || active.is_some_and(|value| value != expected)
        || archived.is_some_and(|value| value != expected)
        || (active.is_none() && archived.is_none())
    {
        return Err("The original upload is unresolved or another run owns this path".into());
    }

    Ok(active.is_some())
}

/// Drops the owned transfer before acknowledging local cancellation or completion.
///
/// The acknowledgement covers this future only, not other tabs or remote work.
///
/// # Errors
/// Returns `Aborted` when local cancellation was requested. A missing handshake
/// means local stop is unconfirmed and must not authorize an Abort control.
pub(crate) async fn run_owned<F: Future>(
    work: F,
    cancellation: AbortRegistration,
    stopped: oneshot::Sender<()>,
) -> Result<F::Output, Aborted> {
    let mut owned = Box::pin(Abortable::new(work, cancellation));
    let result = owned.as_mut().await;
    drop(owned);
    let _ = stopped.send(());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, future::AbortHandle};
    use std::{
        cell::Cell,
        rc::Rc,
        task::{Context, Poll},
    };

    fn head() -> ResumeHead {
        let intent = DirectUploadIntent {
            version: 1,
            client_operation_id: "11".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache".into(),
                path: "nar/original.nar".into(),
            },
            expected_sha256: "22".repeat(32),
            byte_size: WireInteger::new(9),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        };
        let placement = DirectPlacementRef {
            placement_id: WireInteger::new(1),
            placement_fingerprint: "aa".repeat(32),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            profile_fingerprint: "bb".repeat(32),
            private_policy_digest: "cc".repeat(32),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
        };
        let status = DirectSessionStatus {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "33".repeat(32),
            },
            resource_version: WireInteger::new(1),
            intent: intent.clone(),
            placements: vec![placement],
            state: DirectSessionState::Active,
            parts: vec![],
            next_cursor: None,
            outstanding_grants: true,
        };
        ResumeHead {
            scope: "44".repeat(32),
            run_nonce: "55".repeat(32),
            deployment_id: "deployment".into(),
            principal_id: "66".repeat(32),
            intent,
            session: Some(status),
            complete: None,
        }
    }

    #[test]
    fn lost_ack_replays_the_exact_abort_and_refuses_substituted_controls() {
        let head = head();
        let original = AbortRecord::new(&head).unwrap().merge(None).unwrap();

        let bytes = encode_direct_control(&original.request).unwrap();
        let replay = original.clone().merge(Some(original.clone())).unwrap();
        assert_eq!(encode_direct_control(&replay.request).unwrap(), bytes);

        let mut changed = original.clone();
        changed.request.items[0].expected_resource_version = WireInteger::new(2);
        assert!(changed.clone().merge(Some(original.clone())).is_err());
        assert!(changed.validate_for(&head).is_err());

        let mut foreign = head.clone();
        foreign.principal_id = "77".repeat(32);
        assert!(original.validate_for(&foreign).is_err());
        let mut stale = head.clone();
        stale.session.as_mut().unwrap().resource_version = WireInteger::new(0);
        assert!(original.validate_for(&stale).is_err());

        let mut later = head.clone();
        later.session.as_mut().unwrap().state = DirectSessionState::Aborting;
        later.session.as_mut().unwrap().resource_version = WireInteger::new(2);
        original.validate_for(&later).unwrap();
        assert_eq!(encode_direct_control(&original.request).unwrap(), bytes);
    }

    #[test]
    fn unknown_and_local_cancellation_cannot_retire_or_create_another_run() {
        let original = head();
        for state in [
            DirectSessionState::Active,
            DirectSessionState::Aborting,
            DirectSessionState::BlockedUnknown,
        ] {
            let mut pending = original.clone();
            pending.session.as_mut().unwrap().state = state;
            assert!(retirement_ready(&pending, Some(&pending), None).is_err());
        }

        let mut unknown = original.clone();
        unknown.session = None;
        assert!(AbortRecord::new(&unknown).is_err());
        assert!(retirement_ready(&unknown, Some(&unknown), None).is_err());
        assert!(retirement_ready(&original, None, None).is_err());
    }

    #[test]
    fn terminal_retirement_keeps_exact_history_and_refuses_pointer_races() {
        // Outstanding grants deliberately remain true: this is not resource drain.
        for state in [DirectSessionState::Aborted, DirectSessionState::Committed] {
            let mut terminal = head();
            terminal.session.as_mut().unwrap().state = state;
            assert!(retirement_ready(&terminal, Some(&terminal), None).unwrap());
            assert!(!retirement_ready(&terminal, None, Some(&terminal)).unwrap());
        }

        let mut ended = head();
        ended.session.as_mut().unwrap().state = DirectSessionState::Aborted;
        let mut newer = ended.clone();
        newer.run_nonce = "77".repeat(32);
        assert!(retirement_ready(&ended, Some(&newer), None).is_err());
        let mut changed = ended.clone();
        changed.intent.expected_sha256 = "88".repeat(32);
        assert!(retirement_ready(&ended, Some(&ended), Some(&changed)).is_err());

        let old_id = operation_id("begin", &ended.run_nonce, &ended.intent).unwrap();
        assert_ne!(
            old_id,
            operation_id("begin", &newer.run_nonce, &newer.intent).unwrap()
        );
    }

    #[test]
    fn stale_foreign_status_and_terminal_regression_are_refused() {
        let original = head();
        let mut next = original.session.clone().unwrap();
        next.intent.expected_sha256 = "88".repeat(32);
        assert!(validate_status(&original, &next).is_err());

        next = original.session.clone().unwrap();
        next.resource_version = WireInteger::new(0);
        assert!(validate_status(&original, &next).is_err());

        let mut ended = original.clone();
        ended.session.as_mut().unwrap().state = DirectSessionState::Aborted;
        assert!(validate_status(&ended, original.session.as_ref().unwrap()).is_err());
        assert_eq!(
            original.clone().merge(Some(ended.clone())).unwrap().session,
            ended.session
        );
    }

    #[test]
    fn cancellation_acknowledgment_follows_drop_and_permit_release() {
        struct DropMarker(Rc<Cell<bool>>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let released = Rc::new(Cell::new(false));
        let marker = released.clone();
        let (cancel, registration) = AbortHandle::new_pair();
        let (stopped, mut acknowledged) = oneshot::channel();
        let mut task = Box::pin(run_owned(
            async move {
                let _permit = crate::direct_upload_pool::acquire().await;
                let _request = DropMarker(marker);
                std::future::pending::<()>().await;
            },
            registration,
            stopped,
        ));
        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(task.as_mut().poll(&mut context), Poll::Pending));
        assert!(acknowledged.try_recv().unwrap().is_none());

        cancel.abort();
        assert!(block_on(task).is_err());
        assert!(released.get());
        assert_eq!(acknowledged.try_recv().unwrap(), Some(()));

        let held: Vec<_> = (0..32)
            .map(|_| block_on(crate::direct_upload_pool::acquire()))
            .collect();
        let dispatched = Rc::new(Cell::new(false));
        let attempted = dispatched.clone();
        let (cancel, registration) = AbortHandle::new_pair();
        let (stopped, acknowledged) = oneshot::channel();
        let mut queued = Box::pin(run_owned(
            async move {
                let _permit = crate::direct_upload_pool::acquire().await;
                attempted.set(true);
            },
            registration,
            stopped,
        ));

        assert!(matches!(queued.as_mut().poll(&mut context), Poll::Pending));
        cancel.abort();
        assert!(block_on(queued).is_err());
        assert!(block_on(acknowledged).is_ok());
        assert!(!dispatched.get());
        drop(held);
        drop(block_on(crate::direct_upload_pool::acquire()));
    }

    #[test]
    fn lost_local_task_ownership_does_not_acknowledge_a_stop() {
        let (_cancel, registration) = AbortHandle::new_pair();
        let (stopped, acknowledged) = oneshot::channel();
        let task = run_owned(std::future::pending::<()>(), registration, stopped);
        drop(task);
        assert!(block_on(acknowledged).is_err());

        let (stopped, acknowledged) = oneshot::channel();
        let (_, registration) = AbortHandle::new_pair();
        assert!(block_on(run_owned(
            async { Err::<(), _>("unknown provider reply") },
            registration,
            stopped
        ))
        .unwrap()
        .is_err());
        assert!(block_on(acknowledged).is_ok());
    }
}
