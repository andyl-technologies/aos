//! Shares the actual pidfd/stat/task-context subject engine between fixed roles.
//!
//! Each named recipe owns native observations only. The real role keeps the
//! raw received chunk, initial anchor, financial scope and independent outer
//! posts. Task labels remain separate from the listener creator/socket SID.

use std::error::Error;
use aos_sandbox_linux::pidfd::{PidFdContextReadbackV1, PidFdIdentityReadbackV1,
    PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;

/// Classifies a failed native task comparison without granting a role.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum FixedTaskSubjectClosedV1 {
    /// The actual one-shot observation was already entered.
    #[error("fixed task subject observation is out of order")]
    Order,
    /// The original native owner retains an earlier refusal.
    #[error("fixed task subject observation retains an earlier refusal")]
    Retained,
    /// The actual task or anchor differs from the fixed comparison contract.
    #[error("fixed task subject differs from its comparison contract")]
    Subject,
}

/// Retains one actual task subject and all independently owed native posts.
pub struct FixedTaskSubjectOriginalsV1<E> {
    info: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    identity: PidFdIdentityReadbackV1,
    identity_result: Option<Result<(), aos_sandbox_linux::Error>>,
    context: PidFdContextReadbackV1,
    context_result: Option<Result<(), aos_sandbox_linux::Error>>,
    comparison: Option<Result<(), E>>,
    after: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    alive: Option<Result<bool, aos_sandbox_linux::Error>>,
    completion: Option<Result<(), E>>,
}

impl<E: Copy + Error + From<FixedTaskSubjectClosedV1> + 'static> FixedTaskSubjectOriginalsV1<E> {
    /// Creates empty native destinations without a role, key or financial scope.
    pub fn new() -> Self {
        Self {
            info: None,
            identity: PidFdIdentityReadbackV1::new(),
            identity_result: None,
            context: PidFdContextReadbackV1::new(),
            context_result: None,
            comparison: None,
            after: None,
            alive: None,
            completion: None,
        }
    }

    /// Captures the actual Cache reply sender through the fixed task contract.
    ///
    /// # Errors
    /// Retains original native errors, changed anchor, credentials or context.
    pub fn observe_cache_reply_once(&mut self, chunk: &UnixStreamSubjectChunk,
        anchor: Option<(&UnixStreamSubjectChunk, PidFdProcessIdentity)>, uid: u32, gid: u32,
    ) -> Result<(), E> {
        self.observe_recipe_once(chunk, anchor, uid, gid,
            crate::cache_signer_context::CACHE_SIGNER_TASK_CONTEXT_V1, None)
    }

    /// Captures the actual Root request sender under the fixed non-MLS context.
    ///
    /// # Errors
    /// Refuses changed native identity/anchor, non-root users, configured group,
    /// parent, task context or independently owed liveness/GET_INFO posts.
    pub fn observe_root_request_once(&mut self, chunk: &UnixStreamSubjectChunk,
        anchor: Option<(&UnixStreamSubjectChunk, PidFdProcessIdentity)>, gid: u32,
    ) -> Result<(), E> {
        self.observe_recipe_once(chunk, anchor, 0, gid,
            crate::profile_data::schema::CONTEXT.as_bytes(), Some(1))
    }

    /// Captures the actual Controller request sender under its fixed context.
    ///
    /// # Errors
    /// Refuses changed native identity/anchor, configured credentials, parent,
    /// task context or independently owed liveness/GET_INFO posts.
    pub fn observe_controller_request_once(&mut self, chunk: &UnixStreamSubjectChunk,
        anchor: Option<(&UnixStreamSubjectChunk, PidFdProcessIdentity)>, uid: u32, gid: u32,
    ) -> Result<(), E> {
        self.observe_recipe_once(chunk, anchor, uid, gid,
            crate::profile_data::delivery::CONTEXT.as_bytes(), Some(1))
    }

    /// Returns concrete native sample bytes and retained stat/context files.
    ///
    /// The actual received subject pidfd belongs to the separately owned raw
    /// chunk. This sampler creates no namespace entry or financial permission.
    pub fn receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let (identity, identity_files, _) = PidFdIdentityReadbackV1::receiving_demand_v1()?;
        let (context, context_files, _) = PidFdContextReadbackV1::receiving_demand_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(identity)?.checked_add(context)?.checked_add(256)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(identity_files.checked_add(context_files)?).ok()?))
    }

    fn observe_recipe_once(
        &mut self,
        chunk: &UnixStreamSubjectChunk,
        anchor: Option<(&UnixStreamSubjectChunk, PidFdProcessIdentity)>,
        uid: u32,
        gid: u32,
        expected_context: &'static [u8],
        parent: Option<u32>,
    ) -> Result<(), E> {
        if self.info.is_some() {
            return Err(FixedTaskSubjectClosedV1::Order.into());
        }
        let subject = chunk.subject();
        self.info = Some(subject.pidfd().info());
        if matches!(self.info, Some(Ok(_))) {
            self.identity_result = Some(self.identity.capture_once(subject.pidfd()));
        }
        if matches!(self.identity_result, Some(Ok(()))) {
            self.context_result = Some(self.context.capture_once(subject.pidfd()));
        }
        self.comparison = Some((|| -> Result<(), FixedTaskSubjectClosedV1> {
            let info = self.info.as_ref().and_then(|result| result.as_ref().ok()).ok_or(FixedTaskSubjectClosedV1::Retained)?;
            let actual = subject.credentials();
            let credentials = info.credentials().ok_or(FixedTaskSubjectClosedV1::Subject)?;
            let context = self.context.bytes().ok_or(FixedTaskSubjectClosedV1::Retained)?;
            let identity = self.identity.identity().ok_or(FixedTaskSubjectClosedV1::Retained)?;
            if info != &subject.initial_info()
                || info.pid() != actual.pid().get()
                || actual.uid() != uid || actual.gid() != gid
                || credentials.real_user_id() != uid || credentials.effective_user_id() != uid
                || credentials.saved_user_id() != uid || credentials.filesystem_user_id() != uid
                || credentials.real_group_id() != gid || credentials.effective_group_id() != gid
                || credentials.saved_group_id() != gid || credentials.filesystem_group_id() != gid
                || !crate::cache_signer_context::exact_task_context_matches_v1(context, expected_context, true)
            {
                return Err(FixedTaskSubjectClosedV1::Subject);
            }
            if parent.is_some_and(|parent| info.parent_pid() != parent
                || info.thread_group_id() != actual.pid().get())
            {
                return Err(FixedTaskSubjectClosedV1::Subject);
            }
            if let Some((anchor, anchor_identity)) = anchor {
                if identity != anchor_identity
                    || subject.credentials() != anchor.subject().credentials()
                    || info != &anchor.subject().initial_info()
                    || chunk.socket_context() != anchor.socket_context()
                {
                    return Err(FixedTaskSubjectClosedV1::Subject);
                }
            }
            Ok(())
        })().map_err(E::from));

        // These actual native posts remain owed even if a preceding capture
        // or comparison failed. They never create a new healthy role phase.
        self.after = Some(subject.pidfd().info());
        self.alive = Some(subject.is_alive());
        self.completion = Some((|| -> Result<(), FixedTaskSubjectClosedV1> {
            if self.failure().is_some() { return Err(FixedTaskSubjectClosedV1::Retained); }
            if self.info.as_ref().and_then(|result| result.as_ref().ok())
                != self.after.as_ref().and_then(|result| result.as_ref().ok())
                || !matches!(self.alive, Some(Ok(true)))
            {
                return Err(FixedTaskSubjectClosedV1::Subject);
            }
            Ok(())
        })().map_err(E::from));
        if matches!(self.completion, Some(Ok(()))) { Ok(()) } else { Err(FixedTaskSubjectClosedV1::Retained.into()) }
    }

    /// Borrows complete observed identity DATA without granting a task role.
    pub fn identity(&self) -> Option<PidFdProcessIdentity> {
        if matches!(self.completion, Some(Ok(()))) { self.identity.identity() } else { None }
    }

    /// Borrows the earliest native cause before its fixed classification.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.info)
            .or_else(|| self.identity.failure())
            .or_else(|| cause(&self.identity_result))
            .or_else(|| self.context.failure())
            .or_else(|| cause(&self.context_result))
            .or_else(|| cause(&self.comparison))
            .or_else(|| cause(&self.after))
            .or_else(|| cause(&self.alive))
            .or_else(|| cause(&self.completion))
    }
}

impl<E: Copy + Error + From<FixedTaskSubjectClosedV1> + 'static> Default
    for FixedTaskSubjectOriginalsV1<E>
{
    fn default() -> Self { Self::new() }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
