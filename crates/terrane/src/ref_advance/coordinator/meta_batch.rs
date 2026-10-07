//! Uses a concrete held native store while preserving generic sequential dispatch.
//!
//! This internal specialization adds no Store trait entry or publication algorithm.
//! The same stage-start/stage-finish methods retain current policy, Original,
//! source, log and whole-record fences around immutable content publication.

use super::*;
use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext;
use crate::store::ContentValidator;

/// Groups the ordinary stage inputs without constructing native permission.
pub(crate) struct NativeStage<'input, 'view> {
    /// The actual mutable bounded writer session.
    pub(crate) session: &'input mut WriterSession,
    /// The already admitted candidate; no work is synthesized by this carrier.
    pub(crate) admitted: &'input mut AdmittedCommit,
    /// The original commit deadline origin.
    pub(crate) started: Duration,
    /// The same ordinary reflog reason selected by the publication producer.
    pub(crate) reason: RefLogReason,
    /// The independently selected original/history observations.
    pub(crate) observation: super::super::PublicationObservation<'view>,
    /// The actual predecessor whole Ref record, if already retained.
    pub(crate) retained_previous: Option<&'input RefRecord>,
}

impl<F, B, V, C, R> Coordinator<HeldBucket<'_, F, B, V, true>, C, R>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    /// Stages the same checked candidate with concrete native metadata runs.
    ///
    /// # Errors
    /// Preserves every generic stage fence, validation, current/Original/source,
    /// deadline and log failure; retains native checks through durable effects.
    pub(crate) async fn stage_observed_ref_native(
        &self,
        inputs: NativeStage<'_, '_>,
        context: &ImmutableEffectContext<'_, '_>,
    ) -> Result<RefRecord, AdvanceError> {
        let NativeStage {
            session,
            admitted,
            started,
            reason,
            observation,
            retained_previous,
        } = inputs;

        #[cfg(test)]
        let mut trace = super::super::PhaseTrace::new(
            self.guard.clock(),
            session.reference(),
            Some(admitted.commit.identity()),
            Some(started),
            "stage-entry",
        );
        match self
            .stage_start(
                session,
                admitted,
                observation,
                #[cfg(test)]
                &mut trace,
            )
            .await?
        {
            StageDisposition::Fenced => return self.fence(session).await,
            StageDisposition::PreserveLosing => {
                self.publish_immutable_native(admitted, started, observation.history, context)
                    .await?;
                return self.fence(session).await;
            }
            StageDisposition::Current => {}
        }
        #[cfg(test)]
        trace.mark("stage-immutable-start");
        self.publish_immutable_native(admitted, started, observation.history, context)
            .await?;
        #[cfg(test)]
        trace.mark("stage-immutable-durable");
        self.stage_finish(
            StageFinish {
                session,
                admitted,
                started,
                reason,
                observation,
                retained_previous,
            },
            #[cfg(test)]
            &mut trace,
        )
        .await
    }

    async fn publish_immutable_native(
        &self,
        admitted: &AdmittedCommit,
        started: Duration,
        observation: HistoryObservation<'_>,
        context: &ImmutableEffectContext<'_, '_>,
    ) -> Result<(), AdvanceError> {
        #[cfg(test)]
        let mut trace = super::super::PhaseTrace::new(
            self.guard.clock(),
            admitted
                .commit
                .commit()
                .profile_pair
                .commit_context
                .as_ref()
                .map_or("<missing-signed-context>", |context| context.reference()),
            Some(admitted.commit.identity()),
            Some(started),
            "immutable-entry",
        );
        self.immutable_start(
            admitted,
            started,
            observation,
            #[cfg(test)]
            &mut trace,
        )
        .await?;
        let mut offset = 0;
        while offset < admitted.uploads.len() {
            self.check_time(started)?;
            let first = offset;
            while offset < admitted.uploads.len()
                && matches!(&admitted.uploads[offset], crate::guard::StagedUpload::Meta { kind, .. }
                    if !matches!(kind, IdentityKind::Pack | IdentityKind::Index))
            {
                offset += 1;
            }
            if offset == first {
                self.store()
                    .put_contextual(admitted.uploads[offset].as_upload()?, context)
                    .await?;
                offset += 1;
            } else {
                let mut uploads = Vec::with_capacity(offset - first);
                for upload in &admitted.uploads[first..offset] {
                    match upload.as_upload()? {
                        ContentUpload::Meta(meta) => uploads.push(meta),
                        ContentUpload::Chunk(_) => return Err(crate::guard::invalid().into()),
                    }
                }
                match self.store().put_meta_batch(&uploads, context).await? {
                    crate::bucket::held::BatchOutcome::Complete(identities) => {
                        if identities.len() != uploads.len() {
                            return Err(crate::guard::invalid().into());
                        }
                        for (identity, upload) in identities.iter().zip(&uploads) {
                            if TERRANE_V1
                                .calculate(upload.kind(), upload.bytes())
                                .map_err(|_| crate::guard::invalid())?
                                != *identity
                            {
                                return Err(crate::guard::invalid().into());
                            }
                        }
                    }
                    crate::bucket::held::BatchOutcome::Sequential => {
                        for upload in &admitted.uploads[first..offset] {
                            self.store()
                                .put_contextual(upload.as_upload()?, context)
                                .await?;
                            self.check_time(started)?;
                        }
                    }
                }
            }
            self.check_time(started)?;
        }
        #[cfg(test)]
        trace.mark("immutable-upload-bodies-durable");
        // Signed Commit remains a separate ordinary admission after all inputs.
        // It carries the same actual context and deadline, rather than extending
        // generic Store semantics or treating a body as publication authority.
        let bytes = admitted
            .commit
            .commit()
            .encode()
            .map_err(|_| crate::guard::invalid())?;
        let actual = self
            .store()
            .put_contextual(
                ContentUpload::Meta(MetaUpload::new(IdentityKind::Commit, &bytes)?),
                context,
            )
            .await?;
        let expected = TERRANE_V1
            .from_digest(IdentityKind::Commit, &admitted.commit.identity())
            .map_err(|_| crate::guard::invalid())?;
        if actual != expected {
            return Err(crate::guard::invalid().into());
        }
        self.check_time(started)
    }
}
