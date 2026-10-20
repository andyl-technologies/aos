//! Moves actual post-body obligations before disposing World-owned fields.
//!
//! The Main-paid Pending retains each extracted obligation before any body
//! destructor can unwind. A consumed proof, missing loan or transferred shell
//! never substitutes for World return.

use super::*;

type CleanupError = crate::ProductionVmConstructionCleanupError;
type PostBody = crate::ProductionVmConstructionPostBody;

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    pub(super) fn take_retained_post_body(&mut self) -> Result<Option<PostBody>, CleanupError> {
        self.require_external_body_acceptance()?;
        if !self.body_cleanup_complete {
            return Err(CleanupError::Retained(
                "same Pending body cleanup is incomplete",
            ));
        }
        if self.post_body_taken {
            return Ok(None);
        }

        if !self.body_disposed {
            if self.post_body.is_none() {
                self.post_body = Some(self.extract_post_body()?);
            }
            // The actual obligation is now inside the same Main-paid owner.
            // A destructor unwind leaves that owner poisoned and retained; it
            // cannot turn a moved loan into successful body disposal.
            self.launch_input = None;
            self.launcher = None;
            self.construction_custody = None;
            self.checkpoint_input = None;
            self.generation_storage = None;
            self.returned_guard = None;
            // World/Target postbody return retains the original native guard
            // itself. This extra caller alias must close before actual World
            // return; Main continues funding its allocation through role Free.
            self.world_admission = None;
            self.finish_launcher = None;
            self.take_launcher_post_body = None;
            self.body_disposed = true;
        }

        self.post_body_taken = true;
        Ok(self.post_body.take())
    }

    /// A transferred shell stays returnable until Main owns its actual body.
    pub(super) fn require_external_body_acceptance(&mut self) -> Result<(), CleanupError> {
        if !self.transferred {
            return Ok(());
        }
        match self.service.external_body_accepted() {
            Ok(true) => Ok(()),
            Ok(false) => Err(CleanupError::Retained(
                "same external Source body has not entered Main custody",
            )),
            Err(first) => {
                self.history.body_acceptance.get_or_insert(first);
                Err(CleanupError::Retained(
                    "same external Source body acceptance is unobservable",
                ))
            }
        }
    }

    fn extract_post_body(&mut self) -> Result<PostBody, CleanupError> {
        if self.controls.is_some()
            || self.returned_guard.is_some()
            || self.generation_storage.is_some()
        {
            return Err(CleanupError::Retained(
                "same Pending still owns native body members",
            ));
        }
        // Exactly one local phase can own this World's obligation. A completed
        // transfer owns none locally and must merge with its external launcher
        // in Main; its history-only value cannot close the role alone.
        let local_owners = usize::from(self.carrier_active)
            + usize::from(self.launch_input.is_some())
            + usize::from(self.launcher.is_some())
            + usize::from(self.world.is_some())
            + usize::from(self.not_started.is_some());
        if local_owners != 1 && !(local_owners == 0 && self.transferred) {
            return Err(CleanupError::Retained(
                "same Pending post-body phase is inconsistent",
            ));
        }

        if self.carrier_active {
            let custody = self
                .construction_custody
                .as_mut()
                .ok_or(CleanupError::Retained(
                    "same active construction carrier is absent",
                ))?;
            return ProductionVmCleanupOwner::take_post_body(custody.as_mut())?.ok_or(
                CleanupError::Retained("same construction carrier has no post-body obligation"),
            );
        }
        if let Some(launcher) = self.launch_input.as_mut() {
            return ProductionVmCleanupOwner::take_post_body(launcher.as_mut())?.ok_or(
                CleanupError::Retained("same launcher input has no post-body obligation"),
            );
        }
        if let Some(launcher) = self.launcher.as_mut() {
            let take = self.take_launcher_post_body.ok_or(CleanupError::Retained(
                "same retained launcher post-body projection is absent",
            ))?;
            return take(launcher.as_mut())?.ok_or(CleanupError::Retained(
                "same retained launcher has no post-body obligation",
            ));
        }
        if let Some(world) = self.world.take() {
            return Ok(PostBody::world(world, None));
        }
        if let Some(not_started) = self.not_started.take() {
            return Ok(PostBody::never_entered(not_started));
        }
        Ok(PostBody::history_only())
    }
}
