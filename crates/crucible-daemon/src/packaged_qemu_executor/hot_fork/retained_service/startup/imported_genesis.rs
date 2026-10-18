//! Preserves parent-authenticated input through an independent genesis World.
//!
//! The capsule never consumes its one-shot replay selection here. Only the
//! Main queue's checked physical-return projection may export it to replay.

use super::*;

impl RetainedServiceStart {
    pub(in crate::packaged_qemu_executor::hot_fork::retained_service) fn start_imported_genesis(
        &mut self,
        factory: &RetainedTemplateServiceFactory,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceAdmissionError> {
        let imported = self
            .imported
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?;
        if !imported.is_unlaunched() || self.parent_receiver.is_some() {
            return Err(HostOperationalError::Unavailable.into());
        }
        imported
            .check_original()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        self.imported_export_pending = true;
        // Genesis creates separate borrowed controls. Its additional receiver
        // covers those aliases; the capsule keeps its own receiver for replay.
        match imported
            .authentication_owner()
            .retain_service_receiver("retain imported genesis ancestry")
        {
            Ok(receiver) => self.parent_receiver = receiver,
            Err(first) => {
                if self.first.is_none() {
                    self.first = Some(RetainedServiceStartCause::Parent(first));
                }
                return Err(HostOperationalError::Unavailable.into());
            }
        }
        let original = imported
            .authentication_owner()
            .host_operation_supervisor()
            .ok_or(HostOperationalError::Unavailable)?;
        let constrained = factory.clone().with_outer_supervisor(original.clone());
        let basis = imported.basis().ok_or(HostOperationalError::Unavailable)?;
        let started = Self::start_fields(
            &mut self.attempted,
            &mut self.phase,
            &mut self.admission,
            ServiceContextBinding::Main(self.preclaim.as_ref()),
            &constrained,
            &basis.source,
            None,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        );
        let post = imported.check_original();
        if self.imported_genesis_post.is_none() {
            self.imported_genesis_post = post.as_ref().err().copied();
        }
        started?;
        post.map_err(|source| HostOperationalError::OriginalBoundary { source }.into())
    }

    /// Applies the existing post-start budget update under the same import.
    pub(crate) fn update_imported_genesis_budgets(
        &mut self,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let result: Result<(), RetainedServiceAdmissionError> = (|| {
            let imported = self
                .imported
                .as_ref()
                .ok_or(HostOperationalError::Unavailable)?;
            if !self.imported_export_pending || !imported.is_unlaunched() {
                return Err(HostOperationalError::Unavailable.into());
            }
            imported
                .check_original()
                .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
            let budgets = imported
                .basis()
                .ok_or(HostOperationalError::Unavailable)?
                .budgets;
            let service = match &self.phase {
                ServiceStartPhase::Ready(service) if self.first.is_none() => service,
                _ => return Err(HostOperationalError::Unavailable.into()),
            };
            let effect = service
                .context()
                .host_operation_supervisor()
                .ok_or(HostOperationalError::Unavailable)?
                .update_budgets(0, budgets);
            let post = imported.check_original();
            if self.imported_genesis_post.is_none() {
                self.imported_genesis_post = post.as_ref().err().copied();
            }
            effect.map_err(|source| HostOperationalError::OriginalBoundary { source })?;
            post.map_err(|source| HostOperationalError::OriginalBoundary { source })?;
            Ok(())
        })();
        result.map_err(|first| self.refuse(first))
    }

    /// Copies only the capture source under the caller's actual decode account.
    ///
    /// The caller retains a receiver before projection, releases this Service
    /// lock before World admission, and destroys the copy before acknowledging
    /// that receiver. The original capsule stays in this Main throughout.
    pub(crate) fn project_imported_genesis_source(
        &mut self,
    ) -> Result<ScenarioDefForm, RetainedServiceStartRefusal> {
        let Some(imported) = self.imported.as_ref() else {
            return Err(RetainedServiceStartRefusal);
        };
        if !self.imported_export_pending || self.ready().is_none() || !imported.is_unlaunched() {
            return Err(RetainedServiceStartRefusal);
        }
        if let Err(source) = imported.check_original() {
            return Err(self.refuse(HostOperationalError::OriginalBoundary { source }.into()));
        }
        let copied = match imported.basis() {
            Some(basis) => basis.source.try_clone_admitted(),
            None => return Err(RetainedServiceStartRefusal),
        };
        let post = imported.check_original();
        if self.imported_genesis_post.is_none() {
            self.imported_genesis_post = post.as_ref().err().copied();
        }
        match copied {
            Err(first) => {
                if self.first.is_none() {
                    self.first = Some(RetainedServiceStartCause::GenesisSource(first));
                }
                Err(RetainedServiceStartRefusal)
            }
            Ok(source) => {
                post.map_err(|source| {
                    self.refuse(HostOperationalError::OriginalBoundary { source }.into())
                })?;
                Ok(source)
            }
        }
    }

    /// Borrows the independent original post from genesis input projections.
    pub(crate) fn imported_genesis_post_failure(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.imported_genesis_post.as_ref()
    }

    /// Moves pristine parent-paid input only from the checked World-return cut.
    ///
    /// The sole caller uses Main.with_start_after_world_return. This method
    /// performs no work and does not reopen the consumed genesis producer.
    pub(crate) fn take_unlaunched_import_after_world_return(
        &mut self,
    ) -> Result<crate::imported_checkpoint::RetainedImportedCheckpoint, RetainedServiceStartRefusal>
    {
        if !self.imported_export_pending
            || self.first.is_some()
            || !matches!(self.phase, ServiceStartPhase::Ready(_))
            || !self
                .imported
                .as_ref()
                .is_some_and(|input| input.is_unlaunched())
        {
            return Err(RetainedServiceStartRefusal);
        }
        let Some(imported) = self.imported.take() else {
            return Err(RetainedServiceStartRefusal);
        };
        self.imported_export_pending = false;
        Ok(imported)
    }
}
