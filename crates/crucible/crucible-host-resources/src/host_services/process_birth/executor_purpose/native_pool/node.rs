//! Consumes a genuine node claim and retains its Source/Target allocation roles.
// SPDX-License-Identifier: Apache-2.0

use super::*;

impl AuthenticatedNativeNodeClaim {
    pub(in super::super) fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }

    pub(in super::super) fn pool_capacity(&self) -> Result<usize, ServiceBirthError> {
        self.bounds()?;
        self.held
            .as_ref()
            .map(|held| held.capacity)
            .ok_or_else(|| ServiceBirthError::policy("native node pool is absent"))
    }

    /// Moves the exact retained node into a prepaid subdivision destination.
    ///
    /// All prefix/bounds checks run while the node remains in its source slot.
    /// The destination owns the real subdivision before the independent post.
    /// Both slots belong to the same containing constructor; neither is credit
    /// without its genuine, already-issued native holder.
    ///
    /// # Errors
    /// Refuses absent source, occupied destination, wrong/inactive Preparation,
    /// stale bounds or independent post without discarding either actual owner.
    pub fn move_to_subdivision(
        source: &mut Option<Self>,
        destination: &mut Option<AuthenticatedNativeSubdivision>,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolRefusal> {
        let held = source.as_ref().and_then(|node| node.held.as_ref().cloned());
        let result = (|| {
            if destination.is_some() {
                return Err(ServiceBirthError::policy(
                    "native subdivision destination is occupied",
                ));
            }
            let held = held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
            let node = source
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node source is absent"))?;
            held.root.verify_native_preparation(original)?;
            let bounds = node.bounds()?;
            let node = source
                .take()
                .ok_or_else(|| ServiceBirthError::policy("native node source is absent"))?;
            *destination = Some(AuthenticatedNativeSubdivision {
                owner: Arc::clone(&held.root.owner),
                bounds,
                local_file_descriptors: bounds.file_descriptors / 2,
                node: Some(node),
            });
            Ok(())
        })();
        let after = postcut(held.as_ref(), original);
        match (result, after) {
            (Ok(()), None) => Ok(()),
            (result, after) => Err(NativePoolRefusal {
                cause: result.err().unwrap_or_else(|| {
                    ServiceBirthError::policy("native node issuer postcut refused")
                }),
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }

    pub(in super::super) fn reserve_target_window(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolRefusal> {
        let result = (|| {
            let held = self
                .held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
            held.root.verify_native_preparation(original)?;
            let mut window = self.target_window.lock().map_err(|_| {
                ServiceBirthError::policy("native Target landing custody is uncertain")
            })?;
            if window.is_none() {
                // Retain before the independent postcut, including refusal.
                *window = Some(self.occupy_window(WindowRole::Target)?);
            }
            window
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native Target landing is absent"))?
                .descriptor_peak()?;
            Ok(())
        })();
        let after = postcut(self.held.as_ref(), original);
        match (result, after) {
            (Ok(()), None) => Ok(()),
            (result, after) => Err(NativePoolRefusal {
                cause: result
                    .err()
                    .unwrap_or_else(|| ServiceBirthError::policy("Target landing postcut refused")),
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }

    pub(in super::super) fn retained_world_cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        let ledger = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
        ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)?;
        ledger.retained_cleanup(self.world_epoch)
    }

    pub(in super::super) fn verify_world_cleanup(
        &self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        {
            let ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
            ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)?;
            ledger.verify_cleanup(self.world_epoch, cleanup)?;
        }
        held.verify_return_custody(cleanup)?;
        held.ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?
            .verify_cleanup(self.world_epoch, cleanup)
    }

    /// Observes the recorded irreversible return of this exact node assignment.
    ///
    /// This factual observation issues no replacement member or readiness grant.
    #[must_use]
    pub fn is_physically_returned(&self) -> bool {
        self.held.is_none()
    }

    /// Returns a retained raw node before any subdivision was published.
    ///
    /// The actual holder resolves its same World's once-entered Cleanup. Native
    /// landing/descriptor predicates still refuse every issued unclosed alias;
    /// the caller supplies no assertion of control free or replacement clock.
    ///
    /// # Errors
    /// Retains the node on uncertain/live custody or saved Cleanup refusal.
    /// A late independent post may fail after actual return; observe that fact
    /// with [`Self::is_physically_returned`] before another retirement attempt.
    pub fn retire_before_subdivision(&mut self) -> Result<(), NativePoolReturnError> {
        if self.is_physically_returned() {
            return Ok(());
        }
        let cleanup = self.retained_world_cleanup()?;
        self.retire_after_control_free(&cleanup)
    }

    pub(in super::super) fn retire_after_control_free(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolReturnError> {
        let Some(held) = self.held.as_ref().cloned() else {
            return Ok(());
        };
        // Resolve only an already-latched result. Never run a postcheck against
        // a substituted operation or initialize missing Cleanup by verification.
        let saved = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?
            .saved_cleanup(self.world_epoch)?;
        if !Arc::ptr_eq(&saved, cleanup) {
            return Err(ServiceBirthError::policy("native node return Cleanup is foreign").into());
        }
        let result = (|| {
            self.verify_world_cleanup(&saved)?;
            if let Some(window) = self.target_window.get_mut().map_err(|_| {
                ServiceBirthError::policy("native Target landing custody is uncertain")
            })? {
                window.close_after_controls()?;
            }
            let mut ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
            ledger.verify_cleanup(self.world_epoch, &saved)?;
            let prepared = ledger.prepare_node_return(
                self.world_epoch,
                self.assignment_epoch,
                self.node_index,
            )?;
            let (work, consumed) = held
                .root
                .owner
                .host_descriptors
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
                .as_mut()
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
                .close_pool_assignment(prepared.windows, prepared.tables);
            if consumed {
                ledger.commit_node_return(prepared);
            }
            drop(ledger);
            if consumed {
                drop(self.held.take());
            }
            work
        })();
        NativePoolReturnError::finish(
            result,
            saved.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup),
        )
    }

    /// Takes the initial Source's separately reserved Main-table landing once.
    ///
    /// # Errors
    /// Refuses duplicate/stale custody or the same Original before/after entry.
    pub fn take_source_host_window(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedNativeNodeHostWindow, NativePoolRefusal> {
        self.take_window(WindowRole::Source, original)
    }

    /// Takes the Target's separately reserved Main-table landing once.
    ///
    /// This holder is funding only; a real Target permit/CPU handoff is required.
    ///
    /// # Errors
    /// Refuses duplicate/stale custody or the same Original before/after entry.
    pub fn take_target_host_window(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedNativeNodeHostWindow, NativePoolRefusal> {
        self.take_window(WindowRole::Target, original)
    }

    pub(in super::super) fn occupy_window(
        &self,
        role: WindowRole,
    ) -> Result<AuthenticatedNativeNodeHostWindow, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
        let mut ledger = held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native pool ledger is uncertain"))?;
        ledger.take_window(
            self.world_epoch,
            self.assignment_epoch,
            self.node_index,
            role,
        )?;
        Ok(AuthenticatedNativeNodeHostWindow {
            held: Some(Arc::clone(held)),
            world_epoch: self.world_epoch,
            assignment_epoch: self.assignment_epoch,
            node_index: self.node_index,
            role,
            closed: false,
        })
    }

    fn take_window(
        &self,
        role: WindowRole,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedNativeNodeHostWindow, NativePoolRefusal> {
        let result = (|| {
            let held = self
                .held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
            held.root.verify_native_preparation(original)?;
            let prepared = PreparedRefusal::reserve(&held.root.owner)?;
            let window = self.occupy_window(role)?;
            Ok((window, prepared))
        })();
        let after = postcut(self.held.as_ref(), original);
        match (result, after) {
            (Ok((window, _prepared)), None) => Ok(window),
            (Err(cause), after) => Err(NativePoolRefusal {
                cause,
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
            (Ok((window, prepared)), Some(after)) => Err(NativePoolRefusal {
                cause: ServiceBirthError::policy("native window postcut refused"),
                after: Some(after).into(),
                _retained: RetainedClaim::window(window, prepared),
            }),
        }
    }

    /// Observes this checked reservation's bounds without issuing new credit.
    ///
    /// # Errors
    /// Refuses lost custody, stale identity or uncertain containing ledger.
    pub fn bounds(&self) -> Result<HostResourceVector, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
        held.root.check()?;
        let ledger = held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native pool ledger is uncertain"))?;
        ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)
    }
}

impl Drop for AuthenticatedNativeNodeClaim {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            std::mem::forget(held);
        }
    }
}

#[cfg(test)]
mod tests;
