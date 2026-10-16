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

    /// Moves this exact node into its real normal family issuer.
    ///
    /// The genuine roster retains the consumed holder through exclusive control
    /// free. No scalar vector or decoded identity can construct this issuer.
    ///
    /// # Errors
    /// Retains a born issuer on independent post-refusal; rejects foreign or
    /// inactive Preparation, absent node custody or stale assignment.
    pub fn into_subdivision(
        self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedNativeSubdivision, NativePoolRefusal> {
        let mut born = None;
        let held = self.held.as_ref().cloned();
        let result = (|| {
            let held = held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
            held.root.verify_native_preparation(original)?;
            let bounds = self.bounds()?;
            born = Some(AuthenticatedNativeSubdivision {
                owner: Arc::clone(&held.root.owner),
                bounds,
                local_file_descriptors: bounds.file_descriptors / 2,
                node: Some(self),
            });
            Ok(())
        })();
        let after = postcut(held.as_ref(), original);
        match (result, after) {
            (Ok(()), None) => born.ok_or_else(|| NativePoolRefusal {
                cause: ServiceBirthError::policy("native node issuer is absent"),
                after: None,
                _retained: None,
            }),
            (result, after) => Err(NativePoolRefusal {
                cause: result.err().unwrap_or_else(|| {
                    ServiceBirthError::policy("native node issuer postcut refused")
                }),
                after,
                _retained: born.map(RetainedClaim::subdivision),
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
                after,
                _retained: None,
            }),
        }
    }

    pub(in super::super) fn retire_after_control_free(&mut self) -> Result<(), ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        if let Some(window) = self
            .target_window
            .get_mut()
            .map_err(|_| ServiceBirthError::policy("native Target landing custody is uncertain"))?
        {
            window.close_after_controls()?;
        }
        let mut ledger = held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
        let prepared =
            ledger.prepare_node_return(self.world_epoch, self.assignment_epoch, self.node_index)?;
        held.root
            .owner
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
            .close_pool_assignment(prepared.windows, prepared.tables)?;
        ledger.commit_node_return(prepared);
        drop(ledger);
        drop(self.held.take());
        Ok(())
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
            self.occupy_window(role)
        })();
        let after = postcut(self.held.as_ref(), original);
        match (result, after) {
            (Ok(window), None) => Ok(window),
            (Err(cause), after) => Err(NativePoolRefusal {
                cause,
                after,
                _retained: None,
            }),
            (Ok(window), Some(after)) => Err(NativePoolRefusal {
                cause: ServiceBirthError::policy("native window postcut refused"),
                after: Some(after),
                _retained: Some(RetainedClaim::window(window)),
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
