//! Closes a node landing only from the actual host-control retirement owners.
// SPDX-License-Identifier: Apache-2.0

use super::*;

impl AuthenticatedNativeNodeHostWindow {
    pub(in super::super) fn matches(&self, subdivision: &AuthenticatedNativeSubdivision) -> bool {
        subdivision.node.as_ref().is_some_and(|node| {
            node.assignment_epoch == self.assignment_epoch
                && node.world_epoch == self.world_epoch
                && node.node_index == self.node_index
                && node
                    .held
                    .as_ref()
                    .zip(self.held.as_ref())
                    .is_some_and(|(left, right)| Arc::ptr_eq(left, right))
        })
    }

    pub(in super::super) fn close_after_controls(&mut self) -> Result<(), ServiceBirthError> {
        if self.closed {
            return Ok(());
        }
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native landing custody is absent"))?;
        let mut ledger = held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native landing retirement is uncertain"))?;
        let peak = ledger.window_peak(
            self.world_epoch,
            self.assignment_epoch,
            self.node_index,
            self.role,
        )?;
        held.root
            .owner
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
            .close_pool_windows(peak)?;
        ledger.close_window(
            self.world_epoch,
            self.assignment_epoch,
            self.node_index,
            self.role,
        )?;
        self.closed = true;
        Ok(())
    }

    /// Observes the exact already assigned landing peak without opening a table.
    ///
    /// # Errors
    /// Refuses lost custody, a stale assignment or uncertain containing ledger.
    pub fn descriptor_peak(&self) -> Result<u64, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native window custody is absent"))?;
        held.root.check()?;
        held.ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native pool ledger is uncertain"))?
            .window_peak(
                self.world_epoch,
                self.assignment_epoch,
                self.node_index,
                self.role,
            )
    }
}

impl Drop for AuthenticatedNativeNodeHostWindow {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            if !self.closed {
                std::mem::forget(held);
            }
        }
    }
}
