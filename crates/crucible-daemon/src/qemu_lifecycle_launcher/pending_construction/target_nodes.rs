//! Moves the Source-paid selected launch rows through their original Main owner.
//!
//! These methods borrow the actual F-typed Source Pending selected by Main.
//! The same Vec is lent once and must return before Source cleanup can dispose
//! its World-paid payload. A layout or matching name grants no native role.

use super::*;
use crate::qemu_hot_fork_reconciliation::TargetNodeConstruction;

impl<F: QemuAttemptResourceGuardFactory> PendingSourceConstruction<F> {
    /// Moves the same pristine rows before any Target construction operation.
    pub(crate) fn take_target_nodes(
        &mut self,
    ) -> Option<(
        Vec<TargetNodeConstruction<F::Guard>>,
        Vec<TargetNodeConstruction<F::Guard>>,
        crucible_qemu::QemuHotForkWorkerGeometry,
    )> {
        if self.target_nodes_lent || self.target_retained_nodes_lent {
            return None;
        }
        let rows = self.target_nodes.as_ref()?;
        let retained = self.target_retained_nodes.as_ref()?;
        let source = self.target_node_selection.as_ref()?;
        if rows.is_empty()
            || !rows
                .iter()
                .all(|row| row.is_vacant() && row.belongs_to(source))
            || !source.matches_nodes(rows.iter().map(|row| &row.node))
            || !source.matches_nodes(retained.iter().map(|row| &row.node))
            || !retained
                .iter()
                .all(|row| row.is_vacant() && row.belongs_to(source))
        {
            return None;
        }
        let geometry = self.worker_geometry?;
        // Every refusal precedes these pure moves; neither owned Vec can be
        // lost because a second Option unexpectedly disappeared after a take.
        let (rows, retained) = match (self.target_nodes.take(), self.target_retained_nodes.take()) {
            (Some(rows), Some(retained)) => (rows, retained),
            (rows, retained) => {
                self.target_nodes = rows;
                self.target_retained_nodes = retained;
                return None;
            }
        };
        self.target_nodes_lent = true;
        self.target_retained_nodes_lent = true;
        Some((rows, retained, geometry))
    }

    /// Restores only this Source's actual closed selected storage.
    ///
    /// Native Target return, external Loop destruction and terminal history
    /// disposal precede this pure move. An uncertain/foreign handback returns
    /// the same Vec without dropping a row or changing the outstanding latch.
    pub(crate) fn return_target_nodes(
        &mut self,
        rows: Vec<TargetNodeConstruction<F::Guard>>,
    ) -> Result<(), Vec<TargetNodeConstruction<F::Guard>>> {
        let Some(source) = self.target_node_selection.as_ref() else {
            return Err(rows);
        };
        if !self.target_nodes_lent
            || self.target_nodes.is_some()
            || rows.is_empty()
            || !rows
                .iter()
                .all(|row| row.is_vacant() && row.belongs_to(source))
            || !source.matches_nodes(rows.iter().map(|row| &row.node))
        {
            return Err(rows);
        }
        self.target_nodes = Some(rows);
        self.target_nodes_lent = false;
        Ok(())
    }

    /// Restores the other prepaid allocation only after terminal history disposal.
    pub(crate) fn return_target_retained_nodes(
        &mut self,
        rows: Vec<TargetNodeConstruction<F::Guard>>,
    ) -> Result<(), Vec<TargetNodeConstruction<F::Guard>>> {
        let Some(source) = self.target_node_selection.as_ref() else {
            return Err(rows);
        };
        if !self.target_retained_nodes_lent
            || self.target_retained_nodes.is_some()
            || rows.is_empty()
            || !rows
                .iter()
                .all(|row| row.is_vacant() && row.belongs_to(source))
            || !source.matches_nodes(rows.iter().map(|row| &row.node))
        {
            return Err(rows);
        }
        self.target_retained_nodes = Some(rows);
        self.target_retained_nodes_lent = false;
        Ok(())
    }

    /// Disposes the vacant payload before its actual World controls can return.
    pub(super) fn close_target_nodes(
        &mut self,
    ) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        if self.target_nodes_lent
            || self.target_retained_nodes_lent
            || self
                .target_nodes
                .as_ref()
                .is_some_and(|rows| !rows.iter().all(|row| row.is_vacant()))
            || self
                .target_retained_nodes
                .as_ref()
                .is_some_and(|rows| !rows.iter().all(|row| row.is_vacant()))
        {
            return Err(crate::ProductionVmConstructionCleanupError::Retained(
                "Source retains its checked-out Target launch storage",
            ));
        }
        // Cleanup runs outside the Source mutex. Every owned target/body/report
        // is already absent; only this Source-paid metadata payload is disposed.
        self.target_nodes = None;
        self.target_retained_nodes = None;
        self.target_node_selection = None;
        // The original Source generation owner is not necessarily still live:
        // external body destruction may precede this exact metadata handback.
        // Dispose the remaining alias only after every lent row came back.
        self.target_node_storage = None;
        Ok(())
    }
}
