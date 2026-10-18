//! Retires a failed rearm through its same original construction carrier.
//!
//! The failed Loop, capture metadata and raw causes stay together. Native body
//! cleanup uses the ordinary Source retirement engine and its saved Cleanup.
//! The original failure moves into terminal history before the carrier dies.

use super::*;
use std::error::Error;
use std::fmt;

type CleanupError = crate::ProductionVmConstructionCleanupError;

pub(in crate::vm_lifecycle) struct SourceRearmBody {
    failure: ProductionVmHotForkSourceWorldPreparationFailure,
    source: Option<ProductionVmHotForkSourceWorld>,
    history_transferred: bool,
}

/// Keeps original rearm diagnostics after actual native body destruction.
///
/// The accessors borrow the same retained causes and diagnostics; this history
/// grants no cleanup or Source rearm authority. Typed inspection uses
/// [`Self::first_error`] rather than a dynamic error chain.
#[derive(Debug)]
pub struct SourceRearmHistory {
    first: Option<preparation::ProductionVmHotForkSourcePreparationError>,
    message: String,
    unreconciled_nodes: Vec<NodeId>,
    rollback_diagnostics: BTreeMap<NodeId, String>,
}

impl SourceRearmHistory {
    /// Reports whether every retained cause and diagnostic is absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.first.is_none()
            && self.message.is_empty()
            && self.unreconciled_nodes.is_empty()
            && self.rollback_diagnostics.is_empty()
    }

    /// Borrows the original typed rearm refusal without following another owner.
    #[must_use]
    pub fn first_error(&self) -> Option<&ProductionVmHotForkSourcePreparationError> {
        self.first.as_ref()
    }

    /// Borrows the retained preparation diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Borrows the original list of nodes whose rollback remains unresolved.
    #[must_use]
    pub fn unreconciled_nodes(&self) -> &[NodeId] {
        &self.unreconciled_nodes
    }

    /// Borrows the original per-node rollback diagnostics without copying them.
    #[must_use]
    pub fn rollback_diagnostics(&self) -> &BTreeMap<NodeId, String> {
        &self.rollback_diagnostics
    }
}

impl fmt::Display for SourceRearmHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(first) = &self.first {
            write!(formatter, "Source rearm: {first}")?;
        } else {
            write!(formatter, "Source rearm: {}", self.message)?;
        }
        write!(
            formatter,
            "; unreconciled={:?}; rollback={:?}",
            self.unreconciled_nodes, self.rollback_diagnostics
        )
    }
}

impl Error for SourceRearmHistory {}

impl SourceRearmBody {
    pub(in crate::vm_lifecycle) fn new(
        failure: ProductionVmHotForkSourceWorldPreparationFailure,
    ) -> Self {
        Self {
            failure,
            source: None,
            history_transferred: false,
        }
    }

    pub(in crate::vm_lifecycle) fn retry_body(&mut self) -> Result<(), CleanupError> {
        if self.source.is_none() {
            if self.failure.retained_source.is_some() {
                return Err(CleanupError::Retained(
                    "rearm failure retains another Source",
                ));
            }
            let lifecycle = self.failure.lifecycle.take().ok_or(CleanupError::Retained(
                "failed Source rearm lifecycle is absent",
            ))?;
            let metadata = self.failure.metadata.get_or_insert_default();
            self.source = Some(ProductionVmHotForkSourceWorld {
                lifecycle: Some(lifecycle),
                continuation: metadata.continuation.take(),
                prepared: std::mem::take(&mut metadata.prepared),
                disk_custody: std::mem::take(&mut metadata.disk_custody),
                cleanup_observer: metadata.cleanup_observer.take(),
                retirement: None,
                target_backends_lent: false,
                #[cfg(feature = "private-measurement-domain")]
                managed_parent_park_history: metadata.managed_parent_park_history.take(),
            });
        }
        self.source
            .as_mut()
            .ok_or(CleanupError::Retained("failed Source rearm body is absent"))?
            .retry_source_retirement_body()
    }

    pub(in crate::vm_lifecycle) fn take_post_body(
        &mut self,
    ) -> Result<Option<crate::ProductionVmConstructionPostBody>, CleanupError> {
        let source = self.source.as_mut().ok_or(CleanupError::Retained(
            "failed Source rearm body was not retired",
        ))?;
        if !self.history_transferred {
            let history = source
                .retirement
                .as_mut()
                .filter(|state| state.body_closed)
                .and_then(|state| state.history.as_mut())
                .ok_or(CleanupError::Retained(
                    "Source retirement history is unavailable",
                ))?;
            if history.rearm.is_some() {
                return Err(CleanupError::Retained(
                    "Source rearm history is already occupied",
                ));
            }
            history.rearm = Some(SourceRearmHistory {
                first: self.failure.first.take(),
                message: std::mem::take(&mut self.failure.message),
                unreconciled_nodes: std::mem::take(&mut self.failure.unreconciled_nodes),
                rollback_diagnostics: std::mem::take(&mut self.failure.rollback_diagnostics),
            });
            self.history_transferred = true;
        }
        source.take_source_retirement_post_body()
    }
}

impl ProductionVmHotForkSourceWorldPreparationFailure {
    pub(super) fn retain_native_rearm_failure_on_drop(&mut self) -> bool {
        if self.retained_source.is_some() {
            return false;
        }
        let Some(lifecycle) = self.lifecycle.as_mut() else {
            return false;
        };
        let storage = std::mem::replace(
            &mut lifecycle.construction_custody,
            LifecycleConstructionCustody::Unissued(None),
        );
        let (carrier, destination) = match storage {
            LifecycleConstructionCustody::Main {
                carrier,
                destination,
            } => (carrier, destination),
            unissued @ LifecycleConstructionCustody::Unissued(_) => {
                lifecycle.construction_custody = unissued;
                return false;
            }
        };
        let retained = Self {
            retained_source: self.retained_source.take(),
            lifecycle: self.lifecycle.take(),
            message: std::mem::take(&mut self.message),
            first: self.first.take(),
            metadata: self.metadata.take(),
            unreconciled_nodes: std::mem::take(&mut self.unreconciled_nodes),
            rollback_diagnostics: std::mem::take(&mut self.rollback_diagnostics),
        };
        drop(destination.deliver(carrier.install_owned_source_rearm_failure(retained)));
        true
    }
}

#[cfg(test)]
mod tests;
